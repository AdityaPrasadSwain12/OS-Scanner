"""Bounded CycloneDX JSON export for normalized endpoint software inventory."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5

from app.models import ScanResult, Software
from app.reporting import AtomicReportWriter, serialize_report
from app.security import redact_text, redact_value

_SPEC_VERSION = "1.6"
_DEFAULT_MAX_COMPONENTS = 100_000
_PURL_TYPES = {
    "apk": "apk",
    "cargo": "cargo",
    "composer": "composer",
    "deb": "deb",
    "dpkg": "deb",
    "gem": "gem",
    "golang": "golang",
    "go": "golang",
    "homebrew": "brew",
    "brew": "brew",
    "maven": "maven",
    "npm": "npm",
    "nuget": "nuget",
    "pacman": "alpm",
    "pip": "pypi",
    "pypi": "pypi",
    "rpm": "rpm",
}


class SbomLimitError(ValueError):
    """Raised instead of silently emitting an incomplete component inventory."""


def _safe_text(value: str | None, *, maximum: int) -> str | None:
    if value is None:
        return None
    redacted = redact_text(value, max_length=maximum).strip()
    return redacted or None


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _property(name: str, value: str | None) -> dict[str, str] | None:
    return {"name": name, "value": value} if value is not None else None


def _software_completeness(result: ScanResult) -> str:
    observed = result.metadata.get("observed_inventory_sections")
    if isinstance(observed, list) and "software" in observed:
        return "observed"
    unobserved = result.metadata.get("unobserved_inventory_sections")
    if isinstance(unobserved, list) and "software" in unobserved:
        return "unobserved"
    return "unknown"


def _software_identity(software: Software) -> tuple[str, ...]:
    fields = (
        _safe_text(software.name, maximum=512),
        _safe_text(software.version, maximum=256),
        _safe_text(software.vendor, maximum=512),
        _safe_text(software.package_manager, maximum=128),
        _safe_text(software.architecture, maximum=64),
        _safe_text(software.source, maximum=256),
    )
    return tuple(value or "" for value in fields)


def _package_url(
    name: str,
    version: str,
    package_manager: str,
    architecture: str,
) -> str | None:
    """Create a conservative Package URL only for known package ecosystems.

    Free-form application names (for example Windows registry entries) are not
    guessed into an ecosystem because that would create misleading advisory
    matches. The original package-manager evidence remains in properties.
    """

    purl_type = _PURL_TYPES.get(package_manager.casefold())
    if not purl_type or not name or not version or "/" in name or "\\" in name:
        return None
    safe = ".-_~"
    value = f"pkg:{purl_type}/{quote(name, safe=safe)}@{quote(version, safe=safe)}"
    if architecture:
        value += f"?arch={quote(architecture, safe=safe)}"
    return value


def _component(identity: tuple[str, ...], installation_date: str | None) -> dict[str, Any]:
    name, version, vendor, package_manager, architecture, source = identity
    canonical = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
    reference = f"software:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
    component: dict[str, Any] = {
        "bom-ref": reference,
        "type": "library" if package_manager.casefold() in _PURL_TYPES else "application",
        "name": name,
    }
    if version:
        component["version"] = version
    if vendor:
        component["supplier"] = {"name": vendor}
    purl = _package_url(name, version, package_manager, architecture)
    if purl:
        component["purl"] = purl

    properties = [
        _property("com.endpoint-scanner.package-manager", package_manager or None),
        _property("com.endpoint-scanner.architecture", architecture or None),
        _property("com.endpoint-scanner.inventory-source", source or None),
        _property("com.endpoint-scanner.installation-date", installation_date),
    ]
    present = [item for item in properties if item is not None]
    if present:
        component["properties"] = present
    return component


def build_cyclonedx_sbom(
    result: ScanResult,
    *,
    max_components: int = _DEFAULT_MAX_COMPONENTS,
) -> dict[str, Any]:
    """Build a deterministic CycloneDX 1.6 document without filesystem access."""

    if not 1 <= max_components <= _DEFAULT_MAX_COMPONENTS:
        raise ValueError(f"max_components must be between 1 and {_DEFAULT_MAX_COMPONENTS}")
    if result.endpoint_id is None:
        raise ValueError("CycloneDX endpoint SBOM export requires an endpoint scan result")
    if len(result.software) > max_components:
        raise SbomLimitError(
            f"software inventory has {len(result.software)} records; maximum is {max_components}"
        )

    # Exact normalized duplicates collapse deterministically. If duplicate records disagree only
    # on installation date, retain the lexicographically earliest known value.
    records: dict[tuple[str, ...], str | None] = {}
    for software in result.software:
        identity = _software_identity(software)
        date = software.installation_date.isoformat() if software.installation_date else None
        previous = records.get(identity)
        if identity not in records or (date is not None and (previous is None or date < previous)):
            records[identity] = date

    components = [
        _component(identity, records[identity])
        for identity in sorted(
            records,
            key=lambda item: (tuple(part.casefold() for part in item), item),
        )
    ]
    endpoint_id = _safe_text(result.endpoint_id, maximum=128) or "unknown-endpoint"
    metadata_properties = [
        _property("com.endpoint-scanner.scan-id", _safe_text(result.scan_id, maximum=128)),
        _property("com.endpoint-scanner.endpoint-id", endpoint_id),
        _property("com.endpoint-scanner.scan-type", result.scan_type.value),
        _property("com.endpoint-scanner.scan-status", result.status.value),
        _property("com.endpoint-scanner.schema-version", result.schema_version),
        _property("com.endpoint-scanner.software-completeness", _software_completeness(result)),
        _property("com.endpoint-scanner.policy-id", _safe_text(result.policy_id, maximum=128)),
        _property(
            "com.endpoint-scanner.policy-version",
            _safe_text(result.policy_version, maximum=64),
        ),
        _property("com.endpoint-scanner.policy-checksum", result.policy_checksum),
    ]
    observed_at = result.finished_at or result.timestamp
    serial_seed = f"endpoint-security-scanner:{result.scan_id}:{endpoint_id}"
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": _SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, serial_seed)}",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(observed_at),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "endpoint-security-scanner",
                        "version": result.scanner_version,
                    }
                ]
            },
            "component": {
                "bom-ref": (
                    "endpoint:"
                    + hashlib.sha256(endpoint_id.encode("utf-8")).hexdigest()
                ),
                "type": "device",
                "name": "managed-endpoint",
            },
            "properties": [item for item in metadata_properties if item is not None],
        },
        "components": components,
    }
    redacted = redact_value(
        document,
        max_depth=12,
        max_nodes=max(20_000, len(components) * 40 + 1_000),
    )
    if not isinstance(redacted, dict):
        raise ValueError("SBOM redaction produced an invalid document")
    return redacted


def serialize_cyclonedx_sbom(
    result: ScanResult,
    *,
    max_components: int = _DEFAULT_MAX_COMPONENTS,
    max_bytes: int = 50 * 1024 * 1024,
) -> bytes:
    """Serialize a deterministic, privacy-redacted CycloneDX JSON document."""

    document = build_cyclonedx_sbom(result, max_components=max_components)
    return serialize_report(document, max_bytes=max_bytes, redactor=redact_value)


class AtomicCycloneDxWriter:
    """Persist CycloneDX JSON atomically with the report writer's safe permissions."""

    def __init__(
        self,
        directory: Path,
        *,
        max_components: int = _DEFAULT_MAX_COMPONENTS,
        max_bytes: int = 50 * 1024 * 1024,
    ) -> None:
        if not 1 <= max_components <= _DEFAULT_MAX_COMPONENTS:
            raise ValueError(f"max_components must be between 1 and {_DEFAULT_MAX_COMPONENTS}")
        self.max_components = max_components
        self._writer = AtomicReportWriter(directory, max_bytes=max_bytes)

    def write(self, result: ScanResult) -> Path:
        document = build_cyclonedx_sbom(result, max_components=self.max_components)
        return self._writer.write(f"{result.scan_id}.cdx", document, redactor=redact_value)
