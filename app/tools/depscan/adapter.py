"""Bounded OWASP dep-scan adapter for approved local evidence.

The adapter deliberately consumes dep-scan's CycloneDX VDR artifact instead of
scraping its console tables.  A request may identify either an existing
CycloneDX SBOM or an approved source directory from which dep-scan generates an
SBOM.  Caller-controlled command fragments, templates, remote URLs, images,
custom databases, and arbitrary cdxgen arguments are not accepted.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from app.tools._validation import (
    approved_local_path,
    clean_text,
    parse_json_document,
    read_bounded_text,
)
from app.tools.base import ToolAdapter, ToolExecution, ToolState
from app.tools.runner import SafeSubprocessRunner, ToolUnavailableError

_VERSION_PATTERN = re.compile(r"\b\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9_.-]+)?\b")
_SUPPORTED_CYCLONEDX_VERSIONS = {"1.4", "1.5", "1.6", "1.7"}
_PROFILES = {
    "appsec",
    "generic",
    "operational",
    "research",
    "threat-modeling",
}
_SEVERITIES = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "none": "INFO",
    "unknown": "UNKNOWN",
    "unspecified": "UNKNOWN",
}
_SEVERITY_RANK = {
    "UNKNOWN": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}
_DEFAULT_EXECUTABLES = (
    "depscan",
    "depscan.exe",
    "depscan-windows-amd64.exe",
    "depscan-linux-amd64",
    "depscan-linux-arm64",
    "depscan-linux-amd64-musl",
    "depscan-linux-arm64-musl",
    "depscan-darwin-amd64",
    "depscan-darwin-arm64",
)


class DepScanMode(StrEnum):
    """Explicit, non-overlapping dep-scan input contracts."""

    LIVE_OS = "LIVE_OS"
    SOURCE = "SOURCE"
    SBOM = "SBOM"


@dataclass(frozen=True, slots=True)
class DepScanRequest:
    """One dependency assessment over live OS data or approved local evidence."""

    mode: DepScanMode
    source: Path | None = None
    profile: str = "operational"
    deep: bool = True


class DepScanAdapter(
    ToolAdapter[DepScanRequest, dict[str, Any], list[dict[str, Any]]]
):
    """Execute dep-scan without a shell and normalize its CycloneDX VDR."""

    name = "depscan"

    def __init__(
        self,
        *,
        approved_roots: tuple[str | Path, ...] = (),
        runner: SafeSubprocessRunner | None = None,
        executable: str | None = None,
        timeout_seconds: float = 900.0,
        max_console_bytes: int = 2 * 1024 * 1024,
        max_report_bytes: int = 50 * 1024 * 1024,
        max_report_files: int = 512,
        max_vulnerabilities: int = 100_000,
        max_components: int = 250_000,
        max_source_files: int = 250_000,
        max_source_bytes: int = 20 * 1024 * 1024 * 1024,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        if not 1024 <= max_console_bytes <= 100 * 1024 * 1024:
            raise ValueError("dep-scan console limit must be between 1 KiB and 100 MiB")
        if not 1024 <= max_report_bytes <= 100 * 1024 * 1024:
            raise ValueError("dep-scan report limit must be between 1 KiB and 100 MiB")
        if not 1 <= max_report_files <= 10_000:
            raise ValueError("dep-scan report-file limit must be between 1 and 10000")
        if not 1 <= max_vulnerabilities <= 1_000_000:
            raise ValueError("invalid dep-scan vulnerability limit")
        if not 1 <= max_components <= 1_000_000:
            raise ValueError("invalid dep-scan component limit")
        if not 1 <= max_source_files <= 1_000_000:
            raise ValueError("invalid dep-scan source-file limit")
        if not 1024 <= max_source_bytes <= 1024 * 1024 * 1024 * 1024:
            raise ValueError("invalid dep-scan source-size limit")

        self._approved_roots = tuple(
            Path(item).expanduser().resolve(strict=False) for item in approved_roots
        )
        self._executable_candidates = (
            (executable,) if executable is not None else _DEFAULT_EXECUTABLES
        )
        self._runner = runner or SafeSubprocessRunner(
            self._executable_candidates,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_console_bytes,
            environment=environment,
        )
        self._max_report_bytes = max_report_bytes
        self._max_report_files = max_report_files
        self._max_vulnerabilities = max_vulnerabilities
        self._max_components = max_components
        self._max_source_files = max_source_files
        self._max_source_bytes = max_source_bytes

    def _find_executable(self) -> str | None:
        return next(
            (
                candidate
                for candidate in self._executable_candidates
                if self._runner.is_available(candidate)
            ),
            None,
        )

    def executable_path(self) -> str | None:
        executable = self._find_executable()
        if executable is None:
            return None
        resolved = self._runner.resolve(executable)
        return str(resolved) if resolved is not None else None

    def is_available(self) -> bool:
        return self._find_executable() is not None

    def version(self, *, timeout_seconds: float = 5.0) -> str | None:
        if not 0 < timeout_seconds <= 60:
            raise ValueError("version timeout must be between 0 and 60 seconds")
        executable = self._find_executable()
        if executable is None:
            return None
        try:
            result = self._runner.run(executable, ("--version",), timeout_seconds=timeout_seconds)
        except (OSError, ValueError):
            return None
        if not result.succeeded:
            return None
        combined = f"{result.stdout} {result.stderr}"
        match = _VERSION_PATTERN.search(combined)
        return match.group(0) if match else clean_text(combined, maximum=128) or None

    def validate_input(self, value: DepScanRequest) -> DepScanRequest:
        return self._validate_input(value, deadline_at=None)

    def _validate_input(
        self, value: DepScanRequest, *, deadline_at: float | None
    ) -> DepScanRequest:
        if not isinstance(value, DepScanRequest):
            raise TypeError("dep-scan input must be a DepScanRequest")
        if not isinstance(value.mode, DepScanMode):
            raise TypeError("dep-scan mode must be a DepScanMode")
        profile = clean_text(value.profile, maximum=64).casefold()
        if profile not in _PROFILES:
            raise ValueError("unsupported dep-scan profile")
        if type(value.deep) is not bool:
            raise TypeError("dep-scan deep flag must be a boolean")
        if value.mode is DepScanMode.LIVE_OS:
            if value.source is not None:
                raise ValueError("live OS dep-scan does not accept a caller-selected source")
            if value.deep is not True:
                raise ValueError("live OS dep-scan always requires deep analysis")
            return replace(value, profile=profile)
        if value.source is None:
            raise ValueError("source and SBOM dep-scan modes require a local source")
        source = approved_local_path(value.source, self._approved_roots)
        if value.mode is DepScanMode.SBOM:
            if not source.is_file():
                raise ValueError("SBOM dep-scan mode requires a regular file")
            self._validate_sbom(source)
        elif value.mode is DepScanMode.SOURCE:
            if not source.is_dir():
                raise ValueError("source dep-scan mode requires a directory")
            self._validate_directory_scope(source, deadline_at=deadline_at)
        else:  # pragma: no cover - exhaustive guard for future enum members
            raise ValueError("unsupported dep-scan mode")
        return replace(value, source=source, profile=profile)

    def _validate_sbom(self, source: Path) -> None:
        if not source.name.casefold().endswith((".json", ".cdx")):
            raise ValueError("dep-scan file input must be a CycloneDX JSON SBOM")
        document = parse_json_document(
            read_bounded_text(source, max_bytes=self._max_report_bytes),
            max_chars=self._max_report_bytes,
        )
        if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
            raise ValueError("dep-scan file input must be a CycloneDX JSON SBOM")
        spec_version = clean_text(document.get("specVersion"), maximum=16)
        if spec_version not in _SUPPORTED_CYCLONEDX_VERSIONS:
            raise ValueError("unsupported CycloneDX SBOM specification version")
        components = document.get("components", [])
        if not isinstance(components, list):
            raise ValueError("CycloneDX components must be an array")
        if len(components) > self._max_components:
            raise ValueError("CycloneDX SBOM contains too many top-level components")

    def _validate_directory_scope(
        self, source: Path, *, deadline_at: float | None
    ) -> None:
        root = source.resolve(strict=True)
        stack = [root]
        visited: set[Path] = set()
        file_count = 0
        total_bytes = 0
        while stack:
            directory = stack.pop()
            canonical_directory = directory.resolve(strict=True)
            if canonical_directory in visited:
                continue
            if canonical_directory != root and not canonical_directory.is_relative_to(root):
                raise PermissionError("dep-scan source tree escapes the selected directory")
            visited.add(canonical_directory)
            with os.scandir(canonical_directory) as entries:
                for entry in entries:
                    if deadline_at is not None and time.monotonic() >= deadline_at:
                        raise TimeoutError(
                            "scan deadline exceeded during dep-scan source validation"
                        )
                    try:
                        canonical = Path(entry.path).resolve(strict=True)
                    except (OSError, RuntimeError) as exc:
                        raise ValueError("dep-scan source contains an unresolvable entry") from exc
                    if canonical != root and not canonical.is_relative_to(root):
                        raise PermissionError("dep-scan source tree contains an escaping link")
                    if canonical.is_dir():
                        stack.append(canonical)
                        continue
                    if not canonical.is_file():
                        raise ValueError("dep-scan source tree contains a special file")
                    file_count += 1
                    if file_count > self._max_source_files:
                        raise ValueError("dep-scan source tree exceeds the file-count limit")
                    total_bytes += canonical.stat().st_size
                    if total_bytes > self._max_source_bytes:
                        raise ValueError("dep-scan source tree exceeds the byte-size limit")
        if file_count == 0:
            raise ValueError("dep-scan source directory is empty")

    def parse(self, output: str) -> dict[str, Any]:
        document = parse_json_document(output, max_chars=self._max_report_bytes)
        if not isinstance(document, dict):
            raise ValueError("dep-scan VDR must be a JSON object")
        if document.get("bomFormat") != "CycloneDX":
            raise ValueError("dep-scan report is not a CycloneDX VDR")
        spec_version = clean_text(document.get("specVersion"), maximum=16)
        if spec_version not in _SUPPORTED_CYCLONEDX_VERSIONS:
            raise ValueError("unsupported CycloneDX VDR specification version")
        vulnerabilities = document.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise ValueError("CycloneDX vulnerabilities must be an array")
        if len(vulnerabilities) > self._max_vulnerabilities:
            raise ValueError("dep-scan VDR contains too many vulnerabilities")
        if any(not isinstance(item, dict) for item in vulnerabilities):
            raise ValueError("CycloneDX vulnerability entries must be objects")
        components = document.get("components", [])
        if not isinstance(components, list):
            raise ValueError("CycloneDX components must be an array")
        if len(components) > self._max_components:
            raise ValueError("dep-scan VDR contains too many top-level components")
        return document

    def _component_index(self, document: Mapping[str, Any]) -> dict[str, dict[str, str]]:
        raw_components = document.get("components", [])
        assert isinstance(raw_components, list)
        stack: list[object] = list(reversed(raw_components))
        index: dict[str, dict[str, str]] = {}
        seen = 0
        while stack:
            raw_component = stack.pop()
            if not isinstance(raw_component, Mapping):
                continue
            seen += 1
            if seen > self._max_components:
                raise ValueError("dep-scan VDR contains too many nested components")
            bom_ref = clean_text(raw_component.get("bom-ref"), maximum=2048)
            component = {
                "name": clean_text(raw_component.get("name"), maximum=512),
                "version": clean_text(raw_component.get("version"), maximum=256),
                "purl": clean_text(raw_component.get("purl"), maximum=2048),
                "group": clean_text(raw_component.get("group"), maximum=512),
                "type": clean_text(raw_component.get("type"), maximum=64),
            }
            if bom_ref:
                index[bom_ref] = component
            if component["purl"]:
                index.setdefault(component["purl"], component)
            nested = raw_component.get("components", [])
            if isinstance(nested, list):
                stack.extend(reversed(nested))
        return index

    @staticmethod
    def _purl_identity(value: str) -> tuple[str, str, str]:
        if not value.startswith("pkg:"):
            return "", "", ""
        body = value[4:].split("?", 1)[0].split("#", 1)[0]
        ecosystem, separator, package_part = body.partition("/")
        if not separator:
            return clean_text(unquote(ecosystem), maximum=128), "", ""
        path, marker, version = package_part.rpartition("@")
        if not marker:
            path = package_part
            version = ""
        name = unquote(path.rsplit("/", 1)[-1])
        return (
            clean_text(unquote(ecosystem), maximum=128),
            clean_text(name, maximum=512),
            clean_text(unquote(version), maximum=256),
        )

    @staticmethod
    def _properties(vulnerability: Mapping[str, Any]) -> dict[str, str]:
        raw_properties = vulnerability.get("properties", [])
        if not isinstance(raw_properties, list):
            return {}
        properties: dict[str, str] = {}
        for raw_property in raw_properties[:256]:
            if not isinstance(raw_property, Mapping):
                continue
            name = clean_text(raw_property.get("name"), maximum=256)
            raw_value = raw_property.get("value")
            if name == "depscan:insights" and isinstance(raw_value, str):
                value = "\n".join(
                    item
                    for line in raw_value.splitlines()[:64]
                    if (item := clean_text(line, maximum=256))
                )[:4096]
            else:
                value = clean_text(raw_value, maximum=4096)
            if name:
                properties[name] = value
        return properties

    @staticmethod
    def _analysis(vulnerability: Mapping[str, Any]) -> dict[str, Any]:
        raw_analysis = vulnerability.get("analysis", {})
        if not isinstance(raw_analysis, Mapping):
            return {}
        response = raw_analysis.get("response", [])
        responses = (
            [clean_text(item, maximum=128) for item in response[:32]]
            if isinstance(response, list)
            else []
        )
        return {
            "state": clean_text(raw_analysis.get("state"), maximum=128),
            "justification": clean_text(raw_analysis.get("justification"), maximum=128),
            "response": [item for item in responses if item],
            "detail": clean_text(raw_analysis.get("detail"), maximum=16_384),
            "first_issued": clean_text(raw_analysis.get("firstIssued"), maximum=64),
            "last_updated": clean_text(raw_analysis.get("lastUpdated"), maximum=64),
        }

    @staticmethod
    def _ratings(
        vulnerability: Mapping[str, Any],
    ) -> tuple[list[dict[str, Any]], str, float | None]:
        raw_ratings = vulnerability.get("ratings", [])
        if not isinstance(raw_ratings, list):
            raw_ratings = []
        ratings: list[dict[str, Any]] = []
        severity = "UNKNOWN"
        cvss_scores: list[float] = []
        for raw_rating in raw_ratings[:32]:
            if not isinstance(raw_rating, Mapping):
                continue
            raw_source = raw_rating.get("source", {})
            source = raw_source if isinstance(raw_source, Mapping) else {}
            method = clean_text(raw_rating.get("method"), maximum=64)
            vector = clean_text(raw_rating.get("vector"), maximum=512)
            raw_severity = clean_text(raw_rating.get("severity"), maximum=32).casefold()
            normalized_severity = _SEVERITIES.get(raw_severity, "UNKNOWN")
            if _SEVERITY_RANK[normalized_severity] > _SEVERITY_RANK[severity]:
                severity = normalized_severity
            score: float | None = None
            try:
                candidate = float(str(raw_rating.get("score")))
            except (TypeError, ValueError):
                pass
            else:
                if 0 <= candidate <= 10 and candidate == candidate:
                    score = candidate
                    if method.casefold().startswith("cvss") or vector.upper().startswith(
                        ("CVSS:", "AV:")
                    ):
                        cvss_scores.append(candidate)
            ratings.append(
                {
                    "source": {
                        "name": clean_text(source.get("name"), maximum=128),
                        "url": clean_text(source.get("url"), maximum=2048),
                    },
                    "method": method,
                    "score": score,
                    "severity": normalized_severity,
                    "vector": vector,
                    "justification": clean_text(
                        raw_rating.get("justification"), maximum=4096
                    ),
                }
            )
        cvss_score = max(cvss_scores, default=None)
        if cvss_score is not None:
            score_severity = (
                "CRITICAL"
                if cvss_score >= 9
                else "HIGH"
                if cvss_score >= 7
                else "MEDIUM"
                if cvss_score >= 4
                else "LOW"
                if cvss_score > 0
                else "INFO"
            )
            if _SEVERITY_RANK[score_severity] > _SEVERITY_RANK[severity]:
                severity = score_severity
        return ratings, severity, cvss_score

    @staticmethod
    def _affected_versions(raw_affect: Mapping[str, Any]) -> tuple[list[str], list[str]]:
        raw_versions = raw_affect.get("versions", [])
        if not isinstance(raw_versions, list):
            return [], []
        affected: set[str] = set()
        fixed: set[str] = set()
        for raw_version in raw_versions[:2048]:
            if not isinstance(raw_version, Mapping):
                continue
            value = clean_text(
                raw_version.get("version") or raw_version.get("range"), maximum=512
            )
            if not value:
                continue
            status = clean_text(raw_version.get("status"), maximum=32).casefold()
            if status in {"unaffected", "fixed"}:
                fixed.add(value)
            elif status in {"", "affected"}:
                affected.add(value)
        return sorted(affected)[:512], sorted(fixed)[:512]

    @staticmethod
    def _references(vulnerability: Mapping[str, Any]) -> tuple[list[str], list[str]]:
        urls: set[str] = set()
        aliases: set[str] = set()
        raw_source = vulnerability.get("source", {})
        source = raw_source if isinstance(raw_source, Mapping) else {}
        source_url = clean_text(source.get("url"), maximum=2048)
        if source_url.startswith("https://"):
            urls.add(source_url)
        raw_advisories = vulnerability.get("advisories", [])
        if isinstance(raw_advisories, list):
            for raw_advisory in raw_advisories[:128]:
                if not isinstance(raw_advisory, Mapping):
                    continue
                url = clean_text(raw_advisory.get("url"), maximum=2048)
                if url.startswith("https://"):
                    urls.add(url)
        raw_references = vulnerability.get("references", [])
        if isinstance(raw_references, list):
            for raw_reference in raw_references[:128]:
                if not isinstance(raw_reference, Mapping):
                    continue
                alias = clean_text(raw_reference.get("id"), maximum=128)
                if alias:
                    aliases.add(alias)
                raw_reference_source = raw_reference.get("source", {})
                reference_source = (
                    raw_reference_source
                    if isinstance(raw_reference_source, Mapping)
                    else {}
                )
                url = clean_text(reference_source.get("url"), maximum=2048)
                if url.startswith("https://"):
                    urls.add(url)
        return sorted(urls)[:128], sorted(aliases)[:512]

    @staticmethod
    def _document_provenance(document: Mapping[str, Any]) -> dict[str, Any]:
        raw_metadata = document.get("metadata", {})
        metadata = raw_metadata if isinstance(raw_metadata, Mapping) else {}
        raw_component = metadata.get("component", {})
        component = raw_component if isinstance(raw_component, Mapping) else {}
        tools: list[dict[str, str]] = []
        raw_tools = metadata.get("tools", [])
        tool_entries: Sequence[object]
        if isinstance(raw_tools, list):
            tool_entries = raw_tools
        elif isinstance(raw_tools, Mapping):
            components = raw_tools.get("components", [])
            tool_entries = components if isinstance(components, list) else []
        else:
            tool_entries = []
        for raw_tool in tool_entries[:32]:
            if not isinstance(raw_tool, Mapping):
                continue
            tools.append(
                {
                    "vendor": clean_text(raw_tool.get("vendor"), maximum=128),
                    "name": clean_text(raw_tool.get("name"), maximum=128),
                    "version": clean_text(raw_tool.get("version"), maximum=128),
                }
            )
        return {
            "bom_format": "CycloneDX",
            "spec_version": clean_text(document.get("specVersion"), maximum=16),
            "serial_number": clean_text(document.get("serialNumber"), maximum=256),
            "document_version": document.get("version")
            if isinstance(document.get("version"), int)
            else None,
            "timestamp": clean_text(metadata.get("timestamp"), maximum=64),
            "root_component": {
                "name": clean_text(component.get("name"), maximum=512),
                "version": clean_text(component.get("version"), maximum=256),
                "purl": clean_text(component.get("purl"), maximum=2048),
            },
            "tools": tools,
        }

    def normalize(self, parsed: dict[str, Any]) -> list[dict[str, Any]]:
        component_index = self._component_index(parsed)
        document_provenance = self._document_provenance(parsed)
        raw_vulnerabilities = parsed.get("vulnerabilities", [])
        assert isinstance(raw_vulnerabilities, list)
        normalized: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for raw_vulnerability in raw_vulnerabilities:
            assert isinstance(raw_vulnerability, dict)
            vulnerability_id = clean_text(raw_vulnerability.get("id"), maximum=128)
            if not vulnerability_id:
                raise ValueError("CycloneDX vulnerability is missing its identifier")
            raw_source = raw_vulnerability.get("source", {})
            source = raw_source if isinstance(raw_source, Mapping) else {}
            source_record = {
                "name": clean_text(source.get("name"), maximum=128),
                "url": clean_text(source.get("url"), maximum=2048),
            }
            properties = self._properties(raw_vulnerability)
            insights = [
                clean_text(item, maximum=256)
                for item in properties.get("depscan:insights", "").splitlines()[:64]
                if clean_text(item, maximum=256)
            ]
            prioritized = properties.get("depscan:prioritized", "").casefold() == "true"
            known_exploited = any(
                item.casefold() in {"known exploits", "known exploited"}
                for item in insights
            ) or properties.get("depscan:known_exploited", "").casefold() == "true"
            ratings, severity, cvss_score = self._ratings(raw_vulnerability)
            references, aliases = self._references(raw_vulnerability)
            analysis = self._analysis(raw_vulnerability)
            raw_affects = raw_vulnerability.get("affects", [])
            affects = raw_affects if isinstance(raw_affects, list) else []
            if len(affects) > 2048:
                raise ValueError("CycloneDX vulnerability contains too many affected components")
            if not affects:
                affects = [{}]
            raw_cwes = raw_vulnerability.get("cwes", [])
            cwes: list[str] = []
            if isinstance(raw_cwes, list):
                for raw_cwe in raw_cwes[:128]:
                    cwe = clean_text(raw_cwe, maximum=32).upper()
                    if cwe.isdigit():
                        cwe = f"CWE-{cwe}"
                    if cwe.startswith("CWE-"):
                        cwes.append(cwe)
            vulnerability_bom_ref = clean_text(
                raw_vulnerability.get("bom-ref"), maximum=2048
            )
            timestamps = {
                key: clean_text(raw_vulnerability.get(key), maximum=64)
                for key in ("created", "published", "updated", "rejected")
                if raw_vulnerability.get(key) is not None
            }
            for raw_affect in affects[:2048]:
                if not isinstance(raw_affect, Mapping):
                    continue
                bom_ref = clean_text(raw_affect.get("ref"), maximum=2048)
                component = component_index.get(bom_ref, {})
                purl = component.get("purl", "") or (bom_ref if bom_ref.startswith("pkg:") else "")
                ecosystem, purl_name, purl_version = self._purl_identity(purl)
                affected_versions, fixed_versions = self._affected_versions(raw_affect)
                package_name = component.get("name", "") or purl_name or "unknown"
                package_version = component.get("version", "") or purl_version
                if not package_version and affected_versions:
                    package_version = affected_versions[0]
                identity = (
                    vulnerability_id.casefold(),
                    bom_ref,
                    package_name.casefold(),
                    package_version,
                )
                if identity in seen:
                    continue
                seen.add(identity)
                normalized.append(
                    {
                        "vulnerability_id": vulnerability_id,
                        "aliases": [
                            item
                            for item in aliases
                            if item.casefold() != vulnerability_id.casefold()
                        ],
                        "package": {
                            "name": package_name,
                            "version": package_version,
                            "ecosystem": ecosystem,
                            "purl": purl,
                            "bom_ref": bom_ref,
                            "group": component.get("group", ""),
                            "type": component.get("type", ""),
                        },
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "exploitability": None,
                        "known_exploited": known_exploited,
                        "vulnerability_bom_ref": vulnerability_bom_ref,
                        "cwes": sorted(set(cwes)),
                        "timestamps": timestamps,
                        "summary": clean_text(
                            raw_vulnerability.get("description"), maximum=16_384
                        ),
                        "details": clean_text(analysis.get("detail"), maximum=16_384),
                        "recommendation": clean_text(
                            raw_vulnerability.get("recommendation"), maximum=16_384
                        ),
                        "affected_versions": affected_versions,
                        "fixed_versions": fixed_versions,
                        "references": references,
                        "source": source_record,
                        "ratings": ratings,
                        "analysis": analysis,
                        "properties": properties,
                        "insights": insights,
                        "prioritized": prioritized,
                        "provenance": document_provenance,
                    }
                )
                if len(normalized) > self._max_vulnerabilities:
                    raise ValueError("normalized dep-scan vulnerability limit exceeded")
        return normalized

    def _report_paths(
        self, report_root: Path
    ) -> tuple[list[Path], list[Path], int, int]:
        stack = [report_root.resolve(strict=True)]
        artifacts: list[Path] = []
        vdr_files: list[Path] = []
        file_count = 0
        total_bytes = 0
        while stack:
            directory = stack.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    if entry.is_symlink():
                        raise ValueError("dep-scan report directory contains a symbolic link")
                    canonical = path.resolve(strict=True)
                    if canonical != report_root and not canonical.is_relative_to(report_root):
                        raise ValueError("dep-scan report path escaped the temporary directory")
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(canonical)
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        raise ValueError("dep-scan report directory contains a special file")
                    file_count += 1
                    if file_count > self._max_report_files:
                        raise ValueError("dep-scan produced too many report files")
                    total_bytes += entry.stat(follow_symlinks=False).st_size
                    if total_bytes > self._max_report_bytes:
                        raise ValueError("dep-scan temporary output exceeded the byte-size limit")
                    artifacts.append(canonical)
                    if canonical.name.casefold().endswith(".vdr.json"):
                        vdr_files.append(canonical)
        if not vdr_files:
            raise ValueError("dep-scan did not produce a CycloneDX VDR report")
        return sorted(vdr_files), sorted(artifacts), file_count, total_bytes

    def _artifact_metadata(self, path: Path) -> dict[str, Any]:
        with path.open("rb") as handle:
            content = handle.read(self._max_report_bytes + 1)
        if len(content) > self._max_report_bytes:
            raise ValueError("dep-scan artifact exceeds the byte-size limit")
        name = clean_text(path.name, maximum=256)
        artifact: dict[str, Any] = {
            "name": name,
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "kind": "vdr" if name.casefold().endswith(".vdr.json") else "report",
        }
        if path.suffix.casefold() != ".json":
            return artifact
        try:
            document = parse_json_document(
                content.decode("utf-8", errors="strict"),
                max_chars=self._max_report_bytes,
            )
        except (UnicodeDecodeError, ValueError):
            return artifact
        if not isinstance(document, Mapping) or document.get("bomFormat") != "CycloneDX":
            return artifact
        vulnerabilities = document.get("vulnerabilities")
        artifact["kind"] = "vdr" if isinstance(vulnerabilities, list) else "sbom"
        components = document.get("components", [])
        artifact["cyclonedx"] = {
            **self._document_provenance(document),
            "component_count": len(components) if isinstance(components, list) else None,
            "vulnerability_count": (
                len(vulnerabilities) if isinstance(vulnerabilities, list) else None
            ),
        }
        return artifact

    @staticmethod
    def _source_label(request: DepScanRequest) -> str:
        return "live_os" if request.mode is DepScanMode.LIVE_OS else str(request.source)

    def execute(
        self,
        value: DepScanRequest,
        *,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> ToolExecution[list[dict[str, Any]]]:
        try:
            request = self._validate_input(value, deadline_at=deadline_at)
        except TimeoutError as exc:
            return ToolExecution(
                tool=self.name,
                status=ToolState.TIMEOUT,
                error=clean_text(exc, maximum=512),
            )
        except (OSError, TypeError, ValueError) as exc:
            return ToolExecution(
                tool=self.name,
                status=ToolState.FAILED,
                error=clean_text(exc, maximum=512),
            )
        executable = self._find_executable()
        if executable is None:
            return ToolExecution(
                tool=self.name,
                status=ToolState.UNAVAILABLE,
                error="OWASP dep-scan executable is unavailable",
                metadata={"source": self._source_label(request)},
            )
        if deadline_at is not None:
            remaining = deadline_at - time.monotonic()
            if remaining <= 0:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.TIMEOUT,
                    error="scan deadline exhausted before dep-scan execution",
                )
            timeout_seconds = (
                remaining if timeout_seconds is None else min(timeout_seconds, remaining)
            )

        with tempfile.TemporaryDirectory(prefix="endpoint-scanner-depscan-") as temporary:
            workspace_root = Path(temporary).resolve(strict=True)
            report_root = workspace_root / "reports"
            report_root.mkdir(mode=0o700)
            if request.mode is DepScanMode.LIVE_OS:
                scan_source = workspace_root / "live-os-input"
                scan_source.mkdir(mode=0o700)
                input_option = "--src"
            else:
                assert request.source is not None
                scan_source = request.source
                input_option = "--bom" if request.mode is DepScanMode.SBOM else "--src"
            arguments = [
                input_option,
                str(scan_source),
                "--reports-dir",
                str(report_root),
                "--profile",
                request.profile,
                "--vulnerability-analyzer",
                "VDRAnalyzer",
                "--reachability-analyzer",
                "off",
                "--fail-on-error",
                "--no-vuln-table",
                "--quiet",
            ]
            if request.mode is DepScanMode.LIVE_OS:
                arguments.extend(("--type", "os", "--deep"))
            elif request.deep and request.mode is DepScanMode.SOURCE:
                arguments.append("--deep")
            try:
                result = self._runner.run(
                    executable,
                    tuple(arguments),
                    timeout_seconds=timeout_seconds,
                    cwd=workspace_root,
                )
            except ToolUnavailableError:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.UNAVAILABLE,
                    error="OWASP dep-scan executable is unavailable",
                    metadata={"source": self._source_label(request)},
                )
            except (OSError, ValueError) as exc:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.FAILED,
                    error=clean_text(exc, maximum=512),
                )
            if result.timed_out:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.TIMEOUT,
                    duration_seconds=result.duration_seconds,
                    exit_code=result.returncode,
                    error="OWASP dep-scan execution timed out",
                    metadata={"source": self._source_label(request)},
                )
            if result.returncode != 0:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.FAILED,
                    duration_seconds=result.duration_seconds,
                    exit_code=result.returncode,
                    error=clean_text(result.stderr, maximum=1024)
                    or "OWASP dep-scan execution failed",
                    metadata={"source": self._source_label(request)},
                )

            warnings: list[str] = []
            if result.stdout_truncated:
                warnings.append("dep-scan console stdout was truncated")
            if result.stderr_truncated:
                warnings.append("dep-scan console stderr was truncated")
            records: list[dict[str, Any]] = []
            report_metadata: list[dict[str, Any]] = []
            artifact_metadata: list[dict[str, Any]] = []
            seen: set[tuple[str, str, str, str]] = set()
            try:
                report_paths, artifact_paths, report_file_count, report_bytes = (
                    self._report_paths(report_root)
                )
                artifact_metadata = [self._artifact_metadata(path) for path in artifact_paths]
                artifact_checksums = {
                    path: item["sha256"]
                    for path, item in zip(artifact_paths, artifact_metadata, strict=True)
                }
                for report_path in report_paths:
                    try:
                        raw_report = read_bounded_text(
                            report_path, max_bytes=self._max_report_bytes
                        )
                        document_records = self.normalize(self.parse(raw_report))
                    except (OSError, ValueError) as exc:
                        warnings.append(
                            f"dep-scan report "
                            f"{clean_text(report_path.name, maximum=256)} was rejected: "
                            f"{clean_text(exc, maximum=256)}"
                        )
                        continue
                    report_name = clean_text(report_path.name, maximum=256)
                    checksum = str(artifact_checksums[report_path])
                    for record in document_records:
                        package = record.get("package", {})
                        package_data = package if isinstance(package, Mapping) else {}
                        identity = (
                            str(record.get("vulnerability_id", "")).casefold(),
                            str(package_data.get("bom_ref", "")),
                            str(package_data.get("name", "")).casefold(),
                            str(package_data.get("version", "")),
                        )
                        if identity in seen:
                            continue
                        seen.add(identity)
                        provenance = record.get("provenance", {})
                        if isinstance(provenance, dict):
                            record["provenance"] = {
                                **provenance,
                                "report_file": report_name,
                                "report_sha256": checksum,
                            }
                        records.append(record)
                        if len(records) > self._max_vulnerabilities:
                            raise ValueError(
                                "combined dep-scan vulnerability limit exceeded"
                            )
                    report_metadata.append(
                        {
                            "name": report_name,
                            "sha256": checksum,
                            "vulnerability_count": len(document_records),
                        }
                    )
            except (OSError, ValueError) as exc:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.FAILED,
                    duration_seconds=result.duration_seconds,
                    exit_code=result.returncode,
                    error=clean_text(exc, maximum=512),
                    warnings=tuple(warnings),
                    metadata={"source": self._source_label(request)},
                )
            if not report_metadata:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.FAILED,
                    duration_seconds=result.duration_seconds,
                    exit_code=result.returncode,
                    error="dep-scan produced no valid CycloneDX VDR reports",
                    warnings=tuple(warnings),
                    metadata={"source": self._source_label(request)},
                )
            return ToolExecution(
                tool=self.name,
                status=ToolState.PARTIAL if warnings else ToolState.SUCCESS,
                payload=records,
                duration_seconds=result.duration_seconds,
                exit_code=result.returncode,
                warnings=tuple(warnings),
                metadata={
                    "source": self._source_label(request),
                    "input_kind": request.mode.value.casefold(),
                    "profile": request.profile,
                    "deep": request.deep
                    and request.mode in {DepScanMode.LIVE_OS, DepScanMode.SOURCE},
                    "vulnerability_count": len(records),
                    "report_file_count": report_file_count,
                    "report_bytes": report_bytes,
                    "reports": report_metadata,
                    "artifacts": artifact_metadata,
                },
            )

    def scan(
        self,
        source: str | Path,
        *,
        mode: DepScanMode | None = None,
        profile: str = "operational",
        deep: bool = True,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> ToolExecution[list[dict[str, Any]]]:
        source_path = Path(source)
        selected_mode = mode or (
            DepScanMode.SBOM if source_path.is_file() else DepScanMode.SOURCE
        )
        if selected_mode is DepScanMode.LIVE_OS:
            raise ValueError("use scan_live_os() for a live OS dependency assessment")
        return self.execute(
            DepScanRequest(
                mode=selected_mode,
                source=source_path,
                profile=profile,
                deep=deep,
            ),
            timeout_seconds=timeout_seconds,
            deadline_at=deadline_at,
        )

    def scan_live_os(
        self,
        *,
        profile: str = "operational",
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> ToolExecution[list[dict[str, Any]]]:
        """Run dep-scan's fixed live-OS deep profile without a caller path."""

        return self.execute(
            DepScanRequest(mode=DepScanMode.LIVE_OS, profile=profile, deep=True),
            timeout_seconds=timeout_seconds,
            deadline_at=deadline_at,
        )
