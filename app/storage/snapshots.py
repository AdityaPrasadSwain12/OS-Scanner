"""Deterministic endpoint-inventory change detection."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .serialization import canonical_json

_COLLECTION_SECTIONS = frozenset(
    {
        "software",
        "packages",
        "services",
        "users",
        "groups",
        "network_interfaces",
        "listening_ports",
        "ports",
        "persistence",
        "vulnerabilities",
        "compliance",
        "attack_surface",
        "browser_extensions",
        "certificates",
        "updates",
    }
)

_EVENT_NAMES = {
    "os": "OS_CHANGED",
    "operating_system": "OS_CHANGED",
    "hardware": "HARDWARE_CHANGED",
    "software": "SOFTWARE_CHANGED",
    "packages": "SOFTWARE_CHANGED",
    "processes": "PROCESSES_CHANGED",
    "services": "SERVICES_CHANGED",
    "users": "USERS_CHANGED",
    "groups": "GROUPS_CHANGED",
    "network": "NETWORK_CHANGED",
    "network_interfaces": "NETWORK_CHANGED",
    "listening_ports": "PORTS_CHANGED",
    "ports": "PORTS_CHANGED",
    "security": "SECURITY_POSTURE_CHANGED",
    "security_posture": "SECURITY_POSTURE_CHANGED",
    "persistence": "PERSISTENCE_CHANGED",
    "vulnerabilities": "VULNERABILITIES_CHANGED",
    "compliance": "COMPLIANCE_CHANGED",
    "attack_surface": "ATTACK_SURFACE_CHANGED",
    "browser_extensions": "BROWSER_EXTENSIONS_CHANGED",
    "certificates": "CERTIFICATES_CHANGED",
    "updates": "UPDATES_CHANGED",
}

_IDENTITY_FIELDS = {
    "software": ("name", "vendor", "architecture", "package_manager"),
    "packages": ("name", "ecosystem", "architecture", "source"),
    "services": ("name",),
    "users": ("uid", "username", "name"),
    "groups": ("gid", "name"),
    "network_interfaces": ("name", "mac_address"),
    "listening_ports": ("protocol", "address", "port"),
    "ports": ("protocol", "address", "port"),
    "persistence": ("kind", "name", "location", "executable_path"),
    "vulnerabilities": (
        "id",
        "vulnerability_id",
        "package",
        "package_name",
        "installed_version",
    ),
    "compliance": ("rule_id", "id"),
    "attack_surface": ("asset_type", "hostname"),
    "browser_extensions": ("browser", "extension_id"),
    "certificates": ("store", "thumbprint", "serial_number"),
    "updates": ("update_id",),
}

_VOLATILE_FIELDS = {
    "endpoint": frozenset({"last_seen_at"}),
    "security": frozenset({"configuration_drift", "scan_age_days", "scan_stale"}),
    "compliance": frozenset(
        {"scan_id", "endpoint_id", "evaluated_at", "schema_version", "scanner_version"}
    ),
    "vulnerabilities": frozenset(
        {"scan_id", "endpoint_id", "detected_at", "schema_version", "scanner_version"}
    ),
}


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def normalize_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize unordered top-level inventories to prevent false drift."""

    if not isinstance(snapshot, Mapping):
        raise TypeError("snapshot must be a mapping")
    normalized: dict[str, Any] = {}
    for key, value in snapshot.items():
        name = str(key)
        if name == "processes":
            # Point-in-time process telemetry belongs in the local report, not
            # in differential synchronization where it would create constant churn.
            continue
        volatile = _VOLATILE_FIELDS.get(name, frozenset())
        if isinstance(value, Mapping) and volatile:
            value = {item_key: item for item_key, item in value.items() if item_key not in volatile}
        elif isinstance(value, (list, tuple)) and volatile:
            value = [
                (
                    {
                        item_key: field
                        for item_key, field in item.items()
                        if item_key not in volatile
                    }
                    if isinstance(item, Mapping)
                    else item
                )
                for item in value
            ]
        if name in _COLLECTION_SECTIONS and isinstance(value, (list, tuple)):
            normalized[name] = sorted(value, key=canonical_json)
        else:
            normalized[name] = value
    # Strict serialization here validates unsupported and non-finite values early.
    canonical_json(normalized)
    return normalized


def _identity(section: str, item: Any) -> str:
    if not isinstance(item, Mapping):
        return canonical_json(item)
    fields = _IDENTITY_FIELDS.get(section, ())
    selected = [(field, item.get(field)) for field in fields if item.get(field) is not None]
    return canonical_json(selected if selected else item)


def _collection_counts(section: str, before: Any, after: Any) -> tuple[int, int, int]:
    if not isinstance(before, list) or not isinstance(after, list):
        return (0, 0, 1)
    before_index = {_identity(section, item): item for item in before}
    after_index = {_identity(section, item): item for item in after}
    added = len(after_index.keys() - before_index.keys())
    removed = len(before_index.keys() - after_index.keys())
    modified = sum(
        before_index[key] != after_index[key] for key in before_index.keys() & after_index.keys()
    )
    return added, removed, modified


@dataclass(frozen=True, slots=True)
class SectionChange:
    section: str
    event: str
    before_hash: str | None
    after_hash: str | None
    added_count: int = 0
    removed_count: int = 0
    modified_count: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "section": self.section,
            "event": self.event,
            "before_hash": self.before_hash,
            "after_hash": self.after_hash,
            "added_count": self.added_count,
            "removed_count": self.removed_count,
            "modified_count": self.modified_count,
        }


@dataclass(frozen=True, slots=True)
class SnapshotChange:
    snapshot_id: int
    endpoint_id: str
    scan_id: str
    snapshot_hash: str
    previous_hash: str | None
    initial: bool
    changed: bool
    changes: tuple[SectionChange, ...]

    @property
    def events(self) -> tuple[str, ...]:
        if self.initial:
            return ("INITIAL_SNAPSHOT",)
        return tuple(change.event for change in self.changes)

    def as_dict(self) -> dict[str, object]:
        return {
            "snapshot_id": self.snapshot_id,
            "endpoint_id": self.endpoint_id,
            "scan_id": self.scan_id,
            "snapshot_hash": self.snapshot_hash,
            "previous_hash": self.previous_hash,
            "initial": self.initial,
            "changed": self.changed,
            "events": list(self.events),
            "changes": [change.as_dict() for change in self.changes],
        }


def compare_snapshots(
    before: Mapping[str, Any] | None, after: Mapping[str, Any]
) -> tuple[SectionChange, ...]:
    if before is None:
        return ()
    changes: list[SectionChange] = []
    for section in sorted(before.keys() | after.keys()):
        old_value = before.get(section)
        new_value = after.get(section)
        if old_value == new_value and section in before and section in after:
            continue
        added, removed, modified = _collection_counts(section, old_value, new_value)
        changes.append(
            SectionChange(
                section=section,
                event=_EVENT_NAMES.get(section, f"{section.upper()}_CHANGED"),
                before_hash=_digest(old_value) if section in before else None,
                after_hash=_digest(new_value) if section in after else None,
                added_count=added,
                removed_count=removed,
                modified_count=modified,
            )
        )
    return tuple(changes)


def snapshot_hash(snapshot: Mapping[str, Any]) -> str:
    return _digest(normalize_snapshot(snapshot))
