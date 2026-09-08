"""Normalize dependency-free macOS inventory into scanner-owned models."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ValidationError

from app.models import (
    Hardware,
    ListeningPort,
    NetworkInterface,
    NetworkProtocol,
    OperatingSystem,
    OperatingSystemFamily,
    Process,
    Service,
    ServiceState,
    Software,
    User,
)

from .osquery import NormalizationOutcome


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _records(value: object) -> list[Mapping[str, Any]]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _validate_section_shape(
    inventory: Mapping[str, Any],
    input_name: str,
    outcome: NormalizationOutcome,
) -> None:
    value = inventory.get(input_name)
    if input_name in {"os_info", "hardware"}:
        if not isinstance(value, Mapping):
            outcome.warnings.append(f"invalid native macOS {input_name} payload omitted")
        return
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        outcome.warnings.append(f"invalid native macOS {input_name} payload omitted")
    elif any(not isinstance(item, Mapping) for item in value):
        outcome.warnings.append(f"invalid native macOS {input_name} record omitted")


def _normalize_section(
    inventory: Mapping[str, Any],
    outcome: NormalizationOutcome,
    input_name: str,
    output_name: str,
    normalizer: Any,
) -> None:
    if input_name not in inventory:
        return
    before = len(outcome.warnings)
    _validate_section_shape(inventory, input_name, outcome)
    normalizer(inventory, outcome)
    if len(outcome.warnings) > before:
        outcome.rejected_sections.add(output_name)


def _integer(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(str(value))
    except ValueError:
        return None


def _float(value: object) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(str(value))
    except ValueError:
        return None


def _text(value: object, maximum: int) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    return result[:maximum] or None


def _date(value: object) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value or "").strip()
    match = re.match(r"^(\d{4}-\d{2}-\d{2})", text)
    if match is None:
        return None
    try:
        return date.fromisoformat(match.group(1))
    except ValueError:
        return None


def _append[ModelT: BaseModel](
    target: list[ModelT],
    model: type[ModelT],
    values: Mapping[str, Any],
    outcome: NormalizationOutcome,
    label: str,
) -> None:
    try:
        target.append(model.model_validate(dict(values)))
    except (ValidationError, ValueError):
        outcome.warnings.append(f"invalid native macOS {label} metadata omitted")


def _normalize_os(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "os_info" not in inventory:
        return
    values = _mapping(inventory.get("os_info"))
    name = _text(values.get("name"), 512)
    version = _text(values.get("version"), 128)
    if not name or not version:
        outcome.warnings.append("native macOS OS identity omitted because it is incomplete")
        return
    uptime = _integer(values.get("uptime_seconds"))
    boot_time = (
        datetime.now(UTC) - timedelta(seconds=uptime)
        if uptime is not None and uptime >= 0
        else None
    )
    try:
        operating_system = OperatingSystem(
            family=OperatingSystemFamily.MACOS,
            name=name,
            version=version,
            build=_text(values.get("build"), 128),
            kernel=_text(values.get("kernel"), 256),
            architecture=_text(values.get("architecture"), 64),
            hostname=_text(values.get("hostname"), 512),
            machine_id=_text(values.get("machine_id"), 512),
            boot_time=boot_time,
            uptime_seconds=uptime if uptime is not None and uptime >= 0 else None,
            timezone=_text(values.get("timezone"), 128),
        )
    except ValidationError:
        outcome.warnings.append("invalid native macOS operating-system metadata omitted")
        return
    outcome.data["os"] = operating_system
    if operating_system.hostname:
        outcome.data["hostname"] = operating_system.hostname


def _normalize_hardware(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "hardware" not in inventory:
        return
    if not _mapping(inventory.get("hardware")):
        outcome.warnings.append("invalid native macOS hardware metadata omitted")
        return
    try:
        outcome.data["hardware"] = Hardware.model_validate(
            dict(_mapping(inventory.get("hardware")))
        )
    except (ValidationError, ValueError):
        outcome.warnings.append("invalid native macOS hardware metadata omitted")


def _normalize_software(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "software" not in inventory:
        return
    software: list[Software] = []
    seen: set[tuple[str, str | None, str | None]] = set()
    for record in _records(inventory.get("software")):
        name = _text(record.get("name"), 512)
        if not name:
            outcome.warnings.append("invalid native macOS software metadata omitted")
            continue
        version = _text(record.get("version"), 256)
        architecture = _text(record.get("architecture"), 64)
        identity = (name.casefold(), version, architecture)
        if identity in seen:
            continue
        seen.add(identity)
        _append(
            software,
            Software,
            {
                "name": name,
                "version": version,
                "vendor": _text(record.get("vendor"), 512),
                "installation_path": _text(record.get("installation_path"), 4096),
                "installation_date": _date(record.get("installation_date")),
                "package_manager": _text(record.get("package_manager"), 128),
                "architecture": architecture,
                "source": _text(record.get("source"), 256) or "native",
            },
            outcome,
            "software",
        )
    outcome.data["software"] = software


def _normalize_processes(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "processes" not in inventory:
        return
    processes: list[Process] = []
    for record in _records(inventory.get("processes")):
        name = _text(record.get("name"), 512)
        pid = _integer(record.get("pid"))
        if not name or pid is None:
            outcome.warnings.append("invalid native macOS process metadata omitted")
            continue
        _append(
            processes,
            Process,
            {
                "pid": pid,
                "name": name,
                "executable_path": _text(record.get("executable_path"), 4096),
                "parent_pid": _integer(record.get("parent_pid")),
                "user": _text(record.get("user"), 512),
                "cpu_percent": _float(record.get("cpu_percent")),
                "memory_bytes": _integer(record.get("memory_bytes")),
            },
            outcome,
            "process",
        )
    outcome.data["processes"] = processes


def _service_state(value: object) -> ServiceState:
    normalized = str(value or "").strip().casefold()
    if normalized in {"running", "active"}:
        return ServiceState.RUNNING
    if normalized in {"stopped", "inactive"}:
        return ServiceState.STOPPED
    if normalized == "paused":
        return ServiceState.PAUSED
    return ServiceState.UNKNOWN


def _normalize_services(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "services" not in inventory:
        return
    services: list[Service] = []
    for record in _records(inventory.get("services")):
        name = _text(record.get("name"), 512)
        if not name:
            outcome.warnings.append("invalid native macOS service metadata omitted")
            continue
        lowered = name.casefold()
        _append(
            services,
            Service,
            {
                "name": name,
                "display_name": _text(record.get("display_name"), 512),
                "state": _service_state(record.get("state")),
                "startup_type": _text(record.get("startup_type"), 128),
                "executable_path": _text(record.get("executable_path"), 4096),
                "service_account": _text(record.get("service_account"), 512),
                "security_relevant": any(
                    marker in lowered
                    for marker in ("audit", "firewall", "ssh", "security", "endpoint")
                ),
            },
            outcome,
            "service",
        )
    outcome.data["services"] = services


def _normalize_users(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "users" not in inventory:
        return
    users: list[User] = []
    for record in _records(inventory.get("users")):
        raw_groups = record.get("groups")
        groups = (
            {
                group
                for value in raw_groups
                if (group := _text(value, 256)) is not None
            }
            if isinstance(raw_groups, list)
            else set()
        )
        _append(
            users,
            User,
            {
                "username": _text(record.get("username"), 512),
                "uid": _text(record.get("uid"), 128),
                "enabled": (
                    record.get("enabled")
                    if isinstance(record.get("enabled"), bool)
                    else None
                ),
                "groups": groups,
                "is_administrator": record.get("is_administrator") is True,
                "is_guest": record.get("is_guest") is True,
            },
            outcome,
            "user",
        )
    outcome.data["users"] = users


def _normalize_interfaces(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "network_interfaces" not in inventory:
        return
    interfaces: list[NetworkInterface] = []
    for record in _records(inventory.get("network_interfaces")):
        _append(
            interfaces,
            NetworkInterface,
            record,
            outcome,
            "network interface",
        )
    outcome.data["network_interfaces"] = interfaces


def _normalize_ports(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "listening_ports" not in inventory:
        return
    ports: list[ListeningPort] = []
    for record in _records(inventory.get("listening_ports")):
        values = dict(record)
        raw_protocol = str(values.get("protocol") or "").casefold()
        values["protocol"] = (
            NetworkProtocol.TCP
            if raw_protocol == "tcp"
            else NetworkProtocol.UDP
            if raw_protocol == "udp"
            else NetworkProtocol.UNKNOWN
        )
        _append(ports, ListeningPort, values, outcome, "listening port")
    outcome.data["listening_ports"] = ports


def normalize_macos_inventory(
    inventory: Mapping[str, Any], outcome: NormalizationOutcome
) -> NormalizationOutcome:
    """Add each independently observed native macOS inventory section."""

    _normalize_section(inventory, outcome, "os_info", "os", _normalize_os)
    _normalize_section(inventory, outcome, "hardware", "hardware", _normalize_hardware)
    _normalize_section(inventory, outcome, "software", "software", _normalize_software)
    _normalize_section(inventory, outcome, "processes", "processes", _normalize_processes)
    _normalize_section(inventory, outcome, "services", "services", _normalize_services)
    _normalize_section(inventory, outcome, "users", "users", _normalize_users)
    _normalize_section(
        inventory,
        outcome,
        "network_interfaces",
        "network_interfaces",
        _normalize_interfaces,
    )
    _normalize_section(
        inventory,
        outcome,
        "listening_ports",
        "listening_ports",
        _normalize_ports,
    )
    return outcome


__all__ = ["normalize_macos_inventory"]
