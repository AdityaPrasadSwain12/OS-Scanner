"""Normalize the self-contained Linux inventory collector."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
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
            outcome.warnings.append(f"invalid native Linux {input_name} payload omitted")
        return
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        outcome.warnings.append(f"invalid native Linux {input_name} payload omitted")
    elif any(not isinstance(item, Mapping) for item in value):
        outcome.warnings.append(f"invalid native Linux {input_name} record omitted")


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
    if isinstance(value, bool):
        return None
    try:
        return int(str(value))
    except (TypeError, ValueError):
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
        outcome.warnings.append(f"invalid native Linux {label} metadata omitted")


def _service_state(value: object) -> ServiceState:
    normalized = str(value or "").strip().casefold()
    if normalized in {"active", "running", "started", "+"}:
        return ServiceState.RUNNING
    if normalized in {
        "dead",
        "failed",
        "inactive",
        "stopped",
        "exited",
        "-",
    }:
        return ServiceState.STOPPED
    if normalized in {"reloading", "paused"}:
        return ServiceState.PAUSED
    return ServiceState.UNKNOWN


def _normalize_os(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "os_info" not in inventory:
        return
    values = _mapping(inventory.get("os_info"))
    if not values:
        outcome.warnings.append("invalid native Linux operating-system metadata omitted")
        return
    name = str(values.get("name") or "Linux")[:512]
    version = str(values.get("version") or values.get("kernel") or "unknown")[:128]
    uptime = _integer(values.get("uptime_seconds"))
    boot_time = (
        datetime.now(UTC) - timedelta(seconds=max(0, uptime)) if uptime is not None else None
    )
    try:
        operating_system = OperatingSystem(
            family=OperatingSystemFamily.LINUX,
            name=name,
            version=version,
            build=str(values.get("build") or "")[:128] or None,
            kernel=str(values.get("kernel") or "")[:256] or None,
            architecture=str(values.get("architecture") or "")[:64] or None,
            hostname=str(values.get("hostname") or "")[:512] or None,
            machine_id=str(values.get("machine_id") or "")[:512] or None,
            boot_time=boot_time,
            uptime_seconds=max(0, uptime) if uptime is not None else None,
            timezone=str(values.get("timezone") or "")[:128] or None,
        )
    except ValidationError:
        outcome.warnings.append("invalid native Linux operating-system metadata omitted")
        return
    outcome.data["os"] = operating_system
    if operating_system.hostname:
        outcome.data["hostname"] = operating_system.hostname


def _normalize_hardware(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "hardware" not in inventory:
        return
    if not _mapping(inventory.get("hardware")):
        outcome.warnings.append("invalid native Linux hardware metadata omitted")
        return
    try:
        outcome.data["hardware"] = Hardware.model_validate(
            dict(_mapping(inventory.get("hardware")))
        )
    except (ValidationError, ValueError):
        outcome.warnings.append("invalid native Linux hardware metadata omitted")


def _normalize_software(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "software" not in inventory:
        return
    software: list[Software] = []
    for record in _records(inventory.get("software")):
        _append(software, Software, record, outcome, "software")
    outcome.data["software"] = software


def _normalize_processes(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "processes" not in inventory:
        return
    processes: list[Process] = []
    for record in _records(inventory.get("processes")):
        values = dict(record)
        # Native inventory intentionally never transmits process arguments.
        values.pop("command_line", None)
        _append(processes, Process, values, outcome, "process")
    outcome.data["processes"] = processes


def _normalize_services(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "services" not in inventory:
        return
    services: list[Service] = []
    for record in _records(inventory.get("services")):
        values = dict(record)
        values["state"] = _service_state(values.get("state"))
        name = str(values.get("name") or "").casefold()
        values["security_relevant"] = any(
            marker in name for marker in ("audit", "firewall", "ssh", "wazuh", "falcon", "mdatp")
        )
        _append(services, Service, values, outcome, "service")
    outcome.data["services"] = services


def _normalize_users(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "users" not in inventory:
        return
    users: list[User] = []
    for record in _records(inventory.get("users")):
        _append(users, User, record, outcome, "user")
    outcome.data["users"] = users


def _normalize_interfaces(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "network_interfaces" not in inventory:
        return
    interfaces: list[NetworkInterface] = []
    for record in _records(inventory.get("network_interfaces")):
        _append(interfaces, NetworkInterface, record, outcome, "network interface")
    outcome.data["network_interfaces"] = interfaces


def _normalize_ports(inventory: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    if "listening_ports" not in inventory:
        return
    ports: list[ListeningPort] = []
    for record in _records(inventory.get("listening_ports")):
        values = dict(record)
        protocol = str(values.pop("protocol", "")).strip().casefold()
        values["protocol"] = (
            NetworkProtocol.TCP
            if protocol == "tcp"
            else NetworkProtocol.UDP
            if protocol == "udp"
            else NetworkProtocol.UNKNOWN
        )
        address = str(values.pop("local_address", values.get("address", "")))
        port = values.pop("local_port", values.get("port"))
        values["address"] = address
        values["port"] = port
        values["exposed"] = address in {
            "0.0.0.0",  # noqa: S104 - observed listener binding
            "::",
            "*",
            "any",
        }
        _append(ports, ListeningPort, values, outcome, "listening port")
    outcome.data["listening_ports"] = ports


def normalize_linux_inventory(
    inventory: Mapping[str, Any], outcome: NormalizationOutcome
) -> NormalizationOutcome:
    """Add independently observed native Linux sections to an existing outcome."""

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


__all__ = ["normalize_linux_inventory"]
