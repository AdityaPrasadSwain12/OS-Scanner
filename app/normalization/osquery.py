"""Normalize validated osquery rows into scanner-owned endpoint models."""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any

from pydantic import ValidationError

from app.models import (
    CPU,
    GPU,
    BrowserExtension,
    Disk,
    Hardware,
    IPAddress,
    ListeningPort,
    NetworkInterface,
    NetworkProtocol,
    OperatingSystem,
    OperatingSystemFamily,
    PersistenceItem,
    Process,
    SecurityPosture,
    Service,
    ServiceState,
    Software,
    User,
)
from app.security.redaction import redact_text


def _text(value: object, *, maximum: int = 4096) -> str | None:
    if value is None:
        return None
    normalized = str(value).replace("\x00", "").replace("\r", " ").replace("\n", " ").strip()
    return normalized[:maximum] or None


def _integer(value: object, *, minimum: int = 0) -> int | None:
    try:
        result = int(str(value))
    except (TypeError, ValueError, OverflowError):
        return None
    return result if result >= minimum else None


def _signed_integer(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError, OverflowError):
        return None


def _boolean(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().casefold()
    if normalized in {"1", "true", "yes", "enabled", "active", "running"}:
        return True
    if normalized in {"0", "false", "no", "disabled", "inactive", "stopped"}:
        return False
    return None


def _timestamp(value: object) -> datetime | None:
    if value in (None, "", "0", 0):
        return None
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            return datetime.fromtimestamp(float(str(value)), tz=UTC)
        text = str(value).strip()
        dmtf = re.fullmatch(r"(\d{14})(?:\.(\d{1,6}))?([+-])(\d{3})", text)
        if dmtf:
            microseconds = (dmtf.group(2) or "").ljust(6, "0")
            offset_minutes = int(dmtf.group(4)) * (1 if dmtf.group(3) == "+" else -1)
            parsed = datetime.strptime(f"{dmtf.group(1)}{microseconds}", "%Y%m%d%H%M%S%f").replace(
                tzinfo=timezone(timedelta(minutes=offset_minutes))
            )
            return parsed.astimezone(UTC)
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _date_value(value: object) -> date | None:
    if value in (None, "", "0", 0):
        return None
    text = str(value).strip()
    try:
        if re.fullmatch(r"\d{8}", text):
            return datetime.strptime(text, "%Y%m%d").date()
        parsed = _timestamp(value)
        if parsed is not None:
            return parsed.date()
        return date.fromisoformat(text[:10])
    except (ValueError, TypeError, OverflowError):
        return None


def _family(platform_name: object, os_name: object) -> OperatingSystemFamily:
    combined = f"{platform_name or ''} {os_name or ''}".casefold()
    if "windows" in combined:
        return OperatingSystemFamily.WINDOWS
    if "darwin" in combined or "macos" in combined or "mac os" in combined:
        return OperatingSystemFamily.MACOS
    if any(value in combined for value in ("linux", "ubuntu", "debian", "rhel", "fedora")):
        return OperatingSystemFamily.LINUX
    return OperatingSystemFamily.UNKNOWN


@dataclass(slots=True)
class NormalizationOutcome:
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    rejected_sections: set[str] = field(default_factory=set)


def _rows(executions: Mapping[str, object], query: str) -> Sequence[Mapping[str, object]]:
    execution = executions.get(query)
    payload = getattr(execution, "payload", None)
    if payload is None and isinstance(execution, Mapping):
        payload = execution.get("payload")
    if not isinstance(payload, list):
        return ()
    return tuple(row for row in payload if isinstance(row, Mapping))


def _observed(executions: Mapping[str, object], *queries: str) -> bool:
    """Return true only when at least one query produced an observed row set.

    A successful query may legitimately return an empty list. Missing, failed,
    unavailable, and timed-out queries must not be normalized as authoritative
    empty inventory because that erases collection completeness.
    """

    for query in queries:
        execution = executions.get(query)
        payload = getattr(execution, "payload", None)
        status = getattr(execution, "status", None)
        if isinstance(execution, Mapping):
            payload = execution.get("payload", payload)
            status = execution.get("status", status)
        if not isinstance(payload, list):
            continue
        if status is None:
            return True
        normalized = str(getattr(status, "value", status)).upper()
        if normalized in {"SUCCESS", "PARTIAL"}:
            return True
    return False


def _fully_observed(executions: Mapping[str, object], *queries: str) -> bool:
    selected = tuple(query for query in queries if query in executions)
    return bool(selected) and all(_observed(executions, query) for query in selected)


def _append_validated(
    output: list[Any], model: type[Any], values: Mapping[str, Any], warnings: list[str], label: str
) -> None:
    try:
        output.append(model.model_validate(values))
    except ValidationError as exc:
        warnings.append(f"{label} row rejected during normalization: {exc.errors()[0]['type']}")


def _normalize_disks(executions: Mapping[str, object], outcome: NormalizationOutcome) -> list[Disk]:
    disks: list[Disk] = []
    for row in _rows(executions, "mounts"):
        name = _text(row.get("device"), maximum=512)
        mount_point = _text(row.get("path"), maximum=4096)
        if not name and not mount_point:
            continue
        block_count = _integer(row.get("blocks"))
        block_size = _integer(row.get("blocks_size"))
        free_blocks = _integer(row.get("blocks_free"))
        capacity = (
            block_count * block_size if block_count is not None and block_size is not None else None
        )
        free = (
            free_blocks * block_size if free_blocks is not None and block_size is not None else None
        )
        _append_validated(
            disks,
            Disk,
            {
                "name": name or mount_point or "unknown",
                "mount_point": mount_point,
                "capacity_bytes": capacity,
                "free_bytes": free,
                "disk_type": _text(row.get("type"), maximum=64),
            },
            outcome.warnings,
            "disk",
        )
    for row in _rows(executions, "logical_drives"):
        name = _text(row.get("device_id"), maximum=512)
        if not name:
            continue
        _append_validated(
            disks,
            Disk,
            {
                "name": name,
                "mount_point": name,
                "capacity_bytes": _integer(row.get("size")),
                "free_bytes": _integer(row.get("free_space")),
                "disk_type": _text(
                    row.get("file_system") or row.get("description") or row.get("type"),
                    maximum=64,
                ),
            },
            outcome.warnings,
            "disk",
        )
    return disks


def _normalize_system(executions: Mapping[str, object], outcome: NormalizationOutcome) -> None:
    os_rows = _rows(executions, "os_info")
    system_rows = _rows(executions, "system_info")
    uptime_rows = _rows(executions, "uptime")
    kernel_rows = _rows(executions, "kernel_info")
    time_rows = _rows(executions, "time_info")
    platform_rows = _rows(executions, "platform_info")
    cpu_rows = _rows(executions, "cpu_info")
    tpm_rows = _rows(executions, "tpm_info")
    os_row = os_rows[0] if os_rows else {}
    system = system_rows[0] if system_rows else {}
    platform_row = platform_rows[0] if platform_rows else {}

    if os_row and _fully_observed(
        executions, "os_info", "system_info", "uptime", "kernel_info", "time_info"
    ):
        uptime_seconds: int | None = None
        if uptime_rows:
            uptime = uptime_rows[0]
            uptime_seconds = _integer(uptime.get("total_seconds"))
            if uptime_seconds is None:
                uptime_seconds = (
                    (_integer(uptime.get("days")) or 0) * 86_400
                    + (_integer(uptime.get("hours")) or 0) * 3_600
                    + (_integer(uptime.get("minutes")) or 0) * 60
                    + (_integer(uptime.get("seconds")) or 0)
                )
        values: dict[str, Any] = {
            "family": _family(os_row.get("platform"), os_row.get("name")),
            "name": _text(os_row.get("name"), maximum=512) or "Unknown",
            "version": _text(os_row.get("version"), maximum=128) or "unknown",
            "build": _text(os_row.get("build"), maximum=128),
            "architecture": _text(os_row.get("arch"), maximum=64),
            "hostname": _text(system.get("hostname"), maximum=512),
            "machine_id": _text(system.get("machine_id"), maximum=512),
            "kernel": (_text(kernel_rows[0].get("version"), maximum=256) if kernel_rows else None),
            "timezone": (
                _text(time_rows[0].get("local_timezone"), maximum=128) if time_rows else None
            ),
            "uptime_seconds": uptime_seconds,
            "boot_time": (_timestamp(uptime_rows[0].get("boot_time")) if uptime_rows else None)
            or (
                (datetime.now(UTC) - timedelta(seconds=uptime_seconds)).replace(
                    second=0, microsecond=0
                )
                if uptime_seconds is not None
                else None
            ),
        }
        try:
            outcome.data["os"] = OperatingSystem.model_validate(values)
        except ValidationError as exc:
            outcome.warnings.append(f"operating system data rejected: {exc.errors()[0]['type']}")

    disks = _normalize_disks(executions, outcome)
    gpus: list[GPU] = []
    for row in _rows(executions, "video_info"):
        model = _text(row.get("model") or row.get("series"), maximum=512)
        if not model:
            continue
        _append_validated(
            gpus,
            GPU,
            {
                "vendor": _text(row.get("manufacturer"), maximum=256),
                "model": model,
            },
            outcome.warnings,
            "GPU",
        )
    for row in _rows(executions, "pci_devices"):
        device_class = _text(row.get("pci_class"), maximum=128) or ""
        if not any(marker in device_class.casefold() for marker in ("display", "vga", "3d")):
            continue
        model = _text(row.get("model") or row.get("model_id"), maximum=512)
        if not model:
            continue
        _append_validated(
            gpus,
            GPU,
            {
                "vendor": _text(row.get("vendor") or row.get("vendor_id"), maximum=256),
                "model": model,
            },
            outcome.warnings,
            "GPU",
        )

    hardware_observed = bool(system) and _fully_observed(
        executions,
        "system_info",
        "cpu_info",
        "platform_info",
        "video_info",
        "pci_devices",
        "tpm_info",
        "mounts",
        "logical_drives",
    )
    if hardware_observed:
        cpu_row = cpu_rows[0] if cpu_rows else {}
        cpu_values = {
            "vendor": _text(cpu_row.get("manufacturer"), maximum=256),
            "model": _text(system.get("cpu_brand") or cpu_row.get("model"), maximum=512),
            "physical_cores": _integer(system.get("cpu_physical_cores"), minimum=1),
            "logical_processors": _integer(system.get("cpu_logical_cores"), minimum=1),
            "architecture": _text(os_row.get("arch"), maximum=64),
        }
        motherboard = (
            " ".join(
                part
                for value in (
                    system.get("board_vendor"),
                    system.get("board_model"),
                    system.get("board_version"),
                )
                if (part := _text(value, maximum=256))
            )
            or None
        )
        firmware_version = (
            " ".join(
                part
                for value in (platform_row.get("version"), platform_row.get("revision"))
                if (part := _text(value, maximum=128))
            )
            or None
        )
        tpm = tpm_rows[0] if tpm_rows else {}
        values = {
            "cpu": CPU.model_validate(cpu_values),
            "memory_bytes": _integer(system.get("physical_memory")),
            "disks": disks,
            "gpus": gpus,
            "motherboard": motherboard,
            "bios_uefi": _text(platform_row.get("firmware_type"), maximum=512),
            "firmware_version": firmware_version,
            "manufacturer": _text(system.get("hardware_vendor"), maximum=256),
            "device_model": _text(system.get("hardware_model"), maximum=256),
            "tpm_present": (True if tpm else False if _observed(executions, "tpm_info") else None),
            "tpm_version": _text(
                tpm.get("spec_version") or tpm.get("manufacturer_version"), maximum=64
            ),
        }
        try:
            outcome.data["hardware"] = Hardware.model_validate(values)
        except ValidationError as exc:
            outcome.warnings.append(f"hardware data rejected: {exc.errors()[0]['type']}")
        hostname = _text(system.get("hostname"), maximum=512)
        if hostname:
            outcome.data["hostname"] = hostname


def _normalize_software(executions: Mapping[str, object], outcome: NormalizationOutcome) -> None:
    software: list[Software] = []
    seen: set[tuple[str, str | None, str | None]] = set()
    sources = (
        ("software", "windows"),
        ("software_macos", "macos-app"),
        ("packages", "deb"),
        ("packages_rpm", "rpm"),
        ("packages_homebrew", "homebrew"),
    )
    for query, manager in sources:
        for row in _rows(executions, query):
            name = _text(row.get("name"), maximum=512)
            if not name:
                continue
            version = _text(row.get("version"), maximum=256)
            architecture = _text(row.get("architecture"), maximum=64)
            values: dict[str, Any] = {
                "name": name,
                "version": version,
                "vendor": _text(row.get("publisher") or row.get("vendor"), maximum=512),
                "installation_path": _text(row.get("install_location"), maximum=4096),
                "installation_date": _date_value(
                    row.get("install_date") or row.get("install_time")
                ),
                "package_manager": manager,
                "architecture": architecture,
                "source": "osquery",
            }
            identity = (name.casefold(), version, architecture)
            if identity in seen:
                continue
            seen.add(identity)
            _append_validated(software, Software, values, outcome.warnings, "software")
    if _fully_observed(executions, *(query for query, _manager in sources)):
        outcome.data["software"] = software


def _normalize_processes(executions: Mapping[str, object], outcome: NormalizationOutcome) -> None:
    processes: list[Process] = []
    usernames = {
        str(row.get("uid")): username
        for row in _rows(executions, "users")
        if row.get("uid") is not None
        and (username := _text(row.get("username"), maximum=512)) is not None
    }
    for row in _rows(executions, "processes"):
        pid = _integer(row.get("pid"))
        name = _text(row.get("name"), maximum=512)
        if pid is None or not name:
            continue
        _append_validated(
            processes,
            Process,
            {
                "pid": pid,
                "name": name,
                "executable_path": _text(row.get("path"), maximum=4096),
                "parent_pid": _integer(row.get("parent")),
                "user": usernames.get(str(row.get("uid"))) or _text(row.get("uid"), maximum=512),
                "start_time": _timestamp(row.get("start_time")),
                "memory_bytes": _integer(row.get("resident_size")),
            },
            outcome.warnings,
            "process",
        )
    if _observed(executions, "processes"):
        outcome.data["processes"] = processes


def _normalize_services(executions: Mapping[str, object], outcome: NormalizationOutcome) -> None:
    services: list[Service] = []
    state_map = {
        "running": ServiceState.RUNNING,
        "active": ServiceState.RUNNING,
        "stopped": ServiceState.STOPPED,
        "inactive": ServiceState.STOPPED,
        "paused": ServiceState.PAUSED,
    }
    for query in ("services", "services_linux", "services_macos"):
        for row in _rows(executions, query):
            name = _text(row.get("name"), maximum=512)
            if not name:
                continue
            status = str(row.get("status", "")).casefold()
            _append_validated(
                services,
                Service,
                {
                    "name": name,
                    "display_name": _text(row.get("display_name"), maximum=512),
                    "state": state_map.get(status, ServiceState.UNKNOWN),
                    "startup_type": _text(row.get("start_type"), maximum=128),
                    "executable_path": _text(row.get("path"), maximum=4096),
                    "service_account": _text(row.get("user_account"), maximum=512),
                },
                outcome.warnings,
                "service",
            )
    if _fully_observed(executions, "services", "services_linux", "services_macos"):
        outcome.data["services"] = services


def _normalize_users(executions: Mapping[str, object], outcome: NormalizationOutcome) -> None:
    group_names = {
        str(row.get("gid")): name
        for row in _rows(executions, "groups")
        if (name := _text(row.get("groupname"), maximum=256)) is not None
        and row.get("gid") is not None
    }
    memberships: dict[str, set[str]] = {}
    for row in _rows(executions, "user_groups"):
        uid = _text(row.get("uid"), maximum=128)
        group = group_names.get(str(row.get("gid")))
        if uid and group:
            memberships.setdefault(uid, set()).add(group)
    administrator_groups = {"admin", "administrators", "sudo", "wheel"}
    last_logins: dict[str, datetime] = {}
    for row in _rows(executions, "last_logins"):
        username = _text(row.get("username"), maximum=512)
        observed_at = _timestamp(row.get("time"))
        type_name = str(row.get("type_name") or "").casefold()
        if not username or observed_at is None or (type_name and "user" not in type_name):
            continue
        existing = last_logins.get(username.casefold())
        if existing is None or observed_at > existing:
            last_logins[username.casefold()] = observed_at
    account_enabled: dict[str, bool | None] = {}
    epoch_days = int(datetime.now(UTC).timestamp() // 86_400)
    for row in _rows(executions, "account_status_linux"):
        username = _text(row.get("username"), maximum=512)
        if not username:
            continue
        expiry_day = _signed_integer(row.get("expire"))
        password_status = str(row.get("password_status") or "").strip().casefold()
        if expiry_day is not None and expiry_day >= 0 and expiry_day <= epoch_days:
            enabled: bool | None = False
        elif password_status in {"active", "empty"}:
            enabled = True
        else:
            # A locked password alone does not disable SSH keys or non-password
            # authentication, so it cannot safely be reported as a disabled account.
            enabled = None
        account_enabled[username.casefold()] = enabled
    users: list[User] = []
    for row in _rows(executions, "users"):
        username = _text(row.get("username"), maximum=512)
        if not username:
            continue
        membership_uid = _text(row.get("uid"), maximum=128)
        uid = _text(row.get("uuid") or row.get("uid"), maximum=128)
        groups = memberships.get(membership_uid or "", set())
        is_administrator = membership_uid == "0" or bool(
            {group.casefold() for group in groups} & administrator_groups
        )
        _append_validated(
            users,
            User,
            {
                "username": username,
                "uid": uid,
                "enabled": account_enabled.get(username.casefold()),
                "groups": groups,
                "is_administrator": is_administrator,
                "is_guest": username.casefold() in {"guest", "nobody"},
                "last_login": last_logins.get(username.casefold()),
            },
            outcome.warnings,
            "user",
        )
    if _observed(executions, "users") and _fully_observed(
        executions, "users", "groups", "user_groups", "last_logins"
    ):
        outcome.data["users"] = users


def _prefix_from_mask(mask: object) -> int | None:
    if not mask:
        return None
    try:
        text = str(mask)
        if text.isdigit():
            return int(text)
        network = f"::/{text}" if ":" in text else f"0.0.0.0/{text}"
        return ipaddress.ip_network(network).prefixlen
    except (ValueError, TypeError):
        return None


def _ip_values(value: object) -> list[str]:
    if value is None:
        return []
    raw_values = re.split(r"[,;\s]+", str(value).strip(" []\"'"))
    normalized: list[str] = []
    for raw in raw_values:
        candidate = raw.strip(" []\"'")
        if not candidate:
            continue
        try:
            normalized.append(ipaddress.ip_address(candidate.split("%", 1)[0]).compressed)
        except ValueError:
            continue
    return normalized


def _normalize_interfaces(executions: Mapping[str, object], outcome: NormalizationOutcome) -> None:
    grouped: dict[str, dict[str, Any]] = {}
    for row in _rows(executions, "interfaces"):
        name = _text(row.get("interface"), maximum=512)
        if not name:
            continue
        interface = grouped.setdefault(
            name, {"name": name, "addresses": [], "_address_types": set()}
        )
        if row.get("mac"):
            interface["mac_address"] = _text(row.get("mac"), maximum=64)
        interface_type = _text(row.get("type"), maximum=128) or ""
        lowered_name = f"{name} {interface_type}".casefold()
        interface["is_vpn"] = any(
            marker in lowered_name for marker in ("vpn", "tun", "tap", "wireguard", "utun", "ppp")
        )
        flags = _integer(row.get("flags"))
        host_platform = str(row.get("host_platform") or "").strip().casefold()
        if flags is not None and host_platform and host_platform != "windows":
            interface["is_up"] = bool(flags & 1)
        address_type = str(row.get("address_type") or "").strip().casefold()
        if address_type:
            interface["_address_types"].add(address_type)
        address = _text(row.get("address"), maximum=128)
        if address:
            try:
                interface["addresses"].append(
                    IPAddress(
                        address=address.split("%", 1)[0],
                        prefix_length=_prefix_from_mask(row.get("mask")),
                    )
                )
            except (ValidationError, ValueError):
                outcome.warnings.append(f"invalid address omitted for interface {name}")
    for row in _rows(executions, "interfaces_windows"):
        name = _text(row.get("interface"), maximum=512)
        if not name:
            continue
        interface = grouped.setdefault(
            name, {"name": name, "addresses": [], "_address_types": set()}
        )
        enabled = _boolean(row.get("enabled"))
        connection_status = _integer(row.get("connection_status"))
        if enabled is False or connection_status in {0, 4, 5, 6, 7, 10, 11}:
            interface["is_up"] = False
        elif connection_status == 2:
            interface["is_up"] = True
        else:
            interface["is_up"] = None
        dhcp_enabled = _boolean(row.get("dhcp_enabled"))
        interface["dhcp_enabled"] = dhcp_enabled
        dhcp_servers = _ip_values(row.get("dhcp_server"))
        lease_obtained = _timestamp(row.get("dhcp_lease_obtained"))
        lease_expires = _timestamp(row.get("dhcp_lease_expires"))
        if (
            lease_obtained is not None
            and lease_expires is not None
            and lease_expires < lease_obtained
        ):
            outcome.warnings.append(f"invalid DHCP lease window omitted for interface {name}")
            lease_obtained = None
            lease_expires = None
        interface["dhcp_server"] = (
            dhcp_servers[0] if dhcp_servers and dhcp_enabled is not False else None
        )
        interface["dhcp_lease_obtained"] = lease_obtained if dhcp_enabled is not False else None
        interface["dhcp_lease_expires"] = lease_expires if dhcp_enabled is not False else None
        interface["dns_servers"] = _ip_values(row.get("dns_server_search_order"))
    for row in _rows(executions, "routes"):
        destination = str(row.get("destination") or "").strip().casefold()
        netmask = str(row.get("netmask") or "").strip().casefold()
        is_default = destination in {"default", "0.0.0.0/0", "::/0"} or (
            destination in {"0.0.0.0", "::"}  # noqa: S104 - observed route value
            and netmask in {"", "0", "0.0.0.0", "::"}  # noqa: S104
        )
        if not is_default:
            continue
        name = _text(row.get("interface"), maximum=512)
        gateways = _ip_values(row.get("gateway"))
        if not name or not gateways:
            continue
        interface = grouped.setdefault(
            name, {"name": name, "addresses": [], "_address_types": set()}
        )
        current = list(interface.get("gateways", []))
        interface["gateways"] = list(dict.fromkeys([*current, *gateways]))
    global_dns: list[str] = []
    for row in _rows(executions, "dns_resolvers"):
        servers = _ip_values(row.get("address"))
        name = _text(row.get("interface"), maximum=512)
        if name and servers:
            interface = grouped.setdefault(
                name, {"name": name, "addresses": [], "_address_types": set()}
            )
            current = list(interface.get("dns_servers", []))
            interface["dns_servers"] = list(dict.fromkeys([*current, *servers]))
        else:
            global_dns.extend(servers)
    if global_dns:
        for interface in grouped.values():
            current = list(interface.get("dns_servers", []))
            interface["dns_servers"] = list(dict.fromkeys([*current, *global_dns]))
    interfaces: list[NetworkInterface] = []
    for values in grouped.values():
        address_types = values.pop("_address_types", set())
        if "dhcp_enabled" not in values:
            if "dhcp" in address_types:
                values["dhcp_enabled"] = True
            elif address_types and address_types <= {"manual", "auto"}:
                values["dhcp_enabled"] = False
        _append_validated(
            interfaces, NetworkInterface, values, outcome.warnings, "network interface"
        )
    if _fully_observed(
        executions,
        "interfaces",
        "interfaces_windows",
        "routes",
        "dns_resolvers",
    ):
        outcome.data["network_interfaces"] = interfaces


def _normalize_ports(executions: Mapping[str, object], outcome: NormalizationOutcome) -> None:
    process_names = {
        pid: name
        for row in _rows(executions, "processes")
        if (pid := _integer(row.get("pid"))) is not None
        and (name := _text(row.get("name"), maximum=512)) is not None
    }
    ports: list[ListeningPort] = []
    for row in _rows(executions, "listening_ports"):
        protocol_text = str(row.get("protocol", "")).casefold()
        protocol = (
            NetworkProtocol.TCP
            if protocol_text in {"6", "tcp"}
            else NetworkProtocol.UDP
            if protocol_text in {"17", "udp"}
            else NetworkProtocol.UNKNOWN
        )
        port = _integer(row.get("local_port"))
        address = _text(row.get("local_address"), maximum=128)
        if port is None or not address:
            continue
        pid = _integer(row.get("pid"))
        _append_validated(
            ports,
            ListeningPort,
            {
                "protocol": protocol,
                "address": address,
                "port": port,
                "pid": pid,
                "process": process_names.get(pid) if pid is not None else None,
                "exposed": address in {"0.0.0.0", "::", "*"},  # noqa: S104
            },
            outcome.warnings,
            "listening port",
        )
    if _observed(executions, "listening_ports"):
        outcome.data["listening_ports"] = ports


def _normalize_persistence(executions: Mapping[str, object], outcome: NormalizationOutcome) -> None:
    items: list[PersistenceItem] = []
    for row in _rows(executions, "startup_items"):
        name = _text(row.get("name"), maximum=512)
        kind = _text(row.get("type"), maximum=128) or "startup_item"
        if not name:
            continue
        _append_validated(
            items,
            PersistenceItem,
            {
                "name": name,
                "kind": kind,
                "location": _text(row.get("source"), maximum=4096),
                "executable_path": _text(row.get("path"), maximum=4096),
                "enabled": str(row.get("status", "enabled")).casefold() != "disabled",
            },
            outcome.warnings,
            "persistence",
        )
    for row in _rows(executions, "scheduled_tasks_windows"):
        name = _text(row.get("name"), maximum=512)
        if not name:
            continue
        _append_validated(
            items,
            PersistenceItem,
            {
                "name": name,
                "kind": "scheduled_task",
                "location": _text(row.get("path"), maximum=4096),
                "executable_path": _text(row.get("action"), maximum=4096),
                "enabled": _boolean(row.get("enabled")),
            },
            outcome.warnings,
            "scheduled task",
        )
    for row in _rows(executions, "crontab"):
        event = _text(row.get("event"), maximum=256) or "scheduled"
        path = _text(row.get("path"), maximum=4096)
        command = _text(row.get("command"), maximum=4096)
        name = f"{path or 'crontab'}: {event}"[:512]
        _append_validated(
            items,
            PersistenceItem,
            {
                "name": name,
                "kind": "cron",
                "location": path,
                "executable_path": redact_text(command) if command else None,
                "enabled": True,
            },
            outcome.warnings,
            "cron entry",
        )
    if _fully_observed(
        executions,
        "startup_items",
        "scheduled_tasks_windows",
        "crontab",
    ):
        outcome.data["persistence"] = items


def _normalize_extensions(executions: Mapping[str, object], outcome: NormalizationOutcome) -> None:
    extensions: list[BrowserExtension] = []
    queries = (
        ("browser_extensions", None),
        ("browser_extensions_firefox", "Firefox"),
        ("browser_extensions_safari", "Safari"),
    )
    for query, default_browser in queries:
        for row in _rows(executions, query):
            extension_id = _text(row.get("identifier"), maximum=512)
            browser = _text(row.get("browser_type"), maximum=512) or default_browser
            if not extension_id or not browser:
                continue
            _append_validated(
                extensions,
                BrowserExtension,
                {
                    "browser": browser,
                    "extension_id": extension_id,
                    "name": _text(row.get("name"), maximum=512),
                    "version": _text(row.get("version"), maximum=128),
                    "enabled": _boolean(row.get("active")),
                },
                outcome.warnings,
                "browser extension",
            )
    if _fully_observed(
        executions,
        "browser_extensions",
        "browser_extensions_firefox",
        "browser_extensions_safari",
    ):
        outcome.data["browser_extensions"] = extensions


def _normalize_security(executions: Mapping[str, object], outcome: NormalizationOutcome) -> None:
    if not _observed(executions, "secure_boot"):
        return
    rows = _rows(executions, "secure_boot")
    enabled = _boolean(rows[0].get("secure_boot")) if rows else None
    outcome.data["security"] = SecurityPosture(secure_boot_enabled=enabled)


def normalize_osquery(executions: Mapping[str, object]) -> NormalizationOutcome:
    """Normalize independently successful registered queries; bad rows are isolated."""

    outcome = NormalizationOutcome()
    normalizers = (
        (_normalize_system, frozenset({"os", "hardware"})),
        (_normalize_software, frozenset({"software"})),
        (_normalize_processes, frozenset({"processes"})),
        (_normalize_services, frozenset({"services"})),
        (_normalize_users, frozenset({"users"})),
        (_normalize_interfaces, frozenset({"network_interfaces"})),
        (_normalize_ports, frozenset({"listening_ports"})),
        (_normalize_persistence, frozenset({"persistence"})),
        (_normalize_extensions, frozenset({"browser_extensions"})),
        (_normalize_security, frozenset({"security"})),
    )
    for normalizer, sections in normalizers:
        before = len(outcome.warnings)
        normalizer(executions, outcome)
        if len(outcome.warnings) > before:
            outcome.rejected_sections.update(
                section for section in sections if section in outcome.data
            )
    outcome.data.setdefault("hostname", socket.gethostname()[:512] or "unknown")
    return outcome


def fallback_endpoint_identity() -> dict[str, Any]:
    """Provide bounded local identity when osquery is absent, never a false posture result."""

    system = platform.system()
    family = _family(system, system)
    hostname = socket.gethostname()[:512] or "unknown"
    operating_system = OperatingSystem(
        family=family,
        name=system or "Unknown",
        version=platform.release() or "unknown",
        build=platform.version()[:128] or None,
        kernel=platform.version()[:256] or None,
        architecture=platform.machine()[:64] or None,
        hostname=hostname,
    )
    hardware = Hardware(
        cpu=CPU(
            model=platform.processor()[:512] or None,
            logical_processors=os.cpu_count(),
            architecture=platform.machine()[:64] or None,
        )
    )
    return {"hostname": hostname, "os": operating_system, "hardware": hardware}
