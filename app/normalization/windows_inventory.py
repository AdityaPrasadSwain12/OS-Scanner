"""Normalize dependency-free Windows inventory into scanner-owned models."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import ValidationError

from app.models import (
    CPU,
    GPU,
    BrowserExtension,
    CertificateInfo,
    Disk,
    Hardware,
    IPAddress,
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

from .osquery import (
    NormalizationOutcome,
    _append_validated,
    _boolean,
    _date_value,
    _integer,
    _text,
    _timestamp,
)


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _records(value: object) -> Sequence[Mapping[str, Any]]:
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, Mapping))
    if isinstance(value, Mapping):
        return (value,)
    return ()


def _section_records(
    value: object,
    outcome: NormalizationOutcome,
    label: str,
) -> Sequence[Mapping[str, Any]]:
    """Return records while making discarded structure visible to authority logic."""

    if isinstance(value, list):
        if any(not isinstance(item, Mapping) for item in value):
            outcome.warnings.append(f"invalid Windows {label} record omitted")
    elif not isinstance(value, Mapping):
        outcome.warnings.append(f"invalid Windows {label} payload omitted")
    return _records(value)


def _finish_section(
    outcome: NormalizationOutcome,
    section: str,
    warning_count: int,
) -> None:
    if len(outcome.warnings) > warning_count:
        outcome.rejected_sections.add(section)


def _normalize_os(values: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    name = _text(values.get("Name"), maximum=512)
    version = _text(values.get("Version"), maximum=128)
    if not name or not version:
        outcome.warnings.append("Windows OS identity omitted because name or version is missing")
        return
    try:
        operating_system = OperatingSystem(
            family=OperatingSystemFamily.WINDOWS,
            name=name,
            version=version,
            build=_text(values.get("Build"), maximum=128),
            architecture=_text(values.get("Architecture"), maximum=64),
            hostname=_text(values.get("Hostname"), maximum=512),
            machine_id=_text(values.get("MachineId"), maximum=512),
            boot_time=_timestamp(values.get("BootTime")),
            uptime_seconds=_integer(values.get("UptimeSeconds")),
            timezone=_text(values.get("Timezone"), maximum=128),
            installed_at=_timestamp(values.get("InstalledAt")),
            domain=(
                _text(values.get("Domain"), maximum=512)
                if _boolean(values.get("PartOfDomain")) is True
                else None
            ),
        )
    except ValidationError as exc:
        outcome.warnings.append(f"Windows OS identity rejected: {exc.errors()[0]['type']}")
        return
    outcome.data["os"] = operating_system
    if operating_system.hostname:
        outcome.data["hostname"] = operating_system.hostname


def _normalize_hardware(values: Mapping[str, Any], outcome: NormalizationOutcome) -> None:
    cpu_rows = _records(values.get("CPUs"))
    physical_values = [
        value
        for row in cpu_rows
        if (value := _integer(row.get("PhysicalCores"), minimum=1)) is not None
    ]
    logical_values = [
        value
        for row in cpu_rows
        if (value := _integer(row.get("LogicalProcessors"), minimum=1)) is not None
    ]
    first_cpu = cpu_rows[0] if cpu_rows else {}
    cpu: CPU | None = None
    if cpu_rows:
        try:
            cpu = CPU(
                vendor=_text(first_cpu.get("Vendor"), maximum=256),
                model=_text(first_cpu.get("Model"), maximum=512),
                physical_cores=sum(physical_values) if physical_values else None,
                logical_processors=sum(logical_values) if logical_values else None,
                architecture=_text(first_cpu.get("Architecture"), maximum=64),
            )
        except ValidationError as exc:
            outcome.warnings.append(f"Windows CPU metadata rejected: {exc.errors()[0]['type']}")

    disks: list[Disk] = []
    for row in _records(values.get("Disks")):
        name = _text(row.get("Name"), maximum=512)
        if not name:
            outcome.warnings.append("invalid Windows disk metadata omitted")
            continue
        _append_validated(
            disks,
            Disk,
            {
                "name": name,
                "mount_point": _text(row.get("MountPoint"), maximum=4096),
                "capacity_bytes": _integer(row.get("CapacityBytes")),
                "free_bytes": _integer(row.get("FreeBytes")),
                "disk_type": _text(row.get("DiskType"), maximum=64),
                "serial_number": _text(row.get("SerialNumber"), maximum=256),
            },
            outcome.warnings,
            "Windows disk",
        )

    gpus: list[GPU] = []
    for row in _records(values.get("GPUs")):
        model = _text(row.get("Model"), maximum=512)
        if not model:
            outcome.warnings.append("invalid Windows GPU metadata omitted")
            continue
        _append_validated(
            gpus,
            GPU,
            {
                "vendor": _text(row.get("Vendor"), maximum=256),
                "model": model,
                "memory_bytes": _integer(row.get("MemoryBytes")),
            },
            outcome.warnings,
            "Windows GPU",
        )

    try:
        outcome.data["hardware"] = Hardware(
            cpu=cpu,
            memory_bytes=_integer(values.get("MemoryBytes")),
            disks=disks,
            gpus=gpus,
            motherboard=_text(values.get("Motherboard"), maximum=512),
            bios_uefi=_text(values.get("BiosUefi"), maximum=512),
            firmware_version=_text(values.get("FirmwareVersion"), maximum=256),
            firmware_release_date=_timestamp(values.get("FirmwareReleaseDate")),
            manufacturer=_text(values.get("Manufacturer"), maximum=256),
            device_model=_text(values.get("DeviceModel"), maximum=256),
        )
    except ValidationError as exc:
        outcome.warnings.append(f"Windows hardware metadata rejected: {exc.errors()[0]['type']}")


def _normalize_software(rows: Sequence[Mapping[str, Any]], outcome: NormalizationOutcome) -> None:
    software: list[Software] = []
    seen: set[tuple[str, str | None, str | None]] = set()
    for row in rows:
        name = _text(row.get("Name"), maximum=512)
        if not name:
            outcome.warnings.append("invalid Windows software metadata omitted")
            continue
        version = _text(row.get("Version"), maximum=256)
        architecture = _text(row.get("Architecture"), maximum=64)
        identity = (name.casefold(), version, architecture)
        if identity in seen:
            continue
        seen.add(identity)
        _append_validated(
            software,
            Software,
            {
                "name": name,
                "version": version,
                "vendor": _text(row.get("Vendor"), maximum=512),
                "installation_path": _text(row.get("InstallationPath"), maximum=4096),
                "installation_date": _date_value(row.get("InstallationDate")),
                "package_manager": (
                    _text(row.get("PackageManager"), maximum=128) or "windows_registry"
                ),
                "architecture": architecture,
                "source": _text(row.get("Source"), maximum=256) or "native",
                "package_id": _text(row.get("PackageId"), maximum=512),
            },
            outcome.warnings,
            "Windows software",
        )
    outcome.data["software"] = software


def _normalize_processes(rows: Sequence[Mapping[str, Any]], outcome: NormalizationOutcome) -> None:
    processes: list[Process] = []
    for row in rows:
        pid = _integer(row.get("Pid"))
        name = _text(row.get("Name"), maximum=512)
        if pid is None or not name:
            outcome.warnings.append("invalid Windows process metadata omitted")
            continue
        _append_validated(
            processes,
            Process,
            {
                "pid": pid,
                "name": name,
                "executable_path": _text(row.get("ExecutablePath"), maximum=4096),
                "parent_pid": _integer(row.get("ParentPid")),
                "user": _text(row.get("User"), maximum=512),
                "start_time": _timestamp(row.get("StartTime")),
                "memory_bytes": _integer(row.get("MemoryBytes")),
            },
            outcome.warnings,
            "Windows process",
        )
    outcome.data["processes"] = processes


def _normalize_services(rows: Sequence[Mapping[str, Any]], outcome: NormalizationOutcome) -> None:
    state_map = {
        "running": ServiceState.RUNNING,
        "stopped": ServiceState.STOPPED,
        "paused": ServiceState.PAUSED,
    }
    services: list[Service] = []
    for row in rows:
        name = _text(row.get("Name"), maximum=512)
        if not name:
            outcome.warnings.append("invalid Windows service metadata omitted")
            continue
        state = str(row.get("State") or "").strip().casefold()
        _append_validated(
            services,
            Service,
            {
                "name": name,
                "display_name": _text(row.get("DisplayName"), maximum=512),
                "state": state_map.get(state, ServiceState.UNKNOWN),
                "startup_type": _text(row.get("StartupType"), maximum=128),
                "executable_path": _text(row.get("ExecutablePath"), maximum=4096),
                "service_account": _text(row.get("ServiceAccount"), maximum=512),
            },
            outcome.warnings,
            "Windows service",
        )
    outcome.data["services"] = services


def _normalize_users(rows: Sequence[Mapping[str, Any]], outcome: NormalizationOutcome) -> None:
    users: list[User] = []
    for row in rows:
        username = _text(row.get("Name"), maximum=512)
        if not username:
            outcome.warnings.append("invalid Windows user metadata omitted")
            continue
        raw_groups = row.get("Groups")
        groups = (
            {group for value in raw_groups if (group := _text(value, maximum=256)) is not None}
            if isinstance(raw_groups, list)
            else set()
        )
        _append_validated(
            users,
            User,
            {
                "username": username,
                "uid": _text(row.get("SID"), maximum=128),
                "enabled": _boolean(row.get("Enabled")),
                "groups": groups,
                "is_administrator": _boolean(row.get("IsAdministrator")) is True,
                "is_guest": _boolean(row.get("IsGuest")) is True,
                "last_login": _timestamp(row.get("LastLogon")),
                "password_required": _boolean(row.get("PasswordRequired")),
                "password_expires": _timestamp(row.get("PasswordExpires")),
                "user_may_change_password": _boolean(row.get("UserMayChangePassword")),
            },
            outcome.warnings,
            "Windows user",
        )
    outcome.data["users"] = users


def _ip_list(
    value: object,
    outcome: NormalizationOutcome,
    label: str,
) -> list[str]:
    if not isinstance(value, list):
        value = [value] if value else []
    addresses: list[str] = []
    for item in value:
        try:
            normalized = ipaddress.ip_address(str(item).split("%", 1)[0]).compressed
        except ValueError:
            outcome.warnings.append(f"invalid {label} address omitted")
            continue
        if normalized not in addresses:
            addresses.append(normalized)
    return addresses


def _normalize_interfaces(rows: Sequence[Mapping[str, Any]], outcome: NormalizationOutcome) -> None:
    interfaces: list[NetworkInterface] = []
    for row in rows:
        name = _text(row.get("Name"), maximum=512)
        if not name:
            outcome.warnings.append("invalid Windows network interface metadata omitted")
            continue
        addresses: list[IPAddress] = []
        for address_row in _records(row.get("Addresses")):
            address = _text(address_row.get("Address"), maximum=128)
            if not address:
                outcome.warnings.append(
                    f"invalid address omitted for Windows interface {name}"
                )
                continue
            try:
                addresses.append(
                    IPAddress(
                        address=address.split("%", 1)[0],
                        prefix_length=_integer(address_row.get("PrefixLength")),
                    )
                )
            except (ValidationError, ValueError):
                outcome.warnings.append(f"invalid address omitted for Windows interface {name}")
        description = _text(row.get("Description"), maximum=512) or ""
        vpn_markers = ("vpn", "wireguard", "tunnel", "tap", "tun", "ppp")
        mac_address = _text(row.get("MacAddress"), maximum=64)
        if mac_address and len(re.sub(r"[^0-9A-Fa-f]", "", mac_address)) != 12:
            outcome.warnings.append(f"invalid MAC address omitted for Windows interface {name}")
            mac_address = None
        lease_obtained = _timestamp(row.get("DhcpLeaseObtained"))
        lease_expires = _timestamp(row.get("DhcpLeaseExpires"))
        if lease_obtained and lease_expires and lease_expires < lease_obtained:
            outcome.warnings.append(
                f"invalid DHCP lease window omitted for Windows interface {name}"
            )
            lease_obtained = None
            lease_expires = None
        values = {
            "name": name,
            "mac_address": mac_address,
            "addresses": addresses,
            "gateways": _ip_list(
                row.get("Gateways"), outcome, f"Windows interface {name} gateway"
            ),
            "dns_servers": _ip_list(
                row.get("DnsServers"), outcome, f"Windows interface {name} DNS server"
            ),
            "dhcp_enabled": _boolean(row.get("DhcpEnabled")),
            "dhcp_server": next(
                iter(
                    _ip_list(
                        row.get("DhcpServer"),
                        outcome,
                        f"Windows interface {name} DHCP server",
                    )
                ),
                None,
            ),
            "dhcp_lease_obtained": lease_obtained,
            "dhcp_lease_expires": lease_expires,
            "is_up": _boolean(row.get("IsUp")),
            "is_vpn": any(marker in f"{name} {description}".casefold() for marker in vpn_markers),
        }
        try:
            interfaces.append(NetworkInterface.model_validate(values))
        except ValidationError as exc:
            outcome.warnings.append(
                f"Windows network interface rejected: {exc.errors()[0]['type']}"
            )
    outcome.data["network_interfaces"] = interfaces


def _normalize_ports(rows: Sequence[Mapping[str, Any]], outcome: NormalizationOutcome) -> None:
    ports: list[ListeningPort] = []
    for row in rows:
        protocol_text = str(row.get("Protocol") or "").strip().casefold()
        protocol = (
            NetworkProtocol.TCP
            if protocol_text == "tcp"
            else NetworkProtocol.UDP
            if protocol_text == "udp"
            else NetworkProtocol.UNKNOWN
        )
        address = _text(row.get("Address"), maximum=128)
        port = _integer(row.get("Port"))
        if not address or port is None:
            outcome.warnings.append("invalid Windows listening port metadata omitted")
            continue
        normalized_address = address.split("%", 1)[0]
        try:
            parsed_address = ipaddress.ip_address(normalized_address)
            bind_scope = (
                "WILDCARD"
                if parsed_address.is_unspecified
                else "LOOPBACK"
                if parsed_address.is_loopback
                else "INTERFACE"
            )
        except ValueError:
            bind_scope = "UNKNOWN"
        _append_validated(
            ports,
            ListeningPort,
            {
                "protocol": protocol,
                "address": address,
                "port": port,
                "pid": _integer(row.get("Pid")),
                "process": _text(row.get("Process"), maximum=512),
                "exposed": bind_scope == "WILDCARD",
                "bind_scope": bind_scope,
                "remote_reachability": "NOT_TESTED",
            },
            outcome.warnings,
            "Windows listening port",
        )
    outcome.data["listening_ports"] = ports


def _normalize_extensions(
    rows: Sequence[Mapping[str, Any]], outcome: NormalizationOutcome
) -> None:
    extensions: list[BrowserExtension] = []
    risky_permissions = {
        "<all_urls>",
        "debugger",
        "management",
        "nativemessaging",
        "proxy",
        "webrequestblocking",
    }
    seen: set[tuple[str, str, str | None]] = set()
    for row in rows:
        browser = _text(row.get("Browser"), maximum=512)
        extension_id = _text(row.get("ExtensionId"), maximum=512)
        if not browser or not extension_id:
            outcome.warnings.append("invalid Windows browser extension metadata omitted")
            continue
        version = _text(row.get("Version"), maximum=128)
        identity = (browser.casefold(), extension_id.casefold(), version)
        if identity in seen:
            continue
        seen.add(identity)
        raw_permissions = row.get("Permissions")
        permissions = (
            [
                permission
                for value in raw_permissions
                if (permission := _text(value, maximum=512)) is not None
            ][:512]
            if isinstance(raw_permissions, list)
            else []
        )
        _append_validated(
            extensions,
            BrowserExtension,
            {
                "browser": browser,
                "extension_id": extension_id,
                "name": _text(row.get("Name"), maximum=512),
                "version": version,
                "enabled": _boolean(row.get("Enabled")),
                "permissions": permissions,
                "risky": any(value.casefold() in risky_permissions for value in permissions),
            },
            outcome.warnings,
            "Windows browser extension",
        )
    outcome.data["browser_extensions"] = extensions


def _normalize_certificates(
    rows: Sequence[Mapping[str, Any]], outcome: NormalizationOutcome
) -> None:
    certificates: list[CertificateInfo] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        store = _text(row.get("Store"), maximum=512)
        subject = _text(row.get("Subject"), maximum=4096)
        if not store or not subject:
            outcome.warnings.append("invalid Windows certificate metadata omitted")
            continue
        thumbprint = _text(row.get("Thumbprint"), maximum=256)
        serial_number = _text(row.get("SerialNumber"), maximum=512)
        identity = (store.casefold(), (thumbprint or serial_number or subject).casefold())
        if identity in seen:
            continue
        seen.add(identity)
        _append_validated(
            certificates,
            CertificateInfo,
            {
                "store": store,
                "subject": subject,
                "issuer": _text(row.get("Issuer"), maximum=4096),
                "thumbprint": thumbprint,
                "serial_number": serial_number,
                "not_before": _timestamp(row.get("NotBefore")),
                "not_after": _timestamp(row.get("NotAfter")),
                "signature_algorithm": _text(row.get("SignatureAlgorithm"), maximum=256),
                "public_key_algorithm": _text(row.get("PublicKeyAlgorithm"), maximum=256),
                "key_size": _integer(row.get("KeySize")),
                "has_private_key": _boolean(row.get("HasPrivateKey")),
                "self_signed": _boolean(row.get("SelfSigned")),
                "expired": _boolean(row.get("Expired")),
            },
            outcome.warnings,
            "Windows certificate",
        )
    outcome.data["certificates"] = certificates


def normalize_windows_inventory(
    inventory: Mapping[str, Any], outcome: NormalizationOutcome
) -> NormalizationOutcome:
    """Add each independently observed native Windows inventory section."""

    if "os_info" in inventory:
        before = len(outcome.warnings)
        raw = inventory.get("os_info")
        if not isinstance(raw, Mapping):
            outcome.warnings.append("invalid Windows OS identity payload omitted")
        _normalize_os(_mapping(raw), outcome)
        _finish_section(outcome, "os", before)
    if "hardware" in inventory:
        before = len(outcome.warnings)
        raw = inventory.get("hardware")
        if not isinstance(raw, Mapping):
            outcome.warnings.append("invalid Windows hardware payload omitted")
        _normalize_hardware(_mapping(raw), outcome)
        _finish_section(outcome, "hardware", before)
    if "software" in inventory:
        before = len(outcome.warnings)
        _normalize_software(
            _section_records(inventory.get("software"), outcome, "software"), outcome
        )
        _finish_section(outcome, "software", before)
    if "processes" in inventory:
        before = len(outcome.warnings)
        _normalize_processes(
            _section_records(inventory.get("processes"), outcome, "process"), outcome
        )
        _finish_section(outcome, "processes", before)
    if "services" in inventory:
        before = len(outcome.warnings)
        _normalize_services(
            _section_records(inventory.get("services"), outcome, "service"), outcome
        )
        _finish_section(outcome, "services", before)
    if "users" in inventory:
        before = len(outcome.warnings)
        _normalize_users(
            _section_records(inventory.get("users"), outcome, "user"), outcome
        )
        _finish_section(outcome, "users", before)
    if "network_interfaces" in inventory:
        before = len(outcome.warnings)
        _normalize_interfaces(
            _section_records(
                inventory.get("network_interfaces"), outcome, "network interface"
            ),
            outcome,
        )
        _finish_section(outcome, "network_interfaces", before)
    if "listening_ports" in inventory:
        before = len(outcome.warnings)
        _normalize_ports(
            _section_records(
                inventory.get("listening_ports"), outcome, "listening port"
            ),
            outcome,
        )
        _finish_section(outcome, "listening_ports", before)
    if "browser_extensions" in inventory:
        before = len(outcome.warnings)
        _normalize_extensions(
            _section_records(
                inventory.get("browser_extensions"), outcome, "browser extension"
            ),
            outcome,
        )
        _finish_section(outcome, "browser_extensions", before)
    if "certificates" in inventory:
        before = len(outcome.warnings)
        _normalize_certificates(
            _section_records(inventory.get("certificates"), outcome, "certificate"),
            outcome,
        )
        _finish_section(outcome, "certificates", before)
    return outcome


__all__ = ["normalize_windows_inventory"]
