"""Strict, bounded parsers for fixed native macOS inventory commands."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from pathlib import PurePath
from typing import Any

from app.tools._validation import clean_text, parse_json_document

_MAX_JSON_CHARS = 8 * 1024 * 1024
_SIZE_UNITS = {
    "b": 1,
    "kb": 1024,
    "mb": 1024**2,
    "gb": 1024**3,
    "tb": 1024**4,
    "pb": 1024**5,
}


def _canonical(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).casefold())


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _lookup(values: Mapping[str, Any], *aliases: str) -> Any:
    indexed = {_canonical(key): value for key, value in values.items()}
    for alias in aliases:
        key = _canonical(alias)
        if key in indexed:
            return indexed[key]
    return None


def _nested(values: Mapping[str, Any], *aliases: str) -> Mapping[str, Any]:
    return _mapping(_lookup(values, *aliases))


def _text(value: object, *, maximum: int = 4096) -> str | None:
    result = clean_text(value, maximum=maximum)
    return result or None


def _integer(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    text = str(value).strip().replace(",", "")
    try:
        return int(text)
    except ValueError:
        match = re.search(r"-?\d+", text)
        return int(match.group(0)) if match else None


def _size_bytes(value: object) -> int | None:
    integer = _integer(value)
    text = str(value).strip().casefold()
    if integer is not None and re.fullmatch(r"[\d,]+", text):
        return integer
    match = re.search(r"([\d,.]+)\s*(b|kb|mb|gb|tb|pb)\b", text)
    if match is None:
        return None
    try:
        amount = float(match.group(1).replace(",", ""))
    except ValueError:
        return None
    return int(amount * _SIZE_UNITS[match.group(2)])


def _sp_records(output: str, data_type: str, *, maximum: int) -> list[Mapping[str, Any]]:
    document = parse_json_document(output, max_chars=_MAX_JSON_CHARS)
    if not isinstance(document, Mapping):
        raise ValueError("system_profiler response must be an object")
    raw_records = document.get(data_type)
    if not isinstance(raw_records, list):
        raise ValueError(f"system_profiler response is missing {data_type}")
    if len(raw_records) > maximum:
        raise ValueError(f"{data_type} record limit exceeded")
    if any(not isinstance(record, Mapping) for record in raw_records):
        raise ValueError(f"{data_type} contains a malformed record")
    return list(raw_records)


def _architecture(hardware: Mapping[str, Any]) -> str | None:
    raw = _text(
        _lookup(hardware, "platform_cpu_type", "cpu_type", "architecture"),
        maximum=64,
    )
    chip = _text(
        _lookup(hardware, "chip_type", "processor_name", "cpu_name"),
        maximum=512,
    )
    searchable = f"{raw or ''} {chip or ''}".casefold()
    if "arm" in searchable or "apple m" in searchable:
        return "arm64"
    if any(marker in searchable for marker in ("intel", "x86", "i386")):
        return "x86_64"
    return raw


def _uptime_seconds(value: object) -> int | None:
    text = str(value or "").casefold()
    if not text:
        return None
    days_match = re.search(r"(\d+)\s+days?", text)
    hours_match = re.search(r"(\d+)\s+hours?", text)
    minutes_match = re.search(r"(\d+)\s+minutes?", text)
    days = int(days_match.group(1)) if days_match else 0
    hours = int(hours_match.group(1)) if hours_match else 0
    minutes = int(minutes_match.group(1)) if minutes_match else 0
    clock = re.search(r"\b(\d+):(\d+)\b", text)
    if clock:
        hours = int(clock.group(1))
        minutes = int(clock.group(2))
    if not any((days_match, hours_match, minutes_match, clock)):
        return None
    return days * 86_400 + hours * 3_600 + minutes * 60


def macos_os_info(output: str) -> dict[str, Any]:
    """Parse an independently complete OS identity observation."""

    software_records = _sp_records(output, "SPSoftwareDataType", maximum=8)
    hardware_records = _sp_records(output, "SPHardwareDataType", maximum=8)
    if not software_records or not hardware_records:
        raise ValueError("system_profiler did not return OS and hardware identity")
    software = software_records[0]
    hardware = hardware_records[0]
    raw_version = _text(
        _lookup(software, "os_version", "system_version", "version"), maximum=512
    )
    if raw_version is None:
        raise ValueError("system_profiler did not return the macOS version")
    match = re.fullmatch(r"(.+?)\s+(\d[\w.-]*)(?:\s*\(([^)]+)\))?", raw_version)
    if match:
        name = clean_text(match.group(1), maximum=512)
        version = clean_text(match.group(2), maximum=128)
        build = _text(match.group(3), maximum=128) or _text(
            _lookup(software, "build_version", "build"), maximum=128
        )
    else:
        name = "macOS"
        version = clean_text(raw_version, maximum=128)
        build = None
    if not version:
        raise ValueError("system_profiler returned an invalid macOS version")
    return {
        "name": name or "macOS",
        "version": version,
        "build": build,
        "kernel": _text(_lookup(software, "kernel_version"), maximum=256),
        "architecture": _architecture(hardware),
        "hostname": _text(
            _lookup(software, "local_host_name", "computer_name", "hostname"),
            maximum=512,
        ),
        "machine_id": _text(
            _lookup(hardware, "platform_UUID", "provisioning_UDID"), maximum=512
        ),
        "uptime_seconds": _uptime_seconds(_lookup(software, "uptime")),
        "timezone": _text(_lookup(software, "time_zone", "timezone"), maximum=128),
    }


def _core_count(value: object) -> int | None:
    text = str(value or "")
    proc = re.search(r"\bproc\s+(\d+)", text, flags=re.IGNORECASE)
    if proc:
        return int(proc.group(1))
    return _integer(value)


def _boolean(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    normalized = str(value or "").strip().casefold()
    if normalized in {"true", "yes", "enabled", "1", "on"}:
        return True
    if normalized in {"false", "no", "disabled", "0", "off"}:
        return False
    return None


def macos_hardware(output: str) -> dict[str, Any]:
    """Parse hardware, storage, and display data from one bounded snapshot."""

    hardware_records = _sp_records(output, "SPHardwareDataType", maximum=8)
    storage_records = _sp_records(output, "SPStorageDataType", maximum=512)
    display_records = _sp_records(output, "SPDisplaysDataType", maximum=64)
    if not hardware_records:
        raise ValueError("system_profiler did not return hardware data")
    hardware = hardware_records[0]
    cpu_model = _text(
        _lookup(hardware, "chip_type", "processor_name", "cpu_name"), maximum=512
    )
    cpu_searchable = (cpu_model or "").casefold()
    vendor = (
        "Apple"
        if "apple" in cpu_searchable
        else "Intel"
        if "intel" in cpu_searchable
        else None
    )
    physical_cores = _core_count(
        _lookup(hardware, "total_number_of_cores", "total_number_cores", "number_processors")
    )
    architecture = _architecture(hardware)
    processor_description = _lookup(hardware, "number_processors")
    logical_processors = (
        physical_cores
        if architecture == "arm64"
        else _core_count(processor_description)
        if "proc" in str(processor_description or "").casefold()
        else None
    )
    disks: list[dict[str, Any]] = []
    for record in storage_records:
        physical = _nested(record, "physical_drive", "physical drive")
        name = _text(
            _lookup(record, "bsd_name", "_name", "name")
            or _lookup(physical, "device_name", "_name"),
            maximum=512,
        )
        if name is None:
            raise ValueError("system_profiler returned storage without an identity")
        disks.append(
            {
                "name": name,
                "mount_point": _text(_lookup(record, "mount_point"), maximum=4096),
                "capacity_bytes": _size_bytes(
                    _lookup(record, "size_in_bytes", "capacity_in_bytes", "capacity")
                    or _lookup(physical, "size_in_bytes", "capacity_in_bytes", "size")
                ),
                "free_bytes": _size_bytes(
                    _lookup(record, "free_space_in_bytes", "free_space")
                ),
                "disk_type": _text(
                    _lookup(physical, "medium_type", "protocol")
                    or _lookup(record, "file_system", "filesystem"),
                    maximum=64,
                ),
                "encrypted": _boolean(
                    _lookup(record, "filevault", "encrypted", "encryption")
                ),
                "serial_number": _text(
                    _lookup(physical, "serial_number"), maximum=256
                ),
            }
        )
    gpus: list[dict[str, Any]] = []
    for record in display_records:
        model = _text(
            _lookup(record, "sppci_model", "chipset_model", "_name", "model"),
            maximum=512,
        )
        if model is None:
            raise ValueError("system_profiler returned a display adapter without a model")
        gpus.append(
            {
                "model": model,
                "vendor": _text(
                    _lookup(record, "spdisplays_vendor", "vendor"), maximum=256
                ),
                "memory_bytes": _size_bytes(
                    _lookup(
                        record,
                        "spdisplays_vram",
                        "spdisplays_vram_shared",
                        "vram",
                    )
                ),
            }
        )
    machine_model = _text(_lookup(hardware, "machine_model"), maximum=256)
    machine_name = _text(_lookup(hardware, "machine_name"), maximum=256)
    return {
        "cpu": {
            "vendor": vendor,
            "model": cpu_model,
            "physical_cores": physical_cores,
            "logical_processors": logical_processors,
            "architecture": architecture,
        },
        "memory_bytes": _size_bytes(_lookup(hardware, "physical_memory", "memory")),
        "disks": disks,
        "gpus": gpus,
        "motherboard": machine_model,
        "bios_uefi": "Apple Boot ROM",
        "firmware_version": _text(
            _lookup(hardware, "boot_rom_version", "system_firmware_version"), maximum=256
        ),
        "manufacturer": "Apple Inc.",
        "device_model": machine_name or machine_model,
    }


def _software_architecture(value: object) -> str | None:
    raw = _text(value, maximum=64)
    if raw is None:
        return None
    normalized = raw.casefold()
    if normalized in {"arch_arm_i64", "arch_universal", "universal"}:
        return "universal"
    if "arm" in normalized:
        return "arm64"
    if any(marker in normalized for marker in ("i64", "x86_64", "intel")):
        return "x86_64"
    return raw


def macos_software(output: str) -> list[dict[str, Any]]:
    records = _sp_records(output, "SPApplicationsDataType", maximum=50_000)
    software: list[dict[str, Any]] = []
    for record in records:
        name = _text(_lookup(record, "_name", "name"), maximum=512)
        if name is None:
            raise ValueError("system_profiler returned an application without a name")
        software.append(
            {
                "name": name,
                "version": _text(_lookup(record, "version"), maximum=256),
                "vendor": _text(_lookup(record, "publisher", "vendor"), maximum=512),
                "installation_path": _text(_lookup(record, "path"), maximum=4096),
                "installation_date": _text(
                    _lookup(record, "lastModified", "install_date"), maximum=128
                ),
                "package_manager": "macos-app",
                "architecture": _software_architecture(_lookup(record, "arch_kind")),
                "source": "system_profiler",
            }
        )
    return software


def macos_processes(output: str) -> list[dict[str, Any]]:
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) > 100_000:
        raise ValueError("process record limit exceeded")
    processes: list[dict[str, Any]] = []
    for line in lines:
        fields = line.strip().split(maxsplit=5)
        if len(fields) != 6:
            raise ValueError("ps returned a malformed process record")
        try:
            pid = int(fields[0])
            parent_pid = int(fields[1])
            cpu_percent = float(fields[3])
            memory_bytes = int(fields[4]) * 1024
        except ValueError as exc:
            raise ValueError("ps returned invalid numeric process data") from exc
        executable = clean_text(fields[5], maximum=4096)
        if not executable:
            raise ValueError("ps returned a process without an executable")
        name = clean_text(PurePath(executable).name or executable, maximum=512)
        processes.append(
            {
                "pid": pid,
                "parent_pid": parent_pid,
                "user": clean_text(fields[2], maximum=512),
                "cpu_percent": cpu_percent,
                "memory_bytes": memory_bytes,
                "name": name,
                "executable_path": executable,
            }
        )
    return processes


def macos_services(output: str) -> list[dict[str, Any]]:
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) > 50_001:
        raise ValueError("launch service record limit exceeded")
    services: list[dict[str, Any]] = []
    for line in lines:
        fields = line.split(maxsplit=2)
        if fields and fields[0].casefold() == "pid":
            continue
        if len(fields) != 3:
            raise ValueError("launchctl returned a malformed service record")
        pid_text, status_text, label = fields
        if pid_text != "-" and not pid_text.isdigit():
            raise ValueError("launchctl returned an invalid service PID")
        try:
            last_exit_status = int(status_text)
        except ValueError as exc:
            raise ValueError("launchctl returned an invalid service status") from exc
        services.append(
            {
                "name": clean_text(label, maximum=512),
                "pid": int(pid_text) if pid_text.isdigit() else None,
                "last_exit_status": last_exit_status,
                "state": "running" if pid_text.isdigit() else "unknown",
                "startup_type": "loaded",
            }
        )
    return services


def _dscl_records(output: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_key: str | None = None

    def finish() -> None:
        nonlocal current, last_key
        if current:
            if len(records) >= 50_000:
                raise ValueError("local user record limit exceeded")
            records.append(current)
        current = {}
        last_key = None

    for line in [*output.splitlines(), "-"]:
        if line.strip() == "-":
            finish()
            continue
        if line[:1].isspace() and last_key is not None:
            continuation = clean_text(line, maximum=4096)
            if continuation:
                current[last_key] = clean_text(
                    f"{current[last_key]} {continuation}", maximum=16_384
                )
            continue
        key, separator, value = line.partition(":")
        if not separator:
            raise ValueError("dscl returned a malformed user record")
        normalized_key = _canonical(key)
        if not normalized_key:
            raise ValueError("dscl returned an empty user attribute")
        current[normalized_key] = clean_text(value, maximum=16_384)
        last_key = normalized_key
    return records


def macos_users(output: str) -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    for record in _dscl_records(output):
        aliases = record.get("recordname", "").split()
        username = clean_text(aliases[0], maximum=512) if aliases else ""
        uid = record.get("uniqueid", "").strip()
        if not username or not uid.isdigit():
            raise ValueError("dscl returned a user without a valid name and UID")
        primary_gid = record.get("primarygroupid", "").strip()
        authorities = record.get("authenticationauthority", "").casefold()
        users.append(
            {
                "username": username,
                "uid": uid,
                "enabled": False if "disableduser" in authorities else None,
                "groups": [],
                "is_administrator": uid == "0" or primary_gid == "80",
                "is_guest": username.casefold() in {"guest", "nobody"},
                "home_directory": _text(record.get("nfshomedirectory"), maximum=4096),
                "shell": _text(record.get("usershell"), maximum=4096),
                "generated_uid": _text(record.get("generateduid"), maximum=512),
            }
        )
    if not users:
        raise ValueError("dscl did not return local users")
    return users


def _list_values(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _ip_values(value: object) -> list[str]:
    addresses: list[str] = []
    for item in _list_values(value):
        for candidate in re.split(r"[,\s]+", str(item).strip(" []\"'")):
            candidate = candidate.strip(" []\"'")
            if not candidate:
                continue
            try:
                addresses.append(ipaddress.ip_address(candidate.split("%", 1)[0]).compressed)
            except ValueError:
                continue
    return list(dict.fromkeys(addresses))


def _prefix(value: object, *, ipv6: bool = False) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if text.isdigit():
        parsed = int(text)
        maximum = 128 if ipv6 else 32
        return parsed if 0 <= parsed <= maximum else None
    try:
        base = "::" if ipv6 else "0.0.0.0"  # noqa: S104 - netmask parsing sentinel
        return ipaddress.ip_network(f"{base}/{text}").prefixlen
    except ValueError:
        return None


def _address_records(
    addresses: list[str], masks: list[object], *, ipv6: bool = False
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, address in enumerate(addresses):
        mask = masks[index] if index < len(masks) else masks[0] if masks else None
        records.append({"address": address, "prefix_length": _prefix(mask, ipv6=ipv6)})
    return records


def macos_network_interfaces(output: str) -> list[dict[str, Any]]:
    records = _sp_records(output, "SPNetworkDataType", maximum=2_048)
    grouped: dict[str, dict[str, Any]] = {}
    for record in records:
        ipv4 = _nested(record, "ipv4")
        ipv6 = _nested(record, "ipv6")
        dns = _nested(record, "dns")
        dhcp = _nested(record, "dhcp")
        ethernet = _nested(record, "ethernet")
        name = _text(
            _lookup(record, "interface", "bsd_device_name")
            or _lookup(ipv4, "interface_name")
            or _lookup(ipv6, "interface_name")
            or _lookup(record, "_name"),
            maximum=512,
        )
        if name is None:
            raise ValueError("system_profiler returned a network service without an interface")
        ipv4_addresses = _ip_values(_lookup(ipv4, "addresses", "address"))
        ipv6_addresses = _ip_values(_lookup(ipv6, "addresses", "address"))
        ipv4_masks = _list_values(_lookup(ipv4, "subnet_masks", "subnet_mask"))
        ipv6_masks = _list_values(
            _lookup(ipv6, "prefix_length", "prefix_lengths", "subnet_masks")
        )
        addresses = [
            *_address_records(ipv4_addresses, ipv4_masks),
            *_address_records(ipv6_addresses, ipv6_masks, ipv6=True),
        ]
        gateways = _ip_values(
            [
                *_list_values(_lookup(ipv4, "router", "routers")),
                *_list_values(_lookup(ipv6, "router", "routers")),
                *_list_values(_lookup(dhcp, "dhcp_routers", "routers")),
            ]
        )
        dns_servers = _ip_values(_lookup(dns, "server_addresses", "servers"))
        configuration = str(
            _lookup(ipv4, "configuration_method", "configuration") or ""
        ).casefold()
        searchable = f"{name} {_lookup(record, 'type', 'hardware') or ''}".casefold()
        parsed: dict[str, Any] = {
            "name": name,
            "mac_address": _text(
                _lookup(ethernet, "MAC Address", "mac_address")
                or _lookup(record, "MAC Address", "mac_address"),
                maximum=64,
            ),
            "addresses": addresses,
            "gateways": gateways,
            "dns_servers": dns_servers,
            "dhcp_enabled": (
                True if "dhcp" in configuration else False if configuration else None
            ),
            "dhcp_server": next(
                iter(_ip_values(_lookup(dhcp, "dhcp_server_identifier", "server_identifier"))),
                None,
            ),
            "is_up": True if addresses else None,
            "is_vpn": any(
                marker in searchable for marker in ("vpn", "utun", "tun", "tap", "ppp")
            ),
        }
        existing = grouped.get(name)
        if existing is None:
            grouped[name] = parsed
            continue
        for field in ("mac_address", "dhcp_enabled", "dhcp_server"):
            old_value = existing.get(field)
            new_value = parsed.get(field)
            if old_value is not None and new_value is not None and old_value != new_value:
                raise ValueError(f"system_profiler returned conflicting {field} for {name}")
            if old_value is None:
                existing[field] = new_value
        existing_addresses = {
            (item.get("address"), item.get("prefix_length"))
            for item in existing["addresses"]
            if isinstance(item, Mapping)
        }
        for address in parsed["addresses"]:
            identity = (address.get("address"), address.get("prefix_length"))
            if identity not in existing_addresses:
                existing_addresses.add(identity)
                existing["addresses"].append(address)
        for field in ("gateways", "dns_servers"):
            existing[field] = list(dict.fromkeys([*existing[field], *parsed[field]]))
        existing["is_up"] = True if existing.get("is_up") or parsed.get("is_up") else None
        existing["is_vpn"] = bool(existing.get("is_vpn") or parsed.get("is_vpn"))
    return list(grouped.values())


def _lsof_endpoint(value: str) -> tuple[str, int]:
    local = value.split("->", 1)[0].strip()
    if local.startswith("["):
        closing = local.find("]")
        if closing < 0 or not local[closing + 1 :].startswith(":"):
            raise ValueError("lsof returned a malformed IPv6 listener")
        address = local[1:closing]
        port_text = local[closing + 2 :]
    else:
        address, separator, port_text = local.rpartition(":")
        if not separator:
            raise ValueError("lsof returned a listener without a port")
    if not port_text.isdigit():
        raise ValueError("lsof returned a non-numeric listener port")
    port = int(port_text)
    if not 0 <= port <= 65_535:
        raise ValueError("lsof returned an invalid listener port")
    normalized_address = "*" if address in {"", "*"} else address.split("%", 1)[0]
    if normalized_address != "*":
        try:
            normalized_address = ipaddress.ip_address(normalized_address).compressed
        except ValueError as exc:
            raise ValueError("lsof returned an invalid listener address") from exc
    return normalized_address, port


def macos_listening_ports(output: str) -> list[dict[str, Any]]:
    if len(output.splitlines()) > 300_000:
        raise ValueError("listener field limit exceeded")
    pid: int | None = None
    process: str | None = None
    pending: dict[str, Any] | None = None
    ports: list[dict[str, Any]] = []

    def finish() -> None:
        nonlocal pending
        if pending is None:
            return
        if "address" not in pending:
            raise ValueError("lsof returned a listener without an address")
        if pending["protocol"] != "tcp" or pending.get("state", "LISTEN") == "LISTEN":
            ports.append(pending)
        pending = None

    for line in [*output.splitlines(), "P"]:
        if not line:
            continue
        field, value = line[0], line[1:]
        if field == "p":
            finish()
            if not value.isdigit():
                raise ValueError("lsof returned an invalid process identifier")
            pid = int(value)
            process = None
        elif field == "c":
            process = clean_text(value, maximum=512) or None
        elif field == "P":
            finish()
            protocol = value.casefold()
            if protocol not in {"tcp", "udp"}:
                if value:
                    raise ValueError("lsof returned an unsupported listener protocol")
                continue
            pending = {"protocol": protocol, "pid": pid, "process": process}
        elif field == "t":
            if pending is None:
                raise ValueError("lsof returned an address family without a protocol")
            pending["address_family"] = value.casefold()
        elif field == "n":
            if pending is None:
                raise ValueError("lsof returned an address without a protocol")
            address, endpoint_port = _lsof_endpoint(value)
            if address == "*":
                address = (
                    "::"
                    if pending.get("address_family") == "ipv6"
                    else "0.0.0.0"  # noqa: S104 - observed wildcard binding
                )
            pending.update(
                {
                    "address": address,
                    "port": endpoint_port,
                    "exposed": address in {"*", "0.0.0.0", "::"},  # noqa: S104
                }
            )
        elif field == "T" and value.startswith("ST="):
            if pending is None:
                raise ValueError("lsof returned state without a protocol")
            pending["state"] = value[3:].upper()
    identities: set[tuple[object, ...]] = set()
    unique: list[dict[str, Any]] = []
    for record in ports:
        identity = (
            record["protocol"],
            record["address"],
            record["port"],
            record.get("pid"),
        )
        if identity not in identities:
            identities.add(identity)
            record.pop("state", None)
            record.pop("address_family", None)
            unique.append(record)
    return unique
