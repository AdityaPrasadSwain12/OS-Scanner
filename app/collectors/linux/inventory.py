"""Bounded, tool-free Linux inventory readers and native-output parsers."""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import shlex
import socket
import stat
import struct
import time
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import islice
from pathlib import Path
from typing import Any

from app.tools._validation import clean_text

_MAX_PACKAGES = 100_000
_MAX_PROCESSES = 20_000
_MAX_USERS = 100_000
_MAX_INTERFACES = 1_024
_MAX_LISTENERS = 100_000
_MAX_SOCKET_LINKS = 250_000


@dataclass(frozen=True, slots=True)
class InventoryRead:
    """One independently collected inventory section and any non-fatal errors."""

    data: Any
    errors: tuple[str, ...] = ()


def _limited_entries(entries: Iterable[Path], maximum: int) -> tuple[list[Path], bool]:
    selected = list(islice(entries, maximum + 1))
    return selected[:maximum], len(selected) > maximum


def read_fixed_file(path: Path, *, maximum_bytes: int = 1024 * 1024) -> str:
    """Read one fixed regular file without following its final symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError("inventory source is not a regular file")
        # procfs/sysfs pseudo-files commonly report a page-sized ``st_size``
        # regardless of their actual content. The bounded read below is the
        # authoritative limit for both pseudo-files and disk-backed files.
        data = os.read(descriptor, maximum_bytes + 1)
        if len(data) > maximum_bytes:
            raise ValueError("inventory source exceeds the size limit")
        return data.decode("utf-8", errors="replace")
    finally:
        os.close(descriptor)


def _optional_file(path: Path, maximum_bytes: int) -> str | None:
    try:
        return read_fixed_file(path, maximum_bytes=maximum_bytes)
    except FileNotFoundError:
        return None


def _optional_linked_file(
    root: Path,
    absolute: str,
    maximum_bytes: int,
    *,
    allowed_directories: tuple[str, ...],
) -> str | None:
    """Read a fixed file or a symlink resolving beneath explicit system roots."""

    path = _rooted(root, absolute)
    try:
        return read_fixed_file(path, maximum_bytes=maximum_bytes)
    except FileNotFoundError:
        return None
    except OSError:
        if not path.is_symlink():
            raise
        resolved = path.resolve(strict=True)
        allowed = tuple(_rooted(root, directory).resolve() for directory in allowed_directories)
        if not any(resolved.is_relative_to(directory) for directory in allowed):
            raise ValueError("inventory symlink resolves outside its approved roots") from None
        return read_fixed_file(resolved, maximum_bytes=maximum_bytes)


def _deadline(deadline_at: float | None) -> None:
    if deadline_at is not None and time.monotonic() >= deadline_at:
        raise TimeoutError("scan deadline exceeded during Linux inventory collection")


def _rooted(root: Path, absolute: str) -> Path:
    return root / absolute.lstrip("/")


def _unquote_assignment(value: str) -> str:
    try:
        parsed = shlex.split(value, comments=False, posix=True)
    except ValueError:
        return value.strip().strip("\"'")
    return parsed[0] if len(parsed) == 1 else value.strip().strip("\"'")


def _assignments(output: str, *, maximum_lines: int = 10_000) -> dict[str, str]:
    values: dict[str, str] = {}
    for index, raw in enumerate(output.splitlines()):
        if index >= maximum_lines:
            raise ValueError("assignment source exceeds the line limit")
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator and key.replace("_", "").isalnum():
            values[key.casefold()] = clean_text(_unquote_assignment(value), maximum=4096)
    return values


def collect_os_info(
    *,
    root: Path = Path("/"),
    maximum_bytes: int = 1024 * 1024,
    deadline_at: float | None = None,
) -> InventoryRead:
    """Collect distribution, kernel, host, boot, and machine identity."""

    _deadline(deadline_at)
    release_text = _optional_linked_file(
        root,
        "/etc/os-release",
        maximum_bytes,
        allowed_directories=("/etc", "/usr/lib"),
    )
    if release_text is None:
        release_text = _optional_file(_rooted(root, "/usr/lib/os-release"), maximum_bytes)
    release = _assignments(release_text or "")

    def read_value(path: str, maximum: int = 4096) -> str | None:
        try:
            value = _optional_file(_rooted(root, path), min(maximum, maximum_bytes))
        except (OSError, ValueError):
            return None
        return clean_text(value, maximum=maximum).strip() if value is not None else None

    kernel = read_value("/proc/sys/kernel/osrelease", 256) or platform.release()
    kernel_build = read_value("/proc/sys/kernel/version", 256) or platform.version()
    hostname = read_value("/proc/sys/kernel/hostname", 512) or socket.gethostname()
    machine_id = read_value("/etc/machine-id", 512) or read_value("/var/lib/dbus/machine-id", 512)
    timezone = read_value("/etc/timezone", 128)
    uptime_seconds: int | None = None
    uptime = read_value("/proc/uptime", 128)
    if uptime:
        with suppress(ValueError):
            uptime_seconds = max(0, int(float(uptime.split(maxsplit=1)[0])))
    name = release.get("pretty_name") or release.get("name") or "Linux"
    version = release.get("version_id") or release.get("version") or kernel or "unknown"
    return InventoryRead(
        {
            "name": name,
            "version": version,
            "build": release.get("build_id") or kernel_build,
            "kernel": kernel,
            "architecture": platform.machine() or None,
            "hostname": hostname,
            "machine_id": machine_id,
            "uptime_seconds": uptime_seconds,
            "timezone": timezone,
            "distribution_id": release.get("id"),
            "version_codename": release.get("version_codename"),
        }
    )


def _cpu_details(output: str) -> dict[str, Any]:
    logical = 0
    vendor: str | None = None
    model: str | None = None
    physical_cores: set[tuple[str, str]] = set()
    current: dict[str, str] = {}
    for index, raw in enumerate([*output.splitlines(), ""]):
        if index > 200_000:
            raise ValueError("CPU inventory exceeds the line limit")
        line = raw.strip()
        if not line:
            if current:
                logical += 1
                vendor = vendor or current.get("vendor_id") or current.get("cpu implementer")
                model = model or current.get("model name") or current.get("processor")
                physical = current.get("physical id", "0")
                core = current.get("core id") or current.get("processor")
                if core is not None:
                    physical_cores.add((physical, core))
                current = {}
            continue
        key, separator, value = line.partition(":")
        if separator:
            current[key.strip().casefold()] = clean_text(value, maximum=512)
    return {
        "vendor": vendor,
        "model": model,
        "physical_cores": len(physical_cores) or None,
        "logical_processors": logical or os.cpu_count(),
        "architecture": platform.machine() or None,
    }


def _memory_bytes(output: str) -> int | None:
    for line in output.splitlines()[:10_000]:
        key, separator, value = line.partition(":")
        if separator and key.casefold() == "memtotal":
            fields = value.split()
            try:
                return int(fields[0]) * 1024
            except (IndexError, ValueError):
                return None
    return None


def _decode_mount_field(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def _mounted_disks(output: str, *, root: Path, deadline_at: float | None) -> list[dict[str, Any]]:
    virtual_types = {
        "autofs",
        "bpf",
        "cgroup",
        "cgroup2",
        "configfs",
        "debugfs",
        "devpts",
        "devtmpfs",
        "efivarfs",
        "fusectl",
        "hugetlbfs",
        "mqueue",
        "overlay",
        "proc",
        "pstore",
        "ramfs",
        "securityfs",
        "sysfs",
        "tmpfs",
        "tracefs",
    }
    disks: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, line in enumerate(output.splitlines()):
        if index >= 20_000:
            raise ValueError("mount inventory exceeds the line limit")
        _deadline(deadline_at)
        fields = line.split()
        if len(fields) < 3:
            continue
        device = _decode_mount_field(fields[0])
        mount_point = _decode_mount_field(fields[1])
        filesystem = clean_text(fields[2], maximum=64)
        lowered_filesystem = filesystem.casefold()
        if (
            lowered_filesystem in virtual_types
            or lowered_filesystem.startswith("fuse")
            or lowered_filesystem in {"9p", "ceph", "cifs", "nfs", "nfs4", "smb3"}
            or not mount_point.startswith("/")
        ):
            continue
        identity = (device, mount_point)
        if identity in seen:
            continue
        seen.add(identity)
        stat_path = Path(mount_point) if root == Path("/") else root / mount_point.lstrip("/")
        statvfs = getattr(os, "statvfs", None)
        if statvfs is None:
            continue
        try:
            usage = statvfs(stat_path)
        except OSError:
            continue
        capacity = usage.f_blocks * usage.f_frsize
        free = usage.f_bavail * usage.f_frsize
        disks.append(
            {
                "name": clean_text(device, maximum=512),
                "mount_point": clean_text(mount_point, maximum=4096),
                "capacity_bytes": max(0, capacity),
                "free_bytes": max(0, min(free, capacity)),
                "disk_type": filesystem,
            }
        )
        if len(disks) >= 256:
            break
    return disks


def collect_hardware(
    *,
    root: Path = Path("/"),
    maximum_bytes: int = 8 * 1024 * 1024,
    deadline_at: float | None = None,
) -> InventoryRead:
    """Collect CPU, memory, mounted disk, and firmware identity."""

    _deadline(deadline_at)
    cpu_text = _optional_file(_rooted(root, "/proc/cpuinfo"), maximum_bytes) or ""
    memory_text = _optional_file(_rooted(root, "/proc/meminfo"), maximum_bytes) or ""
    mounts = _optional_file(_rooted(root, "/proc/self/mounts"), maximum_bytes) or ""

    def dmi(name: str, maximum: int = 512) -> str | None:
        try:
            value = _optional_file(
                _rooted(root, f"/sys/devices/virtual/dmi/id/{name}"),
                min(maximum_bytes, 4096),
            )
        except (OSError, ValueError):
            return None
        return clean_text(value, maximum=maximum).strip() if value else None

    return InventoryRead(
        {
            "cpu": _cpu_details(cpu_text),
            "memory_bytes": _memory_bytes(memory_text),
            "disks": _mounted_disks(mounts, root=root, deadline_at=deadline_at),
            "motherboard": dmi("board_name"),
            "bios_uefi": dmi("bios_vendor"),
            "firmware_version": dmi("bios_version", 256),
            "manufacturer": dmi("sys_vendor", 256),
            "device_model": dmi("product_name", 256),
        }
    )


def _passwd_records(output: str) -> list[tuple[str, str, str, str]]:
    records: list[tuple[str, str, str, str]] = []
    for index, line in enumerate(output.splitlines()):
        if index >= _MAX_USERS:
            raise ValueError("account inventory exceeds the record limit")
        fields = line.split(":")
        if len(fields) >= 7 and fields[0]:
            records.append((fields[0], fields[2], fields[3], fields[6]))
    return records


def _uid_names(root: Path, maximum_bytes: int) -> dict[str, str]:
    passwd = _optional_file(_rooted(root, "/etc/passwd"), maximum_bytes) or ""
    return {uid: username for username, uid, _gid, _shell in _passwd_records(passwd)}


def collect_processes(
    *,
    root: Path = Path("/"),
    maximum_bytes: int = 8 * 1024 * 1024,
    deadline_at: float | None = None,
) -> InventoryRead:
    """Collect bounded process metadata directly from procfs."""

    _deadline(deadline_at)
    proc = _rooted(root, "/proc")
    uid_names = _uid_names(root, min(maximum_bytes, 8 * 1024 * 1024))
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    serialized_bytes = 2  # JSON array delimiters; used as an aggregate memory/output budget.
    byte_limit_reached = False
    entries, truncated = _limited_entries(
        (entry for entry in proc.iterdir() if entry.name.isdigit()), _MAX_PROCESSES
    )
    entries.sort(key=lambda entry: int(entry.name))
    for entry in entries:
        _deadline(deadline_at)
        try:
            status_text = read_fixed_file(entry / "status", maximum_bytes=128 * 1024)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as exc:
            if len(errors) < 5:
                errors.append(f"process {entry.name} metadata: {clean_text(exc, maximum=128)}")
            continue
        status_values: dict[str, str] = {}
        for line in status_text.splitlines()[:1_024]:
            key, separator, value = line.partition(":")
            if separator:
                status_values[key] = value.strip()
        name = clean_text(status_values.get("Name"), maximum=512)
        if not name:
            continue
        uid_fields = status_values.get("Uid", "").split(maxsplit=1)
        uid = uid_fields[0] if uid_fields else ""
        record: dict[str, Any] = {
            "pid": int(entry.name),
            "name": name,
            "user": uid_names.get(uid, uid or None),
        }
        parent = status_values.get("PPid", "")
        if parent.isdigit():
            record["parent_pid"] = int(parent)
        rss_fields = status_values.get("VmRSS", "").split(maxsplit=1)
        rss = rss_fields[0] if rss_fields else ""
        if rss.isdigit():
            record["memory_bytes"] = int(rss) * 1024
        try:
            executable = os.readlink(entry / "exe")
            record["executable_path"] = clean_text(executable, maximum=4096)
        except OSError:
            pass
        encoded_size = len(
            json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        separator_size = 1 if records else 0
        if serialized_bytes + separator_size + encoded_size > maximum_bytes:
            byte_limit_reached = True
            break
        serialized_bytes += separator_size + encoded_size
        records.append(record)
    if truncated:
        errors.append("process inventory reached its record limit")
    if byte_limit_reached:
        message = "process inventory reached its byte limit"
        if len(errors) >= 5:
            errors[-1] = message
        else:
            errors.append(message)
    return InventoryRead(records, tuple(errors[:5]))


def collect_users(
    *,
    root: Path = Path("/"),
    maximum_bytes: int = 8 * 1024 * 1024,
    deadline_at: float | None = None,
) -> InventoryRead:
    """Collect accounts and group membership without reading password material."""

    _deadline(deadline_at)
    passwd_text = read_fixed_file(_rooted(root, "/etc/passwd"), maximum_bytes=maximum_bytes)
    group_text = _optional_file(_rooted(root, "/etc/group"), maximum_bytes) or ""
    group_names: dict[str, str] = {}
    memberships: dict[str, set[str]] = {}
    for index, line in enumerate(group_text.splitlines()):
        if index >= _MAX_USERS:
            raise ValueError("group inventory exceeds the record limit")
        fields = line.split(":")
        if len(fields) < 4 or not fields[0]:
            continue
        group_names[fields[2]] = clean_text(fields[0], maximum=256)
        for member in fields[3].split(","):
            if member:
                memberships.setdefault(member, set()).add(group_names[fields[2]])
    disabled_shells = {"/bin/false", "/usr/bin/false", "/sbin/nologin", "/usr/sbin/nologin"}
    admin_groups = {"adm", "admin", "sudo", "wheel"}
    users: list[dict[str, Any]] = []
    for username, uid, gid, shell in _passwd_records(passwd_text):
        groups = set(memberships.get(username, set()))
        if gid in group_names:
            groups.add(group_names[gid])
        # Login shells alone cannot prove that an account is enabled: PAM,
        # directory services, SSH keys, and other controls may apply.
        enabled: bool | None = False if shell in disabled_shells else None
        users.append(
            {
                "username": clean_text(username, maximum=512),
                "uid": clean_text(uid, maximum=128),
                "enabled": enabled,
                "groups": sorted(groups),
                "is_administrator": uid == "0"
                or bool({group.casefold() for group in groups} & admin_groups),
                "is_guest": username.casefold() in {"guest", "nobody"},
            }
        )
    return InventoryRead(users)


def _ipv4_address(interface: str) -> str | None:
    try:
        import fcntl  # Linux-only import; this module is also type-checked on Windows.

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as descriptor:
            request = struct.pack("256s", interface.encode("utf-8")[:15])
            ioctl = getattr(fcntl, "ioctl", None)
            if ioctl is None:
                return None
            response = ioctl(descriptor.fileno(), 0x8915, request)
        return socket.inet_ntoa(response[20:24])
    except (ImportError, OSError, ValueError):
        return None


def _ipv6_interfaces(output: str) -> dict[str, list[dict[str, Any]]]:
    addresses: dict[str, list[dict[str, Any]]] = {}
    for index, line in enumerate(output.splitlines()):
        if index >= 100_000:
            raise ValueError("IPv6 inventory exceeds the record limit")
        fields = line.split()
        if len(fields) != 6:
            continue
        raw, _index, prefix, _scope, _flags, name = fields
        try:
            address = str(ipaddress.IPv6Address(int(raw, 16)))
            prefix_length = int(prefix, 16)
        except ValueError:
            continue
        addresses.setdefault(name, []).append({"address": address, "prefix_length": prefix_length})
    return addresses


def _default_gateways(output: str) -> dict[str, list[str]]:
    gateways: dict[str, list[str]] = {}
    for line in output.splitlines()[1:100_001]:
        fields = line.split()
        if len(fields) < 4 or fields[1] != "00000000" or fields[2] == "00000000":
            continue
        try:
            gateway = socket.inet_ntoa(struct.pack("<I", int(fields[2], 16)))
        except (OSError, ValueError):
            continue
        gateways.setdefault(fields[0], []).append(gateway)
    return gateways


def _default_ipv6_gateways(output: str) -> dict[str, list[str]]:
    gateways: dict[str, list[str]] = {}
    for line in output.splitlines()[:100_000]:
        fields = line.split()
        if len(fields) < 10 or fields[0] != "0" * 32 or fields[1] != "00":
            continue
        if fields[4] == "0" * 32:
            continue
        try:
            gateway = str(ipaddress.IPv6Address(int(fields[4], 16)))
        except ValueError:
            continue
        gateways.setdefault(fields[-1], []).append(gateway)
    return gateways


def _dns_servers(output: str) -> list[str]:
    servers: list[str] = []
    for line in output.splitlines()[:10_000]:
        fields = line.split()
        if len(fields) >= 2 and fields[0].casefold() == "nameserver":
            try:
                servers.append(str(ipaddress.ip_address(fields[1].split("%", 1)[0])))
            except ValueError:
                continue
    return list(dict.fromkeys(servers))[:32]


def collect_network_interfaces(
    *,
    root: Path = Path("/"),
    maximum_bytes: int = 8 * 1024 * 1024,
    deadline_at: float | None = None,
) -> InventoryRead:
    """Collect interfaces, addresses, default routes, and DNS from kernel state."""

    _deadline(deadline_at)
    network_root = _rooted(root, "/sys/class/net")
    ipv6 = _ipv6_interfaces(
        _optional_file(_rooted(root, "/proc/net/if_inet6"), maximum_bytes) or ""
    )
    gateways = _default_gateways(
        _optional_file(_rooted(root, "/proc/net/route"), maximum_bytes) or ""
    )
    ipv6_gateways = _default_ipv6_gateways(
        _optional_file(_rooted(root, "/proc/net/ipv6_route"), maximum_bytes) or ""
    )
    dns = _dns_servers(
        _optional_linked_file(
            root,
            "/etc/resolv.conf",
            maximum_bytes,
            allowed_directories=("/etc", "/run"),
        )
        or ""
    )
    interfaces: list[dict[str, Any]] = []
    errors: list[str] = []
    entries, truncated = _limited_entries(network_root.iterdir(), _MAX_INTERFACES)
    entries.sort(key=lambda item: item.name)
    for entry in entries:
        _deadline(deadline_at)
        name = clean_text(entry.name, maximum=512)
        if not name:
            continue
        try:
            mac = _optional_file(entry / "address", 128)
            state = _optional_file(entry / "operstate", 128)
        except (OSError, ValueError) as exc:
            if len(errors) < 5:
                errors.append(f"interface {name} metadata: {clean_text(exc, maximum=128)}")
            continue
        addresses = list(ipv6.get(entry.name, []))
        if root == Path("/") and (ipv4 := _ipv4_address(entry.name)):
            addresses.insert(0, {"address": ipv4})
        combined_gateways = list(
            dict.fromkeys([*gateways.get(entry.name, []), *ipv6_gateways.get(entry.name, [])])
        )[:32]
        lowered = name.casefold()
        interfaces.append(
            {
                "name": name,
                "mac_address": clean_text(mac, maximum=64).strip() if mac else None,
                "addresses": addresses[:256],
                "gateways": combined_gateways,
                "dns_servers": dns,
                "is_up": state.strip().casefold() == "up" if state else None,
                "is_vpn": any(
                    marker in lowered for marker in ("tun", "tap", "vpn", "wg", "wireguard", "ppp")
                ),
            }
        )
    if truncated:
        errors.append("network interface inventory reached its record limit")
    return InventoryRead(interfaces, tuple(errors[:5]))


def _decode_proc_address(raw: str, *, ipv6: bool) -> str:
    if not ipv6:
        return socket.inet_ntoa(struct.pack("<I", int(raw, 16)))
    packed = bytes.fromhex(raw)
    reordered = b"".join(packed[index : index + 4][::-1] for index in range(0, 16, 4))
    return str(ipaddress.IPv6Address(reordered))


def _socket_rows(output: str, *, protocol: str, ipv6: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines()[1:]:
        if len(rows) >= _MAX_LISTENERS:
            raise ValueError("listening socket inventory exceeds the record limit")
        fields = line.split()
        if len(fields) < 10:
            continue
        if protocol == "tcp" and fields[3].casefold() != "0a":
            continue
        raw_address, separator, raw_port = fields[1].partition(":")
        if not separator:
            continue
        try:
            address = _decode_proc_address(raw_address, ipv6=ipv6)
            port = int(raw_port, 16)
            inode = fields[9]
        except (OSError, ValueError):
            continue
        if protocol == "udp" and port == 0:
            continue
        rows.append(
            {
                "protocol": protocol,
                "local_address": address,
                "local_port": port,
                "inode": inode,
            }
        )
    return rows


def _socket_owners(
    root: Path,
    inodes: set[str],
    *,
    deadline_at: float | None,
) -> tuple[dict[str, tuple[int, str | None]], bool]:
    owners: dict[str, tuple[int, str | None]] = {}
    if not inodes:
        return owners, False
    inspected = 0
    proc = _rooted(root, "/proc")
    entries, processes_truncated = _limited_entries(
        (entry for entry in proc.iterdir() if entry.name.isdigit()), _MAX_PROCESSES
    )
    entries.sort(key=lambda entry: int(entry.name))
    descriptors_truncated = False
    permission_limited = False
    for entry in entries:
        _deadline(deadline_at)
        try:
            descriptor_entries, process_descriptors_truncated = _limited_entries(
                (entry / "fd").iterdir(), 4_096
            )
            descriptors_truncated = descriptors_truncated or process_descriptors_truncated
        except PermissionError:
            permission_limited = True
            continue
        except (FileNotFoundError, ProcessLookupError):
            continue
        process_name: str | None = None
        for descriptor in descriptor_entries:
            inspected += 1
            if inspected > _MAX_SOCKET_LINKS:
                return owners, True
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            if not target.startswith("socket:[") or not target.endswith("]"):
                continue
            inode = target[8:-1]
            if inode not in inodes or inode in owners:
                continue
            if process_name is None:
                try:
                    process_name = clean_text(
                        read_fixed_file(entry / "comm", maximum_bytes=4096), maximum=512
                    ).strip()
                except OSError:
                    process_name = None
            owners[inode] = (int(entry.name), process_name)
            if len(owners) == len(inodes):
                return owners, (processes_truncated or descriptors_truncated or permission_limited)
    return owners, processes_truncated or descriptors_truncated or permission_limited


def collect_listening_ports(
    *,
    root: Path = Path("/"),
    maximum_bytes: int = 8 * 1024 * 1024,
    deadline_at: float | None = None,
) -> InventoryRead:
    """Collect TCP listeners and bound UDP sockets directly from procfs."""

    _deadline(deadline_at)
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for path, protocol, ipv6 in (
        ("/proc/net/tcp", "tcp", False),
        ("/proc/net/tcp6", "tcp", True),
        ("/proc/net/udp", "udp", False),
        ("/proc/net/udp6", "udp", True),
    ):
        _deadline(deadline_at)
        try:
            output = _optional_file(_rooted(root, path), maximum_bytes)
        except (OSError, ValueError) as exc:
            if len(errors) < 5:
                errors.append(f"{path}: {clean_text(exc, maximum=128)}")
            continue
        if output is not None:
            rows.extend(_socket_rows(output, protocol=protocol, ipv6=ipv6))
    if len(rows) > _MAX_LISTENERS:
        raise ValueError("listening socket inventory exceeds the record limit")
    owners, owners_truncated = _socket_owners(
        root,
        {str(row["inode"]) for row in rows},
        deadline_at=deadline_at,
    )
    for row in rows:
        pid, process = owners.get(str(row["inode"]), (None, None))
        row.pop("inode", None)
        row["pid"] = pid
        row["process"] = process
    rows.sort(
        key=lambda item: (
            str(item["protocol"]),
            str(item["local_address"]),
            int(item["local_port"]),
        )
    )
    if owners_truncated:
        errors.append("socket owner enrichment was permission or traversal limited")
    return InventoryRead(rows, tuple(errors[:5]))


def _package_lines(output: str) -> list[str]:
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) > _MAX_PACKAGES:
        raise ValueError("software inventory exceeds the record limit")
    return lines


def parse_dpkg_packages(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in _package_lines(output):
        fields = line.split("\t")
        if len(fields) < 2 or not fields[0].strip():
            continue
        name = fields[0].split(":", 1)[0]
        records.append(
            {
                "name": clean_text(name, maximum=512),
                "version": clean_text(fields[1], maximum=256),
                "architecture": clean_text(fields[2], maximum=64) if len(fields) > 2 else None,
                "package_manager": "dpkg",
                "source": "native",
            }
        )
    return records


def parse_rpm_packages(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in _package_lines(output):
        fields = line.split("\t")
        if len(fields) < 2 or not fields[0].strip():
            continue
        records.append(
            {
                "name": clean_text(fields[0], maximum=512),
                "version": clean_text(fields[1], maximum=256),
                "architecture": clean_text(fields[2], maximum=64) if len(fields) > 2 else None,
                "vendor": clean_text(fields[3], maximum=512) if len(fields) > 3 else None,
                "package_manager": "rpm",
                "source": "native",
            }
        )
    return records


def _split_package_version(value: str) -> tuple[str, str | None]:
    for index in range(len(value) - 1, 0, -1):
        if value[index] == "-" and index + 1 < len(value) and value[index + 1].isdigit():
            return value[:index], value[index + 1 :]
    return value, None


def parse_apk_packages(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in _package_lines(output):
        name, version = _split_package_version(line.strip())
        if name:
            records.append(
                {
                    "name": clean_text(name, maximum=512),
                    "version": clean_text(version, maximum=256) if version else None,
                    "package_manager": "apk",
                    "source": "native",
                }
            )
    return records


def parse_pacman_packages(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in _package_lines(output):
        fields = line.split(maxsplit=1)
        if not fields:
            continue
        records.append(
            {
                "name": clean_text(fields[0], maximum=512),
                "version": clean_text(fields[1], maximum=256) if len(fields) > 1 else None,
                "package_manager": "pacman",
                "source": "native",
            }
        )
    return records


def parse_systemd_services(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    current: dict[str, str] = {}
    allowed = {"Id", "LoadState", "ActiveState", "UnitFileState", "ExecStart"}
    for index, raw in enumerate([*output.splitlines(), ""]):
        if index > 200_000:
            raise ValueError("service inventory exceeds the line limit")
        line = raw.strip()
        if not line:
            name = current.get("Id")
            if name and current.get("LoadState") != "not-found":
                executable_match = re.search(
                    r"(?:^|\{\s*)path=([^\s;}]+)", current.get("ExecStart", "")
                )
                records.append(
                    {
                        "name": clean_text(name, maximum=512),
                        "display_name": clean_text(name, maximum=512),
                        "state": clean_text(current.get("ActiveState"), maximum=64),
                        "startup_type": clean_text(current.get("UnitFileState"), maximum=128),
                        "executable_path": clean_text(executable_match.group(1), maximum=4096)
                        if executable_match
                        else None,
                    }
                )
                if len(records) > 100_000:
                    raise ValueError("service inventory exceeds the record limit")
            current = {}
            continue
        key, separator, value = line.partition("=")
        if separator and key in allowed:
            current[key] = value
    return records


def parse_openrc_services(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in _package_lines(output):
        stripped = line.strip()
        if not stripped or stripped.endswith(":"):
            continue
        name = stripped.split()[0]
        state = "running" if "started" in stripped.casefold() else "stopped"
        records.append(
            {"name": clean_text(name, maximum=512), "state": state, "startup_type": None}
        )
    return records


def parse_sysv_services(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in _package_lines(output):
        stripped = line.strip()
        state = "unknown"
        if stripped.startswith("[") and "]" in stripped:
            marker, _, remainder = stripped.partition("]")
            stripped = remainder.strip()
            state = "running" if "+" in marker else "stopped" if "-" in marker else "unknown"
        if stripped:
            records.append(
                {
                    "name": clean_text(stripped.split()[0], maximum=512),
                    "state": state,
                    "startup_type": None,
                }
            )
    return records


def uptime_boot_time(uptime_seconds: int | None) -> datetime | None:
    """Return a UTC boot timestamp derived from a trusted monotonic duration."""

    if uptime_seconds is None:
        return None
    return datetime.now(UTC) - timedelta(seconds=uptime_seconds)


InventorySupplier = Callable[..., InventoryRead]
