from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from app.collectors.linux import LinuxCollector
from app.collectors.linux import inventory as linux_inventory
from app.collectors.linux.inventory import (
    collect_hardware,
    collect_listening_ports,
    collect_network_interfaces,
    collect_os_info,
    collect_processes,
    collect_users,
    parse_apk_packages,
    parse_dpkg_packages,
    parse_openrc_services,
    parse_pacman_packages,
    parse_rpm_packages,
    parse_systemd_services,
    parse_sysv_services,
)
from app.normalization import normalize_native
from app.tools import CommandResult


def _write(root: Path, name: str, value: str) -> None:
    path = root / name.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


class InventoryRunner:
    def is_available(self, executable: str | Path) -> bool:
        return str(executable) in {"dpkg-query", "systemctl"}

    def run(
        self,
        executable: str | Path,
        arguments: tuple[str, ...] = (),
        *,
        timeout_seconds: float | None = None,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        del timeout_seconds, cwd
        name = str(executable)
        output = (
            "openssl\t3.0.1\tamd64\n"
            if name == "dpkg-query"
            else (
                "Id=sshd.service\n"
                "LoadState=loaded\n"
                "ActiveState=active\n"
                "UnitFileState=enabled\n"
                "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; }\n"
            )
        )
        return CommandResult(
            executable=name,
            arguments=arguments,
            returncode=0,
            stdout=output,
            stderr="",
            duration_seconds=0.01,
        )


def test_linux_fixed_files_collect_os_hardware_process_and_users(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, "/etc/os-release", 'NAME="Example Linux"\nVERSION_ID="24.04"\n')
    _write(tmp_path, "/etc/machine-id", "machine-123\n")
    _write(tmp_path, "/etc/timezone", "Etc/UTC\n")
    _write(tmp_path, "/proc/sys/kernel/hostname", "endpoint-01\n")
    _write(tmp_path, "/proc/sys/kernel/osrelease", "6.8.0-test\n")
    _write(tmp_path, "/proc/sys/kernel/version", "build-1\n")
    _write(tmp_path, "/proc/uptime", "120.75 50.00\n")
    _write(
        tmp_path,
        "/proc/cpuinfo",
        "processor : 0\nvendor_id : GenuineIntel\nmodel name : Test CPU\n"
        "physical id : 0\ncore id : 0\n\n"
        "processor : 1\nvendor_id : GenuineIntel\nmodel name : Test CPU\n"
        "physical id : 0\ncore id : 1\n",
    )
    _write(tmp_path, "/proc/meminfo", "MemTotal:       2048 kB\n")
    _write(tmp_path, "/proc/self/mounts", "")
    _write(tmp_path, "/sys/devices/virtual/dmi/id/sys_vendor", "Acme\n")
    _write(tmp_path, "/sys/devices/virtual/dmi/id/product_name", "Server 1\n")
    _write(
        tmp_path,
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
    )
    _write(
        tmp_path,
        "/etc/group",
        "root:x:0:\nsudo:x:27:alice\nalice:x:1000:\nnogroup:x:65534:\n",
    )
    _write(tmp_path, "/etc/shadow", "root:!:1:2:3\nalice:secret-hash:1:2:3\n")
    _write(
        tmp_path,
        "/proc/42/status",
        "Name:\ttestd\nPid:\t42\nPPid:\t1\nUid:\t1000 1000 1000 1000\nVmRSS:\t16 kB\n",
    )
    _write(tmp_path, "/proc/42/cmdline", "testd\x00--token\x00secret-value\x00")

    original_read_fixed_file = linux_inventory.read_fixed_file

    def reject_sensitive_reads(path: Path, *, maximum_bytes: int = 1024 * 1024) -> str:
        if path.name in {"cmdline", "shadow"}:
            raise AssertionError(f"sensitive native inventory read attempted: {path.name}")
        return original_read_fixed_file(path, maximum_bytes=maximum_bytes)

    monkeypatch.setattr(linux_inventory, "read_fixed_file", reject_sensitive_reads)

    os_info = collect_os_info(root=tmp_path).data
    hardware = collect_hardware(root=tmp_path).data
    processes = collect_processes(root=tmp_path).data
    users = collect_users(root=tmp_path).data

    assert os_info["name"] == "Example Linux"
    assert os_info["version"] == "24.04"
    assert os_info["hostname"] == "endpoint-01"
    assert os_info["uptime_seconds"] == 120
    assert hardware["cpu"]["logical_processors"] == 2
    assert hardware["cpu"]["physical_cores"] == 2
    assert hardware["memory_bytes"] == 2 * 1024 * 1024
    assert hardware["manufacturer"] == "Acme"
    assert processes == [
        {
            "pid": 42,
            "name": "testd",
            "user": "alice",
            "parent_pid": 1,
            "memory_bytes": 16 * 1024,
        }
    ]
    alice = next(user for user in users if user["username"] == "alice")
    assert alice["enabled"] is None
    assert alice["is_administrator"] is True
    nobody = next(user for user in users if user["username"] == "nobody")
    assert nobody["enabled"] is False
    assert nobody["is_guest"] is True


def test_linux_process_inventory_enforces_aggregate_byte_budget(tmp_path: Path) -> None:
    _write(tmp_path, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
    for pid in (1, 2):
        _write(
            tmp_path,
            f"/proc/{pid}/status",
            f"Name:\tworker-{pid}\nPPid:\t0\nUid:\t0 0 0 0\n",
        )

    outcome = collect_processes(root=tmp_path, maximum_bytes=100)

    encoded = json.dumps(outcome.data, ensure_ascii=False, separators=(",", ":")).encode()
    assert len(encoded) <= 100
    assert len(outcome.data) == 1
    assert outcome.errors == ("process inventory reached its byte limit",)


def test_linux_network_and_listeners_are_read_from_kernel_files(tmp_path: Path) -> None:
    _write(tmp_path, "/sys/class/net/eth0/address", "02:00:00:00:00:01\n")
    _write(tmp_path, "/sys/class/net/eth0/operstate", "up\n")
    _write(
        tmp_path,
        "/proc/net/if_inet6",
        "00000000000000000000000000000001 01 80 10 80 lo\n"
        "20010db8000000000000000000000001 02 40 00 80 eth0\n",
    )
    _write(
        tmp_path,
        "/proc/net/route",
        "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
        "eth0 00000000 010200C0 0003 0 0 100 00000000 0 0 0\n",
    )
    _write(tmp_path, "/proc/net/ipv6_route", "")
    _write(tmp_path, "/etc/resolv.conf", "nameserver 1.1.1.1\nnameserver 2001:4860:4860::8888\n")
    _write(
        tmp_path,
        "/proc/net/tcp",
        "  sl  local_address rem_address st tx_queue rx_queue tr tm->when "
        "retrnsmt uid timeout inode\n"
        "   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 "
        "00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0\n",
    )
    _write(tmp_path, "/proc/net/tcp6", "header\n")
    _write(tmp_path, "/proc/net/udp", "header\n")
    _write(tmp_path, "/proc/net/udp6", "header\n")

    interfaces = collect_network_interfaces(root=tmp_path).data
    listeners = collect_listening_ports(root=tmp_path).data

    eth0 = next(interface for interface in interfaces if interface["name"] == "eth0")
    assert eth0["is_up"] is True
    assert eth0["addresses"] == [{"address": "2001:db8::1", "prefix_length": 64}]
    assert eth0["gateways"] == ["192.0.2.1"]
    assert eth0["dns_servers"] == ["1.1.1.1", "2001:4860:4860::8888"]
    assert listeners == [
        {
            "protocol": "tcp",
            "local_address": "127.0.0.1",
            "local_port": 22,
            "pid": None,
            "process": None,
        }
    ]


def test_linux_package_and_service_parsers_cover_distribution_families() -> None:
    assert parse_dpkg_packages("openssl:amd64\t3.0.1\tamd64\n")[0] == {
        "name": "openssl",
        "version": "3.0.1",
        "architecture": "amd64",
        "package_manager": "dpkg",
        "source": "native",
    }
    assert parse_rpm_packages("openssl\t3.0.1-2\tx86_64\tVendor\n")[0]["package_manager"] == "rpm"
    assert parse_apk_packages("busybox-1.36.1-r2\n")[0]["version"] == "1.36.1-r2"
    assert parse_pacman_packages("linux 6.8.1.arch1-1\n")[0]["name"] == "linux"

    systemd = parse_systemd_services(
        "Id=sshd.service\nLoadState=loaded\nActiveState=active\n"
        "UnitFileState=enabled\n"
        "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; }\n"
    )
    assert systemd[0]["state"] == "active"
    assert systemd[0]["startup_type"] == "enabled"
    assert systemd[0]["executable_path"] == "/usr/sbin/sshd"
    assert parse_openrc_services("sshd [ started ]\n")[0]["state"] == "running"
    assert parse_sysv_services(" [ - ] cron\n")[0]["state"] == "stopped"


def test_linux_inventory_commands_use_only_fixed_arguments() -> None:
    collector = LinuxCollector(InventoryRunner())
    choices = tuple(collector.inventory_checks())

    assert len(choices) == 2
    assert {command.name for choice in choices for command in choice} == {
        "software",
        "services",
    }
    assert all(
        all(ord(character) >= 32 for argument in command.arguments for character in argument)
        for choice in choices
        for command in choice
    )
    result = collector.collect(("inventory",))
    assert result.data["inventory"]["software"][0]["name"] == "openssl"
    assert result.data["inventory"]["services"][0]["name"] == "sshd.service"


def test_linux_inventory_normalizes_every_core_section() -> None:
    outcome = normalize_native(
        {
            "platform": "linux",
            "data": {
                "inventory": {
                    "os_info": {
                        "name": "Example Linux",
                        "version": "24.04",
                        "kernel": "6.8.0",
                        "architecture": "x86_64",
                        "hostname": "endpoint-01",
                        "machine_id": "machine-123",
                        "uptime_seconds": 120,
                        "timezone": "Etc/UTC",
                    },
                    "hardware": {
                        "cpu": {"model": "Test CPU", "logical_processors": 2},
                        "memory_bytes": 2 * 1024 * 1024,
                        "disks": [],
                    },
                    "software": [
                        {"name": "openssl", "version": "3.0.1", "package_manager": "dpkg"}
                    ],
                    "processes": [
                        {
                            "pid": 1,
                            "name": "systemd",
                            "user": "root",
                            "command_line": "systemd --token secret-value",
                        }
                    ],
                    "services": [
                        {"name": "sshd.service", "state": "active", "startup_type": "enabled"}
                    ],
                    "users": [
                        {
                            "username": "root",
                            "uid": "0",
                            "enabled": True,
                            "groups": ["root"],
                            "is_administrator": True,
                        }
                    ],
                    "network_interfaces": [
                        {
                            "name": "eth0",
                            "mac_address": "02:00:00:00:00:01",
                            "addresses": [{"address": "192.0.2.10", "prefix_length": 24}],
                            "gateways": ["192.0.2.1"],
                            "dns_servers": ["1.1.1.1"],
                            "is_up": True,
                        }
                    ],
                    "listening_ports": [
                        {
                            "protocol": "tcp",
                            "local_address": "0.0.0.0",  # noqa: S104 - observed test listener
                            "local_port": 22,
                            "pid": 1,
                            "process": "sshd",
                        }
                    ],
                }
            },
        },
    )

    assert outcome.data["hostname"] == "endpoint-01"
    assert outcome.data["os"].family.value == "LINUX"
    assert outcome.data["hardware"].memory_bytes == 2 * 1024 * 1024
    assert outcome.data["software"][0].name == "openssl"
    assert outcome.data["processes"][0].pid == 1
    assert outcome.data["processes"][0].command_line is None
    assert outcome.data["services"][0].state.value == "RUNNING"
    assert outcome.data["services"][0].security_relevant is True
    assert outcome.data["users"][0].is_administrator is True
    assert outcome.data["network_interfaces"][0].gateways == ["192.0.2.1"]
    assert outcome.data["listening_ports"][0].exposed is True
    assert outcome.warnings == []


def test_linux_filesystem_inventory_honors_expired_deadline(tmp_path: Path) -> None:
    (tmp_path / "proc").mkdir()
    with pytest.raises(TimeoutError, match="deadline"):
        collect_processes(root=tmp_path, deadline_at=time.monotonic() - 1)
