from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

import pytest

from app.collectors.base import NativeCommand
from app.collectors.macos import MacOsCollector
from app.collectors.macos.inventory_parsers import (
    macos_hardware,
    macos_listening_ports,
    macos_network_interfaces,
    macos_os_info,
    macos_processes,
    macos_services,
    macos_software,
    macos_users,
)
from app.models import NetworkProtocol, OperatingSystemFamily, ServiceState
from app.normalization.macos_inventory import normalize_macos_inventory
from app.normalization.osquery import NormalizationOutcome
from app.tools import CommandResult, ToolState


def _os_profiler() -> str:
    return json.dumps(
        {
            "SPSoftwareDataType": [
                {
                    "_name": "Software",
                    "os_version": "macOS 15.6.1 (24G90)",
                    "kernel_version": "Darwin 24.6.0",
                    "local_host_name": "finance-mac-17",
                    "uptime": "up 2 days, 3:04",
                }
            ],
            "SPHardwareDataType": [
                {
                    "chip_type": "Apple M4 Pro",
                    "platform_UUID": "A1B2C3D4-E5F6-47A8-9000-000000000001",
                }
            ],
        }
    )


def _hardware_profiler() -> str:
    return json.dumps(
        {
            "SPHardwareDataType": [
                {
                    "chip_type": "Apple M4 Pro",
                    "number_processors": "proc 10:8:2",
                    "physical_memory": "16 GB",
                    "machine_model": "Mac16,1",
                    "machine_name": "MacBook Pro",
                    "boot_rom_version": "11881.141.1",
                }
            ],
            "SPStorageDataType": [
                {
                    "_name": "Macintosh HD",
                    "bsd_name": "disk3s1s1",
                    "mount_point": "/",
                    "size_in_bytes": "500000000000",
                    "free_space_in_bytes": "200000000000",
                    "file_system": "APFS",
                    "filevault": "Yes",
                    "physical_drive": {
                        "medium_type": "SSD",
                        "serial_number": "DISK-SERIAL-1",
                    },
                }
            ],
            "SPDisplaysDataType": [
                {
                    "sppci_model": "Apple M4 Pro",
                    "spdisplays_vendor": "Apple",
                    "spdisplays_vram_shared": "8 GB",
                }
            ],
        }
    )


def _software_profiler() -> str:
    return json.dumps(
        {
            "SPApplicationsDataType": [
                {
                    "_name": "Example Agent",
                    "version": "4.2.1",
                    "path": "/Applications/Example Agent.app",
                    "lastModified": "2026-08-01 12:00:00 +0000",
                    "arch_kind": "arch_arm_i64",
                }
            ]
        }
    )


def _network_profiler() -> str:
    return json.dumps(
        {
            "SPNetworkDataType": [
                {
                    "_name": "Wi-Fi",
                    "interface": "en0",
                    "hardware": "AirPort",
                    "ethernet": {"MAC Address": "AA-BB-CC-DD-EE-FF"},
                    "ipv4": {
                        "Addresses": ["192.0.2.10"],
                        "Configuration Method": "DHCP",
                        "Router": "192.0.2.1",
                        "Subnet Masks": ["255.255.255.0"],
                    },
                    "ipv6": {
                        "Addresses": ["2001:db8::10"],
                        "Prefix Length": ["64"],
                    },
                    "dns": {"Server Addresses": ["192.0.2.53", "2001:db8::53"]},
                    "dhcp": {
                        "DHCP Server Identifier": "192.0.2.1",
                        "DHCP Routers": "192.0.2.1",
                    },
                }
            ]
        }
    )


_PROCESSES = "1 0 root 0.0 1024 /sbin/launchd\n91 1 _auditd 0.2 2048 /usr/sbin/auditd\n"
_SERVICES = "PID\tStatus\tLabel\n1\t0\tcom.apple.launchd\n-\t0\tcom.example.on-demand\n"
_USERS = """RecordName: root
UniqueID: 0
PrimaryGroupID: 0
GeneratedUID: ROOT-UUID
NFSHomeDirectory: /var/root
UserShell: /bin/sh
AuthenticationAuthority: ;ShadowHash;
-
RecordName: Guest
UniqueID: 201
PrimaryGroupID: 201
GeneratedUID: GUEST-UUID
NFSHomeDirectory: /Users/Guest
UserShell: /bin/zsh
AuthenticationAuthority: ;DisabledUser;
-
"""
_PORTS = """p101
csshd
PTCP
tIPv6
n*:22
TST=LISTEN
p202
cmDNSResponder
PUDP
tIPv4
n*:5353
"""


class _FailureRunner:
    def is_available(self, executable: str | Path) -> bool:
        return str(executable) in {"/bin/ps", "/bin/launchctl"}

    def run(
        self,
        executable: str | Path,
        arguments: Sequence[str] = (),
        *,
        timeout_seconds: float | None = None,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        del timeout_seconds, cwd
        output = "malformed" if str(executable) == "/bin/ps" else _SERVICES
        return CommandResult(
            executable=str(executable),
            arguments=tuple(arguments),
            returncode=0,
            stdout=output,
            stderr="",
            duration_seconds=0.01,
        )


def test_macos_inventory_uses_eight_fixed_non_shell_commands() -> None:
    checks = tuple(
        cast(NativeCommand, check)
        for check in MacOsCollector(_FailureRunner()).inventory_checks()
    )

    assert [check.name for check in checks] == [
        "os_info",
        "hardware",
        "software",
        "processes",
        "services",
        "users",
        "network_interfaces",
        "listening_ports",
    ]
    assert {check.executable for check in checks} <= {
        "/usr/sbin/system_profiler",
        "/bin/ps",
        "/bin/launchctl",
        "/usr/bin/dscl",
        "/usr/sbin/lsof",
    }
    assert not {"sh", "bash", "zsh"} & {
        Path(check.executable).name for check in checks
    }
    assert all(isinstance(check.arguments, tuple) for check in checks)
    assert all(0 < check.timeout_seconds <= 120 for check in checks)


def test_macos_inventory_parsers_feed_all_normalized_sections() -> None:
    inventory = {
        "os_info": macos_os_info(_os_profiler()),
        "hardware": macos_hardware(_hardware_profiler()),
        "software": macos_software(_software_profiler()),
        "processes": macos_processes(_PROCESSES),
        "services": macos_services(_SERVICES),
        "users": macos_users(_USERS),
        "network_interfaces": macos_network_interfaces(_network_profiler()),
        "listening_ports": macos_listening_ports(_PORTS),
    }

    outcome = normalize_macos_inventory(inventory, NormalizationOutcome())

    assert outcome.warnings == []
    assert outcome.data["os"].family is OperatingSystemFamily.MACOS
    assert outcome.data["os"].version == "15.6.1"
    assert outcome.data["os"].build == "24G90"
    assert outcome.data["os"].architecture == "arm64"
    assert outcome.data["hostname"] == "finance-mac-17"
    assert outcome.data["hardware"].memory_bytes == 16 * 1024**3
    assert outcome.data["hardware"].cpu.physical_cores == 10
    assert outcome.data["hardware"].disks[0].encrypted is True
    assert outcome.data["hardware"].gpus[0].memory_bytes == 8 * 1024**3
    assert outcome.data["software"][0].installation_date.isoformat() == "2026-08-01"
    assert outcome.data["processes"][1].memory_bytes == 2 * 1024**2
    assert outcome.data["services"][0].state is ServiceState.RUNNING
    assert outcome.data["services"][1].state is ServiceState.UNKNOWN
    assert outcome.data["users"][0].is_administrator is True
    assert outcome.data["users"][1].enabled is False
    interface = outcome.data["network_interfaces"][0]
    assert interface.name == "en0"
    assert interface.mac_address == "aa:bb:cc:dd:ee:ff"
    assert interface.addresses[0].prefix_length == 24
    assert interface.gateways == ["192.0.2.1"]
    assert interface.dns_servers == ["192.0.2.53", "2001:db8::53"]
    assert interface.dhcp_enabled is True
    assert outcome.data["listening_ports"][0].protocol is NetworkProtocol.TCP
    assert outcome.data["listening_ports"][0].address == "::"
    assert outcome.data["listening_ports"][0].exposed is True
    assert outcome.data["listening_ports"][1].port == 5353


def test_macos_inventory_check_failure_is_isolated() -> None:
    result = MacOsCollector(_FailureRunner()).collect(("inventory",))
    statuses = {status.name: status for status in result.statuses}

    assert statuses["processes"].status is ToolState.FAILED
    assert statuses["services"].status is ToolState.SUCCESS
    assert result.overall_status is ToolState.PARTIAL
    assert "processes" not in result.data["inventory"]
    assert result.data["inventory"]["services"][0]["name"] == "com.apple.launchd"


@pytest.mark.parametrize(
    ("parser", "payload"),
    [
        (macos_os_info, "{}"),
        (macos_hardware, "not-json"),
        (macos_processes, "malformed"),
        (macos_users, "RecordName root"),
        (macos_listening_ports, "pnot-a-pid"),
    ],
)
def test_macos_inventory_parsers_fail_closed_on_malformed_output(
    parser: Callable[[str], object], payload: str
) -> None:
    with pytest.raises(ValueError):
        parser(payload)
