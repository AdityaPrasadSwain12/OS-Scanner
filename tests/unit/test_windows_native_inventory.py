from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.collectors.windows import WindowsCollector
from app.collectors.windows.adapter import _json_object, _json_records, _powershell
from app.normalization.osquery import NormalizationOutcome
from app.normalization.windows_inventory import normalize_windows_inventory
from app.tools import CommandResult, ToolState


class WindowsInventoryRunner:
    def __init__(self, *, invalid_processes: bool = False) -> None:
        self.invalid_processes = invalid_processes
        self.calls: list[tuple[str, tuple[str, ...], float | None]] = []

    def is_available(self, executable: str | Path) -> bool:
        return str(executable) == "powershell.exe"

    def run(
        self,
        executable: str | Path,
        arguments: tuple[str, ...] = (),
        *,
        timeout_seconds: float | None = None,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        del cwd
        script = arguments[-1]
        self.calls.append((str(executable), arguments, timeout_seconds))
        if "Win32_OperatingSystem" in script:
            payload: object = {
                "Name": "Microsoft Windows 11 Enterprise",
                "Version": "10.0.26100",
                "Build": "26100",
                "Architecture": "64-bit",
                "Hostname": "WIN-LAB",
                "MachineId": "11111111-2222-3333-4444-555555555555",
                "BootTime": "2026-08-30T00:00:00Z",
                "UptimeSeconds": 3600,
                "Timezone": "India Standard Time",
                "InstalledAt": "2026-01-01T00:00:00Z",
                "Domain": "corp.example",
                "PartOfDomain": True,
            }
        elif "Win32_LogicalDisk" in script:
            payload = {
                "MemoryBytes": 17179869184,
                "Manufacturer": "Contoso",
                "DeviceModel": "Enterprise Workstation",
                "CPUs": [
                    {
                        "Vendor": "GenuineIntel",
                        "Model": "Example CPU",
                        "PhysicalCores": 8,
                        "LogicalProcessors": 16,
                        "Architecture": 64,
                    }
                ],
                "Disks": [
                    {
                        "Name": "C:",
                        "MountPoint": "C:",
                        "CapacityBytes": 1000000,
                        "FreeBytes": 400000,
                        "DiskType": "NTFS",
                        "SerialNumber": "A1B2",
                    }
                ],
                "GPUs": [
                    {
                        "Vendor": "Contoso Graphics",
                        "Model": "Enterprise GPU",
                        "MemoryBytes": 4294967296,
                    }
                ],
                "Motherboard": "Contoso Board",
                "BiosUefi": "UEFI",
                "FirmwareVersion": "1.2.3",
                "FirmwareReleaseDate": "2026-01-02T00:00:00Z",
            }
        elif "Uninstall" in script:
            payload = [
                {
                    "Name": "Business App",
                    "Version": "2.1",
                    "Vendor": "Contoso",
                    "InstallationPath": "C:\\Program Files\\Business App",
                    "InstallationDate": "20260801",
                    "Architecture": "x64",
                    "PackageManager": "windows_registry",
                    "Source": "native",
                    "PackageId": "{11111111-2222-3333-4444-555555555555}",
                }
            ]
        elif "Win32_Process" in script:
            if self.invalid_processes:
                return self._result(arguments, "not-json")
            payload = [
                {
                    "Pid": 100,
                    "ParentPid": 4,
                    "Name": "business.exe",
                    "ExecutablePath": "C:\\Program Files\\Business App\\business.exe",
                    "CommandLine": "business.exe --password top-secret",
                    "StartTime": "2026-08-30T00:05:00Z",
                    "MemoryBytes": 2048,
                    "User": "CORP\\alice",
                }
            ]
        elif "Win32_Service" in script:
            payload = [
                {
                    "Name": "BusinessService",
                    "DisplayName": "Business Service",
                    "State": "Running",
                    "StartupType": "Auto",
                    "ExecutablePath": '"C:\\Program Files\\Business App\\service.exe"',
                    "ServiceAccount": "LocalSystem",
                }
            ]
        elif "Get-LocalUser" in script:
            payload = [
                {
                    "Name": "Administrator",
                    "SID": "S-1-5-21-1000-500",
                    "Enabled": True,
                    "Groups": ["Administrators"],
                    "IsAdministrator": True,
                    "IsGuest": False,
                    "LastLogon": "2026-08-29T10:00:00Z",
                    "PasswordRequired": True,
                    "PasswordExpires": "2026-12-01T00:00:00Z",
                    "UserMayChangePassword": True,
                }
            ]
        elif "Get-NetAdapter" in script:
            payload = [
                {
                    "Name": "Ethernet",
                    "Description": "Contoso Ethernet Adapter",
                    "MacAddress": "00-11-22-33-44-55",
                    "Addresses": [
                        {"Address": "192.0.2.10", "PrefixLength": 24},
                        {"Address": "2001:db8::10", "PrefixLength": 64},
                    ],
                    "Gateways": ["192.0.2.1"],
                    "DnsServers": ["192.0.2.53", "2001:db8::53"],
                    "DhcpEnabled": True,
                    "DhcpServer": "192.0.2.2",
                    "DhcpLeaseObtained": "2026-08-30T00:00:00Z",
                    "DhcpLeaseExpires": "2026-08-31T00:00:00Z",
                    "IsUp": True,
                }
            ]
        elif "Get-NetTCPConnection" in script:
            payload = [
                {
                    "Protocol": "TCP",
                    "Address": "0.0.0.0",  # noqa: S104 - observed listener fixture
                    "Port": 443,
                    "Pid": 100,
                    "Process": "business",
                },
                {
                    "Protocol": "UDP",
                    "Address": "127.0.0.1",
                    "Port": 53,
                    "Pid": 101,
                    "Process": "dns-cache",
                },
            ]
        elif "Win32_UserProfile" in script:
            payload = [
                {
                    "Browser": "Edge",
                    "ExtensionId": "abcdefghijklmnopabcdefghijklmnop",
                    "Name": "Enterprise Extension",
                    "Version": "1.2.3",
                    "Enabled": True,
                    "Permissions": ["storage", "management"],
                    "Profile": "Default",
                }
            ]
        elif "LocalMachine\\Root" in script:
            payload = [
                {
                    "Store": "Cert:\\LocalMachine\\Root",
                    "Subject": "CN=Enterprise Root",
                    "Issuer": "CN=Enterprise Root",
                    "Thumbprint": "ABC123",
                    "SerialNumber": "1234",
                    "NotBefore": "2026-01-01T00:00:00Z",
                    "NotAfter": "2030-01-01T00:00:00Z",
                    "SignatureAlgorithm": "sha256RSA",
                    "PublicKeyAlgorithm": "RSA",
                    "KeySize": 2048,
                    "HasPrivateKey": False,
                    "SelfSigned": True,
                    "Expired": False,
                }
            ]
        else:  # pragma: no cover - a new check must add an explicit fixture
            raise AssertionError(f"unexpected Windows inventory script: {script[:80]}")
        return self._result(arguments, json.dumps(payload))

    @staticmethod
    def _result(arguments: tuple[str, ...], output: str) -> CommandResult:
        return CommandResult(
            executable="powershell.exe",
            arguments=arguments,
            returncode=0,
            stdout=output,
            stderr="",
            duration_seconds=0.01,
        )


def test_windows_inventory_collects_and_normalizes_without_external_tools() -> None:
    runner = WindowsInventoryRunner()
    collection = WindowsCollector(runner).collect(["inventory"])

    assert collection.overall_status is ToolState.SUCCESS
    assert tuple(collection.data["inventory"]) == (
        "os_info",
        "hardware",
        "software",
        "processes",
        "services",
        "users",
        "network_interfaces",
        "listening_ports",
        "browser_extensions",
        "certificates",
    )
    assert len(collection.statuses) == 10
    assert all(item.status is ToolState.SUCCESS for item in collection.statuses)
    assert all(call[0] == "powershell.exe" for call in runner.calls)

    outcome = normalize_windows_inventory(collection.data["inventory"], NormalizationOutcome())

    assert outcome.warnings == []
    assert outcome.data["hostname"] == "WIN-LAB"
    assert outcome.data["os"].name == "Microsoft Windows 11 Enterprise"
    assert outcome.data["os"].machine_id == "11111111-2222-3333-4444-555555555555"
    assert outcome.data["hardware"].cpu.physical_cores == 8
    assert outcome.data["hardware"].disks[0].free_bytes == 400000
    assert outcome.data["software"][0].name == "Business App"
    assert outcome.data["software"][0].package_id.startswith("{")
    assert outcome.data["processes"][0].command_line is None
    assert outcome.data["processes"][0].user == "CORP\\alice"
    assert outcome.data["services"][0].state.value == "RUNNING"
    assert outcome.data["users"][0].is_administrator is True
    interface = outcome.data["network_interfaces"][0]
    assert interface.mac_address == "00:11:22:33:44:55"
    assert interface.gateways == ["192.0.2.1"]
    assert interface.dns_servers == ["192.0.2.53", "2001:db8::53"]
    assert len(interface.addresses) == 2
    assert outcome.data["listening_ports"][0].exposed is True
    assert outcome.data["listening_ports"][0].bind_scope == "WILDCARD"
    assert outcome.data["listening_ports"][0].remote_reachability == "NOT_TESTED"
    assert outcome.data["browser_extensions"][0].risky is True
    assert outcome.data["certificates"][0].has_private_key is False


def test_windows_inventory_check_failure_is_isolated() -> None:
    collection = WindowsCollector(WindowsInventoryRunner(invalid_processes=True)).collect(
        ["inventory"]
    )

    statuses = {item.name: item for item in collection.statuses}
    assert statuses["processes"].status is ToolState.FAILED
    assert "invalid JSON" in (statuses["processes"].error or "")
    assert "processes" not in collection.data["inventory"]
    assert collection.data["inventory"]["services"][0]["Name"] == "BusinessService"
    assert collection.overall_status is ToolState.PARTIAL


def test_windows_inventory_commands_are_fixed_and_parsers_are_bounded() -> None:
    commands = tuple(WindowsCollector(WindowsInventoryRunner()).inventory_checks())

    assert {command.name for command in commands} == {
        "os_info",
        "hardware",
        "software",
        "processes",
        "services",
        "users",
        "network_interfaces",
        "listening_ports",
        "browser_extensions",
        "certificates",
    }
    for command in commands:
        assert command.executable == "powershell.exe"
        assert command.arguments[:4] == (
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
        )
        assert "Invoke-Expression" not in command.arguments[-1]
        assert "Start-Process" not in command.arguments[-1]
        assert command.arguments[-1].startswith(
            "$utf8NoBom=[System.Text.UTF8Encoding]::new($false);"
            "[Console]::OutputEncoding=$utf8NoBom;$OutputEncoding=$utf8NoBom;"
        )

    process_command = next(command for command in commands if command.name == "processes")
    assert "CommandLine" not in process_command.arguments[-1]

    unicode_script = "Write-Output '\u00e9_\u65e5\u672c'"
    unicode_command = _powershell(unicode_script)
    assert unicode_command[-1].endswith(unicode_script)

    with pytest.raises(ValueError, match="array of objects"):
        _json_records('["not-an-object"]')
    with pytest.raises(ValueError, match="record limit"):
        _json_records(json.dumps([{}] * 20_001))
    with pytest.raises(ValueError, match="nesting limit"):
        _json_object('{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":1}}}}}}}}}')


def test_windows_empty_observed_inventory_sections_remain_authoritative() -> None:
    outcome = normalize_windows_inventory(
        {
            "software": [],
            "processes": [],
            "services": [],
            "users": [],
            "network_interfaces": [],
            "listening_ports": [],
        },
        NormalizationOutcome(),
    )

    assert outcome.data == {
        "software": [],
        "processes": [],
        "services": [],
        "users": [],
        "network_interfaces": [],
        "listening_ports": [],
    }
    assert outcome.rejected_sections == set()


def test_windows_malformed_rows_are_not_authoritative_empty_inventory() -> None:
    outcome = normalize_windows_inventory(
        {"software": [{"not_name": "malformed"}]},
        NormalizationOutcome(),
    )

    assert outcome.data["software"] == []
    assert outcome.warnings == ["invalid Windows software metadata omitted"]
    assert outcome.rejected_sections == {"software"}
