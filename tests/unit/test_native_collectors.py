from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.collectors import EndpointCollector
from app.collectors.linux import LinuxCollector
from app.collectors.macos import MacOsCollector
from app.collectors.windows import WindowsCollector
from app.tools import CommandResult, ToolState


class NativeFakeRunner:
    def __init__(self, available: set[str]) -> None:
        self.available = available
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def is_available(self, executable: str | Path) -> bool:
        return str(executable) in self.available

    def run(
        self,
        executable: str | Path,
        arguments: tuple[str, ...] = (),
        *,
        timeout_seconds: float | None = None,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        del timeout_seconds, cwd
        executable_text = str(executable)
        self.calls.append((executable_text, tuple(arguments)))
        if executable_text == "ufw":
            output = "Status: active"
        elif executable_text == "getenforce":
            output = "Enforcing"
        elif executable_text == "aa-status":
            output = "apparmor module is loaded"
        elif executable_text == "sshd":
            output = "permitrootlogin no\npasswordauthentication no\npermitemptypasswords no"
        elif executable_text == "systemctl":
            output = "enabled"
        elif executable_text == "powershell.exe" and "Get-HotFix" in arguments[-1]:
            output = json.dumps([{"HotFixID": "KB500000", "InstalledOn": "2026-01-01"}])
        elif executable_text == "powershell.exe":
            output = "false"
        elif executable_text.endswith("socketfilterfw"):
            output = "Firewall is enabled. (State = 1)"
        else:
            output = "enabled"
        return CommandResult(
            executable=executable_text,
            arguments=tuple(arguments),
            returncode=0,
            stdout=output,
            stderr="",
            duration_seconds=0.01,
        )


def test_linux_quick_collector_selects_core_inventory_and_posture() -> None:
    runner = NativeFakeRunner({"ufw", "getenforce", "aa-status", "sshd", "systemctl"})

    result = EndpointCollector(platform_name="Linux", runner=runner).collect("QUICK")

    assert result.platform == "linux"
    assert set(result.data) == {"inventory", "posture"}
    assert result.overall_status == ToolState.PARTIAL
    assert result.data["posture"]["ssh_configuration"]["permitrootlogin"] == "no"
    assert all(isinstance(arguments, tuple) for _, arguments in runner.calls)


def test_windows_on_demand_patch_collection() -> None:
    runner = NativeFakeRunner({"powershell.exe"})

    result = EndpointCollector(platform_name="Windows", runner=runner).collect(
        "ON_DEMAND", ("patches",)
    )

    assert result.overall_status == ToolState.SUCCESS
    assert result.data["patches"]["installed_updates"][0]["update_id"] == "KB500000"
    assert all(call[0] == "powershell.exe" for call in runner.calls)


def test_missing_native_commands_are_reported_without_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(LinuxCollector, "filesystem_checks", lambda self, category: ())
    result = EndpointCollector(platform_name="Linux", runner=NativeFakeRunner(set())).collect(
        "QUICK"
    )

    assert result.overall_status == ToolState.UNAVAILABLE
    assert result.statuses
    assert all(item.status == ToolState.UNAVAILABLE for item in result.statuses)


def test_attack_surface_scan_does_not_run_endpoint_commands() -> None:
    runner = NativeFakeRunner({"ufw"})

    result = EndpointCollector(platform_name="Linux", runner=runner).collect("ATTACK_SURFACE")

    assert result.statuses == ()
    assert runner.calls == []


def test_platform_collectors_produce_new_protective_control_checks() -> None:
    runner = NativeFakeRunner(set())

    def commands(checks: object) -> list[object]:
        flattened: list[object] = []
        for check in checks:  # type: ignore[union-attr]
            flattened.extend(check if isinstance(check, tuple) else (check,))
        return flattened

    windows = commands(WindowsCollector(runner).posture_checks())  # type: ignore[arg-type]
    linux = commands(LinuxCollector(runner).posture_checks())  # type: ignore[arg-type]
    macos = commands(MacOsCollector(runner).posture_checks())  # type: ignore[arg-type]

    assert "local_security_controls" in {check.name for check in windows}  # type: ignore[attr-defined]
    windows_controls = next(  # type: ignore[attr-defined]
        check for check in windows if check.name == "local_security_controls"
    )
    script = windows_controls.arguments[-1]  # type: ignore[attr-defined]
    assert "GuestAccountEnabled" in script
    assert "LockScreenEnabled" in script
    assert "AuditLoggingEnabled" in script
    assert "LocalAdminPasswordManaged" in script

    assert "security_agents" in {check.name for check in linux}  # type: ignore[attr-defined]
    assert {
        "secure_boot_hardware",
        "lock_screen",
        "audit_logging",
    } <= {check.name for check in macos}  # type: ignore[attr-defined]
