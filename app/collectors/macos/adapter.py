"""Tool-free native inventory and security checks for macOS endpoints."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from app.collectors.base import NativeCheckResult, NativeCollector, NativeCommand
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
from app.collectors.parsers import (
    key_value_lines,
    launchctl_disabled_services,
    launchctl_items,
    software_update_history,
    software_update_list,
    text_status,
)
from app.tools.runner import SafeSubprocessRunner

_FIREWALL = "/usr/libexec/ApplicationFirewall/socketfilterfw"
_FDESETUP = "/usr/bin/fdesetup"
_CSRUTIL = "/usr/bin/csrutil"
_SPCTL = "/usr/sbin/spctl"
_SOFTWAREUPDATE = "/usr/sbin/softwareupdate"
_SYSTEMSETUP = "/usr/sbin/systemsetup"
_SYSTEM_PROFILER = "/usr/sbin/system_profiler"
_LAUNCHCTL = "/bin/launchctl"
_DEFAULTS = "/usr/bin/defaults"
_PS = "/bin/ps"
_DSCL = "/usr/bin/dscl"
_LSOF = "/usr/sbin/lsof"


class MacOsCollector(NativeCollector):
    platform_name = "macos"

    @classmethod
    def default_runner(
        cls,
        *,
        timeout_seconds: float = 60.0,
        max_output_bytes: int = 8 * 1024 * 1024,
    ) -> SafeSubprocessRunner:
        return SafeSubprocessRunner(
            (
                _FIREWALL,
                _FDESETUP,
                _CSRUTIL,
                _SPCTL,
                _SOFTWAREUPDATE,
                _SYSTEMSETUP,
                _SYSTEM_PROFILER,
                _LAUNCHCTL,
                _DEFAULTS,
                _PS,
                _DSCL,
                _LSOF,
            ),
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def inventory_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        """Return independent, fixed-command macOS inventory observations."""

        return (
            NativeCommand(
                "os_info",
                _SYSTEM_PROFILER,
                (
                    "SPSoftwareDataType",
                    "SPHardwareDataType",
                    "-json",
                    "-detailLevel",
                    "full",
                ),
                macos_os_info,
                timeout_seconds=60,
            ),
            NativeCommand(
                "hardware",
                _SYSTEM_PROFILER,
                (
                    "SPHardwareDataType",
                    "SPStorageDataType",
                    "SPDisplaysDataType",
                    "-json",
                    "-detailLevel",
                    "full",
                ),
                macos_hardware,
                timeout_seconds=120,
            ),
            NativeCommand(
                "software",
                _SYSTEM_PROFILER,
                (
                    "SPApplicationsDataType",
                    "-json",
                    "-detailLevel",
                    "mini",
                ),
                macos_software,
                timeout_seconds=120,
            ),
            NativeCommand(
                "processes",
                _PS,
                ("-ww", "-axo", "pid=,ppid=,user=,pcpu=,rss=,comm="),
                macos_processes,
                timeout_seconds=30,
            ),
            NativeCommand(
                "services",
                _LAUNCHCTL,
                ("list",),
                macos_services,
                timeout_seconds=60,
            ),
            NativeCommand(
                "users",
                _DSCL,
                (
                    ".",
                    "-readall",
                    "/Users",
                    "RecordName",
                    "UniqueID",
                    "PrimaryGroupID",
                    "GeneratedUID",
                    "NFSHomeDirectory",
                    "UserShell",
                    "AuthenticationAuthority",
                ),
                macos_users,
                timeout_seconds=60,
            ),
            NativeCommand(
                "network_interfaces",
                _SYSTEM_PROFILER,
                ("SPNetworkDataType", "-json", "-detailLevel", "full"),
                macos_network_interfaces,
                timeout_seconds=60,
            ),
            NativeCommand(
                "listening_ports",
                _LSOF,
                ("-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP", "-FpcPtnT"),
                macos_listening_ports,
                timeout_seconds=60,
            ),
        )

    def posture_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        return (
            NativeCommand("firewall", _FIREWALL, ("--getglobalstate",), text_status),
            NativeCommand("disk_encryption", _FDESETUP, ("status",), text_status),
            NativeCommand("system_integrity_protection", _CSRUTIL, ("status",), text_status),
            NativeCommand("gatekeeper", _SPCTL, ("--status",), text_status),
            NativeCommand("automatic_updates", _SOFTWAREUPDATE, ("--schedule",), text_status),
            NativeCommand("remote_login", _SYSTEMSETUP, ("-getremotelogin",), text_status),
            NativeCommand(
                "screen_sharing",
                _LAUNCHCTL,
                ("print-disabled", "system"),
                launchctl_disabled_services,
            ),
            NativeCommand(
                "secure_boot_hardware",
                _SYSTEM_PROFILER,
                ("SPiBridgeDataType", "-detailLevel", "mini"),
                key_value_lines,
            ),
            NativeCommand(
                "lock_screen",
                _DEFAULTS,
                (
                    "read",
                    "/Library/Preferences/com.apple.screensaver",
                    "askForPassword",
                ),
                text_status,
                allowed_returncodes=frozenset({0, 1}),
            ),
            NativeCommand(
                "audit_logging",
                _LAUNCHCTL,
                ("print", "system/com.apple.auditd"),
                text_status,
            ),
        )

    def patch_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        return (
            NativeCommand(
                "installed_updates",
                _SOFTWAREUPDATE,
                ("--history",),
                software_update_history,
                timeout_seconds=120,
            ),
            NativeCommand(
                "pending_updates",
                _SOFTWAREUPDATE,
                ("--list", "--no-scan"),
                software_update_list,
                timeout_seconds=120,
            ),
        )

    def persistence_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        return (
            NativeCommand(
                "loaded_launch_services",
                _LAUNCHCTL,
                ("list",),
                launchctl_items,
                timeout_seconds=60,
            ),
        )

    def filesystem_checks(self, category: str) -> tuple[NativeCheckResult, ...]:
        if category != "persistence":
            return ()
        return (
            self.collect_directory_metadata(
                name="launch_items",
                category=category,
                directories=(
                    Path("/Library/LaunchAgents"),
                    Path("/Library/LaunchDaemons"),
                    Path.home() / "Library/LaunchAgents",
                ),
                deadline_at=self.deadline_at,
            ),
        )
