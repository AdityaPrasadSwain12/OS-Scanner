"""Automatic platform selection and aggregate native collection API."""

from __future__ import annotations

import platform as platform_module
from collections.abc import Sequence

from app.collectors.base import EndpointCollectionResult, NativeCollector, Runner
from app.collectors.linux import LinuxCollector
from app.collectors.macos import MacOsCollector
from app.collectors.windows import WindowsCollector

_SCAN_CATEGORIES: dict[str, tuple[str, ...]] = {
    "QUICK": ("inventory", "posture"),
    "FULL": ("inventory", "posture", "patches", "persistence"),
    "COMPLIANCE": ("inventory", "posture"),
    "VULNERABILITY": ("inventory", "patches"),
    "ATTACK_SURFACE": (),
    "ON_DEMAND": (),
}

# Stable check identifiers consumed by normalization/policy layers.  This is a
# compact machine-readable catalog rather than duplicating prose documentation.
NATIVE_CHECK_CATALOG: dict[str, dict[str, tuple[str, ...]]] = {
    "windows": {
        "inventory": (
            "os_info",
            "hardware",
            "software",
            "processes",
            "services",
            "users",
            "network_interfaces",
            "listening_ports",
        ),
        "posture": (
            "firewall_ufw",
            "firewall_firewalld",
            "firewall_nftables",
            "antivirus",
            "disk_encryption",
            "secure_boot",
            "tpm",
            "uac",
            "remote_desktop",
            "automatic_updates",
            "local_security_controls",
            "local_users",
        ),
        "patches": ("installed_updates", "pending_reboot", "pending_updates"),
        "persistence": (
            "machine_run_items",
            "user_run_items",
            "scheduled_tasks",
            "startup_folders",
        ),
    },
    "linux": {
        "inventory": (
            "os_info",
            "hardware",
            "software",
            "processes",
            "services",
            "users",
            "network_interfaces",
            "listening_ports",
        ),
        "posture": (
            "firewall",
            "selinux",
            "apparmor",
            "ssh_configuration",
            "ssh_configuration_file",
            "automatic_updates",
            "disk_encryption",
            "security_agents",
            "sudo_configuration",
            "password_quality",
            "login_defaults",
        ),
        "patches": ("running_kernel", "available_updates", "pending_reboot"),
        "persistence": ("enabled_systemd_units", "cron_entries"),
    },
    "macos": {
        "inventory": (
            "os_info",
            "hardware",
            "software",
            "processes",
            "services",
            "users",
            "network_interfaces",
            "listening_ports",
        ),
        "posture": (
            "firewall",
            "disk_encryption",
            "system_integrity_protection",
            "gatekeeper",
            "automatic_updates",
            "remote_login",
            "screen_sharing",
            "secure_boot_hardware",
            "lock_screen",
            "audit_logging",
        ),
        "patches": ("installed_updates", "pending_updates"),
        "persistence": ("loaded_launch_services", "launch_items"),
    },
}


class EndpointCollector:
    """Select one local adapter for inventory, posture, patches, and persistence."""

    def __init__(
        self,
        *,
        platform_name: str | None = None,
        runner: Runner | None = None,
        subprocess_timeout_seconds: float = 60.0,
        max_output_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        detected = platform_name or platform_module.system()
        key = detected.casefold()
        if key == "windows":
            collector_type: type[NativeCollector] = WindowsCollector
        elif key == "linux":
            collector_type = LinuxCollector
        elif key in {"darwin", "macos", "mac"}:
            collector_type = MacOsCollector
        else:
            raise RuntimeError(f"unsupported endpoint platform: {detected}")
        configured_runner = runner or collector_type.default_runner(
            timeout_seconds=subprocess_timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        self.native = collector_type(
            configured_runner,
            max_command_timeout_seconds=subprocess_timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def collect(
        self,
        scan_type: str = "FULL",
        selected_collectors: Sequence[str] | None = None,
        *,
        deadline_at: float | None = None,
    ) -> EndpointCollectionResult:
        normalized_scan_type = scan_type.strip().upper()
        if normalized_scan_type not in _SCAN_CATEGORIES:
            raise ValueError("unknown scan type")
        if selected_collectors is None:
            categories = _SCAN_CATEGORIES[normalized_scan_type]
            if normalized_scan_type == "ON_DEMAND":
                raise ValueError("ON_DEMAND scans require selected_collectors")
        else:
            categories = tuple(
                dict.fromkeys(item.strip().casefold() for item in selected_collectors)
            )
            if not categories:
                raise ValueError("selected_collectors cannot be empty")
            if any(item not in NativeCollector.supported_categories for item in categories):
                raise ValueError("selected_collectors contains an unsupported native category")
        self.native.set_deadline(deadline_at)
        return self.native.collect(categories)


def collect_endpoint(
    scan_type: str = "FULL",
    selected_collectors: Sequence[str] | None = None,
    *,
    runner: Runner | None = None,
    platform_name: str | None = None,
    deadline_at: float | None = None,
    subprocess_timeout_seconds: float = 60.0,
    max_output_bytes: int = 8 * 1024 * 1024,
) -> EndpointCollectionResult:
    """Collect platform-specific posture gaps using only fixed safe commands.

    ``selected_collectors`` contains category identifiers (``posture``,
    ``patches``, ``persistence``), never command names or command strings.
    """

    return EndpointCollector(
        platform_name=platform_name,
        runner=runner,
        subprocess_timeout_seconds=subprocess_timeout_seconds,
        max_output_bytes=max_output_bytes,
    ).collect(
        scan_type, selected_collectors, deadline_at=deadline_at
    )
