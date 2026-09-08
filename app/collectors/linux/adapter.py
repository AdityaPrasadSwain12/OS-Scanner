"""Linux-only checks that fill posture, patch, and persistence gaps."""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from app.collectors.base import (
    NativeCheckResult,
    NativeCollector,
    NativeCollectorStatus,
    NativeCommand,
)
from app.collectors.parsers import (
    automatic_update_units,
    enabled_units,
    lsblk_encryption,
    package_updates,
    sshd_effective_config,
    systemd_unit_properties,
    text_status,
)
from app.tools._validation import clean_text
from app.tools.base import ToolState
from app.tools.runner import SafeSubprocessRunner

from .inventory import (
    InventoryRead,
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


def _security_package_updates(output: str) -> list[dict[str, Any]]:
    records = package_updates(output)
    for record in records:
        record["security_related"] = True
    return records


class LinuxCollector(NativeCollector):
    platform_name = "linux"

    @classmethod
    def default_runner(
        cls,
        *,
        timeout_seconds: float = 60.0,
        max_output_bytes: int = 8 * 1024 * 1024,
    ) -> SafeSubprocessRunner:
        return SafeSubprocessRunner(
            (
                "aa-status",
                "apk",
                "apt-get",
                "dnf",
                "dpkg-query",
                "firewall-cmd",
                "getenforce",
                "nft",
                "lsblk",
                "pacman",
                "rc-status",
                "rpm",
                "service",
                "sshd",
                "systemctl",
                "ufw",
                "uname",
                "yum",
                "zypper",
            ),
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def inventory_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        """Return distribution-native package and service inventory commands."""

        return (
            (
                NativeCommand(
                    "software",
                    "dpkg-query",
                    ("-W", "-f=${binary:Package}\\t${Version}\\t${Architecture}\\n"),
                    parse_dpkg_packages,
                    timeout_seconds=120,
                ),
                NativeCommand(
                    "software",
                    "rpm",
                    (
                        "-qa",
                        "--qf",
                        "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\n",
                    ),
                    parse_rpm_packages,
                    timeout_seconds=120,
                ),
                NativeCommand(
                    "software",
                    "apk",
                    ("info", "-v"),
                    parse_apk_packages,
                    timeout_seconds=120,
                ),
                NativeCommand(
                    "software",
                    "pacman",
                    ("-Q",),
                    parse_pacman_packages,
                    timeout_seconds=120,
                ),
            ),
            (
                NativeCommand(
                    "services",
                    "systemctl",
                    (
                        "show",
                        "--all",
                        "--type=service",
                        "--no-pager",
                        "--property=Id,LoadState,ActiveState,UnitFileState,ExecStart",
                    ),
                    parse_systemd_services,
                    timeout_seconds=120,
                ),
                NativeCommand(
                    "services",
                    "rc-status",
                    ("--all",),
                    parse_openrc_services,
                    timeout_seconds=120,
                ),
                NativeCommand(
                    "services",
                    "service",
                    ("--status-all",),
                    parse_sysv_services,
                    timeout_seconds=120,
                ),
            ),
        )

    def posture_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        return (
            NativeCommand("firewall_ufw", "ufw", ("status",), text_status),
            NativeCommand("firewall_firewalld", "firewall-cmd", ("--state",), text_status),
            NativeCommand("firewall_nftables", "nft", ("list", "ruleset"), text_status),
            NativeCommand("selinux", "getenforce", (), text_status),
            NativeCommand(
                "apparmor",
                "aa-status",
                (),
                text_status,
                allowed_returncodes=frozenset({0, 1, 2, 3, 4}),
            ),
            NativeCommand("ssh_configuration", "sshd", ("-T",), sshd_effective_config),
            NativeCommand(
                "automatic_updates",
                "systemctl",
                (
                    "show",
                    "--no-pager",
                    "--property=Id,LoadState,ActiveState,UnitFileState",
                    "unattended-upgrades.service",
                    "apt-daily-upgrade.timer",
                    "dnf-automatic.timer",
                ),
                automatic_update_units,
                allowed_returncodes=frozenset({0, 1}),
            ),
            NativeCommand(
                "disk_encryption",
                "lsblk",
                ("--json", "--output", "NAME,TYPE,FSTYPE,MOUNTPOINTS"),
                lsblk_encryption,
            ),
            NativeCommand(
                "security_agents",
                "systemctl",
                (
                    "show",
                    "--no-pager",
                    "--property=Id,LoadState,ActiveState,UnitFileState",
                    "wazuh-agent.service",
                    "auditd.service",
                    "falcon-sensor.service",
                    "mdatp.service",
                ),
                systemd_unit_properties,
                allowed_returncodes=frozenset({0, 1}),
            ),
        )

    def patch_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        updates = (
            NativeCommand(
                "available_updates",
                "apt-get",
                ("-s", "-o", "Debug::NoLocking=true", "upgrade"),
                package_updates,
                timeout_seconds=120,
            ),
            NativeCommand(
                "available_updates",
                "dnf",
                ("--cacheonly", "check-update", "--security"),
                _security_package_updates,
                allowed_returncodes=frozenset({0, 100}),
                timeout_seconds=120,
            ),
            NativeCommand(
                "available_updates",
                "yum",
                ("--cacheonly", "check-update", "--security"),
                _security_package_updates,
                allowed_returncodes=frozenset({0, 100}),
                timeout_seconds=120,
            ),
            NativeCommand(
                "available_updates",
                "zypper",
                ("--non-interactive", "list-updates"),
                package_updates,
                allowed_returncodes=frozenset({0, 100}),
                timeout_seconds=120,
            ),
        )
        return (
            NativeCommand("running_kernel", "uname", ("-r",), text_status),
            updates,
        )

    def persistence_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        return (
            NativeCommand(
                "enabled_systemd_units",
                "systemctl",
                (
                    "list-unit-files",
                    "--state=enabled",
                    "--no-legend",
                    "--no-pager",
                ),
                enabled_units,
                timeout_seconds=60,
            ),
        )

    def filesystem_checks(self, category: str) -> tuple[NativeCheckResult, ...]:
        if category == "inventory":
            return (
                self._inventory_file_check("os_info", collect_os_info),
                self._inventory_file_check("hardware", collect_hardware),
                self._inventory_file_check("processes", collect_processes),
                self._inventory_file_check("users", collect_users),
                self._inventory_file_check("network_interfaces", collect_network_interfaces),
                self._inventory_file_check("listening_ports", collect_listening_ports),
            )
        if category == "posture":
            return (
                self._fixed_file_check(
                    "ssh_configuration_file", category, Path("/etc/ssh/sshd_config"), _ssh_config
                ),
                self._sudo_check(category),
                self._fixed_file_check(
                    "password_quality",
                    category,
                    Path("/etc/security/pwquality.conf"),
                    _pwquality_config,
                ),
                self._fixed_file_check(
                    "login_defaults", category, Path("/etc/login.defs"), _login_defaults
                ),
            )
        if category == "patches":
            return (
                NativeCheckResult(
                    NativeCollectorStatus(
                        name="pending_reboot",
                        category=category,
                        status=ToolState.SUCCESS,
                        count=1,
                    ),
                    {"required": Path("/var/run/reboot-required").exists()},
                ),
            )
        if category == "persistence":
            return (
                self.collect_directory_metadata(
                    name="cron_entries",
                    category=category,
                    directories=(
                        Path("/etc/cron.d"),
                        Path("/etc/cron.daily"),
                        Path("/etc/cron.hourly"),
                        Path("/etc/cron.monthly"),
                        Path("/etc/cron.weekly"),
                        Path("/var/spool/cron"),
                    ),
                    deadline_at=self.deadline_at,
                ),
            )
        return ()

    def _inventory_file_check(
        self,
        name: str,
        supplier: Callable[..., InventoryRead],
    ) -> NativeCheckResult:
        started = time.monotonic()
        try:
            outcome = supplier(
                root=Path("/"),
                maximum_bytes=self.max_output_bytes,
                deadline_at=self.deadline_at,
            )
        except FileNotFoundError:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name=name,
                    category="inventory",
                    status=ToolState.UNAVAILABLE,
                    duration_seconds=time.monotonic() - started,
                )
            )
        except TimeoutError as exc:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name=name,
                    category="inventory",
                    status=ToolState.TIMEOUT,
                    duration_seconds=time.monotonic() - started,
                    error=clean_text(exc, maximum=512),
                )
            )
        except (OSError, ValueError) as exc:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name=name,
                    category="inventory",
                    status=ToolState.FAILED,
                    duration_seconds=time.monotonic() - started,
                    error=clean_text(exc, maximum=512),
                )
            )
        errors = tuple(clean_text(error, maximum=256) for error in outcome.errors[:5])
        return NativeCheckResult(
            NativeCollectorStatus(
                name=name,
                category="inventory",
                status=ToolState.PARTIAL if errors else ToolState.SUCCESS,
                duration_seconds=time.monotonic() - started,
                count=(
                    len(outcome.data)
                    if isinstance(outcome.data, (dict, list, tuple, set))
                    else None
                ),
                error="; ".join(errors) if errors else None,
            ),
            outcome.data,
        )

    @staticmethod
    def _fixed_file_check(
        name: str,
        category: str,
        path: Path,
        parser: Any,
    ) -> NativeCheckResult:
        started = time.monotonic()
        try:
            data = parser(_read_fixed_file(path))
        except FileNotFoundError:
            return NativeCheckResult(
                NativeCollectorStatus(name=name, category=category, status=ToolState.UNAVAILABLE)
            )
        except (OSError, ValueError) as exc:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name=name,
                    category=category,
                    status=ToolState.FAILED,
                    duration_seconds=time.monotonic() - started,
                    error=clean_text(exc, maximum=512),
                )
            )
        return NativeCheckResult(
            NativeCollectorStatus(
                name=name,
                category=category,
                status=ToolState.SUCCESS,
                duration_seconds=time.monotonic() - started,
                count=len(data) if isinstance(data, (dict, list)) else None,
            ),
            data,
        )

    def _sudo_check(self, category: str) -> NativeCheckResult:
        started = time.monotonic()
        sources = [Path("/etc/sudoers")]
        include_directory = Path("/etc/sudoers.d")
        try:
            if include_directory.is_dir():
                sources.extend(
                    sorted(
                        (
                            entry
                            for entry in include_directory.iterdir()
                            if entry.is_file() and not entry.is_symlink()
                        ),
                        key=lambda item: item.name,
                    )[:100]
                )
            contents = [_read_fixed_file(path) for path in sources if path.exists()]
            if not contents:
                raise FileNotFoundError("sudo configuration is unavailable")
            data = _sudo_config("\n".join(contents))
            data["source_count"] = len(contents)
        except FileNotFoundError:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name="sudo_configuration", category=category, status=ToolState.UNAVAILABLE
                )
            )
        except (OSError, ValueError) as exc:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name="sudo_configuration",
                    category=category,
                    status=ToolState.FAILED,
                    duration_seconds=time.monotonic() - started,
                    error=clean_text(exc, maximum=512),
                )
            )
        return NativeCheckResult(
            NativeCollectorStatus(
                name="sudo_configuration",
                category=category,
                status=ToolState.SUCCESS,
                duration_seconds=time.monotonic() - started,
                count=len(data),
            ),
            data,
        )


def _read_fixed_file(path: Path, *, maximum_bytes: int = 1024 * 1024) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError("security configuration source is not a regular file")
        if details.st_size > maximum_bytes:
            raise ValueError("security configuration source exceeds the size limit")
        data = os.read(descriptor, maximum_bytes + 1)
        if len(data) > maximum_bytes:
            raise ValueError("security configuration source exceeds the size limit")
        return data.decode("utf-8", errors="replace")
    finally:
        os.close(descriptor)


def _active_config_lines(output: str) -> list[str]:
    lines: list[str] = []
    for raw in output.splitlines()[:20_000]:
        line = raw.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


def _ssh_config(output: str) -> dict[str, str]:
    allowed = {
        "authenticationmethods",
        "kbdinteractiveauthentication",
        "passwordauthentication",
        "permitemptypasswords",
        "permitrootlogin",
        "pubkeyauthentication",
        "x11forwarding",
    }
    values: dict[str, str] = {}
    for line in _active_config_lines(output):
        key, _, value = line.partition(" ")
        key = key.casefold()
        if key == "match":
            break
        if key in allowed and key not in values:
            values[key] = clean_text(value, maximum=256)
    return values


def _keyed_config(output: str, allowed: set[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in _active_config_lines(output):
        key, separator, value = line.partition("=")
        if not separator:
            fields = line.split(maxsplit=1)
            if len(fields) != 2:
                continue
            key, value = fields
        normalized = key.strip().casefold()
        if normalized in allowed:
            values[normalized] = clean_text(value, maximum=256)
    return values


def _pwquality_config(output: str) -> dict[str, str]:
    return _keyed_config(
        output,
        {
            "dcredit",
            "dictcheck",
            "difok",
            "enforcing",
            "lcredit",
            "maxclassrepeat",
            "maxrepeat",
            "minlen",
            "ocredit",
            "retry",
            "ucredit",
            "usercheck",
        },
    )


def _login_defaults(output: str) -> dict[str, str]:
    return _keyed_config(
        output,
        {
            "encrypt_method",
            "fail_delay",
            "login_retries",
            "login_timeout",
            "pass_max_days",
            "pass_min_days",
            "pass_warn_age",
            "sha_crypt_max_rounds",
            "sha_crypt_min_rounds",
            "umask",
        },
    )


def _sudo_config(output: str) -> dict[str, int | bool]:
    lines = _active_config_lines(output)
    lowered = [line.casefold() for line in lines]
    return {
        "nopasswd_rule_count": sum("nopasswd:" in line for line in lowered),
        "authenticate_disabled": any("!authenticate" in line for line in lowered),
        "require_tty": any("requiretty" in line and "!requiretty" not in line for line in lowered),
        "use_pty": any("use_pty" in line and "!use_pty" not in line for line in lowered),
        "root_password_required": any("rootpw" in line for line in lowered),
        "target_password_required": any("targetpw" in line for line in lowered),
    }
