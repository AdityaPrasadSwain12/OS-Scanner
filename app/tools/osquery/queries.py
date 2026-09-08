"""Immutable, platform-aware scanner-owned osquery registry.

Remote jobs select identifiers from this registry; they never supply SQL. The
platform metadata prevents a query from being sent to an endpoint on which the
referenced osquery table does not exist.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

ALL_PLATFORMS: Final[frozenset[str]] = frozenset({"windows", "linux", "macos"})
WINDOWS: Final[frozenset[str]] = frozenset({"windows"})
LINUX: Final[frozenset[str]] = frozenset({"linux"})
MACOS: Final[frozenset[str]] = frozenset({"macos"})
POSIX: Final[frozenset[str]] = frozenset({"linux", "macos"})
_IDENTIFIER_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True, slots=True)
class QueryDefinition:
    identifier: str
    category: str
    sql: str
    maximum_rows: int = 10_000
    platforms: frozenset[str] = ALL_PLATFORMS
    batch_columns: tuple[str, ...] = ()
    cache_ttl_seconds: float = 0.0

    def __post_init__(self) -> None:
        """Reject definitions that cannot be composed into controlled SQL safely."""

        if not _IDENTIFIER_PATTERN.fullmatch(self.identifier):
            raise ValueError("osquery query identifiers must be simple SQL identifiers")
        if not self.category or len(self.category) > 128:
            raise ValueError("osquery query categories must contain 1-128 characters")
        sql = self.sql.strip()
        if "\x00" in sql or not sql.casefold().startswith(("select ", "with ")):
            raise ValueError("osquery registry entries must contain a SELECT statement")
        if ";" in sql[:-1] or (";" in sql and not sql.endswith(";")):
            raise ValueError("osquery registry entries must contain one statement")
        if not 1 <= self.maximum_rows <= 100_000:
            raise ValueError("osquery row limits must be between 1 and 100000")
        if not self.platforms or not self.platforms <= ALL_PLATFORMS:
            raise ValueError("osquery platforms must be a non-empty supported subset")
        if len(set(self.batch_columns)) != len(self.batch_columns) or any(
            not _IDENTIFIER_PATTERN.fullmatch(column) for column in self.batch_columns
        ):
            raise ValueError("osquery batch columns must be unique simple SQL identifiers")
        if self.batch_columns and self.maximum_rows != 1:
            raise ValueError("only singleton osquery queries can use scalar batching")
        if not 0 <= self.cache_ttl_seconds <= 3600:
            raise ValueError("osquery cache TTL must be between 0 and 3600 seconds")


_QUERIES: Final[dict[str, QueryDefinition]] = {
    "os_info": QueryDefinition(
        "os_info",
        "operating_system",
        "SELECT name, version, major, minor, patch, build, platform, arch FROM os_version;",
        1,
        batch_columns=("name", "version", "major", "minor", "patch", "build", "platform", "arch"),
    ),
    "system_info": QueryDefinition(
        "system_info",
        "hardware",
        "SELECT hostname, uuid AS machine_id, cpu_brand, cpu_physical_cores, "
        "cpu_logical_cores, "
        "physical_memory, hardware_vendor, hardware_model, hardware_version, "
        "hardware_serial, board_vendor, board_model, board_version, board_serial "
        "FROM system_info;",
        1,
        batch_columns=(
            "hostname",
            "machine_id",
            "cpu_brand",
            "cpu_physical_cores",
            "cpu_logical_cores",
            "physical_memory",
            "hardware_vendor",
            "hardware_model",
            "hardware_version",
            "hardware_serial",
            "board_vendor",
            "board_model",
            "board_version",
            "board_serial",
        ),
    ),
    "cpu_info": QueryDefinition(
        "cpu_info",
        "hardware",
        "SELECT manufacturer, model FROM cpu_info;",
        64,
        cache_ttl_seconds=300,
    ),
    "kernel_info": QueryDefinition(
        "kernel_info",
        "operating_system",
        "SELECT version FROM kernel_info;",
        1,
        batch_columns=("version",),
    ),
    "time_info": QueryDefinition(
        "time_info",
        "operating_system",
        "SELECT local_timezone FROM time;",
        1,
        batch_columns=("local_timezone",),
    ),
    "platform_info": QueryDefinition(
        "platform_info",
        "hardware",
        "SELECT vendor, version, date, revision, firmware_type FROM platform_info;",
        1,
        batch_columns=("vendor", "version", "date", "revision", "firmware_type"),
        cache_ttl_seconds=300,
    ),
    "video_info": QueryDefinition(
        "video_info",
        "hardware",
        "SELECT manufacturer, model, series, driver, driver_version FROM video_info;",
        32,
        WINDOWS,
        cache_ttl_seconds=300,
    ),
    "pci_devices": QueryDefinition(
        "pci_devices",
        "hardware",
        "SELECT pci_class, driver, vendor, vendor_id, model, model_id FROM pci_devices;",
        10_000,
        POSIX,
        cache_ttl_seconds=300,
    ),
    "tpm_info": QueryDefinition(
        "tpm_info",
        "hardware",
        "SELECT activated, enabled, manufacturer_version, manufacturer_name, "
        "product_name, spec_version FROM tpm_info;",
        1,
        WINDOWS,
        batch_columns=(
            "activated",
            "enabled",
            "manufacturer_version",
            "manufacturer_name",
            "product_name",
            "spec_version",
        ),
    ),
    "secure_boot": QueryDefinition(
        "secure_boot",
        "security_posture",
        "SELECT secure_boot FROM secureboot;",
        1,
        batch_columns=("secure_boot",),
    ),
    "uptime": QueryDefinition(
        "uptime",
        "operating_system",
        "SELECT days, hours, minutes, seconds, total_seconds, "
        "(SELECT unix_time FROM time LIMIT 1) - total_seconds AS boot_time "
        "FROM uptime;",
        1,
        batch_columns=("days", "hours", "minutes", "seconds", "total_seconds", "boot_time"),
    ),
    "software": QueryDefinition(
        "software",
        "software",
        "SELECT name, version, publisher, install_location, install_date FROM programs;",
        platforms=WINDOWS,
    ),
    "software_macos": QueryDefinition(
        "software_macos",
        "software",
        "SELECT name, bundle_short_version AS version, path AS install_location FROM apps;",
        platforms=MACOS,
    ),
    "packages": QueryDefinition(
        "packages",
        "software",
        "SELECT name, version, arch AS architecture, source, maintainer AS vendor "
        "FROM deb_packages;",
        platforms=LINUX,
    ),
    "packages_rpm": QueryDefinition(
        "packages_rpm",
        "software",
        "SELECT name, version, arch AS architecture, source, vendor, install_time "
        "FROM rpm_packages;",
        platforms=LINUX,
    ),
    "packages_homebrew": QueryDefinition(
        "packages_homebrew",
        "software",
        "SELECT name, version, path AS install_location FROM homebrew_packages;",
        platforms=MACOS,
    ),
    "processes": QueryDefinition(
        "processes",
        "processes",
        "SELECT pid, parent, name, path, uid, gid, start_time, resident_size FROM processes;",
    ),
    "services": QueryDefinition(
        "services",
        "services",
        "SELECT name, display_name, status, start_type, path, user_account FROM services;",
        platforms=WINDOWS,
    ),
    "services_linux": QueryDefinition(
        "services_linux",
        "services",
        "SELECT id AS name, description AS display_name, active_state AS status, "
        "unit_file_state AS start_type, fragment_path AS path FROM systemd_units "
        "WHERE id LIKE '%.service';",
        platforms=LINUX,
    ),
    "services_macos": QueryDefinition(
        "services_macos",
        "services",
        "SELECT label AS name, label AS display_name, "
        "'' AS status, CASE WHEN lower(CAST(disabled AS TEXT)) IN ('1','true','yes') "
        "THEN 'disabled' WHEN lower(CAST(run_at_load AS TEXT)) IN ('1','true','yes') "
        "THEN 'automatic' ELSE 'manual' END AS start_type, "
        "program AS path, username AS user_account FROM launchd;",
        platforms=MACOS,
    ),
    "users": QueryDefinition(
        "users",
        "users",
        "SELECT uid, gid, uuid, username, description, directory, shell FROM users;",
    ),
    "last_logins": QueryDefinition(
        "last_logins",
        "users",
        "SELECT username, type_name, time FROM last;",
        10_000,
        POSIX,
    ),
    "account_status_linux": QueryDefinition(
        "account_status_linux",
        "users",
        "SELECT username, password_status, expire FROM shadow;",
        10_000,
        LINUX,
    ),
    "groups": QueryDefinition(
        "groups",
        "groups",
        "SELECT gid, groupname FROM groups;",
    ),
    "user_groups": QueryDefinition(
        "user_groups",
        "groups",
        "SELECT uid, gid FROM user_groups;",
    ),
    "interfaces": QueryDefinition(
        "interfaces",
        "network_interfaces",
        "SELECT ia.interface, ia.address, ia.mask, ia.broadcast, ia.point_to_point, "
        "ia.type AS address_type, id.mac, id.type, id.mtu, id.metric, id.flags, "
        "(SELECT platform FROM os_version LIMIT 1) AS host_platform "
        "FROM interface_addresses ia "
        "LEFT JOIN interface_details id ON ia.interface = id.interface;",
    ),
    "interfaces_windows": QueryDefinition(
        "interfaces_windows",
        "network_interfaces",
        "SELECT interface, enabled, connection_status, dhcp_enabled, dhcp_server, "
        "dhcp_lease_obtained, dhcp_lease_expires, dns_server_search_order "
        "FROM interface_details;",
        platforms=WINDOWS,
    ),
    "routes": QueryDefinition(
        "routes",
        "network_interfaces",
        "SELECT destination, netmask, gateway, interface, metric, type FROM routes;",
    ),
    "dns_resolvers": QueryDefinition(
        "dns_resolvers",
        "network_interfaces",
        "SELECT address FROM dns_resolvers;",
        platforms=POSIX,
    ),
    "mounts": QueryDefinition(
        "mounts",
        "hardware",
        "SELECT device, path, type, blocks, blocks_size, blocks_free FROM mounts;",
        platforms=POSIX,
    ),
    "logical_drives": QueryDefinition(
        "logical_drives",
        "hardware",
        "SELECT device_id, type, description, free_space, size, file_system FROM logical_drives;",
        platforms=WINDOWS,
    ),
    "listening_ports": QueryDefinition(
        "listening_ports",
        "listening_ports",
        "SELECT protocol, address AS local_address, port AS local_port, pid FROM listening_ports;",
    ),
    "startup_items": QueryDefinition(
        "startup_items",
        "persistence",
        "SELECT name, path, source, status, type FROM startup_items;",
    ),
    "scheduled_tasks_windows": QueryDefinition(
        "scheduled_tasks_windows",
        "persistence",
        "SELECT name, path, action, enabled, state FROM scheduled_tasks;",
        platforms=WINDOWS,
    ),
    "crontab": QueryDefinition(
        "crontab",
        "persistence",
        "SELECT event, command, path FROM crontab;",
        platforms=POSIX,
    ),
    "browser_extensions": QueryDefinition(
        "browser_extensions",
        "browser_extensions",
        "SELECT browser_type, uid, name, identifier, version, update_url "
        "FROM users CROSS JOIN chrome_extensions USING (uid);",
    ),
    "browser_extensions_firefox": QueryDefinition(
        "browser_extensions_firefox",
        "browser_extensions",
        "SELECT uid, name, identifier, version, active, source_url "
        "FROM users CROSS JOIN firefox_addons USING (uid);",
    ),
    "browser_extensions_safari": QueryDefinition(
        "browser_extensions_safari",
        "browser_extensions",
        "SELECT uid, name, identifier, version, path FROM safari_extensions;",
        platforms=MACOS,
    ),
}

DEFAULT_QUERY_REGISTRY: Mapping[str, QueryDefinition] = MappingProxyType(_QUERIES)
