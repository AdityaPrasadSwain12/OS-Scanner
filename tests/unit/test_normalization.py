from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.models import (
    IPAddress,
    ListeningPort,
    NetworkInterface,
    NetworkProtocol,
    OperatingSystemFamily,
    Process,
    Service,
    ServiceState,
    Software,
)
from app.normalization import merge_inventory, normalize_amass, normalize_osquery


@dataclass
class Result:
    payload: list[dict[str, Any]]
    status: str | None = None


def test_osquery_normalization_isolates_invalid_rows() -> None:
    outcome = normalize_osquery(
        {
            "os_info": Result(
                [{"name": "Ubuntu", "version": "24.04", "platform": "linux", "arch": "x86_64"}]
            ),
            "system_info": Result([{"hostname": "host-1", "physical_memory": "1024"}]),
            "listening_ports": Result(
                [
                    {
                        "protocol": "tcp",
                        "local_address": "0.0.0.0",  # noqa: S104 - parser input, not a bind
                        "local_port": "443",
                        "pid": "2",
                    },
                    {"protocol": "tcp", "local_address": "not-an-ip", "local_port": "22"},
                ]
            ),
        }
    )
    assert outcome.data["os"].family is OperatingSystemFamily.LINUX
    assert outcome.data["hardware"].memory_bytes == 1024
    assert [port.port for port in outcome.data["listening_ports"]] == [443]
    assert outcome.warnings


def test_linux_rpm_and_systemd_rows_normalize_to_portable_models() -> None:
    outcome = normalize_osquery(
        {
            "os_info": Result(
                [{"name": "Rocky Linux", "version": "9.4", "platform": "rhel"}]
            ),
            "packages_rpm": Result(
                [
                    {
                        "name": "openssl-libs",
                        "version": "3.2.2",
                        "architecture": "x86_64",
                        "vendor": "Rocky Enterprise Software Foundation",
                    }
                ]
            ),
            "services_linux": Result(
                [
                    {
                        "name": "sshd.service",
                        "display_name": "OpenSSH server daemon",
                        "status": "active",
                        "start_type": "enabled",
                        "path": "/usr/lib/systemd/system/sshd.service",
                    }
                ]
            ),
        }
    )

    package = outcome.data["software"][0]
    service = outcome.data["services"][0]
    assert package.package_manager == "rpm"
    assert package.architecture == "x86_64"
    assert service.name == "sshd.service"
    assert service.state is ServiceState.RUNNING
    assert service.startup_type == "enabled"


def test_macos_apps_homebrew_and_launchd_rows_normalize_to_portable_models() -> None:
    outcome = normalize_osquery(
        {
            "os_info": Result(
                [{"name": "macOS", "version": "15.1", "platform": "darwin"}]
            ),
            "software_macos": Result(
                [
                    {
                        "name": "Example.app",
                        "version": "2.4",
                        "install_location": "/Applications/Example.app",
                    }
                ]
            ),
            "packages_homebrew": Result(
                [
                    {
                        "name": "jq",
                        "version": "1.7.1",
                        "install_location": "/opt/homebrew/Cellar/jq/1.7.1",
                    }
                ]
            ),
            "services_macos": Result(
                [
                    {
                        "name": "com.example.agent",
                        "display_name": "com.example.agent",
                        "status": "running",
                        "start_type": "automatic",
                        "path": "/Library/Example/agent",
                        "user_account": "root",
                    }
                ]
            ),
        }
    )

    assert outcome.data["os"].family is OperatingSystemFamily.MACOS
    assert [item.package_manager for item in outcome.data["software"]] == [
        "macos-app",
        "homebrew",
    ]
    service = outcome.data["services"][0]
    assert service.state is ServiceState.RUNNING
    assert service.service_account == "root"


def test_user_group_memberships_mark_cross_platform_administrators() -> None:
    outcome = normalize_osquery(
        {
            "users": Result(
                [
                    {"uid": "0", "username": "root"},
                    {"uid": "1001", "username": "alice"},
                    {"uid": "1002", "username": "guest"},
                ]
            ),
            "groups": Result(
                [
                    {"gid": "27", "groupname": "sudo"},
                    {"gid": "100", "groupname": "users"},
                ]
            ),
            "user_groups": Result(
                [
                    {"uid": "1001", "gid": "27"},
                    {"uid": "1001", "gid": "100"},
                    {"uid": "1002", "gid": "100"},
                ]
            ),
        }
    )

    users = {item.username: item for item in outcome.data["users"]}
    assert users["root"].is_administrator is True
    assert users["alice"].is_administrator is True
    assert users["alice"].groups == {"sudo", "users"}
    assert users["guest"].is_administrator is False
    assert users["guest"].is_guest is True


def test_routes_dns_and_mounts_enrich_network_and_disk_inventory() -> None:
    outcome = normalize_osquery(
        {
            "system_info": Result([{"hostname": "host-1", "physical_memory": "4096"}]),
            "mounts": Result(
                [
                    {
                        "device": "/dev/nvme0n1p2",
                        "path": "/",
                        "type": "ext4",
                        "blocks": "1000",
                        "blocks_size": "4096",
                        "blocks_free": "250",
                    }
                ]
            ),
            "interfaces": Result(
                [
                    {
                        "interface": "eth0",
                        "address": "192.0.2.20",
                        "mask": "255.255.255.0",
                        "mac": "AA-BB-CC-DD-EE-FF",
                        "type": "ethernet",
                    }
                ]
            ),
            "routes": Result(
                [
                    {
                        "destination": "0.0.0.0",  # noqa: S104 - observed route
                        "interface": "eth0",
                        "gateway": "192.0.2.1",
                    }
                ]
            ),
            "dns_resolvers": Result(
                [{"address": "1.1.1.1"}, {"address": "2001:4860:4860::8888"}]
            ),
        }
    )

    disk = outcome.data["hardware"].disks[0]
    interface = outcome.data["network_interfaces"][0]
    assert disk.capacity_bytes == 4_096_000
    assert disk.free_bytes == 1_024_000
    assert interface.addresses[0].prefix_length == 24
    assert interface.gateways == ["192.0.2.1"]
    assert interface.dns_servers == ["1.1.1.1", "2001:4860:4860::8888"]


def test_osquery_enriches_endpoint_identity_hardware_and_windows_network() -> None:
    outcome = normalize_osquery(
        {
            "os_info": Result(
                [
                    {
                        "name": "Windows 11 Enterprise",
                        "version": "10.0",
                        "build": "26100",
                        "platform": "windows",
                        "arch": "x86_64",
                    }
                ]
            ),
            "system_info": Result(
                [
                    {
                        "hostname": "enterprise-ws-01",
                        "machine_id": "machine-123",
                        "cpu_brand": "Contoso Secure CPU",
                        "cpu_physical_cores": "8",
                        "cpu_logical_cores": "16",
                        "physical_memory": "34359738368",
                        "hardware_vendor": "Contoso",
                        "hardware_model": "Workstation Pro",
                        "board_vendor": "Contoso",
                        "board_model": "Board-X",
                        "board_version": "rev1",
                    }
                ]
            ),
            "cpu_info": Result([{"manufacturer": "AuthenticAMD", "model": "Model 1"}]),
            "kernel_info": Result([{"version": "10.0.26100.3194"}]),
            "time_info": Result([{"local_timezone": "Asia/Kolkata"}]),
            "platform_info": Result(
                [
                    {
                        "version": "2.7",
                        "revision": "A1",
                        "firmware_type": "UEFI",
                    }
                ]
            ),
            "video_info": Result(
                [{"manufacturer": "NVIDIA", "model": "RTX Enterprise"}]
            ),
            "tpm_info": Result(
                [
                    {
                        "enabled": "1",
                        "manufacturer_name": "IFX",
                        "spec_version": "2.0",
                    }
                ]
            ),
            "secure_boot": Result([{"secure_boot": "1"}]),
            "interfaces": Result(
                [
                    {
                        "interface": "Ethernet 1",
                        "address": "192.0.2.20",
                        "mask": "255.255.255.0",
                        "mac": "00-11-22-33-44-55",
                    }
                ]
            ),
            "interfaces_windows": Result(
                [
                    {
                        "interface": "Ethernet 1",
                        "enabled": "1",
                        "connection_status": "2",
                        "dhcp_enabled": "true",
                        "dns_server_search_order": "1.1.1.1; 8.8.8.8",
                    }
                ]
            ),
        }
    )

    operating_system = outcome.data["os"]
    hardware = outcome.data["hardware"]
    interface = outcome.data["network_interfaces"][0]
    assert outcome.data["hostname"] == "enterprise-ws-01"
    assert operating_system.machine_id == "machine-123"
    assert operating_system.kernel == "10.0.26100.3194"
    assert operating_system.timezone == "Asia/Kolkata"
    assert hardware.cpu.vendor == "AuthenticAMD"
    assert hardware.cpu.model == "Contoso Secure CPU"
    assert hardware.cpu.physical_cores == 8
    assert hardware.cpu.logical_processors == 16
    assert hardware.gpus[0].model == "RTX Enterprise"
    assert hardware.motherboard == "Contoso Board-X rev1"
    assert hardware.bios_uefi == "UEFI"
    assert hardware.firmware_version == "2.7 A1"
    assert hardware.manufacturer == "Contoso"
    assert hardware.device_model == "Workstation Pro"
    assert hardware.tpm_present is True
    assert hardware.tpm_version == "2.0"
    assert outcome.data["security"].secure_boot_enabled is True
    assert interface.is_up is True
    assert interface.dhcp_enabled is True
    assert interface.dns_servers == ["1.1.1.1", "8.8.8.8"]


def test_windows_interface_state_and_dhcp_lease_metadata_are_validated() -> None:
    outcome = normalize_osquery(
        {
            "interfaces_windows": Result(
                [
                    {
                        "interface": "Enabled Without Link State",
                        "enabled": "1",
                        "dhcp_enabled": "false",
                    },
                    {
                        "interface": "Connected DHCP",
                        "enabled": "1",
                        "connection_status": "2",
                        "dhcp_enabled": "true",
                        "dhcp_server": "192.0.2.254",
                        "dhcp_lease_obtained": "20260830120000.000000+330",
                        "dhcp_lease_expires": "20260830180000.000000+330",
                    },
                    {
                        "interface": "Disconnected",
                        "enabled": "1",
                        "connection_status": "7",
                    },
                    {
                        "interface": "Disabled",
                        "enabled": "0",
                        "connection_status": "2",
                    },
                    {
                        "interface": "Invalid DHCP",
                        "enabled": "1",
                        "connection_status": "2",
                        "dhcp_enabled": "true",
                        "dhcp_server": "not-an-ip",
                        "dhcp_lease_obtained": "20260830180000.000000+330",
                        "dhcp_lease_expires": "20260830120000.000000+330",
                    },
                ]
            )
        }
    )

    interfaces = {item.name: item for item in outcome.data["network_interfaces"]}
    assert interfaces["Enabled Without Link State"].is_up is None
    connected = interfaces["Connected DHCP"]
    assert connected.is_up is True
    assert connected.dhcp_server == "192.0.2.254"
    assert connected.dhcp_lease_obtained.isoformat() == "2026-08-30T06:30:00+00:00"
    assert connected.dhcp_lease_expires.isoformat() == "2026-08-30T12:30:00+00:00"
    assert interfaces["Disconnected"].is_up is False
    assert interfaces["Disabled"].is_up is False
    invalid = interfaces["Invalid DHCP"]
    assert invalid.dhcp_server is None
    assert invalid.dhcp_lease_obtained is None
    assert invalid.dhcp_lease_expires is None
    assert "invalid DHCP lease window" in " ".join(outcome.warnings)


def test_posix_interface_flags_and_unknown_address_origin_are_tri_state() -> None:
    outcome = normalize_osquery(
        {
            "interfaces": Result(
                [
                    {
                        "interface": "eth0",
                        "address": "192.0.2.20",
                        "mask": "24",
                        "flags": "1",
                        "host_platform": "linux",
                        "address_type": "unknown",
                    }
                ]
            )
        }
    )

    interface = outcome.data["network_interfaces"][0]
    assert interface.is_up is True
    assert interface.dhcp_enabled is None


def test_linux_shadow_status_reports_active_expired_and_locked_accounts_safely() -> None:
    outcome = normalize_osquery(
        {
            "users": Result(
                [
                    {"uid": "1001", "username": "active-user"},
                    {"uid": "1002", "username": "expired-user"},
                    {"uid": "1003", "username": "locked-user"},
                ]
            ),
            "account_status_linux": Result(
                [
                    {"username": "active-user", "password_status": "active", "expire": "-1"},
                    {"username": "expired-user", "password_status": "active", "expire": "1"},
                    {"username": "locked-user", "password_status": "locked", "expire": "-1"},
                ]
            ),
        }
    )

    users = {item.username: item for item in outcome.data["users"]}
    assert users["active-user"].enabled is True
    assert users["expired-user"].enabled is False
    assert users["locked-user"].enabled is None


def test_osquery_enriches_install_dates_process_owners_and_last_login() -> None:
    outcome = normalize_osquery(
        {
            "packages_rpm": Result(
                [
                    {
                        "name": "openssl-libs",
                        "version": "3.2.2",
                        "install_time": "2026-08-30T08:30:00Z",
                    }
                ]
            ),
            "users": Result(
                [{"uid": "1001", "gid": "1001", "username": "alice"}]
            ),
            "last_logins": Result(
                [
                    {"username": "alice", "type_name": "user", "time": "1700000000"},
                    {"username": "alice", "type_name": "user", "time": "1800000000"},
                    {"username": "alice", "type_name": "boot", "time": "1900000000"},
                ]
            ),
            "processes": Result(
                [
                    {
                        "pid": "42",
                        "parent": "1",
                        "name": "enterprise-agent",
                        "path": "/opt/enterprise/agent",
                        "uid": "1001",
                        "start_time": "1800000000",
                        "resident_size": "4096",
                    }
                ]
            ),
        }
    )

    assert outcome.data["software"][0].installation_date.isoformat() == "2026-08-30"
    assert outcome.data["processes"][0].user == "alice"
    assert outcome.data["users"][0].last_login.timestamp() == 1_800_000_000


def test_failed_queries_do_not_publish_false_empty_inventory() -> None:
    failed = normalize_osquery({"software": Result([], status="FAILED")})
    unavailable = normalize_osquery({"software": Result([], status="UNAVAILABLE")})
    successful_empty = normalize_osquery({"software": Result([], status="SUCCESS")})

    assert "software" not in failed.data
    assert "software" not in unavailable.data
    assert successful_empty.data["software"] == []


def test_partially_failed_grouped_queries_do_not_publish_incomplete_inventory() -> None:
    outcome = normalize_osquery(
        {
            "interfaces": Result(
                [{"interface": "eth0", "address": "192.0.2.20", "mask": "24"}],
                status="SUCCESS",
            ),
            "routes": Result([], status="FAILED"),
        }
    )

    assert "network_interfaces" not in outcome.data


def test_only_default_routes_become_interface_gateways() -> None:
    outcome = normalize_osquery(
        {
            "interfaces": Result(
                [{"interface": "eth0", "address": "192.0.2.20", "mask": "24"}]
            ),
            "routes": Result(
                [
                    {
                        "destination": "0.0.0.0",  # noqa: S104 - observed route
                        "netmask": "0.0.0.0",  # noqa: S104 - observed route
                        "interface": "eth0",
                        "gateway": "192.0.2.1",
                    },
                    {
                        "destination": "198.51.100.0",
                        "netmask": "255.255.255.0",
                        "interface": "eth0",
                        "gateway": "192.0.2.254",
                    },
                ]
            ),
        }
    )

    assert outcome.data["network_interfaces"][0].gateways == ["192.0.2.1"]


def test_merge_inventory_deduplicates_lists() -> None:
    assert merge_inventory(
        {"software": [{"name": "A"}]},
        {"software": [{"name": "A"}, {"name": "B"}]},
    ) == {
        "software": [{"name": "A"}, {"name": "B"}]
    }


def test_merge_inventory_enriches_same_software_across_sources() -> None:
    merged = merge_inventory(
        {
            "software": [
                Software(
                    name="Example Agent",
                    version="2.4.1",
                    architecture="x86_64",
                    vendor="Native vendor",
                    source="native",
                )
            ]
        },
        {
            "software": [
                Software(
                    name="Example Agent",
                    version="2.4.1",
                    architecture="x86_64",
                    vendor="Enriched vendor",
                    source="osquery",
                )
            ]
        },
    )

    assert len(merged["software"]) == 1
    assert merged["software"][0] == Software(
        name="Example Agent",
        version="2.4.1",
        architecture="x86_64",
        vendor="Enriched vendor",
        source="osquery",
    )


def test_merge_inventory_keeps_distinct_software_versions() -> None:
    merged = merge_inventory(
        {"software": [Software(name="Example Agent", version="1.0")]},
        {"software": [Software(name="Example Agent", version="2.0")]},
    )

    assert [item.version for item in merged["software"]] == ["1.0", "2.0"]


def test_merge_inventory_enriches_process_service_and_interface_in_place() -> None:
    merged = merge_inventory(
        {
            "processes": [Process(pid=42, name="agent")],
            "services": [Service(name="AgentService", display_name="Agent")],
            "network_interfaces": [
                NetworkInterface(
                    name="Ethernet",
                    addresses=[IPAddress(address="192.0.2.10")],
                )
            ],
        },
        {
            "processes": [Process(pid=42, name="agent", user="SYSTEM")],
            "services": [Service(name="agentservice", startup_type="automatic")],
            "network_interfaces": [
                NetworkInterface(
                    name="ethernet",
                    mac_address="00:11:22:33:44:55",
                    addresses=[IPAddress(address="192.0.2.10", prefix_length=24)],
                )
            ],
        },
    )

    assert len(merged["processes"]) == 1
    assert merged["processes"][0].user == "SYSTEM"
    assert len(merged["services"]) == 1
    assert merged["services"][0].startup_type == "automatic"
    assert len(merged["network_interfaces"]) == 1
    assert merged["network_interfaces"][0].mac_address == "00:11:22:33:44:55"
    assert merged["network_interfaces"][0].addresses == [
        IPAddress(address="192.0.2.10", prefix_length=24)
    ]


def test_merge_inventory_uses_socket_tuple_as_listener_identity() -> None:
    merged = merge_inventory(
        {
            "listening_ports": [
                ListeningPort(
                    protocol=NetworkProtocol.TCP,
                    address="0.0.0.0",  # noqa: S104 - observed listener
                    port=443,
                )
            ]
        },
        {
            "listening_ports": [
                ListeningPort(
                    protocol=NetworkProtocol.TCP,
                    address="0.0.0.0",  # noqa: S104 - observed listener
                    port=443,
                    pid=42,
                    process="agent",
                ),
                ListeningPort(
                    protocol=NetworkProtocol.TCP,
                    address="127.0.0.1",
                    port=443,
                    pid=42,
                ),
                ListeningPort(
                    protocol=NetworkProtocol.UDP,
                    address="0.0.0.0",  # noqa: S104 - observed listener
                    port=443,
                    pid=42,
                ),
            ]
        },
    )

    assert len(merged["listening_ports"]) == 3
    assert merged["listening_ports"][0].pid == 42
    assert [item.protocol for item in merged["listening_ports"]] == [
        NetworkProtocol.TCP,
        NetworkProtocol.TCP,
        NetworkProtocol.UDP,
    ]


def test_merge_inventory_preserves_order_for_duplicate_model_rows() -> None:
    merged = merge_inventory(
        {
            "software": [
                Software(name="First", version="1"),
                Software(name="Second", version="1"),
            ]
        },
        {
            "software": [
                Software(name="first", version="1", vendor="enriched"),
                Software(name="Third", version="1"),
            ]
        },
    )

    assert [item.name for item in merged["software"]] == ["first", "Second", "Third"]
    assert merged["software"][0].vendor == "enriched"


def test_amass_normalizer_drops_out_of_scope_assets() -> None:
    assets, warnings = normalize_amass(
        [{"hostname": "api.example.test"}, {"hostname": "outside.test"}],
        scan_id="scan-1",
        root_domain="example.test",
    )
    assert [asset.hostname for asset in assets] == ["api.example.test"]
    assert warnings
