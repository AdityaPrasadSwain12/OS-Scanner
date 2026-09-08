"""Normalized endpoint inventory and posture models."""

from __future__ import annotations

import ipaddress
import re
from datetime import date, datetime
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator

from .base import JsonValue, StrictModel, bounded_json, ensure_aware
from .enums import NetworkProtocol, OperatingSystemFamily, ServiceState

ShortText = Annotated[str, Field(min_length=1, max_length=512)]


def _redact_command_field(value: str | None) -> str | None:
    """Redact credentials while retaining the executable and non-secret arguments."""

    if value is None:
        return None
    from app.security.redaction import redact_command_line

    redacted = redact_command_line(value)
    # A string input is guaranteed to retain its string shape.
    return redacted if isinstance(redacted, str) else " ".join(redacted)


class Endpoint(StrictModel):
    endpoint_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    ]
    hostname: ShortText
    os_family: OperatingSystemFamily = OperatingSystemFamily.UNKNOWN
    display_name: str | None = Field(default=None, max_length=512)
    machine_id: str | None = Field(default=None, max_length=512)
    manufacturer: str | None = Field(default=None, max_length=256)
    model: str | None = Field(default=None, max_length=256)
    asset_criticality: float = Field(default=0.5, ge=0.0, le=1.0)
    tags: set[str] = Field(default_factory=set, max_length=100)
    last_seen_at: datetime | None = None

    @field_validator("last_seen_at")
    @classmethod
    def aware_last_seen(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None

    @field_validator("tags")
    @classmethod
    def bounded_tags(cls, value: set[str]) -> set[str]:
        if any(not tag or len(tag) > 64 for tag in value):
            raise ValueError("tags must contain 1-64 character strings")
        return value


class OperatingSystem(StrictModel):
    family: OperatingSystemFamily
    name: ShortText
    version: str = Field(min_length=1, max_length=128)
    build: str | None = Field(default=None, max_length=128)
    kernel: str | None = Field(default=None, max_length=256)
    architecture: str | None = Field(default=None, max_length=64)
    hostname: str | None = Field(default=None, max_length=512)
    machine_id: str | None = Field(default=None, max_length=512)
    boot_time: datetime | None = None
    uptime_seconds: int | None = Field(default=None, ge=0)
    timezone: str | None = Field(default=None, max_length=128)
    installed_at: datetime | None = None
    domain: str | None = Field(default=None, max_length=512)
    supported: bool | None = None

    @field_validator("boot_time", "installed_at")
    @classmethod
    def aware_os_time(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None


class CPU(StrictModel):
    vendor: str | None = Field(default=None, max_length=256)
    model: str | None = Field(default=None, max_length=512)
    physical_cores: int | None = Field(default=None, ge=1, le=65_536)
    logical_processors: int | None = Field(default=None, ge=1, le=65_536)
    architecture: str | None = Field(default=None, max_length=64)


class Disk(StrictModel):
    name: ShortText
    mount_point: str | None = Field(default=None, max_length=4096)
    capacity_bytes: int | None = Field(default=None, ge=0)
    free_bytes: int | None = Field(default=None, ge=0)
    disk_type: str | None = Field(default=None, max_length=64)
    encrypted: bool | None = None
    serial_number: str | None = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def free_does_not_exceed_capacity(self) -> Disk:
        if (
            self.capacity_bytes is not None
            and self.free_bytes is not None
            and self.free_bytes > self.capacity_bytes
        ):
            raise ValueError("free_bytes cannot exceed capacity_bytes")
        return self


class GPU(StrictModel):
    vendor: str | None = Field(default=None, max_length=256)
    model: ShortText
    memory_bytes: int | None = Field(default=None, ge=0)


class Hardware(StrictModel):
    cpu: CPU | None = None
    memory_bytes: int | None = Field(default=None, ge=0)
    disks: list[Disk] = Field(default_factory=list, max_length=256)
    gpus: list[GPU] = Field(default_factory=list, max_length=32)
    motherboard: str | None = Field(default=None, max_length=512)
    bios_uefi: str | None = Field(default=None, max_length=512)
    firmware_version: str | None = Field(default=None, max_length=256)
    firmware_release_date: datetime | None = None
    manufacturer: str | None = Field(default=None, max_length=256)
    device_model: str | None = Field(default=None, max_length=256)
    tpm_present: bool | None = None
    tpm_version: str | None = Field(default=None, max_length=64)

    @field_validator("firmware_release_date")
    @classmethod
    def aware_firmware_release_date(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None


class Software(StrictModel):
    name: ShortText
    version: str | None = Field(default=None, max_length=256)
    vendor: str | None = Field(default=None, max_length=512)
    installation_path: str | None = Field(default=None, max_length=4096)
    installation_date: date | None = None
    package_manager: str | None = Field(default=None, max_length=128)
    architecture: str | None = Field(default=None, max_length=64)
    source: str | None = Field(default=None, max_length=256)
    package_id: str | None = Field(default=None, max_length=512)


class Process(StrictModel):
    pid: int = Field(ge=0)
    name: ShortText
    executable_path: str | None = Field(default=None, max_length=4096)
    parent_pid: int | None = Field(default=None, ge=0)
    user: str | None = Field(default=None, max_length=512)
    start_time: datetime | None = None
    cpu_percent: float | None = Field(default=None, ge=0)
    memory_bytes: int | None = Field(default=None, ge=0)
    command_line: str | None = Field(default=None, max_length=16_384)

    @field_validator("start_time")
    @classmethod
    def aware_start_time(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None

    @field_validator("command_line")
    @classmethod
    def redact_process_command_line(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from app.security.redaction import redact_text

        return redact_text(value)


class Service(StrictModel):
    name: ShortText
    display_name: str | None = Field(default=None, max_length=512)
    state: ServiceState = ServiceState.UNKNOWN
    startup_type: str | None = Field(default=None, max_length=128)
    executable_path: str | None = Field(default=None, max_length=4096)
    service_account: str | None = Field(default=None, max_length=512)
    security_relevant: bool = False
    suspicious: bool = False

    @field_validator("executable_path")
    @classmethod
    def redact_service_command(cls, value: str | None) -> str | None:
        return _redact_command_field(value)


class User(StrictModel):
    username: ShortText
    uid: str | None = Field(default=None, max_length=128)
    enabled: bool | None = None
    groups: set[str] = Field(default_factory=set, max_length=512)
    is_administrator: bool = False
    is_guest: bool = False
    last_login: datetime | None = None
    password_required: bool | None = None
    password_expires: datetime | None = None
    user_may_change_password: bool | None = None

    @field_validator("last_login", "password_expires")
    @classmethod
    def aware_last_login(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None

    @field_validator("groups")
    @classmethod
    def validate_groups(cls, value: set[str]) -> set[str]:
        if any(not group or len(group) > 256 for group in value):
            raise ValueError("group names must contain 1-256 characters")
        return value


class IPAddress(StrictModel):
    address: str
    prefix_length: int | None = Field(default=None, ge=0, le=128)
    family: int | None = Field(default=None)

    @model_validator(mode="after")
    def normalize_address(self) -> IPAddress:
        parsed = ipaddress.ip_address(self.address)
        object.__setattr__(self, "address", parsed.compressed)
        object.__setattr__(self, "family", parsed.version)
        maximum = 32 if parsed.version == 4 else 128
        if self.prefix_length is not None and self.prefix_length > maximum:
            raise ValueError(f"prefix_length exceeds IPv{parsed.version} maximum")
        return self


class NetworkInterface(StrictModel):
    name: ShortText
    mac_address: str | None = None
    addresses: list[IPAddress] = Field(default_factory=list, max_length=256)
    gateways: list[str] = Field(default_factory=list, max_length=32)
    dns_servers: list[str] = Field(default_factory=list, max_length=32)
    dhcp_enabled: bool | None = None
    dhcp_server: str | None = Field(default=None, max_length=128)
    dhcp_lease_obtained: datetime | None = None
    dhcp_lease_expires: datetime | None = None
    is_up: bool | None = None
    is_vpn: bool = False

    @field_validator("mac_address")
    @classmethod
    def normalize_mac(cls, value: str | None) -> str | None:
        if value is None:
            return None
        compact = re.sub(r"[^0-9A-Fa-f]", "", value)
        if len(compact) != 12:
            raise ValueError("invalid MAC address")
        return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).lower()

    @field_validator("gateways", "dns_servers")
    @classmethod
    def normalize_ips(cls, values: list[str]) -> list[str]:
        return [ipaddress.ip_address(value).compressed for value in values]

    @field_validator("dhcp_server")
    @classmethod
    def normalize_dhcp_server(cls, value: str | None) -> str | None:
        return ipaddress.ip_address(value).compressed if value else None

    @field_validator("dhcp_lease_obtained", "dhcp_lease_expires")
    @classmethod
    def aware_dhcp_lease(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None

    @model_validator(mode="after")
    def validate_dhcp_lease_window(self) -> NetworkInterface:
        if (
            self.dhcp_lease_obtained is not None
            and self.dhcp_lease_expires is not None
            and self.dhcp_lease_expires < self.dhcp_lease_obtained
        ):
            raise ValueError("DHCP lease expiry cannot precede lease acquisition")
        return self


class ListeningPort(StrictModel):
    protocol: NetworkProtocol
    address: str
    port: int = Field(ge=0, le=65_535)
    pid: int | None = Field(default=None, ge=0)
    process: str | None = Field(default=None, max_length=512)
    exposed: bool | None = None
    bind_scope: Literal["LOOPBACK", "WILDCARD", "INTERFACE", "UNKNOWN"] = "UNKNOWN"
    remote_reachability: Literal["NOT_TESTED"] = "NOT_TESTED"
    suspicious: bool = False

    @field_validator("address")
    @classmethod
    def normalize_listener(cls, value: str) -> str:
        if value in {"*", "any"}:
            return "0.0.0.0"  # noqa: S104 - normalized observed listener binding
        return ipaddress.ip_address(value.split("%", 1)[0]).compressed

    @model_validator(mode="after")
    def derive_local_bind_scope(self) -> ListeningPort:
        address = ipaddress.ip_address(self.address)
        derived = (
            "WILDCARD"
            if address.is_unspecified
            else "LOOPBACK"
            if address.is_loopback
            else "INTERFACE"
        )
        if self.bind_scope == "UNKNOWN":
            object.__setattr__(self, "bind_scope", derived)
        if self.exposed is None:
            # Backward-compatible name: this means locally bound to all
            # interfaces, not remotely reachable through network controls.
            object.__setattr__(self, "exposed", derived == "WILDCARD")
        return self


class PersistenceItem(StrictModel):
    name: ShortText
    kind: str = Field(min_length=1, max_length=128)
    location: str | None = Field(default=None, max_length=4096)
    executable_path: str | None = Field(default=None, max_length=4096)
    user: str | None = Field(default=None, max_length=512)
    enabled: bool | None = None
    suspicious: bool = False

    @field_validator("executable_path")
    @classmethod
    def redact_persistence_command(cls, value: str | None) -> str | None:
        return _redact_command_field(value)


class BrowserExtension(StrictModel):
    browser: ShortText
    extension_id: str = Field(min_length=1, max_length=512)
    name: str | None = Field(default=None, max_length=512)
    version: str | None = Field(default=None, max_length=128)
    enabled: bool | None = None
    permissions: list[str] = Field(default_factory=list, max_length=512)
    risky: bool = False


class UpdateInfo(StrictModel):
    update_id: ShortText
    title: str | None = Field(default=None, max_length=1024)
    description: str | None = Field(default=None, max_length=4096)
    version: str | None = Field(default=None, max_length=256)
    category: str | None = Field(default=None, max_length=128)
    severity: str | None = Field(default=None, max_length=64)
    kb_ids: list[str] = Field(default_factory=list, max_length=256)
    installed: bool
    security_update: bool | None = None
    installed_at: datetime | None = None
    reboot_required: bool | None = None
    source: str | None = Field(default=None, max_length=256)

    @field_validator("installed_at")
    @classmethod
    def aware_installed_at(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None

    @field_validator("kb_ids")
    @classmethod
    def validate_kb_ids(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 64 for value in values):
            raise ValueError("KB identifiers must contain 1-64 characters")
        return values


class FirewallProfile(StrictModel):
    name: ShortText
    enabled: bool | None = None
    default_inbound_action: str | None = Field(default=None, max_length=64)
    default_outbound_action: str | None = Field(default=None, max_length=64)
    notify_on_listen: bool | None = None
    log_allowed: bool | None = None
    log_blocked: bool | None = None
    log_file: str | None = Field(default=None, max_length=4096)


class AntivirusProduct(StrictModel):
    name: ShortText
    enabled: bool | None = None
    real_time_protection_enabled: bool | None = None
    signatures_up_to_date: bool | None = None
    signature_version: str | None = Field(default=None, max_length=256)
    signature_updated_at: datetime | None = None
    product_state: int | None = Field(default=None, ge=0)
    source: str | None = Field(default=None, max_length=128)

    @field_validator("signature_updated_at")
    @classmethod
    def aware_signature_updated_at(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None


class DiskEncryptionVolume(StrictModel):
    mount_point: ShortText
    volume_status: str | None = Field(default=None, max_length=128)
    protection_enabled: bool | None = None
    encryption_method: str | None = Field(default=None, max_length=128)
    encryption_percentage: float | None = Field(default=None, ge=0, le=100)


class CertificateInfo(StrictModel):
    store: ShortText
    subject: str = Field(min_length=1, max_length=4096)
    issuer: str | None = Field(default=None, max_length=4096)
    thumbprint: str | None = Field(default=None, max_length=256)
    serial_number: str | None = Field(default=None, max_length=512)
    not_before: datetime | None = None
    not_after: datetime | None = None
    signature_algorithm: str | None = Field(default=None, max_length=256)
    public_key_algorithm: str | None = Field(default=None, max_length=256)
    key_size: int | None = Field(default=None, ge=0, le=1_048_576)
    has_private_key: bool | None = None
    self_signed: bool | None = None
    expired: bool | None = None

    @field_validator("not_before", "not_after")
    @classmethod
    def aware_certificate_times(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None

    @model_validator(mode="after")
    def validate_validity_window(self) -> CertificateInfo:
        if self.not_before and self.not_after and self.not_after < self.not_before:
            raise ValueError("certificate expiry cannot precede its validity start")
        return self


class SecurityPosture(StrictModel):
    firewall_enabled: bool | None = None
    antivirus_enabled: bool | None = None
    antivirus_up_to_date: bool | None = None
    disk_encryption_enabled: bool | None = None
    secure_boot_enabled: bool | None = None
    tpm_present: bool | None = None
    tpm_version: str | None = Field(default=None, max_length=64)
    uac_enabled: bool | None = None
    rdp_enabled: bool | None = None
    selinux_enabled: bool | None = None
    apparmor_enabled: bool | None = None
    ssh_root_login_enabled: bool | None = None
    ssh_password_authentication_enabled: bool | None = None
    ssh_permit_empty_passwords: bool | None = None
    automatic_updates_enabled: bool | None = None
    pending_security_updates_count: int | None = Field(default=None, ge=0)
    pending_reboot: bool | None = None
    sip_enabled: bool | None = None
    remote_login_enabled: bool | None = None
    screen_sharing_enabled: bool | None = None
    security_agent_installed: bool | None = None
    security_agent_running: bool | None = None
    security_agent_names: list[str] = Field(default_factory=list, max_length=64)
    security_agent_running_names: list[str] = Field(default_factory=list, max_length=64)
    security_service_enabled: bool | None = None
    security_service_running: bool | None = None
    guest_account_enabled: bool | None = None
    administrator_account_count: int | None = Field(default=None, ge=0)
    excessive_administrator_accounts: bool | None = None
    unexpected_administrator_accounts: list[str] = Field(default_factory=list, max_length=128)
    password_policy_compliant: bool | None = None
    lock_screen_enabled: bool | None = None
    audit_logging_enabled: bool | None = None
    local_admin_password_managed: bool | None = None
    configuration_drift: bool | None = None
    insecure_configuration: bool | None = None
    suspicious_service_detected: bool | None = None
    suspicious_startup_item_detected: bool | None = None
    suspicious_scheduled_task_detected: bool | None = None
    suspicious_listening_port_detected: bool | None = None
    scan_age_days: float | None = Field(default=None, ge=0)
    scan_stale: bool | None = None
    firewall_profiles: list[FirewallProfile] = Field(default_factory=list, max_length=32)
    antivirus_products: list[AntivirusProduct] = Field(default_factory=list, max_length=64)
    encryption_volumes: list[DiskEncryptionVolume] = Field(default_factory=list, max_length=256)
    controls: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("controls", mode="before")
    @classmethod
    def validate_controls(cls, value: Any) -> JsonValue:
        validated = bounded_json(value, max_depth=8, max_nodes=2_000)
        if not isinstance(validated, dict):
            raise ValueError("controls must be an object")
        from app.security.redaction import redact_mapping

        return redact_mapping(validated)

    @field_validator(
        "unexpected_administrator_accounts",
        "security_agent_names",
        "security_agent_running_names",
    )
    @classmethod
    def validate_names(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 512 for value in values):
            raise ValueError("names must contain 1-512 characters")
        return values
