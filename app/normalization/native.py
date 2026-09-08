"""Turn platform-specific posture checks into portable security models."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from app.models import (
    AntivirusProduct,
    DiskEncryptionVolume,
    FirewallProfile,
    PersistenceItem,
    SecurityPosture,
    UpdateInfo,
    User,
)

from .linux_inventory import normalize_linux_inventory
from .macos_inventory import normalize_macos_inventory
from .osquery import NormalizationOutcome
from .windows_inventory import normalize_windows_inventory


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _records(value: object) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _status_text(value: object) -> str:
    mapping = _mapping(value)
    return str(mapping.get("status", value if isinstance(value, str) else "")).strip().casefold()


def _bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    normalized = str(value).strip().casefold()
    if normalized in {"true", "yes", "on", "enabled", "1", "active", "running"}:
        return True
    if normalized in {"false", "no", "off", "disabled", "0", "inactive", "stopped"}:
        return False
    return None


def _registry_dword(value: object) -> bool | None:
    values = _mapping(value)
    for item in values.values():
        text = str(item).strip().casefold()
        match = re.search(r"(?:0x)?([0-9a-f]+)$", text)
        if match:
            return int(match.group(1), 16) != 0
    return None


def _parse_date(value: object) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    for form in ("%m/%d/%Y", "%d/%m/%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, form).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _parse_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if not value:
        return None
    text = str(value).strip()
    milliseconds = re.fullmatch(r"/Date\((\d+)(?:[+-]\d+)?\)/", text)
    if milliseconds:
        try:
            return datetime.fromtimestamp(int(milliseconds.group(1)) / 1000, tz=UTC)
        except (OSError, OverflowError, ValueError):
            return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return _parse_date(value)


def _windows(
    posture: Mapping[str, Any], patches: Mapping[str, Any], persistence: Mapping[str, Any]
) -> NormalizationOutcome:
    outcome = NormalizationOutcome()
    raw_firewall = posture.get("firewall")
    firewall_rows: list[Mapping[str, Any]] = []
    if isinstance(raw_firewall, list):
        firewall_rows = _records(raw_firewall)
    else:
        for profile_name, value in _mapping(raw_firewall).items():
            profile = dict(_mapping(value))
            profile.setdefault("Name", profile_name)
            firewall_rows.append(profile)
    normalized_firewall_profiles: list[FirewallProfile] = []
    for row in firewall_rows[:32]:
        try:
            normalized_firewall_profiles.append(
                FirewallProfile(
                    name=str(row.get("Name") or row.get("name") or "unknown")[:512],
                    enabled=_bool(row.get("Enabled", row.get("enabled"))),
                    default_inbound_action=(
                        str(row.get("DefaultInboundAction") or "")[:64] or None
                    ),
                    default_outbound_action=(
                        str(row.get("DefaultOutboundAction") or "")[:64] or None
                    ),
                    notify_on_listen=_bool(row.get("NotifyOnListen")),
                    log_allowed=_bool(row.get("LogAllowed")),
                    log_blocked=_bool(row.get("LogBlocked")),
                    log_file=str(row.get("LogFile") or "")[:4096] or None,
                )
            )
        except ValidationError:
            outcome.warnings.append("invalid Windows firewall profile metadata omitted")
    profile_states = [
        profile.enabled
        for profile in normalized_firewall_profiles
        if profile.enabled is not None
    ]
    antivirus_payload = _mapping(posture.get("antivirus"))
    antivirus = _mapping(antivirus_payload.get("Defender")) or antivirus_payload
    registered_products = _records(antivirus_payload.get("RegisteredProducts"))
    antivirus_products: list[AntivirusProduct] = []
    volumes = _records(posture.get("disk_encryption"))
    encryption_states = [
        _bool(volume.get("ProtectionStatus"))
        if not isinstance(volume.get("ProtectionStatus"), int)
        else int(volume.get("ProtectionStatus", 0)) == 1
        for volume in volumes
    ]
    tpm = _mapping(posture.get("tpm"))
    remote_deny = _registry_dword(posture.get("remote_desktop"))
    update_policy = _mapping(posture.get("automatic_updates"))
    no_auto_update = _registry_dword(
        {"NoAutoUpdate": update_policy.get("NoAutoUpdate")}
        if "NoAutoUpdate" in update_policy
        else {}
    )
    signature_age = None
    with suppress(TypeError, ValueError):
        signature_age = int(str(antivirus.get("AntivirusSignatureAge")))
    pending_updates = _mapping(patches.get("pending_updates"))
    local_controls = _mapping(posture.get("local_security_controls"))
    antivirus_enabled = _bool(antivirus.get("AntivirusEnabled"))
    realtime_enabled = _bool(antivirus.get("RealTimeProtectionEnabled"))
    signature_updated_at = _parse_datetime(antivirus.get("AntivirusSignatureLastUpdated"))
    if antivirus:
        try:
            antivirus_products.append(
                AntivirusProduct(
                    name="Microsoft Defender Antivirus",
                    enabled=antivirus_enabled,
                    real_time_protection_enabled=realtime_enabled,
                    signatures_up_to_date=(
                        signature_age <= 3 if signature_age is not None else None
                    ),
                    signature_version=(
                        str(antivirus.get("AntivirusSignatureVersion") or "")[:256] or None
                    ),
                    signature_updated_at=signature_updated_at,
                    source="Get-MpComputerStatus",
                )
            )
        except ValidationError:
            outcome.warnings.append("invalid Microsoft Defender metadata omitted")
    known_product_names = {product.name.casefold() for product in antivirus_products}
    for product in registered_products[:64]:
        name = str(product.get("Name") or "").strip()[:512]
        if not name or name.casefold() in known_product_names:
            continue
        state = None
        with suppress(TypeError, ValueError):
            state = int(str(product.get("ProductState")))
        try:
            antivirus_products.append(
                AntivirusProduct(
                    name=name,
                    product_state=state,
                    source="Windows SecurityCenter2",
                )
            )
            known_product_names.add(name.casefold())
        except ValidationError:
            outcome.warnings.append("invalid registered antivirus metadata omitted")
    # A disabled Defender does not prove the endpoint has no protection when a
    # separate Security Center product is registered. Keep the aggregate state
    # unknown instead of generating a false disabled-antivirus finding.
    aggregate_antivirus_enabled = (
        None if antivirus_enabled is False and registered_products else antivirus_enabled
    )
    encryption_volumes: list[DiskEncryptionVolume] = []
    for volume in volumes[:256]:
        mount_point = str(volume.get("MountPoint") or "").strip()[:512]
        if not mount_point:
            continue
        raw_percentage = volume.get("EncryptionPercentage")
        percentage = None
        with suppress(TypeError, ValueError):
            percentage = float(str(raw_percentage))
        protection = volume.get("ProtectionStatus")
        protection_enabled = (
            int(protection) == 1
            if isinstance(protection, int) and not isinstance(protection, bool)
            else _bool(protection)
        )
        try:
            encryption_volumes.append(
                DiskEncryptionVolume(
                    mount_point=mount_point,
                    volume_status=str(volume.get("VolumeStatus") or "")[:128] or None,
                    protection_enabled=protection_enabled,
                    encryption_method=(
                        str(volume.get("EncryptionMethod") or "")[:128] or None
                    ),
                    encryption_percentage=percentage,
                )
            )
        except ValidationError:
            outcome.warnings.append("invalid BitLocker volume metadata omitted")
    security = SecurityPosture(
        firewall_enabled=all(profile_states) if profile_states else None,
        antivirus_enabled=aggregate_antivirus_enabled,
        antivirus_up_to_date=signature_age <= 3 if signature_age is not None else None,
        disk_encryption_enabled=(
            all(state is True for state in encryption_states) if encryption_states else None
        ),
        secure_boot_enabled=_bool(posture.get("secure_boot")),
        tpm_present=_bool(tpm.get("TpmPresent")),
        tpm_version=str(tpm.get("ManufacturerVersion") or "")[:64] or None,
        uac_enabled=_registry_dword(posture.get("uac")),
        rdp_enabled=not remote_deny if remote_deny is not None else None,
        automatic_updates_enabled=not no_auto_update if no_auto_update is not None else None,
        pending_security_updates_count=(
            int(str(pending_updates["SecurityCount"]))
            if str(pending_updates.get("SecurityCount", "")).isdigit()
            else None
        ),
        pending_reboot=_bool(patches.get("pending_reboot")),
        security_service_enabled=antivirus_enabled,
        security_service_running=realtime_enabled,
        guest_account_enabled=_bool(local_controls.get("GuestAccountEnabled")),
        lock_screen_enabled=_bool(local_controls.get("LockScreenEnabled")),
        audit_logging_enabled=_bool(local_controls.get("AuditLoggingEnabled")),
        local_admin_password_managed=_bool(
            local_controls.get("LocalAdminPasswordManaged")
        ),
        firewall_profiles=normalized_firewall_profiles,
        antivirus_products=antivirus_products,
        encryption_volumes=encryption_volumes,
        controls={
            "windows_firewall_profiles": len(normalized_firewall_profiles),
            "defender_realtime_enabled": realtime_enabled,
            "defender_signature_age_days": signature_age,
            "pending_update_count": pending_updates.get("Count"),
            "windows_update_catalog_mode": pending_updates.get("CatalogMode"),
            "windows_update_options": update_policy.get("AUOptions"),
        },
    )
    if posture:
        outcome.data["security"] = security

    updates: list[UpdateInfo] = []
    for record in _records(patches.get("installed_updates")):
        update_id = str(record.get("update_id") or record.get("HotFixID") or "").strip()
        if not update_id:
            continue
        try:
            updates.append(
                UpdateInfo(
                    update_id=update_id,
                    installed=True,
                    security_update=None,
                    installed_at=_parse_date(record.get("installed_on")),
                    source="Get-HotFix",
                )
            )
        except ValidationError:
            outcome.warnings.append("invalid Windows update metadata omitted")
    for record in _records(pending_updates.get("Updates")):
        update_id = str(record.get("UpdateId") or "").strip()
        if not update_id:
            continue
        raw_kb_ids = record.get("KbArticleIds")
        kb_ids = (
            [str(item).strip()[:64] for item in raw_kb_ids if str(item).strip()][:256]
            if isinstance(raw_kb_ids, list)
            else []
        )
        raw_categories = record.get("Categories")
        categories = (
            [str(item).strip() for item in raw_categories if str(item).strip()]
            if isinstance(raw_categories, list)
            else []
        )
        try:
            updates.append(
                UpdateInfo(
                    update_id=update_id,
                    title=str(record.get("Title") or "")[:1024] or None,
                    description=str(record.get("Description") or "")[:4096] or None,
                    version=(
                        str(record.get("Revision"))[:256]
                        if record.get("Revision") is not None
                        else None
                    ),
                    category=", ".join(categories)[:128] or None,
                    severity=str(record.get("MsrcSeverity") or "")[:64] or None,
                    kb_ids=kb_ids,
                    installed=False,
                    security_update=_bool(record.get("SecurityRelated")),
                    installed_at=None,
                    reboot_required=_bool(record.get("RebootRequired")),
                    source="Windows Update Agent cached catalog",
                )
            )
        except ValidationError:
            outcome.warnings.append("invalid pending Windows update metadata omitted")
    if patches:
        outcome.data["updates"] = updates
    if "local_users" in posture:
        users: list[User] = []
        for record in _records(posture.get("local_users")):
            username = str(record.get("Name") or record.get("name") or "").strip()
            if not username:
                continue
            sid = str(record.get("SID") or record.get("sid") or "").strip()
            try:
                users.append(
                    User(
                        username=username,
                        uid=sid or None,
                        enabled=_bool(record.get("Enabled")),
                        is_administrator=_bool(record.get("IsAdministrator")) is True,
                        is_guest=sid.endswith("-501"),
                        last_login=_parse_datetime(record.get("LastLogon")),
                    )
                )
            except ValidationError:
                outcome.warnings.append("invalid Windows local-user metadata omitted")
        outcome.data["users"] = users
    if persistence:
        outcome.data["persistence"] = _persistence_records(
            persistence,
            {
                "machine_run_items": "Run",
                "user_run_items": "Run",
                "scheduled_tasks": "scheduled_task",
                "startup_folders": "startup_folder",
            },
            outcome.warnings,
        )
    return outcome


def _linux(
    posture: Mapping[str, Any], patches: Mapping[str, Any], persistence: Mapping[str, Any]
) -> NormalizationOutcome:
    outcome = NormalizationOutcome()
    ufw = _status_text(posture.get("firewall_ufw"))
    firewalld = _status_text(posture.get("firewall_firewalld"))
    nftables = _status_text(posture.get("firewall_nftables"))
    firewall_observations: list[bool] = []
    if ufw:
        firewall_observations.append(
            "inactive" not in ufw and "disabled" not in ufw
        )
    if firewalld:
        firewall_observations.append(
            "not running" not in firewalld and "inactive" not in firewalld
        )
    if "firewall_nftables" in posture:
        firewall_observations.append(
            any(marker in nftables for marker in ("table ", "chain ", "hook "))
        )
    legacy_firewall = _status_text(posture.get("firewall"))
    if not firewall_observations and legacy_firewall:
        firewall_observations.append(
            not any(
                marker in legacy_firewall
                for marker in ("inactive", "disabled", "not running")
            )
        )
    firewall_enabled = (
        any(firewall_observations) if firewall_observations else None
    )
    selinux_mode = _status_text(posture.get("selinux"))
    apparmor = _status_text(posture.get("apparmor"))
    selinux_enforcing = (
        selinux_mode == "enforcing"
        if selinux_mode in {"enforcing", "permissive", "disabled"}
        else None
    )
    apparmor_match = re.search(r"(\d+)\s+profiles?\s+are\s+in\s+enforce", apparmor)
    apparmor_enforcing = (
        False
        if "not loaded" in apparmor or "module is disabled" in apparmor
        else int(apparmor_match.group(1)) > 0
        if apparmor_match
        else None
    )
    ssh = _mapping(posture.get("ssh_configuration"))
    root_login_mode = str(ssh.get("permitrootlogin", "")).strip().casefold()
    automatic_updates = _status_text(posture.get("automatic_updates"))
    available_updates = _records(patches.get("available_updates"))
    encryption = _mapping(posture.get("disk_encryption"))
    agents = _records(posture.get("security_agents"))
    installed_agents = [str(item.get("name")) for item in agents if _bool(item.get("installed"))]
    running_agents = [str(item.get("name")) for item in agents if _bool(item.get("active"))]
    auditd = next(
        (
            item
            for item in agents
            if str(item.get("name", "")).casefold() == "auditd.service"
        ),
        None,
    )
    ssh_file = _mapping(posture.get("ssh_configuration_file"))
    sudo = _mapping(posture.get("sudo_configuration"))
    password_quality = _mapping(posture.get("password_quality"))
    login_defaults = _mapping(posture.get("login_defaults"))
    try:
        password_minimum = int(str(password_quality.get("minlen")))
    except (TypeError, ValueError):
        password_minimum = None
    password_compliant: bool | None = None
    enforcing = _bool(password_quality.get("enforcing"))
    password_hash = str(login_defaults.get("encrypt_method", "")).strip().upper()
    if password_minimum is not None and enforcing is not None and password_hash:
        password_compliant = (
            password_minimum >= 12
            and enforcing
            and password_hash in {"SHA512", "YESCRYPT"}
        )
    security_update_count = (
        sum(_bool(record.get("security_related")) is True for record in available_updates)
        if "available_updates" in patches
        else None
    )
    security = SecurityPosture(
        firewall_enabled=firewall_enabled,
        selinux_enabled=selinux_enforcing,
        apparmor_enabled=apparmor_enforcing,
        ssh_root_login_enabled=(root_login_mode != "no" if root_login_mode else None),
        ssh_password_authentication_enabled=_bool(ssh.get("passwordauthentication")),
        ssh_permit_empty_passwords=_bool(ssh.get("permitemptypasswords")),
        automatic_updates_enabled=(
            not any(word in automatic_updates for word in ("disabled", "masked", "not-found"))
            if automatic_updates
            else None
        ),
        pending_security_updates_count=security_update_count,
        pending_reboot=_bool(_mapping(patches.get("pending_reboot")).get("required")),
        disk_encryption_enabled=_bool(encryption.get("root_volume_encrypted")),
        security_agent_installed=bool(installed_agents) if agents else None,
        security_agent_running=bool(running_agents) if agents else None,
        security_agent_names=installed_agents,
        security_agent_running_names=running_agents,
        security_service_enabled=(
            _bool(auditd.get("enabled")) if auditd is not None else None
        ),
        security_service_running=(
            _bool(auditd.get("active")) if auditd is not None else None
        ),
        audit_logging_enabled=(
            _bool(auditd.get("active")) if auditd is not None else None
        ),
        password_policy_compliant=password_compliant,
        insecure_configuration=(
            bool(sudo.get("authenticate_disabled")) or int(sudo.get("nopasswd_rule_count", 0)) > 0
            if sudo
            else None
        ),
        controls={
            "firewall_backends": {
                "ufw": ufw or None,
                "firewalld": firewalld or None,
                "nftables_configured": (
                    any(marker in nftables for marker in ("table ", "chain ", "hook "))
                    if "firewall_nftables" in posture
                    else None
                ),
            },
            "selinux_mode": selinux_mode or None,
            "apparmor_status": apparmor[:1024] or None,
            "available_update_count": len(available_updates),
            "running_kernel_version": _status_text(patches.get("running_kernel")) or None,
            "ssh_root_login_mode": root_login_mode or None,
            "ssh_file_configuration": dict(ssh_file),
            "sudo_configuration": dict(sudo),
            "password_quality": dict(password_quality),
            "login_defaults": dict(login_defaults),
            "encrypted_container_count": encryption.get("encrypted_container_count"),
            "running_security_agents": running_agents,
        },
    )
    if posture:
        outcome.data["security"] = security
    if patches:
        outcome.data["updates"] = _available_updates(available_updates, outcome.warnings)
    if persistence:
        outcome.data["persistence"] = _persistence_records(
            persistence,
            {"enabled_systemd_units": "systemd_unit", "cron_entries": "cron"},
            outcome.warnings,
        )
    return outcome


def _macos(
    posture: Mapping[str, Any], patches: Mapping[str, Any], persistence: Mapping[str, Any]
) -> NormalizationOutcome:
    outcome = NormalizationOutcome()
    firewall = _status_text(posture.get("firewall"))
    encryption = _status_text(posture.get("disk_encryption"))
    sip = _status_text(posture.get("system_integrity_protection"))
    updates = _status_text(posture.get("automatic_updates"))
    remote = _status_text(posture.get("remote_login"))
    screen_sharing = _status_text(posture.get("screen_sharing"))
    lock_screen = _status_text(posture.get("lock_screen"))
    audit_logging = _status_text(posture.get("audit_logging"))
    audit_running = (
        True
        if re.search(r"\bstate\s*=\s*running\b|\bpid\s*=\s*\d+", audit_logging)
        else False
        if re.search(r"\b(?:stopped|disabled|waiting|inactive)\b", audit_logging)
        else None
    )
    secure_boot = _mapping(posture.get("secure_boot_hardware"))
    pending_updates = _records(patches.get("pending_updates"))
    pending_security_count = (
        sum(_bool(item.get("security_related")) is True for item in pending_updates)
        if "pending_updates" in patches
        else None
    )
    security = SecurityPosture(
        firewall_enabled=("enabled" in firewall or "state = 1" in firewall) if firewall else None,
        disk_encryption_enabled=("filevault is on" in encryption) if encryption else None,
        sip_enabled=("enabled" in sip) if sip else None,
        secure_boot_enabled=(
            "full" in " ".join(str(value).casefold() for value in secure_boot.values())
            if secure_boot
            else None
        ),
        automatic_updates_enabled=("on" in updates or "enabled" in updates) if updates else None,
        pending_security_updates_count=pending_security_count,
        pending_reboot=(
            any(_bool(item.get("reboot_required")) is True for item in pending_updates)
            if "pending_updates" in patches
            else None
        ),
        remote_login_enabled=(" on" in f" {remote}" or "enabled" in remote) if remote else None,
        screen_sharing_enabled=(
            True
            if screen_sharing in {"enabled", "running"}
            else False
            if screen_sharing in {"disabled", "stopped"}
            else None
        ),
        lock_screen_enabled=(
            True
            if lock_screen in {"1", "true", "yes"}
            else False
            if lock_screen in {"0", "false", "no"}
            else None
        ),
        audit_logging_enabled=audit_running,
        controls={"gatekeeper_status": _status_text(posture.get("gatekeeper")) or None},
    )
    if posture:
        outcome.data["security"] = security
    installed = _records(patches.get("installed_updates"))
    normalized_updates: list[UpdateInfo] = []
    for index, record in enumerate(installed):
        update_id = str(record.get("name") or record.get("title") or f"macos-update-{index}")
        try:
            normalized_updates.append(
                UpdateInfo(
                    update_id=update_id,
                    title=str(record.get("name") or "") or None,
                    version=str(record.get("version") or "") or None,
                    installed=True,
                    installed_at=_parse_datetime(record.get("installed_on")),
                )
            )
        except ValidationError:
            outcome.warnings.append("invalid macOS update metadata omitted")
    if patches:
        outcome.data["updates"] = normalized_updates
    for record in pending_updates:
        update_id = str(record.get("update_id") or "").strip()
        if not update_id:
            continue
        try:
            normalized_updates.append(
                UpdateInfo(
                    update_id=update_id,
                    title=str(record.get("title") or "") or None,
                    installed=False,
                    security_update=_bool(record.get("security_related")) is True,
                    category=(
                        "security"
                        if _bool(record.get("security_related")) is True
                        else None
                    ),
                    reboot_required=_bool(record.get("reboot_required")),
                )
            )
        except ValidationError:
            outcome.warnings.append("invalid pending macOS update metadata omitted")
    if persistence:
        outcome.data["persistence"] = _persistence_records(
            persistence,
            {"loaded_launch_services": "launch_service", "launch_items": "launch_item"},
            outcome.warnings,
        )
    return outcome


def _available_updates(
    records: Sequence[Mapping[str, Any]], warnings: list[str]
) -> list[UpdateInfo]:
    updates: list[UpdateInfo] = []
    for record in records:
        update_id = str(record.get("package") or "").strip()
        if not update_id:
            continue
        try:
            updates.append(
                UpdateInfo(
                    update_id=update_id,
                    title=str(record.get("detail") or "") or None,
                    installed=False,
                    security_update=_bool(record.get("security_related")) is True,
                    category=(
                        "security"
                        if _bool(record.get("security_related")) is True
                        else None
                    ),
                )
            )
        except ValidationError:
            warnings.append("invalid package update metadata omitted")
    return updates


def _persistence_records(
    values: Mapping[str, Any], kinds: Mapping[str, str], warnings: list[str]
) -> list[PersistenceItem]:
    normalized: list[PersistenceItem] = []
    for check, kind in kinds.items():
        for index, record in enumerate(_records(values.get(check))):
            name = str(record.get("name") or record.get("label") or f"{check}-{index}").strip()
            try:
                normalized.append(
                    PersistenceItem(
                        name=name,
                        kind=kind,
                        location=str(record.get("location") or "") or None,
                        executable_path=str(record.get("executable") or record.get("path") or "")
                        or None,
                        enabled=_bool(
                            record.get("enabled")
                            if "enabled" in record
                            else record.get("state")
                        ),
                    )
                )
            except ValidationError:
                warnings.append(f"invalid {kind} persistence metadata omitted")
    return normalized


def normalize_native(collection: object) -> NormalizationOutcome:
    """Normalize an EndpointCollectionResult while accepting a mapping for tests."""

    platform = str(getattr(collection, "platform", "")).casefold()
    data = getattr(collection, "data", {})
    if isinstance(collection, Mapping):
        platform = str(collection.get("platform", platform)).casefold()
        data = collection.get("data", data)
    data = _mapping(data)
    posture = _mapping(data.get("posture"))
    patches = _mapping(data.get("patches"))
    persistence = _mapping(data.get("persistence"))
    inventory = _mapping(data.get("inventory"))
    if platform == "windows":
        return normalize_windows_inventory(
            inventory, _windows(posture, patches, persistence)
        )
    if platform == "linux":
        return normalize_linux_inventory(
            inventory, _linux(posture, patches, persistence)
        )
    if platform in {"macos", "darwin"}:
        return normalize_macos_inventory(
            inventory, _macos(posture, patches, persistence)
        )
    outcome = NormalizationOutcome()
    outcome.warnings.append(f"unsupported native platform: {platform or 'unknown'}")
    return outcome
