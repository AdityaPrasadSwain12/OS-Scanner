from __future__ import annotations

from app.normalization import normalize_native


def test_linux_security_posture_is_normalized() -> None:
    outcome = normalize_native(
        {
            "platform": "linux",
            "data": {
                "posture": {
                    "firewall": {"status": "Status: active"},
                    "selinux": {"status": "Enforcing"},
                    "ssh_configuration": {
                        "permitrootlogin": "yes",
                        "passwordauthentication": "no",
                    },
                    "automatic_updates": {"status": "enabled"},
                },
                "patches": {
                    "available_updates": [
                        {"package": "openssl", "security_related": True}
                    ]
                },
            },
        }
    )
    posture = outcome.data["security"]
    assert posture.firewall_enabled is True
    assert posture.ssh_root_login_enabled is True
    assert posture.ssh_password_authentication_enabled is False
    assert posture.pending_security_updates_count == 1


def test_windows_rdp_registry_value_is_inverted() -> None:
    outcome = normalize_native(
        {
            "platform": "windows",
            "data": {
                "posture": {
                    "firewall": {"domain": {"enabled": True}},
                    "remote_desktop": {"fDenyTSConnections": "0x1"},
                }
            },
        }
    )
    assert outcome.data["security"].rdp_enabled is False


def test_windows_local_protective_controls_are_normalized() -> None:
    outcome = normalize_native(
        {
            "platform": "windows",
            "data": {
                "posture": {
                    "local_security_controls": {
                        "GuestAccountEnabled": False,
                        "LockScreenEnabled": True,
                        "AuditLoggingEnabled": True,
                        "LocalAdminPasswordManaged": True,
                    }
                }
            },
        }
    )
    security = outcome.data["security"]
    assert security.guest_account_enabled is False
    assert security.lock_screen_enabled is True
    assert security.audit_logging_enabled is True
    assert security.local_admin_password_managed is True


def test_windows_detailed_security_products_and_pending_updates_are_preserved() -> None:
    outcome = normalize_native(
        {
            "platform": "windows",
            "data": {
                "posture": {
                    "firewall": [
                        {
                            "Name": "Domain",
                            "Enabled": True,
                            "DefaultInboundAction": "Block",
                            "DefaultOutboundAction": "Allow",
                            "LogBlocked": True,
                        }
                    ],
                    "antivirus": {
                        "Defender": {
                            "AntivirusEnabled": False,
                            "RealTimeProtectionEnabled": False,
                        },
                        "RegisteredProducts": [
                            {"Name": "Approved Endpoint Protection", "ProductState": 266240}
                        ],
                    },
                    "disk_encryption": [
                        {
                            "MountPoint": "C:",
                            "VolumeStatus": "FullyEncrypted",
                            "ProtectionStatus": 1,
                            "EncryptionMethod": "XtsAes256",
                            "EncryptionPercentage": 100,
                        }
                    ],
                },
                "patches": {
                    "pending_updates": {
                        "Count": 1,
                        "SecurityCount": 1,
                        "CatalogMode": "cached-offline",
                        "Updates": [
                            {
                                "UpdateId": "update-guid-1",
                                "Revision": 2,
                                "Title": "Security update",
                                "Description": "Fixes an operating-system issue.",
                                "KbArticleIds": ["KB5000001"],
                                "Categories": ["Security Updates"],
                                "SecurityRelated": True,
                                "MsrcSeverity": "Critical",
                                "RebootRequired": True,
                            }
                        ],
                    }
                },
            },
        }
    )

    security = outcome.data["security"]
    assert security.firewall_profiles[0].default_inbound_action == "Block"
    assert security.antivirus_enabled is None
    assert [product.name for product in security.antivirus_products] == [
        "Microsoft Defender Antivirus",
        "Approved Endpoint Protection",
    ]
    assert security.encryption_volumes[0].protection_enabled is True
    update = outcome.data["updates"][0]
    assert update.installed is False
    assert update.security_update is True
    assert update.kb_ids == ["KB5000001"]
    assert update.source == "Windows Update Agent cached catalog"


def test_linux_security_agents_password_and_sudo_controls_are_normalized() -> None:
    outcome = normalize_native(
        {
            "platform": "linux",
            "data": {
                "posture": {
                    "security_agents": [
                        {
                            "name": "auditd.service",
                            "installed": True,
                            "enabled": True,
                            "active": True,
                        },
                        {
                            "name": "wazuh-agent.service",
                            "installed": True,
                            "enabled": True,
                            "active": True,
                        },
                    ],
                    "ssh_configuration_file": {"permitrootlogin": "no"},
                    "sudo_configuration": {
                        "nopasswd_rule_count": 1,
                        "authenticate_disabled": False,
                    },
                    "password_quality": {"minlen": "14", "enforcing": "1"},
                    "login_defaults": {"encrypt_method": "YESCRYPT"},
                }
            },
        }
    )
    security = outcome.data["security"]
    assert security.security_agent_installed is True
    assert security.security_agent_running is True
    assert security.security_agent_names == ["auditd.service", "wazuh-agent.service"]
    assert security.security_agent_running_names == [
        "auditd.service",
        "wazuh-agent.service",
    ]
    assert security.audit_logging_enabled is True
    assert security.password_policy_compliant is True
    assert security.insecure_configuration is True
    assert security.controls["ssh_file_configuration"] == {"permitrootlogin": "no"}


def test_macos_lock_audit_and_secure_boot_controls_are_normalized() -> None:
    outcome = normalize_native(
        {
            "platform": "macos",
            "data": {
                "posture": {
                    "lock_screen": {"status": "1"},
                    "audit_logging": {"status": "state = running\npid = 123"},
                    "secure_boot_hardware": {"Secure Boot": "Full Security"},
                }
            },
        }
    )
    security = outcome.data["security"]
    assert security.lock_screen_enabled is True
    assert security.audit_logging_enabled is True
    assert security.secure_boot_enabled is True
