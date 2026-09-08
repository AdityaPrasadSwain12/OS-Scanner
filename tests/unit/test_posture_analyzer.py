from __future__ import annotations

from app.analyzers import BaselineAnalyzer
from app.core import AnalysisSettings
from app.models import (
    BrowserExtension,
    ListeningPort,
    NetworkProtocol,
    SecurityPosture,
    Service,
    ServiceState,
    User,
)


def test_explicit_baselines_classify_inventory() -> None:
    analyzer = BaselineAnalyzer(
        AnalysisSettings(
            enforce_administrator_allowlist=True,
            approved_administrator_accounts={"approved-admin"},
            enforce_port_allowlist=True,
            allowed_listening_ports={443},
            enforce_browser_extension_allowlist=True,
            approved_browser_extension_ids={"approved-extension"},
            required_security_agent_names={"wazuh-agent.service"},
        )
    )
    result = analyzer.analyze(
        {
            "security": SecurityPosture(security_agent_names=[]),
            "users": [User(username="temp-admin", is_administrator=True)],
            "listening_ports": [
                ListeningPort(
                    protocol=NetworkProtocol.TCP,
                    address="0.0.0.0",  # noqa: S104 - finding input, not a bind
                    port=4444,
                )
            ],
            "browser_extensions": [
                BrowserExtension(browser="Chrome", extension_id="unapproved-extension")
            ],
        }
    )
    assert result["security"].unexpected_administrator_accounts == ["temp-admin"]
    assert result["security"].security_agent_installed is False
    assert result["listening_ports"][0].suspicious is True
    assert result["browser_extensions"][0].risky is True


def test_disabled_allowlists_do_not_create_false_positives() -> None:
    result = BaselineAnalyzer(AnalysisSettings()).analyze(
        {
            "security": SecurityPosture(),
            "listening_ports": [
                ListeningPort(protocol=NetworkProtocol.TCP, address="127.0.0.1", port=1234)
            ],
        }
    )
    assert result["listening_ports"][0].suspicious is False


def test_required_agent_running_state_is_evaluated_per_agent() -> None:
    analyzer = BaselineAnalyzer(
        AnalysisSettings(required_security_agent_names={"wazuh-agent.service"})
    )
    result = analyzer.analyze(
        {
            "security": SecurityPosture(
                security_agent_names=["auditd.service", "wazuh-agent.service"],
                security_agent_running_names=["auditd.service"],
            ),
            "services": [
                Service(name="auditd.service", state=ServiceState.RUNNING),
                Service(name="wazuh-agent.service", state=ServiceState.STOPPED),
            ],
        }
    )

    security = result["security"]
    assert security.security_agent_installed is True
    assert security.security_agent_running is False
    assert security.controls["missing_required_security_agents"] == []
    assert security.controls["stopped_required_security_agents"] == [
        "wazuh-agent.service"
    ]


def test_approved_security_posture_reports_exact_and_bounded_field_drift() -> None:
    analyzer = BaselineAnalyzer(
        AnalysisSettings(
            approved_security_posture={
                "firewall_enabled": True,
                "ssh_root_login_enabled": False,
            }
        )
    )

    matching = analyzer.analyze(
        {
            "security": SecurityPosture(
                firewall_enabled=True,
                ssh_root_login_enabled=False,
            )
        }
    )["security"]
    assert matching.configuration_drift is False
    assert matching.controls["configuration_baseline_enforced"] is True
    assert matching.controls["configuration_drift_fields"] == []

    drifted = analyzer.analyze(
        {
            "security": SecurityPosture(
                firewall_enabled=False,
                ssh_root_login_enabled=False,
            )
        }
    )["security"]
    assert drifted.configuration_drift is True
    assert drifted.controls["configuration_drift_fields"] == ["firewall_enabled"]


def test_approved_security_posture_keeps_unknown_required_facts_indeterminate() -> None:
    analyzer = BaselineAnalyzer(
        AnalysisSettings(
            approved_security_posture={
                "firewall_enabled": True,
                "disk_encryption_enabled": True,
            }
        )
    )

    security = analyzer.analyze(
        {"security": SecurityPosture(firewall_enabled=True)}
    )["security"]

    assert security.configuration_drift is None
    assert security.controls["configuration_drift_fields"] == []
    assert security.controls["configuration_baseline_unknown_fields"] == [
        "disk_encryption_enabled"
    ]
