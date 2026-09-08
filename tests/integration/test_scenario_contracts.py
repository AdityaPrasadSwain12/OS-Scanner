from __future__ import annotations

import copy
import json
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from app.models import (
    AuthorizationScope,
    CollectorState,
    CollectorStatus,
    Endpoint,
    OperatingSystem,
    OperatingSystemFamily,
    OverallStatus,
    ScanJob,
    ScanResult,
    ScanType,
    SecurityPosture,
)
from app.policies import EvaluationContext, PolicyBundle, PolicyEngine, PolicyLoader
from app.transport import (
    CloudApiClient,
    CloudApiConfig,
    CloudApiError,
    HttpRequest,
    HttpResponse,
    NetworkError,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures"
NOW = datetime(2026, 1, 1, tzinfo=UTC)

scenario_document = cast(
    dict[str, Any], json.loads((FIXTURE_ROOT / "scenarios.json").read_text(encoding="utf-8"))
)
SCENARIOS = cast(list[dict[str, Any]], scenario_document["scenarios"])

EXPECTED_POLICY_RULE = {
    "firewall_disabled": "LIN-FIREWALL-001",
    "antivirus_disabled": "WIN-ANTIVIRUS-001",
    "encryption_disabled": "ENDPOINT-ENCRYPTION-001",
    "outdated_os": "OS-SUPPORT-001",
    "missing_updates": "PATCH-SECURITY-001",
    "rdp_enabled": "WIN-RDP-001",
    "ssh_misconfigured": "LIN-SSH-001",
    "guest_enabled": "ACCOUNT-GUEST-001",
    "unexpected_admin": "ACCOUNT-ADMIN-002",
    "suspicious_service": "SERVICE-SUSPICIOUS-001",
    "suspicious_startup": "PERSISTENCE-STARTUP-001",
    "unexpected_port": "NETWORK-SUSPICIOUS-001",
    "critical_vulnerability": "VULNERABILITY-CRITICAL-001",
    "high_vulnerability": "VULNERABILITY-HIGH-001",
    "compliance_failure": "COMPLIANCE-FAIL-001",
    "tool_unavailable": "TOOL-UNAVAILABLE-001",
}


@pytest.fixture(scope="module")
def enterprise_policy() -> PolicyBundle:
    return PolicyLoader().load_file(
        ROOT / "app" / "policies" / "defaults" / "enterprise-default.yaml"
    )


def _healthy_policy_input() -> dict[str, Any]:
    return {
        "os": {"supported": True},
        "security": {
            "firewall_enabled": True,
            "antivirus_enabled": True,
            "antivirus_up_to_date": True,
            "disk_encryption_enabled": True,
            "secure_boot_enabled": True,
            "tpm_present": True,
            "uac_enabled": True,
            "rdp_enabled": False,
            "selinux_enabled": True,
            "apparmor_enabled": True,
            "ssh_root_login_enabled": False,
            "ssh_password_authentication_enabled": False,
            "ssh_permit_empty_passwords": False,
            "automatic_updates_enabled": True,
            "pending_security_updates_count": 0,
            "pending_reboot": False,
            "sip_enabled": True,
            "remote_login_enabled": False,
            "screen_sharing_enabled": False,
            "security_agent_installed": True,
            "security_agent_running": True,
            "security_service_enabled": True,
            "security_service_running": True,
            "guest_account_enabled": False,
            "excessive_administrator_accounts": False,
            "unexpected_administrator_accounts": [],
            "password_policy_compliant": True,
            "lock_screen_enabled": True,
            "audit_logging_enabled": True,
            "local_admin_password_managed": True,
            "configuration_drift": False,
            "insecure_configuration": False,
            "suspicious_service_detected": False,
            "suspicious_startup_item_detected": False,
            "suspicious_scheduled_task_detected": False,
            "suspicious_listening_port_detected": False,
            "scan_stale": False,
        },
        "services": [],
        "persistence": [],
        "listening_ports": [],
        "vulnerabilities": [],
        "compliance": [],
        "browser_extensions": [],
        "collectors": {"osquery": {"status": "SUCCESS"}},
    }


def _apply_dotted_overrides(data: dict[str, Any], overrides: dict[str, Any]) -> None:
    for path, value in overrides.items():
        cursor = data
        segments = path.split(".")
        for segment in segments[:-1]:
            child = cursor.setdefault(segment, {})
            if not isinstance(child, dict):
                raise AssertionError(f"scenario path traverses a non-object: {path}")
            cursor = child
        cursor[segments[-1]] = value


class _ScenarioExecutor:
    def __init__(self, response: HttpResponse | Exception) -> None:
        self.response = response
        self.requests: list[HttpRequest] = []

    def send(
        self,
        request: HttpRequest,
        *,
        timeout_seconds: float,
        ssl_context: ssl.SSLContext,
        max_response_bytes: int,
    ) -> HttpResponse:
        del timeout_seconds, ssl_context, max_response_bytes
        self.requests.append(request)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda item: str(item["id"]))
def test_documented_scenario_executes_its_real_contract(
    scenario: dict[str, Any], enterprise_policy: PolicyBundle
) -> None:
    scenario_id = str(scenario["id"])
    overrides = cast(dict[str, Any], scenario["overrides"])

    if scenario_id in EXPECTED_POLICY_RULE or scenario_id == "healthy_endpoint":
        policy_input = copy.deepcopy(_healthy_policy_input())
        _apply_dotted_overrides(policy_input, overrides)
        context = EvaluationContext(
            scan_id=f"scenario-{scenario_id}",
            endpoint_id="endpoint-1",
            platform=OperatingSystemFamily(str(scenario["platform"])),
            scan_type=ScanType.FULL,
            detected_at=NOW,
        )
        rule_ids = {
            finding.rule_id
            for finding in PolicyEngine().evaluate(enterprise_policy, policy_input, context)
        }
        if scenario_id == "healthy_endpoint":
            assert rule_ids == set()
        else:
            assert rule_ids == {EXPECTED_POLICY_RULE[scenario_id]}
        return

    if scenario_id in {"offline_endpoint", "api_failure"}:
        if overrides.get("transport.online") is False:
            response: HttpResponse | Exception = NetworkError("endpoint is offline")
            expected_status = None
        else:
            expected_status = int(overrides["transport.status_code"])
            response = HttpResponse(expected_status, {}, b"")
        executor = _ScenarioExecutor(response)
        client = CloudApiClient(
            CloudApiConfig("https://scanner.example.test", max_attempts=1),
            executor=executor,
        )
        if expected_status is None:
            with pytest.raises(NetworkError, match="offline"):
                client.request("GET", "/api/v1/heartbeat", request_id=scenario_id)
        else:
            with pytest.raises(CloudApiError) as error:
                client.request("GET", "/api/v1/heartbeat", request_id=scenario_id)
            assert error.value.status_code == expected_status
            assert error.value.retryable is True
        assert len(executor.requests) == 1
        return

    assert scenario_id == "unauthorized_amass_target"
    authorized_domains = set(cast(list[str], overrides["authorized_domains"]))
    authorization = AuthorizationScope(
        scope_id="scenario-scope",
        authorized=True,
        authorization_reference="scenario-contract",
        valid_from=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=1),
        allowed_domains=authorized_domains,
    )
    with pytest.raises(ValueError, match="outside the authorized domain scope"):
        ScanJob(
            scan_id="scenario-unauthorized-amass",
            scan_type=ScanType.ATTACK_SURFACE,
            target=str(overrides["target"]),
            authorization=authorization,
        )


@pytest.mark.parametrize(
    ("fixture_name", "expected_rules"),
    (
        ("windows_endpoint.json", set()),
        (
            "linux_endpoint.json",
            {
                "LIN-FIREWALL-001",
                "ENDPOINT-ENCRYPTION-001",
                "LIN-SSH-001",
                "LIN-SSH-002",
                "PATCH-SECURITY-001",
                "PATCH-AUTOUPDATE-001",
                "AGENT-EDR-001",
            },
        ),
        ("macos_endpoint.json", set()),
    ),
)
def test_normalized_endpoint_fixture_validates_and_drives_enterprise_policy(
    fixture_name: str,
    expected_rules: set[str],
    enterprise_policy: PolicyBundle,
) -> None:
    document = cast(
        dict[str, Any],
        json.loads((FIXTURE_ROOT / fixture_name).read_text(encoding="utf-8")),
    )
    endpoint = Endpoint.model_validate(document["endpoint"])
    operating_system = OperatingSystem.model_validate(document["operating_system"])
    security = SecurityPosture.model_validate(document["security"])
    assert endpoint.os_family is operating_system.family

    result = ScanResult(
        scan_id=f"fixture-{endpoint.endpoint_id}",
        endpoint_id=endpoint.endpoint_id,
        scan_type=ScanType.FULL,
        timestamp=NOW,
        started_at=NOW,
        finished_at=NOW,
        status=OverallStatus.SUCCESS,
        authorization_scope_id="fixture-scope",
        endpoint=endpoint,
        os=operating_system,
        security=security,
        collectors={
            "fixture": CollectorStatus(name="fixture", status=CollectorState.SUCCESS)
        },
    )
    findings = PolicyEngine().evaluate(
        enterprise_policy,
        result.model_dump(mode="json"),
        EvaluationContext(
            scan_id=result.scan_id,
            endpoint_id=result.endpoint_id,
            platform=endpoint.os_family,
            scan_type=result.scan_type,
            detected_at=NOW,
        ),
    )

    assert {finding.rule_id for finding in findings} == expected_rules
