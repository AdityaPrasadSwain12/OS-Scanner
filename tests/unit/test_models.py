from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.core import (
    AnalysisSettings,
    CloudAPISettings,
    CloudRouteSettings,
    DiscoverySettings,
    PrivacySettings,
    ScannerSettings,
    ToolSettings,
)
from app.models import (
    AuthorizationScope,
    CollectorState,
    CollectorStatus,
    Endpoint,
    IPAddress,
    NetworkInterface,
    OverallStatus,
    PersistenceItem,
    Process,
    ScanJob,
    ScanResult,
    ScanType,
    Service,
)
from app.reporting import serialize_report
from app.transport import CloudApiRoutes, TransportConfigurationError

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def scope(**updates: object) -> AuthorizationScope:
    values: dict[str, object] = {
        "scope_id": "scope-1",
        "authorized": True,
        "authorization_reference": "change-123",
        "valid_from": NOW - timedelta(hours=1),
        "expires_at": NOW + timedelta(hours=1),
        "allowed_endpoint_ids": {"endpoint-123"},
        "allowed_domains": {"example.com"},
        "excluded_domains": {"blocked.example.com"},
    }
    values.update(updates)
    return AuthorizationScope(**values)


def test_strict_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        Endpoint(endpoint_id="endpoint-123", hostname="host", accidental_secret="nope")


def test_timestamps_must_be_timezone_aware() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        Endpoint(endpoint_id="endpoint-123", hostname="host", last_seen_at=datetime(2026, 1, 1))


def test_network_values_are_normalized() -> None:
    interface = NetworkInterface(
        name="ethernet0",
        mac_address="AA-BB-CC-DD-EE-FF",
        addresses=[IPAddress(address="2001:0db8::1", prefix_length=64)],
        gateways=["192.0.2.1"],
    )
    assert interface.mac_address == "aa:bb:cc:dd:ee:ff"
    assert interface.addresses[0].address == "2001:db8::1"
    assert interface.addresses[0].family == 6


def test_authorization_scope_uses_dns_label_boundaries_and_exclusions() -> None:
    authorized = scope()
    assert authorized.allows_domain("api.example.com")
    assert not authorized.allows_domain("evil-example.com")
    assert not authorized.allows_domain("deep.blocked.example.com")


@pytest.mark.parametrize(
    "target",
    ["https://example.com", "*.example.com", "example.com:443", "localhost", "127.0.0.1"],
)
def test_authorization_scope_rejects_non_domain_targets(target: str) -> None:
    with pytest.raises(ValueError):
        scope(allowed_domains={target})


def test_attack_surface_job_requires_explicit_domain_scope() -> None:
    job = ScanJob(
        scan_type=ScanType.ATTACK_SURFACE,
        target="Api.Example.COM.",
        authorization=scope(),
    )
    assert job.target == "api.example.com"
    job.validate_for_execution(NOW)

    with pytest.raises(ValidationError, match="outside the authorized domain scope"):
        ScanJob(scan_type=ScanType.ATTACK_SURFACE, target="example.net", authorization=scope())


def test_job_parameters_are_allowlisted_and_domain_scoped() -> None:
    with pytest.raises(ValidationError, match="unsupported scan parameters"):
        ScanJob(
            scan_type=ScanType.FULL,
            endpoint_id="endpoint-123",
            authorization=scope(),
            parameters={"shell_command": "whoami"},
        )
    with pytest.raises(ValidationError, match="outside authorization scope"):
        ScanJob(
            scan_type=ScanType.ATTACK_SURFACE,
            target="example.com",
            authorization=scope(),
            parameters={"scope": ["example.net"]},
        )
    job = ScanJob(
        scan_type=ScanType.ATTACK_SURFACE,
        target="example.com",
        authorization=scope(),
        parameters={"scope": ["Api.Example.com."]},
    )
    assert job.parameters["scope"] == ["api.example.com"]


def test_endpoint_job_requires_endpoint_allowlist() -> None:
    job = ScanJob(scan_type=ScanType.FULL, endpoint_id="endpoint-123", authorization=scope())
    job.validate_for_execution(NOW)
    with pytest.raises(ValidationError, match="outside the authorized scope"):
        ScanJob(scan_type=ScanType.FULL, endpoint_id="endpoint-999", authorization=scope())
    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        ScanJob(scan_type=ScanType.FULL, endpoint_id="bad/id", authorization=scope())


def test_authorization_rejects_invalid_endpoint_identifier_before_collection() -> None:
    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        scope(allowed_endpoint_ids={"bad/id"})


def test_on_demand_job_requires_controlled_collectors() -> None:
    with pytest.raises(ValidationError, match="approved collector"):
        ScanJob(scan_type=ScanType.ON_DEMAND, endpoint_id="endpoint-123", authorization=scope())
    job = ScanJob(
        scan_type=ScanType.ON_DEMAND,
        endpoint_id="endpoint-123",
        authorization=scope(),
        approved_collectors={"osquery_basic"},
    )
    assert job.approved_collectors == frozenset({"osquery_basic"})


def test_expired_authorization_cannot_execute() -> None:
    expired = scope(valid_from=NOW - timedelta(days=2), expires_at=NOW - timedelta(days=1))
    job = ScanJob(scan_type=ScanType.FULL, endpoint_id="endpoint-123", authorization=expired)
    with pytest.raises(ValueError, match="not active"):
        job.validate_for_execution(NOW)


def test_collector_failures_require_bounded_error() -> None:
    with pytest.raises(ValidationError, match="require a bounded error"):
        CollectorStatus(name="osquery", status=CollectorState.FAILED)
    status = CollectorStatus(
        name="osquery", status=CollectorState.FAILED, error_code="EXIT_NONZERO"
    )
    assert status.status is CollectorState.FAILED


def test_process_command_lines_and_collector_errors_are_redacted() -> None:
    process = Process(pid=1, name="client", command_line="client --token super-secret")
    collector = CollectorStatus(
        name="tool",
        status=CollectorState.FAILED,
        error_message="Authorization: Bearer super-secret",
    )
    assert "super-secret" not in process.command_line
    assert "super-secret" not in collector.error_message


def test_service_and_persistence_commands_are_redacted_in_results_and_reports() -> None:
    secrets = ("service-password", "scheduled-token", "authorization-value")
    result = ScanResult(
        scan_id="scan-command-redaction",
        endpoint_id="endpoint-123",
        scan_type=ScanType.FULL,
        started_at=NOW,
        finished_at=NOW,
        status=OverallStatus.SUCCESS,
        authorization_scope_id="scope-1",
        services=[
            Service(
                name="enterprise-agent",
                executable_path=(
                    '"C:\\Program Files\\Enterprise Agent\\agent.exe" '
                    f"--password={secrets[0]} --mode monitor"
                ),
            )
        ],
        persistence=[
            PersistenceItem(
                name="inventory-sync",
                kind="scheduled_task",
                executable_path=f"/opt/enterprise/bin/sync --token {secrets[1]} --delta",
            ),
            PersistenceItem(
                name="status-publish",
                kind="cron",
                executable_path=(
                    "/usr/bin/curl -H "
                    f"'Authorization: Bearer {secrets[2]}' https://scanner.example.test/status"
                ),
            ),
        ],
    )

    serialized_result = result.model_dump_json()
    serialized_report = serialize_report(result).decode("utf-8")
    for serialized in (serialized_result, serialized_report):
        assert all(secret not in serialized for secret in secrets)
        assert "agent.exe" in serialized
        assert "/opt/enterprise/bin/sync" in serialized
        assert "/usr/bin/curl" in serialized
        assert "<redacted>" in serialized


def test_result_status_is_derived_from_partial_collector_success() -> None:
    collectors = {
        "osquery": CollectorStatus(name="osquery", status=CollectorState.SUCCESS),
        "openscap": CollectorStatus(name="openscap", status=CollectorState.UNAVAILABLE),
    }
    assert ScanResult.status_from_collectors(collectors) is OverallStatus.PARTIAL


def test_cloud_configuration_enforces_tls() -> None:
    with pytest.raises(ValidationError, match="must use HTTPS"):
        CloudAPISettings(base_url="http://scanner.example.com")
    secure = CloudAPISettings(base_url="https://scanner.example.com/")
    assert secure.base_url == "https://scanner.example.com"

    prefixed = CloudAPISettings(
        base_url="https://scanner.example.com/control-plane/"
    )
    assert prefixed.base_url == "https://scanner.example.com/control-plane"

    local = CloudAPISettings(
        base_url="http://127.0.0.1:8080",
        allow_insecure_loopback_http=True,
    )
    assert local.base_url == "http://127.0.0.1:8080"
    with pytest.raises(ValidationError, match="development or test"):
        ScannerSettings(cloud=local)
    assert ScannerSettings(environment="development", cloud=local).cloud is local

    with pytest.raises(ValidationError, match="must use HTTPS"):
        CloudAPISettings(
            base_url="http://192.0.2.1:8080",
            allow_insecure_loopback_http=True,
        )


@pytest.mark.parametrize(
    "base_url",
    (
        "https://user:password@scanner.example.com/control-plane",
        "https://scanner.example.com/control-plane?tenant=one",
        "https://scanner.example.com/control-plane#fragment",
        "https://scanner.example.com/control\\plane",
        "https://scanner.example.com/control\x01plane",
        "https://scanner.example.com/control/./plane",
        "https://scanner.example.com/control/../admin",
        "https://scanner.example.com/control/%2e%2e/admin",
    ),
)
def test_cloud_configuration_rejects_ambiguous_or_traversing_base_paths(
    base_url: str,
) -> None:
    with pytest.raises(ValidationError):
        CloudAPISettings(base_url=base_url)


@pytest.mark.parametrize(
    ("field", "valid_template"),
    (
        (
            "credential_rotation_path_template",
            "/tenant/endpoints/{endpoint_id}/rotate",
        ),
        ("scan_lookup_path_template", "/tenant/scans/{scan_id}"),
        ("next_scan_path_template", "/tenant/jobs/{endpoint_id}/next"),
    ),
)
def test_cloud_route_templates_require_the_exact_locally_defined_placeholder(
    field: str,
    valid_template: str,
) -> None:
    configured = CloudRouteSettings.model_validate({field: valid_template})
    assert getattr(configured, field) == valid_template
    expected_placeholder = "scan_id" if field == "scan_lookup_path_template" else "endpoint_id"
    wrong_placeholder = "endpoint_id" if expected_placeholder == "scan_id" else "scan_id"

    for invalid in (
        valid_template.replace("{endpoint_id}", "static").replace("{scan_id}", "static"),
        valid_template.replace(expected_placeholder, wrong_placeholder),
        f"{valid_template}/{{tenant_id}}",
        valid_template.replace("{", "{{"),
    ):
        with pytest.raises(ValidationError, match="invalid placeholders"):
            CloudRouteSettings.model_validate({field: invalid})


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "relative/api/v1/scans",
        "//evil.example/scans",
        "https://evil.example/scans",
        "/api/v1/scans?tenant=one",
        "/api/v1/scans?",
        "/api/v1/scans#fragment",
        "/api/v1/scans#",
        "/api/v1/../admin",
        "/api/v1/%2e%2e/admin",
        "/api/v1/%252e%252e/admin",
        "/api/v1/%7Bevil%7D",
        "/api/v1/%257Bevil%257D",
        "/api\\v1/scans",
        "/api bad/scans",
        "/api/v1/%zz",
        "/api/v1/scans\x01",
        "/api/v1/scans\x7f",
    ),
)
def test_cloud_route_models_reject_ambiguous_or_unsafe_paths(unsafe_path: str) -> None:
    with pytest.raises(ValidationError, match="safe absolute API path"):
        CloudRouteSettings(scan_submit_path=unsafe_path)
    with pytest.raises(TransportConfigurationError, match="safe absolute path"):
        CloudApiRoutes(scan_submit_path=unsafe_path)


def test_transport_route_templates_enforce_exact_placeholders() -> None:
    assert (
        CloudApiRoutes(scan_lookup_path_template="/tenant/scans/{scan_id}")
        .scan_lookup_path_template
        == "/tenant/scans/{scan_id}"
    )
    for invalid in (
        "/tenant/scans/static",
        "/tenant/scans/{endpoint_id}",
        "/tenant/scans/{scan_id}/{tenant_id}",
        "/tenant/scans/{scan_id}/%7Btenant_id%7D",
        "/tenant/scans/{scan_id}/%257Btenant_id%257D",
        "/tenant/scans/{{scan_id}}",
    ):
        with pytest.raises(TransportConfigurationError, match="invalid placeholders"):
            CloudApiRoutes(scan_lookup_path_template=invalid)


def test_prohibited_privacy_collection_cannot_be_enabled() -> None:
    with pytest.raises(ValidationError):
        PrivacySettings(collect_private_keys=True)


def test_scap_default_must_be_under_local_approved_root(tmp_path) -> None:
    approved = tmp_path / "approved"
    with pytest.raises(ValidationError, match="approved local content root"):
        ToolSettings(
            approved_scap_content_roots=(approved,),
            default_scap_content=tmp_path / "outside" / "baseline.xml",
        )


def test_analysis_allowlists_are_opt_in_and_cannot_be_enforced_empty() -> None:
    assert AnalysisSettings().enforce_port_allowlist is False
    with pytest.raises(ValidationError, match="cannot be enforced while empty"):
        AnalysisSettings(enforce_port_allowlist=True)
    configured = AnalysisSettings(
        enforce_port_allowlist=True,
        allowed_listening_ports={22, 443},
    )
    assert configured.allowed_listening_ports == frozenset({22, 443})


@pytest.mark.parametrize(
    "baseline",
    (
        {"unknown_security_field": True},
        {"configuration_drift": False},
        {"firewall_enabled": "yes"},
    ),
)
def test_approved_security_posture_strictly_validates_fields_and_types(
    baseline: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        AnalysisSettings(approved_security_posture=baseline)  # type: ignore[arg-type]

    configured = AnalysisSettings(
        approved_security_posture={
            "firewall_enabled": True,
            "pending_security_updates_count": 0,
        }
    )
    assert configured.approved_security_posture == {
        "firewall_enabled": True,
        "pending_security_updates_count": 0,
    }


def test_environment_loader_uses_allowlisted_keys_only() -> None:
    settings = ScannerSettings.from_env(
        environ={
            "SCANNER_MAX_CONCURRENCY": "8",
            "SCANNER_DISCOVERY_ENABLED": "false",
            "SCANNER_UNRECOGNIZED_SECRET": "must-not-enter-model",
        }
    )
    assert settings.runtime.max_concurrency == 8
    assert settings.discovery.enabled is False
    assert "must-not-enter-model" not in settings.model_dump_json()


def test_enabled_discovery_requires_local_authorization_roots() -> None:
    with pytest.raises(ValidationError, match="authorized_domains"):
        DiscoverySettings(enabled=True)

    configured = DiscoverySettings(
        enabled=True,
        authorized_domains={"Example.COM."},
    )
    assert configured.authorized_domains == frozenset({"example.com"})


def test_discovery_asset_limit_matches_amass_parser_bound() -> None:
    configured = DiscoverySettings(
        enabled=True,
        authorized_domains={"example.test"},
        max_discovered_assets=100_000,
    )
    assert configured.max_discovered_assets == 100_000
    with pytest.raises(ValueError, match="less than or equal to 100000"):
        DiscoverySettings(
            enabled=True,
            authorized_domains={"example.test"},
            max_discovered_assets=100_001,
        )


def test_environment_loader_uses_scanner_version_key() -> None:
    settings = ScannerSettings.from_env(
        environ={
            "SCANNER_VERSION": "2.3.4",
            "SCANNER_SCHEMA_VERSION": "1.0",
        }
    )

    assert settings.scanner_version == "2.3.4"
    assert settings.schema_version == "1.0"
