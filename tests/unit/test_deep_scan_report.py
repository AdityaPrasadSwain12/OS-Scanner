from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import DiscoverySettings, ScannerSettings, ToolSettings
from app.models.deep_scan import (
    DeepScanAuditContext,
    DeepScanJobAudit,
    DeepScanReport,
    DeepScanToolReadiness,
    build_deep_scan_report,
)
from app.models.enums import (
    AssetType,
    CollectorState,
    OperatingSystemFamily,
    OverallStatus,
    ScanType,
)
from app.models.findings import AttackSurfaceAsset
from app.models.inventory import Endpoint, OperatingSystem, Software, UpdateInfo
from app.models.jobs import ScanJob
from app.models.results import CollectorStatus, ScanResult
from app.orchestrator.collector_pipeline import CollectionBundle, CollectorPipeline
from app.orchestrator.deep_scan import (
    DeepScanRequest,
    StatelessDeepScanOrchestrator,
    build_tool_readiness,
    create_ephemeral_orchestrator,
    run_deep_scan,
)
from app.reporting.deep_scan_json import DeepScanJsonWriter
from app.reporting.json_report import ReportTooLargeError

NOW = datetime(2026, 9, 1, 10, tzinfo=UTC)
FINISHED = NOW + timedelta(seconds=5)
SCOPE_ID = "scope-deep-test"


def _audit_context(
    *,
    attack_surface: bool = False,
    authorization_reference: str = "change-SEC-42",
) -> DeepScanAuditContext:
    jobs = [
        DeepScanJobAudit(
            job_id="job-endpoint",
            scan_id="scan-endpoint",
            scan_type=ScanType.FULL,
            initiated_by="security-operator",
            requested_at=NOW,
            deadline=FINISHED + timedelta(minutes=5),
            endpoint_id="endpoint-1",
        )
    ]
    if attack_surface:
        jobs.append(
            DeepScanJobAudit(
                job_id="job-domain",
                scan_id="scan-domain",
                scan_type=ScanType.ATTACK_SURFACE,
                initiated_by="security-operator",
                requested_at=NOW,
                deadline=FINISHED + timedelta(minutes=5),
                target="example.com",
            )
        )
    return DeepScanAuditContext(
        authorization_scope_id=SCOPE_ID,
        authorization_reference=authorization_reference,
        authorized_by="enterprise-security",
        purpose="approved endpoint assessment",
        valid_from=NOW - timedelta(minutes=1),
        expires_at=FINISHED + timedelta(minutes=10),
        allowed_endpoint_ids=("endpoint-1",),
        allowed_domains=("example.com",) if attack_surface else (),
        allow_subdomains=True,
        jobs=tuple(jobs),
    )


def _endpoint_result(*, observed: tuple[str, ...] = ("os", "software", "updates")) -> ScanResult:
    return ScanResult(
        scan_id="scan-endpoint",
        endpoint_id="endpoint-1",
        scan_type=ScanType.FULL,
        started_at=NOW,
        finished_at=FINISHED,
        status=OverallStatus.SUCCESS,
        authorization_scope_id=SCOPE_ID,
        os=OperatingSystem(
            family=OperatingSystemFamily.WINDOWS,
            name="Windows",
            version="11",
        ),
        software=[Software(name="Example", version="1.0")],
        updates=[
            UpdateInfo(update_id="KB-1", installed=False, security_update=True),
            UpdateInfo(update_id="KB-2", installed=True, security_update=True),
        ],
        collectors={
            "native.inventory": CollectorStatus(
                name="native.inventory",
                status=CollectorState.SUCCESS,
                records_collected=3,
            )
        },
        metadata={"observed_inventory_sections": list(observed)},
    )


def _attack_surface_result(
    *,
    observed: bool = True,
    status: CollectorState = CollectorState.SUCCESS,
) -> ScanResult:
    error = "discovery unavailable" if status is CollectorState.FAILED else None
    overall = OverallStatus.SUCCESS if status is CollectorState.SUCCESS else OverallStatus.FAILED
    return ScanResult(
        scan_id="scan-domain",
        scan_type=ScanType.ATTACK_SURFACE,
        started_at=NOW + timedelta(seconds=1),
        finished_at=FINISHED + timedelta(seconds=1),
        status=overall,
        authorization_scope_id=SCOPE_ID,
        attack_surface=[
            AttackSurfaceAsset(
                scan_id="scan-domain",
                hostname="api.example.com",
                root_domain="example.com",
                asset_type=AssetType.SUBDOMAIN,
                in_scope=True,
            )
        ]
        if observed
        else [],
        collectors={
            "amass": CollectorStatus(
                name="amass",
                status=status,
                records_collected=1 if observed else 0,
                error_code="AMASS_FAILED" if error else None,
                error_message=error,
            )
        },
        metadata={
            "authorized_target": "example.com",
            "observed_inventory_sections": ["attack_surface"] if observed else [],
        },
    )


def test_combined_report_keeps_evidence_separate_and_derives_summary() -> None:
    report = build_deep_scan_report(
        _endpoint_result(),
        [_attack_surface_result()],
        audit_context=_audit_context(attack_surface=True),
        required_endpoint_sections=["os", "software", "updates"],
        requested_attack_surface_domains=["example.com"],
        tool_readiness=[
            DeepScanToolReadiness(
                name="native",
                configured=True,
                scheduled=True,
                status=CollectorState.SUCCESS,
                collector_names=("endpoint:native.inventory",),
                records_collected=3,
            )
        ],
        report_id="deep-test",
        generated_at=FINISHED + timedelta(seconds=2),
    )

    assert report.endpoint_scan.endpoint_id == "endpoint-1"
    assert report.endpoint_scan.attack_surface == []
    assert report.audit_context.jobs[0].job_id == "job-endpoint"
    assert report.audit_context.jobs[1].job_id == "job-domain"
    assert report.audit_context.authorization_reference == "change-SEC-42"
    assert report.attack_surface_scans[0].endpoint_id is None
    assert report.summary.status is OverallStatus.SUCCESS
    assert report.summary.scan_count == 2
    assert report.summary.software_count == 1
    assert report.summary.update_count == 2
    assert report.summary.missing_patch_count == 1
    assert report.summary.attack_surface_asset_count == 1
    assert report.completeness.complete is True


def test_completeness_exposes_missing_sections_domains_and_failed_collectors() -> None:
    report = build_deep_scan_report(
        _endpoint_result(observed=("os",)),
        [_attack_surface_result(observed=False, status=CollectorState.FAILED)],
        audit_context=_audit_context(attack_surface=True),
        required_endpoint_sections=["os", "software", "updates"],
        requested_attack_surface_domains=["example.com"],
        report_id="deep-incomplete",
        generated_at=FINISHED + timedelta(seconds=2),
    )

    assert report.summary.status is OverallStatus.PARTIAL
    assert report.completeness.complete is False
    assert report.completeness.unobserved_endpoint_sections == (
        "software",
        "updates",
    )
    assert report.completeness.unobserved_attack_surface_domains == ("example.com",)
    assert report.completeness.degraded_collectors == ("attack-surface:example.com:amass",)


def test_scheduled_tool_gap_makes_coverage_and_summary_partial() -> None:
    report = build_deep_scan_report(
        _endpoint_result(),
        audit_context=_audit_context(),
        required_endpoint_sections=["os", "software", "updates"],
        tool_readiness=[
            DeepScanToolReadiness(
                name="depscan",
                configured=False,
                scheduled=True,
                status=CollectorState.SKIPPED,
                detail="tool is not configured",
            )
        ],
        report_id="deep-tool-gap",
        generated_at=FINISHED + timedelta(seconds=1),
    )

    assert report.completeness.complete is False
    assert report.completeness.degraded_collectors == ("tool:depscan",)
    assert report.summary.status is OverallStatus.PARTIAL


def test_strict_report_rejects_a_summary_that_does_not_match_evidence() -> None:
    report = build_deep_scan_report(
        _endpoint_result(),
        audit_context=_audit_context(),
        required_endpoint_sections=["os", "software", "updates"],
        report_id="deep-summary",
        generated_at=FINISHED + timedelta(seconds=1),
    )
    payload = report.model_dump(mode="python")
    payload["summary"]["software_count"] = 99

    with pytest.raises(ValidationError, match="summary does not match"):
        DeepScanReport.model_validate(payload)


def test_strict_report_rejects_audit_context_not_bound_to_child_results() -> None:
    report = build_deep_scan_report(
        _endpoint_result(),
        audit_context=_audit_context(),
        required_endpoint_sections=["os", "software", "updates"],
        report_id="deep-audit",
        generated_at=FINISHED + timedelta(seconds=1),
    )
    payload = report.model_dump(mode="python")
    payload["audit_context"]["jobs"][0]["scan_id"] = "scan-unrelated"

    with pytest.raises(ValidationError, match="identify every deep-scan child"):
        DeepScanReport.model_validate(payload)


def test_audit_context_rejects_jobs_outside_authorized_scope() -> None:
    payload = _audit_context(attack_surface=True).model_dump(mode="python")
    payload["allowed_domains"] = ["different.example"]

    with pytest.raises(ValidationError, match="target is outside"):
        DeepScanAuditContext.model_validate(payload)


def test_json_writer_is_deterministic_atomic_and_applies_final_redaction(
    tmp_path: Path,
) -> None:
    report = build_deep_scan_report(
        _endpoint_result(),
        audit_context=_audit_context(
            authorization_reference="change-SEC-42 token=must-not-leak"
        ),
        required_endpoint_sections=["os", "software", "updates"],
        report_id="deep-json",
        generated_at=FINISHED + timedelta(seconds=1),
    )
    unsafe_endpoint = report.endpoint_scan.model_copy(
        update={
            "endpoint": Endpoint(
                endpoint_id="endpoint-1",
                hostname="endpoint",
                tags={"zeta", "alpha"},
            ),
            "metadata": {"api_token": "must-not-leak"},
        }
    )
    unsafe_report = report.model_copy(update={"endpoint_scan": unsafe_endpoint})
    writer = DeepScanJsonWriter()

    first = writer.write(unsafe_report, tmp_path / "first.json")
    second = writer.write(unsafe_report, tmp_path / "second.json")

    assert first.read_bytes() == second.read_bytes()
    assert b"must-not-leak" not in first.read_bytes()
    assert b"<redacted>" in first.read_bytes()
    decoded = json.loads(first.read_text(encoding="utf-8"))
    assert decoded["report_id"] == "deep-json"
    assert decoded["authorization_scope_id"] == SCOPE_ID
    assert decoded["audit_context"]["authorization_scope_id"] == SCOPE_ID
    assert decoded["audit_context"]["authorization_reference"] == (
        "change-SEC-42 token=<redacted>"
    )
    assert decoded["audit_context"]["jobs"][0]["job_id"] == "job-endpoint"
    assert decoded["endpoint_scan"]["endpoint"]["tags"] == ["alpha", "zeta"]
    assert not list(tmp_path.glob("*.tmp"))


def test_json_writer_rejects_non_json_and_does_not_leave_oversized_output(
    tmp_path: Path,
) -> None:
    report = build_deep_scan_report(
        _endpoint_result(),
        audit_context=_audit_context(),
        required_endpoint_sections=["os", "software", "updates"],
        report_id="deep-size",
        generated_at=FINISHED + timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match=r"\.json"):
        DeepScanJsonWriter().write(report, tmp_path / "report.pdf")

    destination = tmp_path / "oversized.json"
    with pytest.raises(ReportTooLargeError):
        DeepScanJsonWriter(max_bytes=32).write(report, destination)
    assert not destination.exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_stateless_factory_opens_no_database_and_creates_no_child_reports(
    tmp_path: Path,
) -> None:
    settings = ScannerSettings(environment="test", data_directory=tmp_path / "persistent")
    owner = create_ephemeral_orchestrator(settings)
    try:
        assert not hasattr(owner.scanner, "storage")
        assert not settings.data_directory.exists()
    finally:
        owner.close()

    assert not settings.database_path.exists()


def test_configured_depscan_live_os_is_scheduled_without_dependency_roots(
    tmp_path: Path,
) -> None:
    settings = ScannerSettings(
        environment="test",
        tools=ToolSettings(depscan_executable=tmp_path / "depscan.exe"),
    )
    endpoint = _endpoint_result().model_copy(
        update={
            "collectors": {
                "native.inventory": CollectorStatus(
                    name="native.inventory",
                    status=CollectorState.SUCCESS,
                ),
                "depscan": CollectorStatus(
                    name="depscan",
                    status=CollectorState.SUCCESS,
                    records_collected=2,
                ),
            }
        }
    )

    readiness = {
        item.name: item
        for item in build_tool_readiness(
            settings,
            endpoint,
            (),
            dependency_sources_requested=False,
            attack_surface_requested=False,
        )
    }

    assert readiness["depscan"].configured is True
    assert readiness["depscan"].scheduled is True
    assert readiness["depscan"].status is CollectorState.SUCCESS
    assert readiness["depscan"].records_collected == 2


def test_tool_readiness_ignores_optional_skips_when_native_collection_succeeds() -> None:
    endpoint = _endpoint_result().model_copy(
        update={
            "collectors": {
                "native.inventory": CollectorStatus(
                    name="native.inventory",
                    status=CollectorState.SUCCESS,
                    records_collected=3,
                ),
                "native.optional-firewall": CollectorStatus(
                    name="native.optional-firewall",
                    status=CollectorState.SKIPPED,
                    error_message="facility is not installed",
                ),
            }
        }
    )

    readiness = {
        item.name: item
        for item in build_tool_readiness(
            ScannerSettings(environment="test"),
            endpoint,
            (),
            dependency_sources_requested=False,
            attack_surface_requested=False,
        )
    }

    assert readiness["native"].status is CollectorState.SUCCESS
    assert readiness["native"].records_collected == 3


class _DeepScanPipeline(CollectorPipeline):
    def __init__(self) -> None:
        # The test supplies its own complete normalized bundles, so external
        # adapters and native subprocess collectors are intentionally absent.
        pass

    def collect(
        self,
        job: ScanJob,
        *,
        deadline_at: float | None = None,
    ) -> CollectionBundle:
        del deadline_at
        if job.scan_type is ScanType.ATTACK_SURFACE:
            assert job.target is not None
            return CollectionBundle(
                inventory={
                    "attack_surface": [
                        AttackSurfaceAsset(
                            scan_id=job.scan_id,
                            hostname=f"api.{job.target}",
                            root_domain=job.target,
                            in_scope=True,
                        )
                    ]
                },
                collectors={
                    "amass": CollectorStatus(
                        name="amass",
                        status=CollectorState.SUCCESS,
                        records_collected=1,
                    )
                },
                observed_inventory_sections={"attack_surface"},
            )
        return CollectionBundle(
            inventory={
                "hostname": "endpoint",
                "os": OperatingSystem(
                    family=OperatingSystemFamily.WINDOWS,
                    name="Windows",
                    version="11",
                ),
                "software": [Software(name="Example", version="1.0")],
                "updates": [UpdateInfo(update_id="KB-1", installed=False)],
            },
            collectors={
                "native.inventory": CollectorStatus(
                    name="native.inventory",
                    status=CollectorState.SUCCESS,
                    records_collected=3,
                )
            },
            observed_inventory_sections={
                "browser_extensions",
                "hardware",
                "listening_ports",
                "network_interfaces",
                "os",
                "persistence",
                "processes",
                "security",
                "services",
                "software",
                "updates",
                "users",
            },
        )


def test_run_deep_scan_leaves_only_final_combined_json(tmp_path: Path) -> None:
    settings = ScannerSettings(
        environment="test",
        data_directory=tmp_path / "persistent",
        discovery=DiscoverySettings(
            enabled=True,
            authorized_domains=frozenset({"example.com"}),
        ),
    )

    def factory(config: ScannerSettings) -> StatelessDeepScanOrchestrator:
        return create_ephemeral_orchestrator(
            config,
            collectors=_DeepScanPipeline(),
        )

    output = tmp_path / "final" / "deep-report.json"
    outcome = run_deep_scan(
        settings,
        DeepScanRequest(
            authorized=True,
            endpoint_id="endpoint-1",
            authorized_domains=("example.com",),
            output_path=output,
        ),
        orchestrator_factory=factory,
    )

    assert outcome.report_path == output.resolve()
    assert outcome.report.summary.scan_count == 2
    assert len(outcome.report.audit_context.jobs) == 2
    assert outcome.report.audit_context.jobs[0].job_id.startswith("job-")
    assert outcome.report.audit_context.authorization_reference == "local-deep-scan-consent"
    assert outcome.report.summary.status is OverallStatus.PARTIAL
    assert outcome.report.completeness.complete is False
    assert "tool:osquery" in outcome.report.completeness.degraded_collectors
    assert (
        json.loads(output.read_text(encoding="utf-8"))["summary"]["attack_surface_asset_count"] == 1
    )
    assert not settings.database_path.exists()
    assert [path for path in tmp_path.rglob("*.json") if path != output] == []


class _FailingDeepScanPipeline(CollectorPipeline):
    def __init__(self, error: Exception) -> None:
        self.error = error

    def collect(
        self,
        job: ScanJob,
        *,
        deadline_at: float | None = None,
    ) -> CollectionBundle:
        del job, deadline_at
        raise self.error


@pytest.mark.parametrize(
    ("error", "expected_state", "expected_code"),
    [
        (
            TimeoutError("global scan deadline exceeded"),
            CollectorState.TIMEOUT,
            "DEEP_SCAN_TIMEOUT",
        ),
        (
            RuntimeError("unexpected collector failure"),
            CollectorState.FAILED,
            "DEEP_SCAN_EXECUTION_FAILED",
        ),
    ],
)
def test_run_deep_scan_persists_terminal_json_when_child_execution_fails(
    tmp_path: Path,
    error: Exception,
    expected_state: CollectorState,
    expected_code: str,
) -> None:
    settings = ScannerSettings(
        environment="test",
        data_directory=tmp_path / "persistent",
    )

    def factory(config: ScannerSettings) -> StatelessDeepScanOrchestrator:
        return create_ephemeral_orchestrator(
            config,
            collectors=_FailingDeepScanPipeline(error),
        )

    output = tmp_path / "terminal-report.json"
    outcome = run_deep_scan(
        settings,
        DeepScanRequest(
            authorized=True,
            endpoint_id="endpoint-1",
            output_path=output,
        ),
        orchestrator_factory=factory,
    )

    collector = outcome.report.endpoint_scan.collectors["deep-scan"]
    assert outcome.report.endpoint_scan.status is OverallStatus.FAILED
    assert outcome.report.summary.status is OverallStatus.FAILED
    assert collector.status is expected_state
    assert collector.error_code == expected_code
    assert outcome.report.completeness.complete is False
    assert "endpoint:deep-scan" in outcome.report.completeness.degraded_collectors
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["status"] == "FAILED"
    assert not settings.database_path.exists()
