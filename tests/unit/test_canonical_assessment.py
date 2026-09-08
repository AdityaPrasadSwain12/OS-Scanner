from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.models.assessment import (
    CanonicalAssessmentReport,
    CoverageState,
    build_canonical_assessment,
)
from app.models.enums import (
    CollectorState,
    NetworkProtocol,
    OperatingSystemFamily,
    OverallStatus,
    ScanType,
    Severity,
)
from app.models.findings import Finding, Vulnerability
from app.models.inventory import (
    AntivirusProduct,
    CertificateInfo,
    DiskEncryptionVolume,
    Endpoint,
    FirewallProfile,
    ListeningPort,
    OperatingSystem,
    SecurityPosture,
    Software,
    UpdateInfo,
)
from app.models.results import CollectorStatus, ScanResult
from app.reporting.assessment_json import (
    CanonicalAssessmentJsonWriter,
    serialize_canonical_assessment,
)

NOW = datetime(2026, 9, 8, 10, tzinfo=UTC)
FINISHED = NOW + timedelta(minutes=2)
GENERATED = FINISHED + timedelta(seconds=5)
REQUIRED = (
    "collector_execution",
    "dependency_vulnerabilities",
    "endpoint_identity",
    "local_listeners",
    "operating_system",
    "patches",
    "software",
)


def _endpoint_scan(*, hostname: str = "workstation-01") -> ScanResult:
    return ScanResult(
        scan_id="scan-canonical-1",
        endpoint_id="endpoint-1",
        scan_type=ScanType.FULL,
        started_at=NOW,
        finished_at=FINISHED,
        status=OverallStatus.SUCCESS,
        authorization_scope_id="scope-1",
        endpoint=Endpoint(
            endpoint_id="endpoint-1",
            hostname=hostname,
            os_family=OperatingSystemFamily.WINDOWS,
        ),
        os=OperatingSystem(
            family=OperatingSystemFamily.WINDOWS,
            name="Microsoft Windows 11 Pro",
            version="10.0.26200",
            build="26200",
            hostname=hostname,
        ),
        software=[Software(name="Example Runtime", version="1.0", package_manager="pypi")],
        listening_ports=[
            ListeningPort(
                protocol=NetworkProtocol.TCP,
                address="0.0.0.0",  # noqa: S104 - scanner fixture for a wildcard listener
                port=8000,
                pid=123,
                process="python.exe",
                bind_scope="WILDCARD",
            )
        ],
        security=SecurityPosture(
            firewall_enabled=True,
            antivirus_enabled=True,
            local_admin_password_managed=False,
            firewall_profiles=[
                FirewallProfile(
                    name="Domain",
                    enabled=True,
                    default_inbound_action="Block",
                    default_outbound_action="Allow",
                    log_blocked=True,
                )
            ],
            antivirus_products=[
                AntivirusProduct(
                    name="Example Endpoint Protection",
                    enabled=True,
                    real_time_protection_enabled=True,
                    signatures_up_to_date=True,
                    signature_version="1.2.3",
                )
            ],
            encryption_volumes=[
                DiskEncryptionVolume(
                    mount_point="C:",
                    volume_status="FullyEncrypted",
                    protection_enabled=True,
                    encryption_method="XTS-AES-256",
                    encryption_percentage=100,
                )
            ],
        ),
        certificates=[
            CertificateInfo(
                store="LocalMachine\\Root",
                subject="CN=Example Root",
                issuer="CN=Example Root",
                not_after=GENERATED + timedelta(days=365),
                self_signed=True,
                expired=False,
            )
        ],
        updates=[
            UpdateInfo(
                update_id="KB-5000001",
                title="Security quality update",
                installed=False,
                security_update=True,
            )
        ],
        findings=[
            Finding(
                finding_id="finding-config-1",
                scan_id="scan-canonical-1",
                rule_id="config-1",
                title="Example configuration finding",
                severity=Severity.HIGH,
                category="configuration",
                description="An insecure configuration was observed.",
                endpoint_id="endpoint-1",
                remediation="Apply the approved secure configuration.",
                detected_at=FINISHED,
            )
        ],
        collectors={
            "native.inventory": CollectorStatus(
                name="native.inventory",
                status=CollectorState.SUCCESS,
                records_collected=5,
            )
        },
        metadata={
            "observed_inventory_sections": [
                "endpoint",
                "os",
                "software",
                "listening_ports",
                "security",
                "updates",
                "antivirus_products",
                "certificates",
                "disk_encryption",
                "firewall_profiles",
            ]
        },
    )


def _vulnerability(identifier: str, source: str) -> Vulnerability:
    return Vulnerability(
        scan_id="scan-canonical-1",
        endpoint_id="endpoint-1",
        vulnerability_id=identifier,
        aliases={"GHSA-aaaa-bbbb-cccc"},
        package_name="Example Runtime",
        package_ecosystem="PyPI",
        installed_version="1.0",
        fixed_versions=["1.1"],
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        summary="A package vulnerability was identified.",
        evidence={"source": source},
        detected_at=FINISHED,
    )


def _tool(name: str = "osv-scanner") -> CollectorStatus:
    return CollectorStatus(
        name=name,
        status=CollectorState.SUCCESS,
        tool_version="2.0.0",
        records_collected=1,
    )


def assessment(*, hostname: str = "workstation-01") -> CanonicalAssessmentReport:
    return build_canonical_assessment(
        _endpoint_scan(hostname=hostname),
        [_vulnerability("CVE-2026-0001", "osv-scanner")],
        analysis_tools=[_tool()],
        required_sections=REQUIRED,
        report_id="assessment-1",
        generated_at=GENERATED,
    )


def test_builder_merges_cloud_results_and_derives_every_summary() -> None:
    report = assessment()

    assert report.summary.status is OverallStatus.SUCCESS
    assert report.summary.finding_count == 3
    assert report.summary.severity_counts[Severity.CRITICAL] == 1
    assert report.summary.severity_counts[Severity.HIGH] == 1
    assert report.summary.severity_counts[Severity.MEDIUM] == 1
    assert report.summary.vulnerability_count == 1
    assert report.summary.missing_patch_count == 1
    assert report.summary.local_listener_count == 1
    assert report.summary.wildcard_listener_count == 1
    assert report.summary.certificate_count == 1
    assert report.summary.firewall_profile_count == 1
    assert report.summary.antivirus_product_count == 1
    assert report.summary.encryption_volume_count == 1
    assert report.summary.remotely_reachable_port_count is None
    assert report.summary.remote_reachability is CoverageState.NOT_TESTED
    assert report.risk.scan_id == report.endpoint_scan.scan_id
    assert report.provenance.vulnerability_sources == ("osv-scanner",)
    remote = next(
        item for item in report.coverage.sections if item.name == "remote_network_exposure"
    )
    assert remote.state is CoverageState.NOT_TESTED
    assert remote.required is False
    assert "external reachability was not tested" in next(
        item.detail for item in report.coverage.sections if item.name == "local_listeners"
    )


def test_report_rejects_tampered_summary_coverage_and_provenance() -> None:
    report = assessment()

    for key, mutation, message in (
        ("summary", {"finding_count": 99}, "severity counts"),
        ("provenance", {"canonical_scan_sha256": "0" * 64}, "provenance"),
    ):
        payload = report.model_dump(mode="python")
        payload[key].update(mutation)
        with pytest.raises(ValidationError, match=message):
            CanonicalAssessmentReport.model_validate(payload)

    payload = report.model_dump(mode="python")
    local = next(
        item for item in payload["coverage"]["sections"] if item["name"] == "local_listeners"
    )
    local["state"] = "NOT_OBSERVED"
    with pytest.raises(ValidationError, match="coverage completeness"):
        CanonicalAssessmentReport.model_validate(payload)


def test_failed_cloud_analysis_is_explicitly_partial() -> None:
    failed = CollectorStatus(
        name="depscan",
        status=CollectorState.FAILED,
        error_code="ANALYSIS_FAILED",
    )
    report = build_canonical_assessment(
        _endpoint_scan(),
        analysis_tools=[failed],
        required_sections=REQUIRED,
        report_id="assessment-partial",
        generated_at=GENERATED,
    )

    assert report.summary.status is OverallStatus.PARTIAL
    assert report.coverage.complete is False
    assert report.coverage.degraded_sources == ("cloud.depscan",)
    assert any("dependency_vulnerabilities" in item for item in report.limitations)


def test_canonical_json_is_deterministic_round_trippable_and_preserves_booleans(
    tmp_path: Path,
) -> None:
    report = assessment()
    first = serialize_canonical_assessment(report)
    second = serialize_canonical_assessment(report.model_dump(mode="json"))

    assert first == second
    assert hashlib.sha256(first.content).hexdigest() == first.sha256
    decoded = json.loads(first.content)
    assert decoded["endpoint_scan"]["security"]["local_admin_password_managed"] is False
    assert decoded["summary"]["remote_reachability"] == "NOT_TESTED"

    destination = CanonicalAssessmentJsonWriter().write(report, tmp_path / "assessment.json")
    assert destination.read_bytes() == first.content
    assert not list(tmp_path.glob("*.tmp"))


def test_cloud_vulnerability_must_belong_to_assessed_device() -> None:
    unrelated = _vulnerability("CVE-2026-0002", "depscan").model_copy(
        update={"endpoint_id": "endpoint-other"}
    )
    with pytest.raises(ValueError, match="must belong"):
        build_canonical_assessment(
            _endpoint_scan(),
            [unrelated],
            analysis_tools=[_tool()],
            required_sections=REQUIRED,
            generated_at=GENERATED,
        )
