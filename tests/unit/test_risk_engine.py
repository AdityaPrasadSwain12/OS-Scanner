from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.analyzers import RiskConfiguration, RiskEngine
from app.models import Finding, FindingStatus, RiskLevel, Severity

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def finding(severity: Severity, **updates: object) -> Finding:
    values: dict[str, object] = {
        "scan_id": "scan-1",
        "rule_id": f"RULE-{severity.value}",
        "title": "Risk input",
        "severity": severity,
        "category": "endpoint_security",
        "description": "Risk input finding.",
        "endpoint_id": "endpoint-1",
        "remediation": "Correct the finding.",
        "detected_at": NOW,
        "first_seen_at": NOW,
    }
    values.update(updates)
    return Finding(**values)


def test_no_findings_is_healthy_when_scan_id_is_explicit() -> None:
    result = RiskEngine().calculate([], scan_id="scan-1", now=NOW)
    assert result.score == 100
    assert result.level is RiskLevel.HEALTHY
    assert result.risk_penalty == 0


def test_single_finding_uses_severity_and_contextual_factors() -> None:
    result = RiskEngine().calculate(
        [finding(Severity.CRITICAL, exploitability=1.0, exposure=1.0, compliance_impact=1.0)],
        asset_criticality=1.0,
        exposure=1.0,
        now=NOW + timedelta(days=90),
    )
    assert result.level is RiskLevel.CRITICAL
    assert result.score == 20
    assert result.factors["exploitability"] > 0
    assert result.finding_counts[Severity.CRITICAL] == 1


def test_resolved_and_suppressed_findings_do_not_reduce_health() -> None:
    findings = [
        finding(Severity.CRITICAL, status=FindingStatus.RESOLVED),
        finding(Severity.HIGH, status=FindingStatus.SUPPRESSED, rule_id="OTHER"),
    ]
    result = RiskEngine().calculate(findings, now=NOW)
    assert result.score == 100
    assert result.factors["active_findings"] == 0


def test_acknowledged_findings_retain_residual_risk() -> None:
    open_score = RiskEngine().calculate([finding(Severity.HIGH)], now=NOW).score
    acknowledged_score = (
        RiskEngine()
        .calculate([finding(Severity.HIGH, status=FindingStatus.ACKNOWLEDGED)], now=NOW)
        .score
    )
    assert open_score < acknowledged_score < 100


def test_configurable_thresholds_and_penalties() -> None:
    config = RiskConfiguration(
        severity_penalties={
            Severity.CRITICAL: 20,
            Severity.HIGH: 10,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
    )
    result = RiskEngine(config).calculate(
        [finding(Severity.HIGH)], asset_criticality=0, exposure=0, now=NOW
    )
    assert result.score == 90
    assert result.level is RiskLevel.HEALTHY


def test_mixed_scan_ids_are_rejected() -> None:
    with pytest.raises(ValueError, match="span multiple scans"):
        RiskEngine().calculate(
            [finding(Severity.LOW), finding(Severity.LOW, scan_id="scan-2", rule_id="OTHER")],
            now=NOW,
        )


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (85, RiskLevel.HEALTHY),
        (84.99, RiskLevel.LOW),
        (70, RiskLevel.LOW),
        (50, RiskLevel.MEDIUM),
        (30, RiskLevel.HIGH),
        (29.99, RiskLevel.CRITICAL),
    ],
)
def test_documented_score_bands(score: float, expected: RiskLevel) -> None:
    assert RiskEngine().level_for_score(score) is expected
