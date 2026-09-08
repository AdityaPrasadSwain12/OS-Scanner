"""Configurable health-oriented endpoint risk scoring."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from pydantic import Field, field_validator, model_validator

from app.models import Finding, FindingStatus, RiskLevel, RiskScore, Severity
from app.models.base import StrictModel, ensure_aware


def _default_severity_penalties() -> dict[Severity, float]:
    return {
        Severity.CRITICAL: 40.0,
        Severity.HIGH: 25.0,
        Severity.MEDIUM: 12.0,
        Severity.LOW: 5.0,
        Severity.INFO: 1.0,
    }


class RiskConfiguration(StrictModel):
    """Tunable scoring inputs. Scores remain in the documented 0-100 bands."""

    severity_penalties: dict[Severity, float] = Field(default_factory=_default_severity_penalties)
    exploitability_weight: float = Field(default=0.25, ge=0.0, le=1.0)
    asset_criticality_weight: float = Field(default=0.20, ge=0.0, le=1.0)
    exposure_weight: float = Field(default=0.20, ge=0.0, le=1.0)
    compliance_impact_weight: float = Field(default=0.20, ge=0.0, le=1.0)
    age_weight: float = Field(default=0.15, ge=0.0, le=1.0)
    age_saturation_days: float = Field(default=90.0, gt=0.0, le=3_650.0)
    acknowledged_multiplier: float = Field(default=0.85, ge=0.0, le=1.0)
    healthy_minimum: float = Field(default=85.0, ge=0.0, le=100.0)
    low_minimum: float = Field(default=70.0, ge=0.0, le=100.0)
    medium_minimum: float = Field(default=50.0, ge=0.0, le=100.0)
    high_minimum: float = Field(default=30.0, ge=0.0, le=100.0)

    @field_validator("severity_penalties")
    @classmethod
    def validate_severity_penalties(cls, values: dict[Severity, float]) -> dict[Severity, float]:
        missing = set(Severity) - set(values)
        if missing:
            raise ValueError(
                f"severity penalties missing: {sorted(str(item) for item in missing)!r}"
            )
        if any(value < 0.0 or value > 100.0 for value in values.values()):
            raise ValueError("severity penalties must be between 0 and 100")
        if not (
            values[Severity.CRITICAL]
            >= values[Severity.HIGH]
            >= values[Severity.MEDIUM]
            >= values[Severity.LOW]
            >= values[Severity.INFO]
        ):
            raise ValueError("severity penalties must descend from CRITICAL to INFO")
        return values

    @model_validator(mode="after")
    def validate_bands(self) -> RiskConfiguration:
        if not (
            100
            >= self.healthy_minimum
            > self.low_minimum
            > self.medium_minimum
            > self.high_minimum
            >= 0
        ):
            raise ValueError("risk band minimums must be strictly descending")
        return self


class RiskEngine:
    """Convert open findings into an auditable endpoint health score.

    The returned ``score`` is health-oriented (100 is healthiest); the separate
    ``risk_penalty`` exposes the accumulated risk for downstream analytics.
    """

    def __init__(self, config: RiskConfiguration | None = None) -> None:
        self.config = config or RiskConfiguration()

    def calculate(
        self,
        findings: Iterable[Finding],
        *,
        scan_id: str | None = None,
        asset_criticality: float = 0.5,
        exposure: float = 0.5,
        now: datetime | None = None,
        policy_version: str | None = None,
        scanner_version: str = "1.1.0",
    ) -> RiskScore:
        if not 0.0 <= asset_criticality <= 1.0:
            raise ValueError("asset_criticality must be between 0 and 1")
        if not 0.0 <= exposure <= 1.0:
            raise ValueError("exposure must be between 0 and 1")
        instant = ensure_aware(now) if now else datetime.now(UTC)
        materialized = list(findings)
        inferred_scan_ids = {finding.scan_id for finding in materialized}
        if scan_id is None:
            if len(inferred_scan_ids) != 1:
                raise ValueError(
                    "scan_id is required when findings are empty or span multiple scans"
                )
            scan_id = next(iter(inferred_scan_ids))
        elif inferred_scan_ids and inferred_scan_ids != {scan_id}:
            raise ValueError("all findings must belong to the requested scan_id")

        active = [
            finding
            for finding in materialized
            if finding.status not in {FindingStatus.RESOLVED, FindingStatus.SUPPRESSED}
        ]
        counts = {severity: 0 for severity in Severity}
        components = {
            "base_severity": 0.0,
            "exploitability": 0.0,
            "asset_criticality": 0.0,
            "exposure": 0.0,
            "compliance_impact": 0.0,
            "finding_age": 0.0,
        }
        for finding in active:
            counts[finding.severity] += 1
            base = self.config.severity_penalties[finding.severity]
            if finding.status is FindingStatus.ACKNOWLEDGED:
                base *= self.config.acknowledged_multiplier
            exploitability_factor = finding.exploitability or 0.0
            exposure_factor = max(exposure, finding.exposure or 0.0)
            compliance_factor = (
                finding.compliance_impact
                if finding.compliance_impact is not None
                else 1.0
                if finding.category == "compliance"
                else 0.0
            )
            age_origin = finding.first_seen_at or finding.detected_at
            age_days = max(0.0, (instant - age_origin).total_seconds() / 86_400.0)
            age_factor = min(1.0, age_days / self.config.age_saturation_days)

            components["base_severity"] += base
            components["exploitability"] += (
                base * self.config.exploitability_weight * exploitability_factor
            )
            components["asset_criticality"] += (
                base * self.config.asset_criticality_weight * asset_criticality
            )
            components["exposure"] += base * self.config.exposure_weight * exposure_factor
            components["compliance_impact"] += (
                base * self.config.compliance_impact_weight * compliance_factor
            )
            components["finding_age"] += base * self.config.age_weight * age_factor

        raw_penalty = sum(components.values())
        risk_penalty = min(100.0, raw_penalty)
        score = max(0.0, 100.0 - risk_penalty)
        rounded_score = round(score, 2)
        rounded_penalty = round(risk_penalty, 2)
        factors = {key: round(value, 4) for key, value in components.items()}
        factors["active_findings"] = float(len(active))
        factors["raw_penalty"] = round(raw_penalty, 4)
        return RiskScore(
            scanner_version=scanner_version,
            scan_id=scan_id,
            score=rounded_score,
            level=self.level_for_score(rounded_score),
            risk_penalty=rounded_penalty,
            finding_counts=counts,
            factors=factors,
            policy_version=policy_version,
            calculated_at=instant,
        )

    # Common integration aliases.
    calculate_risk = calculate
    score = calculate

    def level_for_score(self, score: float) -> RiskLevel:
        if not 0.0 <= score <= 100.0:
            raise ValueError("score must be between 0 and 100")
        if score >= self.config.healthy_minimum:
            return RiskLevel.HEALTHY
        if score >= self.config.low_minimum:
            return RiskLevel.LOW
        if score >= self.config.medium_minimum:
            return RiskLevel.MEDIUM
        if score >= self.config.high_minimum:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL


RiskConfig = RiskConfiguration
