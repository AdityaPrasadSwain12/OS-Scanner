"""Normalized analysis, vulnerability, compliance, and risk records."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import Field, field_validator, model_validator

from .base import (
    Identifier,
    JsonValue,
    VersionedModel,
    bounded_json,
    ensure_aware,
    utc_now,
)
from .enums import AssetType, ComplianceStatus, FindingStatus, RiskLevel, Severity
from .validators import normalize_domain, validate_reference


class ComplianceResult(VersionedModel):
    scan_id: Identifier
    endpoint_id: str | None = Field(default=None, max_length=128)
    rule_id: Identifier
    profile_id: str | None = Field(default=None, max_length=256)
    title: str = Field(min_length=1, max_length=1024)
    status: ComplianceStatus
    severity: Severity = Severity.INFO
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    remediation: str | None = Field(default=None, max_length=16_384)
    references: list[str] = Field(default_factory=list, max_length=64)
    evaluated_at: datetime = Field(default_factory=utc_now)

    @field_validator("evidence", mode="before")
    @classmethod
    def validate_evidence(cls, value: Any) -> JsonValue:
        result = bounded_json(value, max_depth=8, max_nodes=5_000)
        if not isinstance(result, dict):
            raise ValueError("evidence must be an object")
        from app.security.redaction import redact_mapping

        return redact_mapping(result)

    @field_validator("references")
    @classmethod
    def validate_references(cls, values: list[str]) -> list[str]:
        return [validate_reference(value) for value in values]

    @field_validator("evaluated_at")
    @classmethod
    def aware_evaluated_at(cls, value: datetime) -> datetime:
        return ensure_aware(value)


class Vulnerability(VersionedModel):
    scan_id: Identifier
    endpoint_id: str | None = Field(default=None, max_length=128)
    vulnerability_id: Identifier
    package_name: str = Field(min_length=1, max_length=512)
    package_ecosystem: str | None = Field(default=None, max_length=128)
    installed_version: str | None = Field(default=None, max_length=256)
    affected_versions: list[str] = Field(default_factory=list, max_length=512)
    fixed_versions: list[str] = Field(default_factory=list, max_length=512)
    aliases: set[str] = Field(default_factory=set, max_length=512)
    severity: Severity
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    exploitability: float | None = Field(default=None, ge=0.0, le=1.0)
    known_exploited: bool = False
    summary: str | None = Field(default=None, max_length=16_384)
    references: list[str] = Field(default_factory=list, max_length=128)
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=utc_now)

    @field_validator("references")
    @classmethod
    def validate_references(cls, values: list[str]) -> list[str]:
        return [validate_reference(value) for value in values]

    @field_validator("evidence", mode="before")
    @classmethod
    def validate_evidence(cls, value: Any) -> JsonValue:
        result = bounded_json(value, max_depth=8, max_nodes=5_000)
        if not isinstance(result, dict):
            raise ValueError("evidence must be an object")
        from app.security.redaction import redact_mapping

        return redact_mapping(result)

    @field_validator("detected_at")
    @classmethod
    def aware_detected_at(cls, value: datetime) -> datetime:
        return ensure_aware(value)


class AttackSurfaceAsset(VersionedModel):
    scan_id: Identifier
    hostname: str
    asset_type: AssetType = AssetType.SUBDOMAIN
    root_domain: str
    addresses: list[str] = Field(default_factory=list, max_length=256)
    dns_records: dict[str, list[str]] = Field(default_factory=dict)
    in_scope: bool
    source: str = Field(default="amass", min_length=1, max_length=128)
    discovered_at: datetime = Field(default_factory=utc_now)

    @field_validator("root_domain")
    @classmethod
    def normalize_root_domain(cls, value: str) -> str:
        return normalize_domain(value)

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            return normalize_domain(value)

    @field_validator("addresses")
    @classmethod
    def normalize_addresses(cls, values: list[str]) -> list[str]:
        return [ipaddress.ip_address(value).compressed for value in values]

    @field_validator("dns_records")
    @classmethod
    def validate_dns_records(cls, values: dict[str, list[str]]) -> dict[str, list[str]]:
        if len(values) > 64:
            raise ValueError("too many DNS record types")
        normalized: dict[str, list[str]] = {}
        for record_type, records in values.items():
            canonical_type = record_type.upper()
            if not re.fullmatch(r"[A-Z][A-Z0-9-]{0,15}", canonical_type) or len(records) > 1_024:
                raise ValueError("invalid or oversized DNS record set")
            if any(
                not isinstance(record, str) or len(record) > 4_096 or "\x00" in record
                for record in records
            ):
                raise ValueError("invalid DNS record value")
            normalized[canonical_type] = records
        return normalized

    @field_validator("discovered_at")
    @classmethod
    def aware_discovered_at(cls, value: datetime) -> datetime:
        return ensure_aware(value)

    @model_validator(mode="after")
    def asset_belongs_to_root(self) -> AttackSurfaceAsset:
        if self.asset_type is AssetType.IP_ADDRESS:
            try:
                ipaddress.ip_address(self.hostname)
            except ValueError as exc:
                raise ValueError("IP_ADDRESS asset hostname must contain an IP address") from exc
        elif self.asset_type is AssetType.ENDPOINT:
            raise ValueError("endpoint records do not belong in attack-surface assets")
        elif self.hostname != self.root_domain and not self.hostname.endswith(
            f".{self.root_domain}"
        ):
            raise ValueError("asset hostname is outside root_domain")
        return self


class Finding(VersionedModel):
    finding_id: Identifier = Field(default_factory=lambda: f"finding-{uuid4()}")
    scan_id: Identifier
    rule_id: Identifier
    title: str = Field(min_length=1, max_length=1024)
    severity: Severity
    category: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_-]*$")
    description: str = Field(min_length=1, max_length=16_384)
    endpoint_id: str | None = Field(default=None, max_length=128)
    asset: str | None = Field(default=None, max_length=2048)
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    remediation: str = Field(min_length=1, max_length=16_384)
    references: list[str] = Field(default_factory=list, max_length=128)
    detected_at: datetime = Field(default_factory=utc_now)
    first_seen_at: datetime | None = None
    status: FindingStatus = FindingStatus.OPEN
    exploitability: float | None = Field(default=None, ge=0.0, le=1.0)
    exposure: float | None = Field(default=None, ge=0.0, le=1.0)
    compliance_impact: float | None = Field(default=None, ge=0.0, le=1.0)
    tags: set[str] = Field(default_factory=set, max_length=128)

    @field_validator("evidence", mode="before")
    @classmethod
    def validate_evidence(cls, value: Any) -> JsonValue:
        result = bounded_json(value, max_depth=8, max_nodes=5_000)
        if not isinstance(result, dict):
            raise ValueError("evidence must be an object")
        from app.security.redaction import redact_mapping

        return redact_mapping(result)

    @field_validator("references")
    @classmethod
    def validate_references(cls, values: list[str]) -> list[str]:
        return [validate_reference(value) for value in values]

    @field_validator("detected_at", "first_seen_at")
    @classmethod
    def aware_finding_times(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None

    @model_validator(mode="after")
    def has_subject_and_valid_times(self) -> Finding:
        if not self.endpoint_id and not self.asset:
            raise ValueError("finding must identify an endpoint or asset")
        if self.first_seen_at and self.first_seen_at > self.detected_at:
            raise ValueError("first_seen_at cannot follow detected_at")
        return self


class RiskScore(VersionedModel):
    scan_id: Identifier
    score: float = Field(ge=0.0, le=100.0)
    level: RiskLevel
    risk_penalty: float = Field(ge=0.0, le=100.0)
    finding_counts: dict[Severity, int] = Field(default_factory=dict)
    factors: dict[str, float] = Field(default_factory=dict)
    policy_version: str | None = Field(default=None, max_length=64)
    calculated_at: datetime = Field(default_factory=utc_now)

    @field_validator("finding_counts")
    @classmethod
    def nonnegative_counts(cls, values: dict[Severity, int]) -> dict[Severity, int]:
        if any(value < 0 for value in values.values()):
            raise ValueError("finding counts cannot be negative")
        return values

    @field_validator("factors")
    @classmethod
    def finite_factors(cls, values: dict[str, float]) -> dict[str, float]:
        if any(
            value != value or value in (float("inf"), float("-inf")) for value in values.values()
        ):
            raise ValueError("risk factors must be finite")
        return values

    @field_validator("calculated_at")
    @classmethod
    def aware_calculated_at(cls, value: datetime) -> datetime:
        return ensure_aware(value)
