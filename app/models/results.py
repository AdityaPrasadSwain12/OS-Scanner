"""Collector and complete scan result envelopes."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator, model_validator

from .base import (
    Identifier,
    JsonValue,
    VersionedModel,
    bounded_json,
    ensure_aware,
    utc_now,
)
from .enums import CollectorState, OverallStatus, ScanType
from .findings import AttackSurfaceAsset, ComplianceResult, Finding, RiskScore, Vulnerability
from .inventory import (
    BrowserExtension,
    CertificateInfo,
    Endpoint,
    Hardware,
    ListeningPort,
    NetworkInterface,
    OperatingSystem,
    PersistenceItem,
    Process,
    SecurityPosture,
    Service,
    Software,
    UpdateInfo,
    User,
)


class CollectorStatus(VersionedModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    status: CollectorState
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = Field(default=None, ge=0.0)
    tool_version: str | None = Field(default=None, max_length=128)
    records_collected: int = Field(default=0, ge=0)
    error_code: str | None = Field(default=None, max_length=128)
    error_message: str | None = Field(default=None, max_length=2048)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("started_at", "finished_at")
    @classmethod
    def aware_collector_times(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None

    @field_validator("metadata", mode="before")
    @classmethod
    def validate_metadata(cls, value: Any) -> JsonValue:
        result = bounded_json(value, max_depth=6, max_nodes=1_000)
        if not isinstance(result, dict):
            raise ValueError("collector metadata must be an object")
        from app.security.redaction import redact_mapping

        return redact_mapping(result)

    @field_validator("error_message")
    @classmethod
    def redact_error_message(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from app.security.redaction import redact_text

        return redact_text(value, max_length=2_048)

    @model_validator(mode="after")
    def validate_collector_result(self) -> CollectorStatus:
        if self.started_at and self.finished_at and self.finished_at < self.started_at:
            raise ValueError("collector finished_at cannot precede started_at")
        failed = self.status in {CollectorState.FAILED, CollectorState.TIMEOUT}
        if failed and not (self.error_code or self.error_message):
            raise ValueError("failed and timed-out collectors require a bounded error description")
        return self


class CollectorResult(CollectorStatus):
    """Optional normalized payload returned internally by a collector adapter."""

    data: list[dict[str, JsonValue]] = Field(default_factory=list)

    @field_validator("data", mode="before")
    @classmethod
    def validate_data(cls, value: Any) -> list[dict[str, JsonValue]]:
        result = bounded_json(value, max_depth=10, max_nodes=100_000)
        if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
            raise ValueError("collector data must be a list of objects")
        return result


class ScanResult(VersionedModel):
    scan_id: Identifier
    endpoint_id: str | None = Field(default=None, max_length=128)
    scan_type: ScanType
    timestamp: datetime = Field(default_factory=utc_now)
    started_at: datetime
    finished_at: datetime | None = None
    status: OverallStatus
    policy_id: str = Field(default="enterprise-default", min_length=1, max_length=128)
    policy_version: str | None = Field(default=None, max_length=64)
    policy_checksum: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    authorization_scope_id: Identifier
    endpoint: Endpoint | None = None
    os: OperatingSystem | None = None
    hardware: Hardware | None = None
    software: list[Software] = Field(default_factory=list)
    processes: list[Process] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    users: list[User] = Field(default_factory=list)
    network_interfaces: list[NetworkInterface] = Field(default_factory=list)
    listening_ports: list[ListeningPort] = Field(default_factory=list)
    security: SecurityPosture | None = None
    updates: list[UpdateInfo] = Field(default_factory=list)
    browser_extensions: list[BrowserExtension] = Field(default_factory=list)
    certificates: list[CertificateInfo] = Field(default_factory=list)
    persistence: list[PersistenceItem] = Field(default_factory=list)
    compliance: list[ComplianceResult] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    attack_surface: list[AttackSurfaceAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    risk: RiskScore | None = None
    collectors: dict[str, CollectorStatus] = Field(default_factory=dict)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("timestamp", "started_at", "finished_at")
    @classmethod
    def aware_scan_times(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None

    @field_validator("metadata", mode="before")
    @classmethod
    def validate_metadata(cls, value: Any) -> JsonValue:
        result = bounded_json(value, max_depth=8, max_nodes=5_000)
        if not isinstance(result, dict):
            raise ValueError("scan metadata must be an object")
        from app.security.redaction import redact_mapping

        return redact_mapping(result)

    @model_validator(mode="after")
    def validate_result_consistency(self) -> ScanResult:
        if self.finished_at and self.finished_at < self.started_at:
            raise ValueError("finished_at cannot precede started_at")
        if self.scan_type is ScanType.ATTACK_SURFACE:
            if self.endpoint_id or self.endpoint:
                raise ValueError("attack-surface results cannot claim an endpoint")
        elif not self.endpoint_id:
            raise ValueError("endpoint scan results require endpoint_id")
        if self.endpoint and self.endpoint_id != self.endpoint.endpoint_id:
            raise ValueError("endpoint_id does not match endpoint record")
        for key, collector in self.collectors.items():
            if key != collector.name:
                raise ValueError("collector map keys must match collector names")
        nested_scan_ids = (
            [artifact.scan_id for artifact in self.compliance]
            + [artifact.scan_id for artifact in self.vulnerabilities]
            + [artifact.scan_id for artifact in self.findings]
        )
        if any(scan_id != self.scan_id for scan_id in nested_scan_ids):
            raise ValueError("nested artifact scan_id does not match result scan_id")
        if self.risk and self.risk.scan_id != self.scan_id:
            raise ValueError("risk scan_id does not match result scan_id")
        return self

    @staticmethod
    def status_from_collectors(collectors: dict[str, CollectorStatus]) -> OverallStatus:
        if not collectors:
            return OverallStatus.FAILED
        states = {collector.status for collector in collectors.values()}
        if states == {CollectorState.SUCCESS}:
            return OverallStatus.SUCCESS
        if CollectorState.SUCCESS in states or CollectorState.PARTIAL in states:
            return OverallStatus.PARTIAL
        return OverallStatus.FAILED
