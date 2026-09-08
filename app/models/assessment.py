"""Canonical endpoint assessment shared by JSON, dashboard, and PDF outputs.

The endpoint ``ScanResult`` remains the evidence envelope.  This module adds a
strict, derived assessment layer after cloud analysis has completed.  Nothing
in this model treats a locally listening socket as proof of remote exposure.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import Field, field_validator, model_validator

from .base import Identifier, StrictModel, VersionedModel, ensure_aware, utc_now
from .enums import (
    CollectorState,
    ComplianceStatus,
    OverallStatus,
    RiskLevel,
    ScanType,
    Severity,
)
from .findings import Finding, RiskScore, Vulnerability
from .inventory import UpdateInfo
from .results import CollectorStatus, ScanResult


class CoverageState(StrEnum):
    """Evidence coverage without implying that missing data is safe."""

    OBSERVED = "OBSERVED"
    PARTIAL = "PARTIAL"
    NOT_OBSERVED = "NOT_OBSERVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_TESTED = "NOT_TESTED"


class ObservationScope(StrEnum):
    ENDPOINT_LOCAL = "ENDPOINT_LOCAL"
    CLOUD_ANALYSIS = "CLOUD_ANALYSIS"
    REMOTE_NETWORK = "REMOTE_NETWORK"


DEFAULT_REQUIRED_SECTIONS: tuple[str, ...] = (
    "antivirus_products",
    "browser_extensions",
    "certificates",
    "collector_execution",
    "compliance",
    "dependency_vulnerabilities",
    "disk_encryption",
    "endpoint_identity",
    "firewall_profiles",
    "hardware",
    "local_listeners",
    "network_interfaces",
    "operating_system",
    "patches",
    "persistence",
    "processes",
    "security_posture",
    "services",
    "software",
    "users",
)

_DEGRADED_STATES = frozenset(
    {
        CollectorState.PARTIAL,
        CollectorState.FAILED,
        CollectorState.UNAVAILABLE,
        CollectorState.TIMEOUT,
    }
)
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_SECTION_TO_EVIDENCE = {
    "antivirus_products": "security.antivirus_products",
    "browser_extensions": "browser_extensions",
    "certificates": "certificates",
    "compliance": "compliance",
    "disk_encryption": "security.encryption_volumes",
    "hardware": "hardware",
    "firewall_profiles": "security.firewall_profiles",
    "local_listeners": "listening_ports",
    "network_interfaces": "network_interfaces",
    "operating_system": "os",
    "patches": "updates",
    "persistence": "persistence",
    "processes": "processes",
    "security_posture": "security",
    "services": "services",
    "software": "software",
    "users": "users",
}
_UNORDERED_ARRAY_KEYS = frozenset({"aliases", "groups", "tags"})


def _ordered_names(value: object, *, label: str, maximum: int = 128) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError(f"{label} must be a sequence")
    names: set[str] = set()
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or len(item) > 128
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]*", item) is None
        ):
            raise ValueError(f"{label} contains an invalid name")
        names.add(item)
    if len(names) > maximum:
        raise ValueError(f"{label} exceeds its item limit")
    return tuple(sorted(names))


def _canonical_payload(value: Any) -> bytes:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", exclude_none=False)
    value = _canonicalize_unordered_arrays(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonicalize_unordered_arrays(
    value: Any,
    *,
    parent_key: str | None = None,
) -> Any:
    if isinstance(value, dict):
        return {
            key: _canonicalize_unordered_arrays(child, parent_key=key)
            for key, child in value.items()
        }
    if isinstance(value, list):
        children = [_canonicalize_unordered_arrays(child) for child in value]
        if parent_key in _UNORDERED_ARRAY_KEYS:
            return sorted(
                children,
                key=lambda item: json.dumps(
                    item,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
        return children
    return value


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_payload(value)).hexdigest()


def _bounded_text(value: str, *, maximum: int = 16_384) -> str:
    return value if len(value) <= maximum else f"{value[: maximum - 14]}...<truncated>"


def _stable_finding_id(kind: str, *identity: str) -> str:
    material = "\x1f".join((kind, *identity)).encode("utf-8")
    return f"finding-{kind}-{hashlib.sha256(material).hexdigest()[:24]}"


def _vulnerability_sources(item: Vulnerability) -> tuple[str, ...]:
    raw = item.evidence.get("sources")
    if isinstance(raw, list):
        sources = {value[:128] for value in raw if isinstance(value, str) and value}
        if sources:
            return tuple(sorted(sources))
    for key in ("source_tool", "source"):
        value = item.evidence.get(key)
        if isinstance(value, str) and value:
            return (value[:128],)
    return ("vulnerability-analysis",)


def _vulnerability_finding(item: Vulnerability) -> Finding:
    fixed = sorted(set(item.fixed_versions))
    remediation = (
        f"Upgrade {item.package_name} to a fixed version: {', '.join(fixed)}."
        if fixed
        else f"Review the advisory and vendor guidance for {item.package_name}."
    )
    identifiers = tuple(sorted({item.vulnerability_id, *item.aliases}))
    return Finding(
        scanner_version=item.scanner_version,
        finding_id=_stable_finding_id(
            "vulnerability",
            item.vulnerability_id,
            item.package_name.casefold(),
            item.package_ecosystem or "",
            item.installed_version or "",
        ),
        scan_id=item.scan_id,
        rule_id=item.vulnerability_id,
        title=f"{item.vulnerability_id} affects {item.package_name}",
        severity=item.severity,
        category="dependency_vulnerability",
        description=_bounded_text(
            item.summary
            or (
                f"The installed {item.package_name} component matched a vulnerability "
                "advisory during package analysis."
            )
        ),
        endpoint_id=item.endpoint_id,
        evidence={
            "vulnerability_id": item.vulnerability_id,
            "aliases": list(identifiers),
            "package_name": item.package_name,
            "package_ecosystem": item.package_ecosystem,
            "installed_version": item.installed_version,
            "fixed_versions": fixed,
            "cvss_score": item.cvss_score,
            "known_exploited": item.known_exploited,
            "source_names": list(_vulnerability_sources(item)),
        },
        remediation=_bounded_text(remediation),
        references=item.references,
        detected_at=item.detected_at,
        exploitability=item.exploitability,
        tags={"dependency", "vulnerability"},
    )


def _patch_finding(scan: ScanResult, update: UpdateInfo) -> Finding:
    security = update.security_update is True
    supplied_severity = (update.severity or "").upper()
    severity = (
        Severity(supplied_severity)
        if supplied_severity in {item.value for item in Severity}
        else Severity.MEDIUM
        if security
        else Severity.LOW
    )
    title = update.title or update.update_id
    return Finding(
        scanner_version=scan.scanner_version,
        finding_id=_stable_finding_id("patch", update.update_id, update.version or ""),
        scan_id=scan.scan_id,
        rule_id="missing-patch",
        title=f"Missing update: {title}",
        severity=severity,
        category="missing_patch",
        description=(
            "The endpoint update subsystem reported this update as applicable but not installed."
        ),
        endpoint_id=scan.endpoint_id,
        evidence={
            "update_id": update.update_id,
            "kb_ids": update.kb_ids,
            "title": update.title,
            "description": update.description,
            "version": update.version,
            "category": update.category,
            "vendor_severity": update.severity,
            "security_update": update.security_update,
            "reboot_required": update.reboot_required,
            "source": update.source,
        },
        remediation=(
            "Validate applicability, test the update, and deploy it through change control."
        ),
        detected_at=scan.finished_at or scan.timestamp,
        tags={"patch", "update"},
    )


def _compliance_finding(scan: ScanResult, index: int) -> Finding:
    result = scan.compliance[index]
    severity = result.severity if result.severity is not Severity.INFO else Severity.MEDIUM
    return Finding(
        scanner_version=scan.scanner_version,
        finding_id=_stable_finding_id("compliance", result.rule_id, result.profile_id or ""),
        scan_id=scan.scan_id,
        rule_id=result.rule_id,
        title=result.title,
        severity=severity,
        category="compliance",
        description=f"Compliance rule {result.rule_id} returned {result.status.value}.",
        endpoint_id=result.endpoint_id or scan.endpoint_id,
        evidence={
            "profile_id": result.profile_id,
            "compliance_status": result.status.value,
            "evaluated_at": result.evaluated_at.isoformat(),
        },
        remediation=result.remediation or "Review and remediate the failed compliance control.",
        references=result.references,
        detected_at=result.evaluated_at,
        compliance_impact=1.0,
        tags={"compliance"},
    )


def derive_assessment_findings(scan: ScanResult) -> tuple[Finding, ...]:
    """Create the single finding set used for counts, risk, JSON, and PDF."""

    findings = list(scan.findings)
    findings.extend(_vulnerability_finding(item) for item in scan.vulnerabilities)
    findings.extend(_patch_finding(scan, update) for update in scan.updates if not update.installed)
    findings.extend(
        _compliance_finding(scan, index)
        for index, result in enumerate(scan.compliance)
        if result.status in {ComplianceStatus.FAIL, ComplianceStatus.ERROR}
    )
    by_id: dict[str, Finding] = {}
    for finding in findings:
        prior = by_id.get(finding.finding_id)
        if prior is not None and prior != finding:
            raise ValueError(f"conflicting finding ID: {finding.finding_id}")
        by_id[finding.finding_id] = finding
    return tuple(
        sorted(
            by_id.values(),
            key=lambda item: (
                -_SEVERITY_RANK[item.severity],
                item.category,
                item.title.casefold(),
                item.finding_id,
            ),
        )
    )


class CoverageSection(StrictModel):
    name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    scope: ObservationScope
    state: CoverageState
    required: bool
    records_observed: int | None = Field(default=None, ge=0)
    sources: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    detail: str = Field(min_length=1, max_length=2_048)

    @field_validator("sources", mode="before")
    @classmethod
    def canonical_sources(cls, value: object) -> tuple[str, ...]:
        return _ordered_names(value, label="coverage sources", maximum=64)


class AssessmentCoverage(StrictModel):
    required_sections: tuple[str, ...]
    sections: tuple[CoverageSection, ...] = Field(max_length=128)
    degraded_sources: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    complete: bool

    @field_validator("required_sections", mode="before")
    @classmethod
    def canonical_required_sections(cls, value: object) -> tuple[str, ...]:
        return _ordered_names(value, label="required sections")

    @field_validator("degraded_sources", mode="before")
    @classmethod
    def canonical_degraded_sources(cls, value: object) -> tuple[str, ...]:
        return _ordered_names(value, label="degraded sources", maximum=256)

    @model_validator(mode="after")
    def validate_coverage(self) -> AssessmentCoverage:
        names = tuple(item.name for item in self.sections)
        if names != tuple(sorted(set(names))):
            raise ValueError("coverage sections must be unique and in canonical order")
        known = set(names)
        if not set(self.required_sections) <= known:
            raise ValueError("every required coverage section must be declared")
        by_name = {item.name: item for item in self.sections}
        if any(not by_name[name].required for name in self.required_sections):
            raise ValueError("required coverage sections must be marked required")
        expected = not self.degraded_sources and all(
            by_name[name].state is CoverageState.OBSERVED for name in self.required_sections
        )
        if self.complete is not expected:
            raise ValueError("coverage completeness does not match declared observations")
        return self


class AssessmentSummary(StrictModel):
    status: OverallStatus
    started_at: datetime
    finished_at: datetime
    finding_count: int = Field(ge=0)
    severity_counts: dict[Severity, int]
    category_counts: dict[str, int]
    vulnerability_count: int = Field(ge=0)
    known_exploited_vulnerability_count: int = Field(ge=0)
    missing_patch_count: int = Field(ge=0)
    failed_compliance_count: int = Field(ge=0)
    software_count: int = Field(ge=0)
    process_count: int = Field(ge=0)
    service_count: int = Field(ge=0)
    user_count: int = Field(ge=0)
    certificate_count: int = Field(ge=0)
    firewall_profile_count: int = Field(ge=0)
    antivirus_product_count: int = Field(ge=0)
    encryption_volume_count: int = Field(ge=0)
    local_listener_count: int = Field(ge=0)
    wildcard_listener_count: int = Field(ge=0)
    remotely_reachable_port_count: None = None
    remote_reachability: CoverageState = CoverageState.NOT_TESTED
    health_score: float = Field(ge=0.0, le=100.0)
    risk_level: RiskLevel

    @field_validator("started_at", "finished_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return ensure_aware(value)

    @field_validator("severity_counts")
    @classmethod
    def validate_severity_counts(
        cls, value: dict[Severity, int]
    ) -> dict[Severity, int]:
        if set(value) != set(Severity) or any(count < 0 for count in value.values()):
            raise ValueError("severity_counts must contain every severity with nonnegative counts")
        return value

    @field_validator("category_counts")
    @classmethod
    def validate_category_counts(cls, value: dict[str, int]) -> dict[str, int]:
        if len(value) > 128 or any(
            not key or len(key) > 128 or count < 0 for key, count in value.items()
        ):
            raise ValueError("category_counts is invalid")
        return dict(sorted(value.items()))

    @model_validator(mode="after")
    def validate_summary(self) -> AssessmentSummary:
        if self.finished_at < self.started_at:
            raise ValueError("assessment completion cannot precede its start")
        if sum(self.severity_counts.values()) != self.finding_count:
            raise ValueError("severity counts must equal finding_count")
        if sum(self.category_counts.values()) != self.finding_count:
            raise ValueError("category counts must equal finding_count")
        if self.remote_reachability is not CoverageState.NOT_TESTED:
            raise ValueError(
                "this endpoint assessment does not perform remote reachability testing"
            )
        return self


class AssessmentProvenance(StrictModel):
    canonical_scan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    analysis_status_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assessment_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_id: str = Field(min_length=1, max_length=128)
    policy_version: str | None = Field(default=None, max_length=64)
    policy_checksum: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    endpoint_collectors: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    cloud_analyzers: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    vulnerability_sources: tuple[str, ...] = Field(default_factory=tuple, max_length=64)

    @field_validator(
        "endpoint_collectors",
        "cloud_analyzers",
        "vulnerability_sources",
        mode="before",
    )
    @classmethod
    def canonical_names(cls, value: object, info: Any) -> tuple[str, ...]:
        maximum = 2_000 if info.field_name == "endpoint_collectors" else 64
        return _ordered_names(value, label=info.field_name, maximum=maximum)


def _analysis_tools(
    value: Iterable[CollectorStatus],
) -> tuple[CollectorStatus, ...]:
    tools = tuple(sorted(value, key=lambda item: item.name))
    names = tuple(item.name for item in tools)
    if names != tuple(sorted(set(names))):
        raise ValueError("analysis tool status names must be unique")
    return tools


def _inventory_observed(scan: ScanResult, name: str) -> bool:
    raw = scan.metadata.get("observed_inventory_sections")
    declared = {item for item in raw if isinstance(item, str)} if isinstance(raw, list) else set()
    evidence_name = _SECTION_TO_EVIDENCE.get(name)
    if evidence_name in declared or name in declared:
        return True
    if evidence_name is not None and "." in evidence_name:
        parent_name, child_name = evidence_name.split(".", 1)
        parent = getattr(scan, parent_name)
        return parent is not None and bool(getattr(parent, child_name))
    if name == "endpoint_identity":
        return scan.endpoint is not None
    if evidence_name == "os":
        return scan.os is not None
    if evidence_name == "hardware":
        return scan.hardware is not None
    if evidence_name == "security":
        return scan.security is not None
    if evidence_name is None:
        return False
    return bool(getattr(scan, evidence_name))


def _inventory_count(scan: ScanResult, section: str) -> int | None:
    if section == "endpoint_identity":
        return 1 if scan.endpoint is not None else 0
    evidence_name = _SECTION_TO_EVIDENCE.get(section)
    if evidence_name is not None and "." in evidence_name:
        parent_name, child_name = evidence_name.split(".", 1)
        parent = getattr(scan, parent_name)
        return len(getattr(parent, child_name)) if parent is not None else 0
    if evidence_name in {"os", "hardware", "security"}:
        return 1 if getattr(scan, evidence_name) is not None else 0
    if evidence_name is None:
        return None
    return len(getattr(scan, evidence_name))


def build_assessment_coverage(
    scan: ScanResult,
    analysis_tools: tuple[CollectorStatus, ...] | list[CollectorStatus],
    *,
    required_sections: tuple[str, ...] | list[str] = DEFAULT_REQUIRED_SECTIONS,
) -> AssessmentCoverage:
    required = _ordered_names(required_sections, label="required sections")
    required_set = set(required)
    tools = _analysis_tools(analysis_tools)
    degraded = {
        f"endpoint.{name}"
        for name, status in scan.collectors.items()
        if status.status in _DEGRADED_STATES
    }
    degraded.update(
        f"cloud.{tool.name}" for tool in tools if tool.status is not CollectorState.SUCCESS
    )
    sections: list[CoverageSection] = []

    for name in sorted(_SECTION_TO_EVIDENCE | {"endpoint_identity": "endpoint"}):
        observed = _inventory_observed(scan, name)
        detail = "Collected from endpoint-local evidence."
        if name == "local_listeners":
            detail = (
                "Endpoint-local socket bindings were observed; external reachability was "
                "not tested."
            )
        sections.append(
            CoverageSection(
                name=name,
                scope=ObservationScope.ENDPOINT_LOCAL,
                state=CoverageState.OBSERVED if observed else CoverageState.NOT_OBSERVED,
                required=name in required_set,
                records_observed=_inventory_count(scan, name),
                sources=tuple(scan.collectors),
                detail=detail if observed else "No authoritative observation was produced.",
            )
        )

    collector_state = (
        CoverageState.OBSERVED
        if scan.status is OverallStatus.SUCCESS
        else CoverageState.PARTIAL
        if scan.status is OverallStatus.PARTIAL
        else CoverageState.NOT_OBSERVED
    )
    sections.append(
        CoverageSection(
            name="collector_execution",
            scope=ObservationScope.ENDPOINT_LOCAL,
            state=collector_state,
            required="collector_execution" in required_set,
            records_observed=sum(item.records_collected for item in scan.collectors.values()),
            sources=tuple(scan.collectors),
            detail="Endpoint collector execution and record counts were retained.",
        )
    )

    vulnerability_tools = tuple(
        tool
        for tool in tools
        if "osv" in tool.name.casefold() or "depscan" in tool.name.casefold()
    )
    vulnerability_states = {tool.status for tool in vulnerability_tools}
    if vulnerability_tools and vulnerability_states == {CollectorState.SUCCESS}:
        vulnerability_state = CoverageState.OBSERVED
    elif CollectorState.SUCCESS in vulnerability_states:
        vulnerability_state = CoverageState.PARTIAL
    elif scan.vulnerabilities:
        vulnerability_state = CoverageState.OBSERVED
    else:
        vulnerability_state = CoverageState.NOT_OBSERVED
    sections.append(
        CoverageSection(
            name="dependency_vulnerabilities",
            scope=ObservationScope.CLOUD_ANALYSIS,
            state=vulnerability_state,
            required="dependency_vulnerabilities" in required_set,
            records_observed=len(scan.vulnerabilities),
            sources=tuple(tool.name for tool in vulnerability_tools),
            detail=(
                "Package advisory matching completed for the supplied software identities."
                if vulnerability_state is CoverageState.OBSERVED
                else "Package vulnerability coverage was absent or incomplete."
            ),
        )
    )
    sections.append(
        CoverageSection(
            name="remote_network_exposure",
            scope=ObservationScope.REMOTE_NETWORK,
            state=CoverageState.NOT_TESTED,
            required="remote_network_exposure" in required_set,
            sources=(),
            detail=(
                "No remote network scanner was used; firewall, NAT, VPN, and ACL reachability "
                "were not tested."
            ),
        )
    )
    known = {item.name for item in sections}
    unknown_required = required_set - known
    if unknown_required:
        raise ValueError(f"unknown required coverage sections: {sorted(unknown_required)!r}")
    ordered_sections = tuple(sorted(sections, key=lambda item: item.name))
    by_name = {item.name: item for item in ordered_sections}
    complete = not degraded and all(
        by_name[name].state is CoverageState.OBSERVED for name in required
    )
    return AssessmentCoverage(
        required_sections=required,
        sections=ordered_sections,
        degraded_sources=tuple(degraded),
        complete=complete,
    )


def _assessment_status(scan: ScanResult, coverage: AssessmentCoverage) -> OverallStatus:
    if scan.status is OverallStatus.FAILED:
        return OverallStatus.FAILED
    if scan.status is not OverallStatus.SUCCESS or not coverage.complete:
        return OverallStatus.PARTIAL
    return OverallStatus.SUCCESS


def _calculate_risk(
    scan: ScanResult,
    findings: tuple[Finding, ...],
    *,
    calculated_at: datetime,
) -> RiskScore:
    from app.analyzers.risk import RiskEngine

    criticality = scan.endpoint.asset_criticality if scan.endpoint is not None else 0.5
    return RiskEngine().calculate(
        findings,
        scan_id=scan.scan_id,
        asset_criticality=criticality,
        exposure=0.0,
        now=calculated_at,
        policy_version=scan.policy_version,
        scanner_version=scan.scanner_version,
    )


def summarize_assessment(
    scan: ScanResult,
    findings: tuple[Finding, ...],
    coverage: AssessmentCoverage,
    risk: RiskScore,
) -> AssessmentSummary:
    if scan.finished_at is None:
        raise ValueError("canonical assessments require a terminal endpoint result")
    severity_counts = Counter(item.severity for item in findings)
    category_counts = Counter(item.category for item in findings)
    wildcard_addresses = {"0.0.0.0", "::"}  # noqa: S104 - classify observed bindings only
    return AssessmentSummary(
        status=_assessment_status(scan, coverage),
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        finding_count=len(findings),
        severity_counts={severity: severity_counts[severity] for severity in Severity},
        category_counts=dict(sorted(category_counts.items())),
        vulnerability_count=len(scan.vulnerabilities),
        known_exploited_vulnerability_count=sum(
            item.known_exploited for item in scan.vulnerabilities
        ),
        missing_patch_count=sum(not item.installed for item in scan.updates),
        failed_compliance_count=sum(
            item.status in {ComplianceStatus.FAIL, ComplianceStatus.ERROR}
            for item in scan.compliance
        ),
        software_count=len(scan.software),
        process_count=len(scan.processes),
        service_count=len(scan.services),
        user_count=len(scan.users),
        certificate_count=len(scan.certificates),
        firewall_profile_count=(len(scan.security.firewall_profiles) if scan.security else 0),
        antivirus_product_count=(
            len(scan.security.antivirus_products) if scan.security else 0
        ),
        encryption_volume_count=(
            len(scan.security.encryption_volumes) if scan.security else 0
        ),
        local_listener_count=len(scan.listening_ports),
        wildcard_listener_count=sum(
            item.address in wildcard_addresses for item in scan.listening_ports
        ),
        remotely_reachable_port_count=None,
        remote_reachability=CoverageState.NOT_TESTED,
        health_score=risk.score,
        risk_level=risk.level,
    )


def build_assessment_provenance(
    scan: ScanResult,
    tools: tuple[CollectorStatus, ...],
) -> AssessmentProvenance:
    scan_payload = scan.model_dump(mode="json", exclude_none=False)
    tool_payload = [item.model_dump(mode="json", exclude_none=False) for item in tools]
    sources = {
        source
        for vulnerability in scan.vulnerabilities
        for source in _vulnerability_sources(vulnerability)
    }
    return AssessmentProvenance(
        canonical_scan_sha256=_sha256(scan_payload),
        analysis_status_sha256=_sha256(tool_payload),
        assessment_evidence_sha256=_sha256(
            {"analysis_tools": tool_payload, "endpoint_scan": scan_payload}
        ),
        policy_id=scan.policy_id,
        policy_version=scan.policy_version,
        policy_checksum=scan.policy_checksum,
        endpoint_collectors=tuple(scan.collectors),
        cloud_analyzers=tuple(item.name for item in tools),
        vulnerability_sources=tuple(sources),
    )


def _limitations(coverage: AssessmentCoverage) -> tuple[str, ...]:
    limitations = {
        (
            "Local listening ports are endpoint observations and must not be interpreted as "
            "remotely reachable services."
        ),
        (
            "Remote reachability through host firewalls, network ACLs, NAT, VPNs, or proxies "
            "was not tested."
        ),
        (
            "Package vulnerability accuracy depends on the completeness and identity quality "
            "of the generated software inventory or SBOM."
        ),
    }
    missing = [
        item.name
        for item in coverage.sections
        if item.required and item.state is not CoverageState.OBSERVED
    ]
    if missing:
        limitations.add(f"Required sections not fully observed: {', '.join(sorted(missing))}.")
    if coverage.degraded_sources:
        limitations.add(
            f"Degraded evidence sources: {', '.join(coverage.degraded_sources)}."
        )
    return tuple(sorted(limitations))


class CanonicalAssessmentReport(VersionedModel):
    """One immutable-by-contract assessment for APIs, JSON, dashboard, and PDF."""

    report_id: Identifier = Field(default_factory=lambda: f"assessment-{uuid4()}")
    generated_at: datetime = Field(default_factory=utc_now)
    endpoint_scan: ScanResult
    analysis_tools: tuple[CollectorStatus, ...] = Field(default_factory=tuple, max_length=64)
    findings: tuple[Finding, ...] = Field(default_factory=tuple, max_length=100_000)
    risk: RiskScore
    summary: AssessmentSummary
    coverage: AssessmentCoverage
    provenance: AssessmentProvenance
    limitations: tuple[str, ...] = Field(default_factory=tuple, max_length=256)

    @field_validator("generated_at")
    @classmethod
    def aware_generated_at(cls, value: datetime) -> datetime:
        return ensure_aware(value)

    @field_validator("analysis_tools", mode="before")
    @classmethod
    def canonical_analysis_tools(cls, value: object) -> tuple[CollectorStatus, ...]:
        if not isinstance(value, (list, tuple)):
            raise ValueError("analysis_tools must be a sequence")
        tools = tuple(
            item if isinstance(item, CollectorStatus) else CollectorStatus.model_validate(item)
            for item in value
        )
        return _analysis_tools(tools)

    @field_validator("limitations", mode="before")
    @classmethod
    def canonical_limitations(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, (list, tuple, set, frozenset)):
            raise ValueError("limitations must be a sequence")
        items = {
            item
            for item in value
            if isinstance(item, str) and item and len(item) <= 4_096
        }
        if len(items) != len(value) or len(items) > 256:
            raise ValueError("limitations contain invalid or duplicate entries")
        return tuple(sorted(items))

    @model_validator(mode="after")
    def validate_derived_assessment(self) -> CanonicalAssessmentReport:
        scan = self.endpoint_scan
        if scan.scan_type is ScanType.ATTACK_SURFACE or scan.endpoint_id is None:
            raise ValueError("canonical endpoint assessment requires an endpoint scan")
        if scan.finished_at is None or scan.status not in {
            OverallStatus.SUCCESS,
            OverallStatus.PARTIAL,
            OverallStatus.FAILED,
        }:
            raise ValueError("canonical endpoint assessment requires a terminal scan")
        if self.generated_at < scan.finished_at:
            raise ValueError("generated_at cannot precede endpoint scan completion")
        if any(
            item.scan_id != scan.scan_id or item.endpoint_id != scan.endpoint_id
            for item in scan.vulnerabilities
        ):
            raise ValueError("all vulnerabilities must belong to the assessed endpoint scan")
        expected_findings = derive_assessment_findings(scan)
        if self.findings != expected_findings:
            raise ValueError("canonical findings do not match endpoint evidence")
        expected_coverage = build_assessment_coverage(
            scan,
            self.analysis_tools,
            required_sections=self.coverage.required_sections,
        )
        if self.coverage != expected_coverage:
            raise ValueError("assessment coverage does not match endpoint evidence")
        expected_risk = _calculate_risk(scan, self.findings, calculated_at=self.generated_at)
        if self.risk != expected_risk:
            raise ValueError("assessment risk does not match canonical findings")
        expected_summary = summarize_assessment(scan, self.findings, self.coverage, self.risk)
        if self.summary != expected_summary:
            raise ValueError("assessment summary does not match canonical evidence")
        expected_provenance = build_assessment_provenance(scan, self.analysis_tools)
        if self.provenance != expected_provenance:
            raise ValueError("assessment provenance hashes do not match canonical evidence")
        if self.limitations != _limitations(self.coverage):
            raise ValueError("assessment limitations do not match evidence coverage")
        return self


def build_canonical_assessment(
    endpoint_scan: ScanResult,
    cloud_vulnerabilities: Iterable[Vulnerability] = (),
    *,
    analysis_tools: Iterable[CollectorStatus] = (),
    required_sections: tuple[str, ...] | list[str] = DEFAULT_REQUIRED_SECTIONS,
    report_id: str | None = None,
    generated_at: datetime | None = None,
) -> CanonicalAssessmentReport:
    """Merge endpoint and cloud evidence into one strictly derived assessment."""

    if endpoint_scan.finished_at is None:
        raise ValueError("canonical assessments require a terminal endpoint result")
    cloud_records = tuple(cloud_vulnerabilities)
    if any(
        item.scan_id != endpoint_scan.scan_id or item.endpoint_id != endpoint_scan.endpoint_id
        for item in cloud_records
    ):
        raise ValueError("cloud vulnerabilities must belong to the endpoint scan")
    from app.normalization.vulnerability_merge import merge_vulnerabilities

    merged = merge_vulnerabilities((*endpoint_scan.vulnerabilities, *cloud_records))
    scan = endpoint_scan.model_copy(update={"vulnerabilities": merged})
    tools = _analysis_tools(analysis_tools)
    instant = ensure_aware(generated_at) if generated_at is not None else utc_now()
    coverage = build_assessment_coverage(
        scan,
        tools,
        required_sections=required_sections,
    )
    findings = derive_assessment_findings(scan)
    risk = _calculate_risk(scan, findings, calculated_at=instant)
    values: dict[str, Any] = {
        "schema_version": scan.schema_version,
        "scanner_version": scan.scanner_version,
        "generated_at": instant,
        "endpoint_scan": scan,
        "analysis_tools": tools,
        "findings": findings,
        "risk": risk,
        "summary": summarize_assessment(scan, findings, coverage, risk),
        "coverage": coverage,
        "provenance": build_assessment_provenance(scan, tools),
        "limitations": _limitations(coverage),
    }
    if report_id is not None:
        values["report_id"] = report_id
    return CanonicalAssessmentReport.model_validate(values)


__all__ = [
    "DEFAULT_REQUIRED_SECTIONS",
    "AssessmentCoverage",
    "AssessmentProvenance",
    "AssessmentSummary",
    "CanonicalAssessmentReport",
    "CoverageSection",
    "CoverageState",
    "ObservationScope",
    "build_assessment_coverage",
    "build_canonical_assessment",
    "derive_assessment_findings",
    "summarize_assessment",
]
