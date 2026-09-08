"""Strict aggregate model for a complete local deep-scan assessment.

The endpoint result and each authorized external attack-surface result remain
separate evidence envelopes.  This prevents domain discovery evidence from
being presented as if it had been observed on the endpoint itself.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import Field, field_validator, model_validator

from .base import (
    Identifier,
    StrictModel,
    VersionedModel,
    ensure_aware,
    utc_now,
)
from .enums import CollectorState, OverallStatus, ScanType
from .results import ScanResult

_DEGRADED_STATES = frozenset(
    {
        CollectorState.PARTIAL,
        CollectorState.FAILED,
        CollectorState.UNAVAILABLE,
        CollectorState.TIMEOUT,
    }
)


def _ordered_unique_strings(
    value: object,
    *,
    label: str,
    maximum_items: int,
    maximum_length: int,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError(f"{label} must be a sequence of strings")
    normalized: set[str] = set()
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or len(item) > maximum_length
            or "\x00" in item
            or "\r" in item
            or "\n" in item
        ):
            raise ValueError(f"{label} contains an invalid value")
        normalized.add(item)
    if len(normalized) > maximum_items:
        raise ValueError(f"{label} exceeds its item limit")
    return tuple(sorted(normalized))


def _safe_audit_text(value: str | None, *, maximum_length: int) -> str | None:
    """Bound and redact operator-supplied audit text before it reaches a report."""

    if value is None:
        return None
    if "\x00" in value or "\r" in value or "\n" in value:
        raise ValueError("audit text cannot contain control-line characters")
    from app.security.redaction import redact_text

    return redact_text(value, max_length=maximum_length)


class DeepScanJobAudit(StrictModel):
    """Non-secret execution identity retained for one deep-scan child job."""

    job_id: Identifier
    scan_id: Identifier
    scan_type: ScanType
    initiated_by: str | None = Field(default=None, max_length=256)
    requested_at: datetime
    deadline: datetime | None = None
    endpoint_id: Identifier | None = None
    target: str | None = Field(default=None, max_length=253)

    @field_validator("initiated_by")
    @classmethod
    def safe_initiator(cls, value: str | None) -> str | None:
        return _safe_audit_text(value, maximum_length=256)

    @field_validator("requested_at", "deadline")
    @classmethod
    def aware_job_times(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value is not None else None

    @field_validator("target")
    @classmethod
    def canonical_target(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from .validators import normalize_domain

        return normalize_domain(value)

    @model_validator(mode="after")
    def target_matches_scan_type(self) -> DeepScanJobAudit:
        if self.deadline is not None and self.deadline <= self.requested_at:
            raise ValueError("audited job deadline must follow its request time")
        if self.scan_type is ScanType.ATTACK_SURFACE:
            if self.target is None or self.endpoint_id is not None:
                raise ValueError(
                    "audited attack-surface jobs require a target and no endpoint"
                )
        elif self.endpoint_id is None or self.target is not None:
            raise ValueError("audited endpoint jobs require an endpoint and no target")
        return self


class DeepScanAuditContext(StrictModel):
    """Bounded authorization scope and child-job provenance for one report."""

    authorization_scope_id: Identifier
    authorization_reference: str = Field(min_length=1, max_length=512)
    authorized_by: str | None = Field(default=None, max_length=256)
    purpose: str | None = Field(default=None, max_length=1_024)
    valid_from: datetime
    expires_at: datetime
    allowed_endpoint_ids: tuple[Identifier, ...] = Field(max_length=10_000)
    allowed_domains: tuple[str, ...] = Field(default_factory=tuple, max_length=10_000)
    excluded_domains: tuple[str, ...] = Field(default_factory=tuple, max_length=10_000)
    allow_subdomains: bool
    allowed_networks: tuple[str, ...] = Field(default_factory=tuple, max_length=1_024)
    excluded_networks: tuple[str, ...] = Field(default_factory=tuple, max_length=1_024)
    jobs: tuple[DeepScanJobAudit, ...] = Field(min_length=1, max_length=10_001)

    @field_validator("authorization_reference", "authorized_by", "purpose")
    @classmethod
    def safe_authorization_text(cls, value: str | None, info: Any) -> str | None:
        limits = {
            "authorization_reference": 512,
            "authorized_by": 256,
            "purpose": 1_024,
        }
        return _safe_audit_text(value, maximum_length=limits[info.field_name])

    @field_validator("valid_from", "expires_at")
    @classmethod
    def aware_authorization_times(cls, value: datetime) -> datetime:
        return ensure_aware(value)

    @field_validator("allow_subdomains", mode="before")
    @classmethod
    def strict_allow_subdomains(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("allow_subdomains must be a JSON boolean")
        return value

    @field_validator("allowed_endpoint_ids", mode="before")
    @classmethod
    def canonical_endpoint_scope(cls, value: object) -> tuple[str, ...]:
        return _ordered_unique_strings(
            value,
            label="allowed_endpoint_ids",
            maximum_items=10_000,
            maximum_length=128,
        )

    @field_validator("allowed_domains", "excluded_domains", mode="before")
    @classmethod
    def canonical_domain_scope(cls, value: object) -> tuple[str, ...]:
        from .validators import normalize_domain

        domains = _ordered_unique_strings(
            value,
            label="authorization domains",
            maximum_items=10_000,
            maximum_length=253,
        )
        return tuple(sorted(normalize_domain(domain) for domain in domains))

    @field_validator("allowed_networks", "excluded_networks", mode="before")
    @classmethod
    def canonical_network_scope(cls, value: object) -> tuple[str, ...]:
        networks = _ordered_unique_strings(
            value,
            label="authorization networks",
            maximum_items=1_024,
            maximum_length=64,
        )
        try:
            return tuple(sorted({str(ipaddress.ip_network(network)) for network in networks}))
        except ValueError as exc:
            raise ValueError("authorization networks contain an invalid CIDR") from exc

    @model_validator(mode="after")
    def audit_scope_is_consistent(self) -> DeepScanAuditContext:
        if self.expires_at <= self.valid_from:
            raise ValueError("authorization expiration must follow its start time")
        if set(self.allowed_domains) & set(self.excluded_domains):
            raise ValueError("authorization domains cannot be both allowed and excluded")
        if set(self.allowed_networks) & set(self.excluded_networks):
            raise ValueError("authorization networks cannot be both allowed and excluded")
        if len({job.job_id for job in self.jobs}) != len(self.jobs):
            raise ValueError("audited child job IDs must be unique")
        if len({job.scan_id for job in self.jobs}) != len(self.jobs):
            raise ValueError("audited child scan IDs must be unique")
        endpoint_jobs = [job for job in self.jobs if job.scan_type is not ScanType.ATTACK_SURFACE]
        if len(endpoint_jobs) != 1:
            raise ValueError("deep-scan audit context requires exactly one endpoint job")
        allowed_endpoints = set(self.allowed_endpoint_ids)
        allowed_domains = set(self.allowed_domains)
        excluded_domains = set(self.excluded_domains)
        for job in self.jobs:
            if not self.valid_from <= job.requested_at < self.expires_at:
                raise ValueError("audited jobs must be requested within the authorization window")
            if job.deadline is not None and job.deadline > self.expires_at:
                raise ValueError("audited job deadline exceeds the authorization window")
            if job.endpoint_id is not None and job.endpoint_id not in allowed_endpoints:
                raise ValueError("audited endpoint is outside the authorization scope")
            if job.target is not None:
                denied = any(
                    job.target == domain or job.target.endswith(f".{domain}")
                    for domain in excluded_domains
                )
                directly_allowed = job.target in allowed_domains
                subdomain_allowed = self.allow_subdomains and any(
                    job.target.endswith(f".{domain}") for domain in allowed_domains
                )
                if denied or not (directly_allowed or subdomain_allowed):
                    raise ValueError("audited target is outside the authorization scope")
        return self


class DeepScanToolReadiness(StrictModel):
    """Configuration and observed execution state for one scanner capability."""

    name: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9-]*$",
    )
    configured: bool
    scheduled: bool
    status: CollectorState
    version: str | None = Field(default=None, max_length=128)
    collector_names: tuple[str, ...] = Field(default_factory=tuple)
    records_collected: int = Field(default=0, ge=0)
    detail: str | None = Field(default=None, max_length=2_048)

    @field_validator("configured", "scheduled", mode="before")
    @classmethod
    def strict_booleans(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("tool readiness flags must be JSON booleans")
        return value

    @field_validator("collector_names", mode="before")
    @classmethod
    def canonical_collector_names(cls, value: object) -> tuple[str, ...]:
        return _ordered_unique_strings(
            value,
            label="collector_names",
            maximum_items=2_000,
            maximum_length=256,
        )

    @field_validator("detail")
    @classmethod
    def redact_detail(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from app.security.redaction import redact_text

        return redact_text(value, max_length=2_048)

    @model_validator(mode="after")
    def readiness_is_consistent(self) -> DeepScanToolReadiness:
        if not self.scheduled and self.status is not CollectorState.SKIPPED:
            raise ValueError("an unscheduled tool must have SKIPPED status")
        if self.status in {CollectorState.FAILED, CollectorState.TIMEOUT} and not self.detail:
            raise ValueError("failed and timed-out tool readiness requires detail")
        return self


class DeepScanCompleteness(StrictModel):
    """Machine-readable declaration of what was and was not observed."""

    required_endpoint_sections: tuple[str, ...]
    observed_endpoint_sections: tuple[str, ...]
    unobserved_endpoint_sections: tuple[str, ...]
    degraded_collectors: tuple[str, ...] = Field(default_factory=tuple)
    requested_attack_surface_domains: tuple[str, ...] = Field(default_factory=tuple)
    observed_attack_surface_domains: tuple[str, ...] = Field(default_factory=tuple)
    unobserved_attack_surface_domains: tuple[str, ...] = Field(default_factory=tuple)
    complete: bool

    @field_validator(
        "required_endpoint_sections",
        "observed_endpoint_sections",
        "unobserved_endpoint_sections",
        mode="before",
    )
    @classmethod
    def canonical_sections(cls, value: object) -> tuple[str, ...]:
        return _ordered_unique_strings(
            value,
            label="endpoint sections",
            maximum_items=128,
            maximum_length=128,
        )

    @field_validator("degraded_collectors", mode="before")
    @classmethod
    def canonical_degraded_collectors(cls, value: object) -> tuple[str, ...]:
        return _ordered_unique_strings(
            value,
            label="degraded_collectors",
            maximum_items=10_000,
            maximum_length=512,
        )

    @field_validator(
        "requested_attack_surface_domains",
        "observed_attack_surface_domains",
        "unobserved_attack_surface_domains",
        mode="before",
    )
    @classmethod
    def canonical_domains(cls, value: object) -> tuple[str, ...]:
        from .validators import normalize_domain

        normalized = _ordered_unique_strings(
            value,
            label="attack-surface domains",
            maximum_items=10_000,
            maximum_length=253,
        )
        return tuple(sorted(normalize_domain(domain) for domain in normalized))

    @field_validator("complete", mode="before")
    @classmethod
    def strict_complete(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("complete must be a JSON boolean")
        return value

    @model_validator(mode="after")
    def completeness_sets_are_consistent(self) -> DeepScanCompleteness:
        required = set(self.required_endpoint_sections)
        observed = set(self.observed_endpoint_sections)
        unobserved = set(self.unobserved_endpoint_sections)
        if unobserved != required - observed:
            raise ValueError(
                "unobserved endpoint sections must equal required sections not observed"
            )
        requested_domains = set(self.requested_attack_surface_domains)
        observed_domains = set(self.observed_attack_surface_domains)
        unobserved_domains = set(self.unobserved_attack_surface_domains)
        if not observed_domains <= requested_domains:
            raise ValueError("observed attack-surface domains were not requested")
        if unobserved_domains != requested_domains - observed_domains:
            raise ValueError(
                "unobserved attack-surface domains must equal requested domains not observed"
            )
        expected_complete = (
            not unobserved and not unobserved_domains and not self.degraded_collectors
        )
        if self.complete is not expected_complete:
            raise ValueError("complete does not match the declared evidence coverage")
        return self


class DeepScanSummary(StrictModel):
    """Stable counters used by a CLI or future dashboard without reparsing evidence."""

    endpoint_id: Identifier
    status: OverallStatus
    started_at: datetime
    finished_at: datetime
    scan_count: int = Field(ge=1)
    attack_surface_scan_count: int = Field(ge=0)
    software_count: int = Field(ge=0)
    process_count: int = Field(ge=0)
    service_count: int = Field(ge=0)
    user_count: int = Field(ge=0)
    network_interface_count: int = Field(ge=0)
    listening_port_count: int = Field(ge=0)
    update_count: int = Field(ge=0)
    missing_patch_count: int = Field(ge=0)
    browser_extension_count: int = Field(ge=0)
    persistence_count: int = Field(ge=0)
    compliance_result_count: int = Field(ge=0)
    vulnerability_count: int = Field(ge=0)
    attack_surface_asset_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)

    @field_validator("started_at", "finished_at")
    @classmethod
    def aware_summary_times(cls, value: datetime) -> datetime:
        return ensure_aware(value)

    @model_validator(mode="after")
    def summary_times_are_ordered(self) -> DeepScanSummary:
        if self.finished_at < self.started_at:
            raise ValueError("deep-scan summary finished_at cannot precede started_at")
        if self.scan_count != self.attack_surface_scan_count + 1:
            raise ValueError("deep-scan scan_count must include one endpoint scan")
        return self


class DeepScanReport(VersionedModel):
    """One authoritative JSON assessment composed from isolated scan results."""

    report_id: Identifier = Field(default_factory=lambda: f"deep-{uuid4()}")
    generated_at: datetime = Field(default_factory=utc_now)
    authorization_scope_id: Identifier
    audit_context: DeepScanAuditContext
    endpoint_scan: ScanResult
    attack_surface_scans: tuple[ScanResult, ...] = Field(default_factory=tuple, max_length=10_000)
    summary: DeepScanSummary
    completeness: DeepScanCompleteness
    tool_readiness: tuple[DeepScanToolReadiness, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )

    @field_validator("generated_at")
    @classmethod
    def aware_generated_at(cls, value: datetime) -> datetime:
        return ensure_aware(value)

    @model_validator(mode="after")
    def validate_aggregate_consistency(self) -> DeepScanReport:
        if self.endpoint_scan.scan_type is ScanType.ATTACK_SURFACE:
            raise ValueError("endpoint_scan cannot contain an attack-surface result")
        if self.endpoint_scan.endpoint_id is None:
            raise ValueError("endpoint_scan must identify its endpoint")
        if self.endpoint_scan.attack_surface:
            raise ValueError(
                "endpoint attack-surface evidence must remain in separate authorized results"
            )
        scans = (self.endpoint_scan, *self.attack_surface_scans)
        if any(
            result.scan_type is not ScanType.ATTACK_SURFACE for result in self.attack_surface_scans
        ):
            raise ValueError("attack_surface_scans may contain only ATTACK_SURFACE results")
        if len({result.scan_id for result in scans}) != len(scans):
            raise ValueError("all deep-scan child scan IDs must be unique")
        if any(result.authorization_scope_id != self.authorization_scope_id for result in scans):
            raise ValueError("all child results must share the report authorization scope")
        if self.audit_context.authorization_scope_id != self.authorization_scope_id:
            raise ValueError("audit context must share the report authorization scope")
        audits_by_scan_id = {job.scan_id: job for job in self.audit_context.jobs}
        if set(audits_by_scan_id) != {result.scan_id for result in scans}:
            raise ValueError("audit context must identify every deep-scan child result")
        for result in scans:
            job = audits_by_scan_id[result.scan_id]
            if job.scan_type is not result.scan_type:
                raise ValueError("audited job scan types must match child results")
            if job.endpoint_id != result.endpoint_id:
                raise ValueError("audited job endpoints must match child results")
            expected_target = (
                _attack_surface_target(result)
                if result.scan_type is ScanType.ATTACK_SURFACE
                else None
            )
            if job.target != expected_target:
                raise ValueError("audited job targets must match child results")
        if any(
            (result.schema_version, result.scanner_version)
            != (self.schema_version, self.scanner_version)
            for result in scans
        ):
            raise ValueError("all child results must share report schema and scanner versions")
        policy_identity = (
            self.endpoint_scan.policy_id,
            self.endpoint_scan.policy_version,
            self.endpoint_scan.policy_checksum,
        )
        if any(
            (result.policy_id, result.policy_version, result.policy_checksum)
            != policy_identity
            for result in scans
        ):
            raise ValueError("all child results must share one validated policy identity")
        if any(result.finished_at is None for result in scans):
            raise ValueError("deep-scan child results must be terminal")
        terminal_statuses = {
            OverallStatus.SUCCESS,
            OverallStatus.PARTIAL,
            OverallStatus.FAILED,
        }
        if any(result.status not in terminal_statuses for result in scans):
            raise ValueError("deep-scan child results must have terminal result statuses")
        expected_summary = _summary_with_completeness(
            summarize_deep_scan_results(
                self.endpoint_scan,
                self.attack_surface_scans,
            ),
            self.completeness,
        )
        if self.summary != expected_summary:
            raise ValueError("deep-scan summary does not match its child results")
        if self.generated_at < self.summary.finished_at:
            raise ValueError("generated_at cannot precede child scan completion")
        if not (
            self.audit_context.valid_from
            <= self.summary.started_at
            < self.audit_context.expires_at
        ):
            raise ValueError("child execution began outside the authorization window")
        if self.summary.finished_at > self.audit_context.expires_at:
            raise ValueError("child execution exceeded the authorization window")

        targets = {
            result.scan_id: _attack_surface_target(result)
            for result in self.attack_surface_scans
        }
        for result in self.attack_surface_scans:
            if any(
                asset.root_domain != targets[result.scan_id]
                for asset in result.attack_surface
            ):
                raise ValueError(
                    "attack-surface assets must match their authorized result target"
                )
        reported_domains = tuple(sorted(targets.values()))
        if reported_domains != self.completeness.requested_attack_surface_domains:
            raise ValueError("each requested attack-surface domain must have one separate result")
        readiness_names = tuple(item.name for item in self.tool_readiness)
        if readiness_names != tuple(sorted(set(readiness_names))):
            raise ValueError("tool_readiness must contain unique entries in canonical order")
        readiness_gaps = {
            f"tool:{item.name}"
            for item in self.tool_readiness
            if item.scheduled and item.status is not CollectorState.SUCCESS
        }
        declared_tool_gaps = {
            item
            for item in self.completeness.degraded_collectors
            if item.startswith("tool:")
        }
        if declared_tool_gaps != readiness_gaps:
            raise ValueError("completeness must include every scheduled tool readiness gap")
        return self


def _combined_status(results: tuple[ScanResult, ...]) -> OverallStatus:
    if results[0].status is OverallStatus.FAILED:
        return OverallStatus.FAILED
    statuses = {result.status for result in results}
    if statuses == {OverallStatus.SUCCESS}:
        return OverallStatus.SUCCESS
    if statuses & {OverallStatus.SUCCESS, OverallStatus.PARTIAL}:
        return OverallStatus.PARTIAL
    return OverallStatus.FAILED


def summarize_deep_scan_results(
    endpoint_scan: ScanResult,
    attack_surface_scans: tuple[ScanResult, ...] | list[ScanResult] = (),
) -> DeepScanSummary:
    """Derive counters from evidence so serialized summaries cannot drift."""

    attack_results = tuple(attack_surface_scans)
    results = (endpoint_scan, *attack_results)
    finished = [result.finished_at for result in results]
    if any(value is None for value in finished):
        raise ValueError("deep-scan summaries require terminal child results")
    finished_times = [value for value in finished if value is not None]
    return DeepScanSummary(
        endpoint_id=endpoint_scan.endpoint_id or "unknown",
        status=_combined_status(results),
        started_at=min(result.started_at for result in results),
        finished_at=max(finished_times),
        scan_count=len(results),
        attack_surface_scan_count=len(attack_results),
        software_count=len(endpoint_scan.software),
        process_count=len(endpoint_scan.processes),
        service_count=len(endpoint_scan.services),
        user_count=len(endpoint_scan.users),
        network_interface_count=len(endpoint_scan.network_interfaces),
        listening_port_count=len(endpoint_scan.listening_ports),
        update_count=len(endpoint_scan.updates),
        missing_patch_count=sum(not update.installed for update in endpoint_scan.updates),
        browser_extension_count=len(endpoint_scan.browser_extensions),
        persistence_count=len(endpoint_scan.persistence),
        compliance_result_count=len(endpoint_scan.compliance),
        vulnerability_count=len(endpoint_scan.vulnerabilities),
        attack_surface_asset_count=sum(len(result.attack_surface) for result in attack_results),
        finding_count=sum(len(result.findings) for result in results),
    )


def _summary_with_completeness(
    summary: DeepScanSummary,
    completeness: DeepScanCompleteness,
) -> DeepScanSummary:
    if not completeness.complete and summary.status is OverallStatus.SUCCESS:
        return summary.model_copy(update={"status": OverallStatus.PARTIAL})
    return summary


def _metadata_strings(result: ScanResult, key: str) -> tuple[str, ...]:
    raw = result.metadata.get(key, [])
    if not isinstance(raw, list):
        return ()
    return tuple(item for item in raw if isinstance(item, str))


def _attack_surface_target(result: ScanResult) -> str:
    from .validators import normalize_domain

    raw = result.metadata.get("authorized_target")
    if not isinstance(raw, str) or not raw:
        roots = {asset.root_domain for asset in result.attack_surface}
        if len(roots) != 1:
            raise ValueError(
                "attack-surface results require metadata.authorized_target, including empty results"
            )
        raw = next(iter(roots))
    return normalize_domain(raw)


def build_deep_scan_completeness(
    endpoint_scan: ScanResult,
    attack_surface_scans: tuple[ScanResult, ...] | list[ScanResult],
    *,
    required_endpoint_sections: tuple[str, ...] | list[str],
    requested_attack_surface_domains: tuple[str, ...] | list[str],
) -> DeepScanCompleteness:
    """Calculate honest coverage from existing collector provenance metadata."""

    required = set(required_endpoint_sections)
    observed = set(_metadata_strings(endpoint_scan, "observed_inventory_sections"))
    requested_domains = set(requested_attack_surface_domains)
    observed_domains: set[str] = set()
    degraded: set[str] = set()

    for name, collector in endpoint_scan.collectors.items():
        if collector.status in _DEGRADED_STATES:
            degraded.add(f"endpoint:{name}")
    for result in attack_surface_scans:
        target = _attack_surface_target(result)
        if "attack_surface" in _metadata_strings(result, "observed_inventory_sections"):
            observed_domains.add(target)
        for name, collector in result.collectors.items():
            if collector.status in _DEGRADED_STATES:
                degraded.add(f"attack-surface:{target}:{name}")

    missing_sections = required - observed
    missing_domains = requested_domains - observed_domains
    return DeepScanCompleteness(
        required_endpoint_sections=tuple(required),
        observed_endpoint_sections=tuple(observed),
        unobserved_endpoint_sections=tuple(missing_sections),
        degraded_collectors=tuple(degraded),
        requested_attack_surface_domains=tuple(requested_domains),
        observed_attack_surface_domains=tuple(observed_domains),
        unobserved_attack_surface_domains=tuple(missing_domains),
        complete=not missing_sections and not missing_domains and not degraded,
    )


def build_deep_scan_report(
    endpoint_scan: ScanResult,
    attack_surface_scans: tuple[ScanResult, ...] | list[ScanResult] = (),
    *,
    audit_context: DeepScanAuditContext,
    required_endpoint_sections: tuple[str, ...] | list[str],
    requested_attack_surface_domains: tuple[str, ...] | list[str] = (),
    tool_readiness: tuple[DeepScanToolReadiness, ...] | list[DeepScanToolReadiness] = (),
    report_id: str | None = None,
    generated_at: datetime | None = None,
) -> DeepScanReport:
    """Create a validated aggregate without mutating any child evidence."""

    attack_results = tuple(attack_surface_scans)
    readiness = tuple(sorted(tool_readiness, key=lambda item: item.name))
    completeness = build_deep_scan_completeness(
        endpoint_scan,
        attack_results,
        required_endpoint_sections=required_endpoint_sections,
        requested_attack_surface_domains=requested_attack_surface_domains,
    )
    readiness_gaps = {
        f"tool:{item.name}"
        for item in readiness
        if item.scheduled and item.status is not CollectorState.SUCCESS
    }
    if readiness_gaps:
        degraded = tuple(set(completeness.degraded_collectors) | readiness_gaps)
        completeness = DeepScanCompleteness.model_validate(
            {
                **completeness.model_dump(mode="python"),
                "degraded_collectors": degraded,
                "complete": False,
            }
        )
    values: dict[str, Any] = {
        "schema_version": endpoint_scan.schema_version,
        "scanner_version": endpoint_scan.scanner_version,
        "authorization_scope_id": endpoint_scan.authorization_scope_id,
        "audit_context": audit_context,
        "generated_at": generated_at or utc_now(),
        "endpoint_scan": endpoint_scan,
        "attack_surface_scans": attack_results,
        "summary": _summary_with_completeness(
            summarize_deep_scan_results(endpoint_scan, attack_results),
            completeness,
        ),
        "completeness": completeness,
        "tool_readiness": readiness,
    }
    if report_id is not None:
        values["report_id"] = report_id
    return DeepScanReport.model_validate(values)


__all__ = [
    "DeepScanAuditContext",
    "DeepScanCompleteness",
    "DeepScanJobAudit",
    "DeepScanReport",
    "DeepScanSummary",
    "DeepScanToolReadiness",
    "build_deep_scan_completeness",
    "build_deep_scan_report",
    "summarize_deep_scan_results",
]
