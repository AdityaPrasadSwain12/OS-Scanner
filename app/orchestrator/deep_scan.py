"""Stateless, explicitly authorized local deep-scan composition.

Child results remain in process memory. No database, queue, or child report is
created; only the final combined JSON selected by the caller is persisted.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Self
from uuid import uuid4

from pydantic import Field, field_validator, model_validator

from app.analyzers.posture import BaselineAnalyzer
from app.analyzers.risk import RiskConfiguration, RiskEngine
from app.core.config import ScannerSettings
from app.models.base import Identifier, StrictModel, utc_now
from app.models.deep_scan import (
    DeepScanAuditContext,
    DeepScanJobAudit,
    DeepScanReport,
    DeepScanToolReadiness,
    build_deep_scan_report,
)
from app.models.enums import (
    CollectorState,
    OperatingSystemFamily,
    OverallStatus,
    ScanType,
)
from app.models.inventory import Endpoint, Process, SecurityPosture
from app.models.jobs import AuthorizationScope, ScanJob
from app.models.results import CollectorStatus, ScanResult
from app.models.validators import normalize_domain
from app.normalization.osquery import fallback_endpoint_identity
from app.policies.engine import EvaluationContext, PolicyEngine
from app.policies.loader import PolicyLoader
from app.policies.models import PolicyBundle
from app.policies.sync import canonical_policy_bytes
from app.reporting.deep_scan_json import DeepScanJsonWriter
from app.security.redaction import redact_text

from .collector_pipeline import CollectionBundle, CollectorPipeline
from .status import overall_status

_FULL_REQUIRED_SECTIONS = (
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
)
_INVENTORY_FIELDS = (
    "os",
    "hardware",
    "software",
    "processes",
    "services",
    "users",
    "network_interfaces",
    "listening_ports",
    "security",
    "updates",
    "browser_extensions",
    "certificates",
    "persistence",
    "compliance",
    "vulnerabilities",
    "attack_surface",
)
_READYNESS_ALIASES: dict[str, tuple[str, ...]] = {
    "native": ("native",),
    "osquery": ("osquery",),
    "openscap": ("openscap",),
    "osv-scanner": ("osv-scanner",),
    "depscan": ("depscan", "dep-scan", "owasp-depscan"),
    "amass": ("amass",),
}


class DeepScanRequest(StrictModel):
    """Bounded local intent for one endpoint and optional authorized domains."""

    authorized: Literal[True]
    endpoint_id: Identifier | None = None
    dependency_sources: tuple[Path, ...] = Field(default_factory=tuple, max_length=256)
    authorized_domains: tuple[str, ...] = Field(default_factory=tuple, max_length=100)
    timeout_seconds: int = Field(default=1_800, ge=10, le=86_400)
    output_path: Path
    authorization_reference: str = Field(
        default="local-deep-scan-consent",
        min_length=1,
        max_length=512,
    )

    @field_validator("authorized", mode="before")
    @classmethod
    def explicit_boolean_authorization(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("deep scans require explicit boolean authorization")
        return True

    @field_validator("dependency_sources")
    @classmethod
    def canonical_dependency_sources(cls, values: tuple[Path, ...]) -> tuple[Path, ...]:
        resolved: dict[str, Path] = {}
        for value in values:
            text = os.fspath(value)
            if not text or len(text) > 4_096 or "\x00" in text:
                raise ValueError("dependency_sources contains an invalid path")
            path = value.expanduser().resolve(strict=False)
            resolved[os.path.normcase(str(path))] = path
        return tuple(resolved[key] for key in sorted(resolved))

    @field_validator("authorized_domains")
    @classmethod
    def canonical_authorized_domains(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({normalize_domain(value) for value in values}))

    @field_validator("output_path")
    @classmethod
    def json_output_only(cls, value: Path) -> Path:
        return DeepScanJsonWriter.validate_destination(value)

    @model_validator(mode="after")
    def output_is_not_an_input(self) -> DeepScanRequest:
        output = self.output_path.resolve(strict=False)
        if any(
            output == source or output.is_relative_to(source)
            for source in self.dependency_sources
        ):
            raise ValueError("output_path cannot be inside a dependency source")
        return self


@dataclass(frozen=True, slots=True)
class DeepScanOutcome:
    report: DeepScanReport
    report_path: Path


def _policy_checksum(policy: PolicyBundle) -> str:
    return hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()


def _bounded_factor(value: object, default: float) -> float:
    try:
        result = float(str(value))
    except (TypeError, ValueError):
        return default
    return result if 0.0 <= result <= 1.0 else default


class StatelessScanner:
    """Collect and analyze one job without storage, queues, or child files."""

    def __init__(
        self,
        settings: ScannerSettings,
        policy: PolicyBundle,
        *,
        collectors: CollectorPipeline | None = None,
        policy_engine: PolicyEngine | None = None,
        risk_engine: RiskEngine | None = None,
        baseline_analyzer: BaselineAnalyzer | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.settings = settings
        self.policy = policy
        self.collectors = collectors or CollectorPipeline(settings)
        self.policy_engine = policy_engine or PolicyEngine()
        self.risk_engine = risk_engine or RiskEngine(
            RiskConfiguration.model_validate(settings.risk.model_dump(mode="python"))
        )
        self.baseline_analyzer = baseline_analyzer or BaselineAnalyzer(settings.analysis)
        self.clock = clock

    def execute(self, job: ScanJob) -> ScanResult:
        started_at = self.clock()
        job.validate_for_execution(started_at)
        if (job.policy_id, job.policy_version) != (
            self.policy.policy_id,
            self.policy.policy_version,
        ):
            raise ValueError("deep scan requested an unvalidated local policy")
        execution_budget = min(
            float(job.timeout_seconds),
            self.settings.runtime.scan_timeout_seconds,
        )
        if job.deadline is not None:
            execution_budget = min(
                execution_budget,
                (job.deadline - started_at).total_seconds(),
            )
        if execution_budget <= 0:
            raise TimeoutError("deep-scan execution deadline expired")
        execution_deadline = time.monotonic() + execution_budget
        bundle = self.collectors.collect(job, deadline_at=execution_deadline)
        if time.monotonic() >= execution_deadline:
            raise TimeoutError("deep-scan execution deadline exceeded")
        observed_at = self.clock()
        result = self._analyze(
            job,
            bundle,
            started_at=started_at,
            observed_at=observed_at,
            execution_deadline=execution_deadline,
        )
        if time.monotonic() >= execution_deadline:
            raise TimeoutError("deep-scan analysis deadline exceeded")
        finished_at = self.clock()
        endpoint = result.endpoint
        if endpoint is not None:
            endpoint = endpoint.model_copy(update={"last_seen_at": finished_at})
        return result.model_copy(
            update={
                "timestamp": finished_at,
                "finished_at": finished_at,
                "endpoint": endpoint,
            }
        )

    def _analyze(
        self,
        job: ScanJob,
        bundle: CollectionBundle,
        *,
        started_at: datetime,
        observed_at: datetime,
        execution_deadline: float,
    ) -> ScanResult:
        inventory = self.baseline_analyzer.analyze(bundle.inventory)
        if not self.settings.privacy.transmit_process_command_lines:
            inventory["processes"] = [
                process.model_copy(update={"command_line": None})
                if isinstance(process, Process)
                else process
                for process in inventory.get("processes", [])
            ]
        if self.settings.analysis.approved_security_posture and isinstance(
            inventory.get("security"), SecurityPosture
        ):
            posture = inventory["security"]
            assert isinstance(posture, SecurityPosture)
            controls = dict(posture.controls)
            baseline_observed = "security" in bundle.observed_inventory_sections
            controls["configuration_baseline_observed"] = baseline_observed
            inventory["security"] = posture.model_copy(
                update={
                    "configuration_drift": (
                        posture.configuration_drift if baseline_observed else None
                    ),
                    "controls": controls,
                }
            )

        endpoint: Endpoint | None = None
        asset_criticality = _bounded_factor(job.parameters.get("asset_criticality"), 0.5)
        if job.endpoint_id:
            operating_system = inventory.get("os")
            family = (
                operating_system.family
                if operating_system is not None
                else OperatingSystemFamily.UNKNOWN
            )
            hardware = inventory.get("hardware")
            endpoint = Endpoint(
                endpoint_id=job.endpoint_id,
                hostname=str(inventory.get("hostname") or "unknown"),
                os_family=family,
                machine_id=getattr(operating_system, "machine_id", None),
                manufacturer=getattr(hardware, "manufacturer", None),
                model=getattr(hardware, "device_model", None),
                asset_criticality=asset_criticality,
                last_seen_at=observed_at,
            )

        result_values: dict[str, object] = {
            "schema_version": self.settings.schema_version,
            "scanner_version": self.settings.scanner_version,
            "scan_id": job.scan_id,
            "endpoint_id": job.endpoint_id,
            "scan_type": job.scan_type,
            "timestamp": observed_at,
            "started_at": started_at,
            "finished_at": observed_at,
            "status": overall_status(bundle.collectors.values()),
            "policy_id": self.policy.policy_id,
            "policy_version": self.policy.policy_version,
            "policy_checksum": _policy_checksum(self.policy),
            "authorization_scope_id": job.authorization.scope_id,
            "endpoint": endpoint,
            "collectors": bundle.collectors,
            "metadata": {
                "warnings": [str(item)[:2_048] for item in bundle.warnings[:1_000]],
                "tool_versions": bundle.tool_versions,
                "authorized_target": job.target,
                "persistence_mode": "STATELESS",
                "observed_inventory_sections": sorted(
                    field
                    for field in _INVENTORY_FIELDS
                    if field in bundle.observed_inventory_sections
                ),
                "unobserved_inventory_sections": sorted(
                    field
                    for field in _INVENTORY_FIELDS
                    if field not in bundle.observed_inventory_sections
                ),
            },
        }
        result_values.update(
            {field: inventory[field] for field in _INVENTORY_FIELDS if field in inventory}
        )
        preliminary = ScanResult.model_validate(result_values)
        context = EvaluationContext(
            scan_id=job.scan_id,
            endpoint_id=job.endpoint_id,
            asset=job.target,
            scanner_version=self.settings.scanner_version,
            detected_at=observed_at,
            platform=preliminary.os.family if preliminary.os else None,
            scan_type=job.scan_type,
        )
        findings = self.policy_engine.evaluate(
            self.policy,
            preliminary,
            context,
            deadline_at=execution_deadline,
            max_operations=self.settings.runtime.max_policy_operations,
        )
        exposure = (
            1.0 if job.target or any(port.exposed for port in preliminary.listening_ports) else 0.3
        )
        risk = self.risk_engine.calculate(
            findings,
            scan_id=job.scan_id,
            asset_criticality=asset_criticality,
            exposure=exposure,
            now=observed_at,
            policy_version=self.policy.policy_version,
            scanner_version=self.settings.scanner_version,
        )
        return preliminary.model_copy(update={"findings": findings, "risk": risk})


class StatelessDeepScanOrchestrator:
    """Context-managed facade used by the combined deep-scan runner."""

    def __init__(self, scanner: StatelessScanner) -> None:
        self.scanner = scanner
        self._closed = False

    def close(self) -> None:
        self._closed = True

    def __enter__(self) -> Self:
        if self._closed:
            raise RuntimeError("stateless orchestrator is already closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# Compatibility name retained for callers created before the no-database
# execution contract was finalized.
EphemeralOrchestrator = StatelessDeepScanOrchestrator


def _load_local_policy(settings: ScannerSettings) -> PolicyBundle:
    policy_path = settings.policies.directory.expanduser().absolute()
    if not policy_path.exists():
        raise FileNotFoundError(f"policy path does not exist: {policy_path}")
    loader = PolicyLoader(
        trusted_root=policy_path if policy_path.is_dir() else policy_path.parent,
        max_file_bytes=settings.policies.max_file_bytes,
        max_rules=settings.policies.max_rules,
        max_depth=settings.policies.max_expression_depth,
        allow_symlinks=settings.policies.allow_symlinks,
    )
    return (
        loader.load_directory(policy_path)
        if policy_path.is_dir()
        else loader.load_file(policy_path)
    )


def create_stateless_orchestrator(
    settings: ScannerSettings,
    *,
    collectors: CollectorPipeline | None = None,
) -> StatelessDeepScanOrchestrator:
    """Create a truly storage-free scanner; no SQLite connection is opened."""

    return StatelessDeepScanOrchestrator(
        StatelessScanner(
            settings,
            _load_local_policy(settings),
            collectors=collectors,
        )
    )


def create_ephemeral_orchestrator(
    settings: ScannerSettings,
    *,
    collectors: CollectorPipeline | None = None,
) -> EphemeralOrchestrator:
    """Compatibility alias for the storage-free orchestrator factory."""

    return create_stateless_orchestrator(settings, collectors=collectors)


def _default_deep_endpoint_id() -> str:
    raw_hostname = str(fallback_endpoint_identity().get("hostname") or "device")
    label = re.sub(r"[^A-Za-z0-9._-]+", "-", raw_hostname).strip("._-") or "device"
    digest = hashlib.sha256(raw_hostname.encode("utf-8")).hexdigest()[:12]
    return f"local-{label[:96]}-{digest}"


def _validate_dependency_sources(
    settings: ScannerSettings,
    sources: tuple[Path, ...],
) -> tuple[Path, ...]:
    if not sources:
        return ()
    roots: list[Path] = []
    for configured_root in settings.tools.approved_dependency_roots:
        try:
            root = configured_root.expanduser().resolve(strict=True)
        except OSError as exc:
            raise ValueError("an approved dependency root is unavailable") from exc
        if not root.is_dir():
            raise ValueError("approved dependency roots must be directories")
        roots.append(root)
    if not roots:
        raise PermissionError(
            "dependency sources require protected tools.approved_dependency_roots"
        )

    approved: list[Path] = []
    for source in sources:
        try:
            resolved = source.expanduser().resolve(strict=True)
        except OSError as exc:
            raise ValueError("a dependency source does not exist") from exc
        if not (resolved.is_file() or resolved.is_dir()):
            raise ValueError("dependency sources must be regular files or directories")
        if not any(resolved == root or resolved.is_relative_to(root) for root in roots):
            raise PermissionError("dependency source is outside protected approved roots")
        approved.append(resolved)
    return tuple(approved)


def _validate_discovery_scope(
    settings: ScannerSettings,
    domains: tuple[str, ...],
) -> None:
    if not domains or not settings.discovery.enabled:
        return
    local_roots = settings.discovery.authorized_domains
    for domain in domains:
        if not any(domain == root or domain.endswith(f".{root}") for root in local_roots):
            raise PermissionError(
                "attack-surface domain is outside the protected discovery allowlist"
            )


def _build_scope(
    request: DeepScanRequest,
    *,
    endpoint_id: str,
) -> tuple[AuthorizationScope, datetime]:
    started_at = utc_now()
    deadline = started_at + timedelta(seconds=request.timeout_seconds)
    scope = AuthorizationScope(
        scope_id=f"deep-local-{uuid4()}",
        authorized=True,
        authorization_reference=request.authorization_reference,
        authorized_by="local-deep-scan-user",
        purpose="explicitly authorized deep scan of the local endpoint and declared domains",
        valid_from=started_at - timedelta(minutes=1),
        expires_at=deadline + timedelta(minutes=5),
        allowed_endpoint_ids=frozenset({endpoint_id}),
        allowed_domains=frozenset(request.authorized_domains),
        allow_subdomains=True,
    )
    return scope, deadline


def _endpoint_job(
    scanner: StatelessScanner,
    request: DeepScanRequest,
    *,
    endpoint_id: str,
    sources: tuple[Path, ...],
    scope: AuthorizationScope,
    deadline: datetime,
) -> ScanJob:
    return ScanJob(
        job_id=f"job-{uuid4()}",
        scan_id=f"scan-{uuid4()}",
        scan_type=ScanType.FULL,
        authorization=scope,
        endpoint_id=endpoint_id,
        policy_id=scanner.policy.policy_id,
        policy_version=scanner.policy.policy_version,
        approved_sources=tuple(str(source) for source in sources),
        initiated_by="local-deep-scan-explicit-consent",
        requested_at=utc_now(),
        deadline=deadline,
        timeout_seconds=request.timeout_seconds,
    )


def _attack_surface_job(
    scanner: StatelessScanner,
    request: DeepScanRequest,
    *,
    domain: str,
    scope: AuthorizationScope,
    deadline: datetime,
) -> ScanJob:
    return ScanJob(
        job_id=f"job-{uuid4()}",
        scan_id=f"attack-{uuid4()}",
        scan_type=ScanType.ATTACK_SURFACE,
        authorization=scope,
        target=domain,
        policy_id=scanner.policy.policy_id,
        policy_version=scanner.policy.policy_version,
        initiated_by="local-deep-scan-explicit-consent",
        requested_at=utc_now(),
        deadline=deadline,
        timeout_seconds=request.timeout_seconds,
        parameters={"scope": [domain]},
    )


def _build_audit_context(
    scope: AuthorizationScope,
    jobs: tuple[ScanJob, ...],
) -> DeepScanAuditContext:
    """Copy only bounded, non-secret authorization and job facts into the report."""

    return DeepScanAuditContext(
        authorization_scope_id=scope.scope_id,
        authorization_reference=scope.authorization_reference,
        authorized_by=scope.authorized_by,
        purpose=scope.purpose,
        valid_from=scope.valid_from,
        expires_at=scope.expires_at,
        allowed_endpoint_ids=tuple(scope.allowed_endpoint_ids),
        allowed_domains=tuple(scope.allowed_domains),
        excluded_domains=tuple(scope.excluded_domains),
        allow_subdomains=scope.allow_subdomains,
        allowed_networks=tuple(str(network) for network in scope.allowed_networks),
        excluded_networks=tuple(str(network) for network in scope.excluded_networks),
        jobs=tuple(
            DeepScanJobAudit(
                job_id=job.job_id,
                scan_id=job.scan_id,
                scan_type=job.scan_type,
                initiated_by=job.initiated_by,
                requested_at=job.requested_at,
                deadline=job.deadline,
                endpoint_id=job.endpoint_id,
                target=job.target,
            )
            for job in jobs
        ),
    )


def _terminal_execution_result(
    scanner: StatelessScanner,
    job: ScanJob,
    error: Exception,
) -> ScanResult:
    """Return a bounded terminal result when orchestration cannot finish a child scan."""

    finished_at = utc_now()
    started_at = min(job.requested_at, finished_at)
    timed_out = isinstance(error, TimeoutError)
    state = CollectorState.TIMEOUT if timed_out else CollectorState.FAILED
    error_code = "DEEP_SCAN_TIMEOUT" if timed_out else "DEEP_SCAN_EXECUTION_FAILED"
    message = redact_text(str(error), max_length=2_048) or (
        "deep-scan execution timed out" if timed_out else "deep-scan execution failed"
    )
    status = CollectorStatus(
        schema_version=scanner.settings.schema_version,
        scanner_version=scanner.settings.scanner_version,
        name="deep-scan",
        status=state,
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=max(0.0, (finished_at - started_at).total_seconds()),
        error_code=error_code,
        error_message=message,
    )
    return ScanResult(
        schema_version=scanner.settings.schema_version,
        scanner_version=scanner.settings.scanner_version,
        scan_id=job.scan_id,
        endpoint_id=job.endpoint_id,
        scan_type=job.scan_type,
        timestamp=finished_at,
        started_at=started_at,
        finished_at=finished_at,
        status=OverallStatus.FAILED,
        policy_id=scanner.policy.policy_id,
        policy_version=scanner.policy.policy_version,
        policy_checksum=_policy_checksum(scanner.policy),
        authorization_scope_id=job.authorization.scope_id,
        collectors={status.name: status},
        metadata={
            "warnings": [message],
            "tool_versions": {},
            "authorized_target": job.target,
            "persistence_mode": "STATELESS",
            "observed_inventory_sections": [],
            "unobserved_inventory_sections": list(_INVENTORY_FIELDS),
            "terminal_execution_error": error_code,
        },
    )


def _execute_with_terminal_result(
    scanner: StatelessScanner,
    job: ScanJob,
) -> ScanResult:
    try:
        return scanner.execute(job)
    except Exception as error:
        # Authorization and local-scope validation happen before this point. A
        # child execution failure must remain visible in the one final report.
        return _terminal_execution_result(scanner, job, error)


def _collector_matches(tool_name: str, collector_name: str) -> bool:
    return any(
        collector_name == alias or collector_name.startswith(f"{alias}.")
        for alias in _READYNESS_ALIASES[tool_name]
    )


def _reduce_states(statuses: Iterable[CollectorStatus]) -> CollectorState:
    states = {
        status.status
        for status in statuses
        if status.status is not CollectorState.SKIPPED
    }
    if not states:
        return CollectorState.SKIPPED
    if states == {CollectorState.SUCCESS}:
        return CollectorState.SUCCESS
    if states & {CollectorState.SUCCESS, CollectorState.PARTIAL}:
        return CollectorState.PARTIAL
    if CollectorState.FAILED in states:
        return CollectorState.FAILED
    if CollectorState.TIMEOUT in states:
        return CollectorState.TIMEOUT
    if CollectorState.UNAVAILABLE in states:
        return CollectorState.UNAVAILABLE
    return CollectorState.UNAVAILABLE


def _readiness_entry(
    name: str,
    *,
    configured: bool,
    scheduled: bool,
    scoped_statuses: list[tuple[str, CollectorStatus]],
) -> DeepScanToolReadiness:
    detail: str | None
    matching = [
        (scope, status)
        for scope, status in scoped_statuses
        if _collector_matches(name, status.name)
    ]
    if not scheduled:
        state = CollectorState.SKIPPED
        detail = "capability was not requested for this endpoint or target"
    elif matching:
        state = _reduce_states(status for _, status in matching)
        messages = sorted({status.error_message for _, status in matching if status.error_message})
        detail = "; ".join(messages)[:2_048] or None
    elif configured:
        state = CollectorState.UNAVAILABLE
        detail = "scheduled capability produced no collector readiness record"
    else:
        state = CollectorState.SKIPPED
        detail = "capability is not configured in protected local settings"

    if state in {CollectorState.FAILED, CollectorState.TIMEOUT} and not detail:
        detail = f"{name} did not complete successfully"
    versions = sorted(
        {status.tool_version for _, status in matching if status.tool_version is not None}
    )
    collector_names = tuple(f"{scope}:{status.name}" for scope, status in matching)
    return DeepScanToolReadiness(
        name=name,
        configured=configured,
        scheduled=scheduled,
        status=state,
        version=versions[-1] if versions else None,
        collector_names=collector_names,
        records_collected=sum(status.records_collected for _, status in matching),
        detail=redact_text(detail, max_length=2_048) if detail else None,
    )


def build_tool_readiness(
    settings: ScannerSettings,
    endpoint_scan: ScanResult,
    attack_surface_scans: tuple[ScanResult, ...] | list[ScanResult],
    *,
    dependency_sources_requested: bool,
    attack_surface_requested: bool,
) -> tuple[DeepScanToolReadiness, ...]:
    """Derive stable tool readiness from protected config and actual collectors."""

    scoped_statuses: list[tuple[str, CollectorStatus]] = [
        ("endpoint", status) for status in endpoint_scan.collectors.values()
    ]
    for result in attack_surface_scans:
        raw_target = result.metadata.get("authorized_target")
        target = str(raw_target) if isinstance(raw_target, str) else result.scan_id
        scoped_statuses.extend(
            (f"attack-surface[{target}]", status) for status in result.collectors.values()
        )

    tools = settings.tools
    is_linux = (
        endpoint_scan.os is not None and endpoint_scan.os.family is OperatingSystemFamily.LINUX
    )
    depscan_executable = getattr(tools, "depscan_executable", None)
    specs = {
        "native": (True, True),
        "osquery": (tools.osquery_executable is not None, True),
        "openscap": (
            tools.openscap_executable is not None
            and tools.default_scap_content is not None
            and tools.default_scap_profile is not None,
            is_linux,
        ),
        "osv-scanner": (
            tools.osv_scanner_executable is not None and bool(tools.approved_dependency_roots),
            dependency_sources_requested,
        ),
        "depscan": (
            depscan_executable is not None,
            True,
        ),
        "amass": (
            settings.discovery.enabled and tools.amass_executable is not None,
            attack_surface_requested,
        ),
    }
    return tuple(
        _readiness_entry(
            name,
            configured=configured,
            scheduled=scheduled,
            scoped_statuses=scoped_statuses,
        )
        for name, (configured, scheduled) in sorted(specs.items())
    )


StatelessFactory = Callable[[ScannerSettings], StatelessDeepScanOrchestrator]
EphemeralFactory = StatelessFactory


def run_deep_scan(
    settings: ScannerSettings,
    request: DeepScanRequest,
    *,
    orchestrator_factory: StatelessFactory | None = None,
) -> DeepScanOutcome:
    """Execute one FULL endpoint scan and isolated scans for authorized domains."""

    sources = _validate_dependency_sources(settings, request.dependency_sources)
    _validate_discovery_scope(settings, request.authorized_domains)
    endpoint_id = request.endpoint_id or _default_deep_endpoint_id()
    scope, deadline = _build_scope(request, endpoint_id=endpoint_id)
    factory = orchestrator_factory or create_stateless_orchestrator

    with factory(settings) as resources:
        scanner = resources.scanner
        endpoint_job = _endpoint_job(
            scanner,
            request,
            endpoint_id=endpoint_id,
            sources=sources,
            scope=scope,
            deadline=deadline,
        )
        attack_jobs = tuple(
            _attack_surface_job(
                scanner,
                request,
                domain=domain,
                scope=scope,
                deadline=deadline,
            )
            for domain in request.authorized_domains
        )
        endpoint_scan = _execute_with_terminal_result(scanner, endpoint_job)
        attack_results = tuple(
            _execute_with_terminal_result(scanner, job) for job in attack_jobs
        )

        required_sections = list(_FULL_REQUIRED_SECTIONS)
        required_sections.append("vulnerabilities")
        if endpoint_scan.os is not None and endpoint_scan.os.family is OperatingSystemFamily.LINUX:
            required_sections.append("compliance")
        readiness = build_tool_readiness(
            settings,
            endpoint_scan,
            attack_results,
            dependency_sources_requested=bool(sources),
            attack_surface_requested=bool(request.authorized_domains),
        )
        report = build_deep_scan_report(
            endpoint_scan,
            attack_results,
            audit_context=_build_audit_context(scope, (endpoint_job, *attack_jobs)),
            required_endpoint_sections=required_sections,
            requested_attack_surface_domains=request.authorized_domains,
            tool_readiness=readiness,
        )
        report_path = DeepScanJsonWriter(
            max_bytes=max(settings.cloud.max_request_bytes, 50 * 1024 * 1024)
        ).write(report, request.output_path)
        return DeepScanOutcome(report=report, report_path=report_path)


__all__ = [
    "DeepScanOutcome",
    "DeepScanRequest",
    "EphemeralOrchestrator",
    "StatelessDeepScanOrchestrator",
    "StatelessFactory",
    "StatelessScanner",
    "build_tool_readiness",
    "create_ephemeral_orchestrator",
    "create_stateless_orchestrator",
    "run_deep_scan",
]
