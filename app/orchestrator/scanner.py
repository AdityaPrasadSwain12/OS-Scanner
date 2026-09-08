"""Auditable scan lifecycle: validate, collect, analyze, persist, and queue."""

from __future__ import annotations

import hashlib
import logging
import re
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import uuid4

from app.analyzers import BaselineAnalyzer, RiskConfiguration, RiskEngine
from app.core import ScannerSettings
from app.models import (
    Endpoint,
    OperatingSystemFamily,
    OverallStatus,
    Process,
    ScanJob,
    ScanResult,
    SecurityPosture,
)
from app.observability import ScannerMetrics, StructuredLogger, configure_logging
from app.policies import (
    EvaluationContext,
    PolicyBundle,
    PolicyEngine,
    PolicyLoader,
    ValidatedPolicyDocument,
    canonical_policy_bytes,
    canonical_policy_document,
    policy_document_bytes,
)
from app.reporting import AtomicReportWriter, serialize_report
from app.sbom import build_cyclonedx_sbom
from app.security import sanitize_for_log
from app.storage import MaintenanceResult, SnapshotChange, SQLiteStorage, StorageMaintenance
from app.storage.serialization import canonical_json

from .collector_pipeline import CollectionBundle, CollectorPipeline
from .status import overall_status


class ScanExecutionError(RuntimeError):
    """The trusted lifecycle failed outside an isolated collector boundary."""


class _CompletedScanReconciliationError(RuntimeError):
    """A completed scan stayed authoritative while artifact repair failed."""


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


def _policy_checksum(bundle: PolicyBundle) -> str:
    return hashlib.sha256(canonical_policy_bytes(bundle)).hexdigest()


def _event_id(event: str, scan_id: str) -> str:
    digest = hashlib.sha256(scan_id.encode("utf-8")).hexdigest()[:32]
    return f"{event}:{digest}"


def _bounded_factor(value: object, default: float) -> float:
    try:
        result = float(str(value))
    except (TypeError, ValueError):
        return default
    return result if 0.0 <= result <= 1.0 else default


class ScannerOrchestrator:
    """Coordinates trusted components without embedding collector or rule logic."""

    def __init__(
        self,
        settings: ScannerSettings,
        storage: SQLiteStorage,
        policy: PolicyBundle,
        *,
        collectors: CollectorPipeline | None = None,
        policy_engine: PolicyEngine | None = None,
        risk_engine: RiskEngine | None = None,
        baseline_analyzer: BaselineAnalyzer | None = None,
        report_writer: AtomicReportWriter | None = None,
        metrics: ScannerMetrics | None = None,
        logger: StructuredLogger | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        registered_policies: Sequence[PolicyBundle] = (),
        initial_policy_source: str = "local",
    ) -> None:
        self.settings = settings
        self.storage = storage
        self.policy = policy
        self._policy_lock = RLock()
        self._policies = {
            (bundle.policy_id, bundle.policy_version): bundle
            for bundle in (*registered_policies, policy)
        }
        self.collectors = collectors or CollectorPipeline(settings)
        self.policy_engine = policy_engine or PolicyEngine()
        self.risk_engine = risk_engine or RiskEngine(
            RiskConfiguration.model_validate(settings.risk.model_dump(mode="python"))
        )
        self.baseline_analyzer = baseline_analyzer or BaselineAnalyzer(settings.analysis)
        self.report_writer = report_writer or AtomicReportWriter(
            settings.report_directory,
            max_bytes=settings.cloud.max_request_bytes,
        )
        self.storage_maintenance = StorageMaintenance(
            storage,
            self.report_writer.directory,
            settings.retention,
        )
        self.metrics = metrics or ScannerMetrics()
        self.logger = logger
        self.clock = clock
        self.storage.set_schema_version(
            "scan-result",
            settings.schema_version,
            metadata={"scanner_version": settings.scanner_version},
        )
        checksum = _policy_checksum(policy)
        cached = {
            (item["policy_id"], item["version"]): item
            for item in self.storage.list_policy_documents(limit=10_000)
        }
        identity = (policy.policy_id, policy.policy_version)
        existing = cached.get(identity)
        with self.storage.transaction():
            if existing is None:
                self.storage.cache_policy_document(
                    policy.policy_id,
                    policy.policy_version,
                    checksum,
                    canonical_policy_document(policy),
                    source=initial_policy_source,
                    active=True,
                )
            else:
                if existing["checksum"] != checksum:
                    raise ValueError(
                        "active cached policy checksum conflicts with validated policy content"
                    )
                self.storage.activate_policy_document(*identity)
            self.storage.set_policy_version(
                policy.policy_id,
                policy.policy_version,
                checksum,
                metadata={
                    "schema_version": policy.schema_version,
                    "rule_count": len(policy.rules),
                    "source": initial_policy_source,
                },
            )

    @classmethod
    def from_settings(cls, settings: ScannerSettings) -> ScannerOrchestrator:
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
        local_policy = (
            loader.load_directory(policy_path)
            if policy_path.is_dir()
            else loader.load_file(policy_path)
        )
        storage = SQLiteStorage(settings.database_path)
        try:
            return cls._from_loaded_settings(settings, storage, loader, local_policy)
        except BaseException:
            # A long-lived desktop process cannot rely on interpreter exit to
            # release a database opened before policy-cache initialization.
            storage.close()
            raise

    @classmethod
    def _from_loaded_settings(
        cls,
        settings: ScannerSettings,
        storage: SQLiteStorage,
        loader: PolicyLoader,
        local_policy: PolicyBundle,
    ) -> ScannerOrchestrator:
        """Finish construction after storage opens; the caller owns failure cleanup."""

        policy = local_policy
        policy_source = "local"
        cached_documents = storage.list_policy_documents(limit=10_000)
        cloud_assignment_active = any(
            cached["active"] and cached["source"] == "cloud"
            for cached in cached_documents
        )
        registered_policies: list[PolicyBundle] = (
            [] if cloud_assignment_active else [local_policy]
        )
        for cached in cached_documents:
            if cloud_assignment_active and (
                cached["source"] != "cloud" or not cached["assigned"]
            ):
                continue
            try:
                cached_policy = loader.load_document(
                    cached["document"], source_name="cached policy"
                )
                if (
                    cached_policy.policy_id != cached["policy_id"]
                    or cached_policy.policy_version != cached["version"]
                ):
                    raise ValueError("cached policy identity mismatch")
                canonical_checksum = _policy_checksum(cached_policy)
                if canonical_checksum != cached["checksum"]:
                    stored_document_checksum = hashlib.sha256(
                        policy_document_bytes(cached["document"])
                    ).hexdigest()
                    if stored_document_checksum != cached["checksum"]:
                        raise ValueError("cached policy checksum mismatch")
                    canonical_document = canonical_policy_document(cached_policy)
                    storage.migrate_policy_document_canonicalization(
                        cached_policy.policy_id,
                        cached_policy.policy_version,
                        str(cached["checksum"]),
                        canonical_checksum,
                        canonical_document,
                    )
                    cached["checksum"] = canonical_checksum
                    cached["document"] = canonical_document
            except (TypeError, ValueError) as exc:
                storage.record_audit_event(
                    "POLICY_CACHE_REJECTED",
                    "REJECTED",
                    event_id=f"policy-cache-rejected:{uuid4()}",
                    resource_type="policy",
                    resource_id=str(cached.get("policy_id") or "unknown")[:128],
                    details={
                        "policy_version": str(cached.get("version") or "")[:64],
                        "checksum": str(cached.get("checksum") or "")[:128],
                        "reason": type(exc).__name__,
                    },
                )
                continue
            registered_policies.append(cached_policy)
            if cached["active"]:
                policy = cached_policy
                policy_source = str(cached["source"])
        if not registered_policies:
            registered_policies.append(local_policy)
        logger = configure_logging(
            level=getattr(logging, settings.log_level), replace_handlers=False
        )
        return cls(
            settings,
            storage,
            policy,
            logger=logger,
            registered_policies=registered_policies,
            initial_policy_source=policy_source,
        )

    def install_policy_assignment(
        self,
        documents: Sequence[ValidatedPolicyDocument],
        active_policy_id: str,
        active_policy_version: str,
        assignment_id: str,
    ) -> bool:
        """Atomically cache and activate a fully validated cloud assignment."""

        if not documents or len(documents) > 64:
            raise ValueError("policy assignment must contain between 1 and 64 documents")
        by_identity = {
            (item.bundle.policy_id, item.bundle.policy_version): item
            for item in documents
        }
        if len(by_identity) != len(documents):
            raise ValueError("policy assignment contains duplicate ID/version pairs")
        active_identity = (active_policy_id, active_policy_version)
        selected = by_identity.get(active_identity)
        if selected is None:
            raise ValueError("active policy is missing from the validated assignment")

        with self._policy_lock:
            previous_identity = (self.policy.policy_id, self.policy.policy_version)
            changed = previous_identity != active_identity
            with self.storage.transaction():
                self.storage.revoke_cloud_policy_assignments()
                for identity, item in by_identity.items():
                    if _policy_checksum(item.bundle) != item.checksum:
                        raise ValueError("validated policy checksum changed before installation")
                    self.storage.cache_policy_document(
                        *identity,
                        item.checksum,
                        canonical_policy_document(item.bundle),
                        source="cloud",
                    )
                    self.storage.set_policy_version(
                        *identity,
                        item.checksum,
                        metadata={
                            "schema_version": item.bundle.schema_version,
                            "rule_count": len(item.bundle.rules),
                            "source": "cloud",
                            "assignment_id": assignment_id,
                        },
                        active=identity == active_identity,
                    )
                self.storage.activate_policy_document(*active_identity)
                if changed:
                    self.storage.record_audit_event(
                        "POLICY_ACTIVATED",
                        "SUCCESS",
                        event_id=f"policy-activated:{uuid4()}",
                        resource_type="policy",
                        resource_id=active_policy_id,
                        details={
                            "assignment_id": assignment_id,
                            "previous_policy_id": previous_identity[0],
                            "previous_policy_version": previous_identity[1],
                            "policy_version": active_policy_version,
                            "checksum": selected.checksum,
                            "rule_count": len(selected.bundle.rules),
                        },
                    )
            self._policies = {
                identity: item.bundle for identity, item in by_identity.items()
            }
            self.policy = selected.bundle
            return changed

    def resolve_policy(self, job: ScanJob) -> PolicyBundle:
        """Resolve the active policy or an explicitly versioned cached policy."""

        with self._policy_lock:
            if job.policy_version is not None:
                policy = self._policies.get((job.policy_id, job.policy_version))
            elif job.policy_id == self.policy.policy_id:
                policy = self.policy
            else:
                policy = None
        if policy is None:
            raise ValueError("requested policy ID/version is not validated and cached locally")
        return policy

    def maintain_storage(self, *, now: datetime | None = None) -> MaintenanceResult:
        """Apply protected retention and enforce local disk admission limits."""

        return self.storage_maintenance.run(now=now)

    @property
    def policy_checksum(self) -> str:
        """Canonical checksum of the active, fully validated policy bundle."""

        with self._policy_lock:
            return _policy_checksum(self.policy)

    def record_policy_sync_rejection(self, fingerprint: str, reason: str) -> None:
        """Record a sanitized, restart-idempotent rejected assignment audit event."""

        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("policy assignment fingerprint is invalid")
        event_id = f"policy-sync-rejected:{fingerprint[:32]}"
        if self.storage.has_audit_event(event_id):
            return
        self.storage.record_audit_event(
            "POLICY_SYNC_REJECTED",
            "REJECTED",
            event_id=event_id,
            resource_type="policy-assignment",
            resource_id=fingerprint[:32],
            details={
                "document_sha256": fingerprint,
                "reason": str(sanitize_for_log(reason))[:512],
            },
        )

    def reconcile_terminal_statuses(self, *, limit: int = 100) -> int:
        """Repair missing terminal status outbox entries after interrupted failures.

        Enqueue keys are deterministic, so calling this on every service/upload
        iteration is safe and converts a best-effort failure notification into
        durable eventual delivery.
        """

        reconciled = 0
        for record in self.storage.terminal_scan_jobs(limit=limit):
            raw_job = record.get("job")
            if not isinstance(raw_job, Mapping):
                continue
            payload = {
                key: value
                for key, value in raw_job.items()
                if key not in {"status", "initiator"}
            }
            try:
                job = ScanJob.model_validate(payload)
                status = OverallStatus(str(record["result_status"]))
            except (KeyError, TypeError, ValueError):
                continue
            if status not in {
                OverallStatus.SUCCESS,
                OverallStatus.PARTIAL,
                OverallStatus.FAILED,
            }:
                continue
            stored_result: ScanResult | None = None
            if status is not OverallStatus.FAILED:
                normalized = self.storage.get_normalized_result(job.scan_id)
                if normalized is not None:
                    try:
                        stored_result = ScanResult.model_validate(normalized["payload"])
                    except (KeyError, TypeError, ValueError):
                        stored_result = None
            self._queue_terminal_status(job, status, result=stored_result)
            reconciled += 1
        return reconciled

    def execute(self, job: ScanJob) -> ScanResult:
        """Execute one job exactly within its explicit authorization envelope."""

        attempted_at = self.clock()
        started_at = attempted_at
        started_monotonic = time.monotonic()
        try:
            job.validate_for_execution(attempted_at)
            policy = self.resolve_policy(job)
        except ValueError as exc:
            self.storage.record_audit_event(
                "SCAN_REJECTED",
                "REJECTED",
                event_id=_event_id("scan-rejected", job.scan_id),
                actor=job.initiated_by,
                resource_type="domain" if job.target else "endpoint",
                resource_id=job.target or job.endpoint_id,
                scan_id=job.scan_id,
                endpoint_id=job.endpoint_id,
                authorization_scope_id=job.authorization.scope_id,
                details={"reason": str(sanitize_for_log(exc))[:2048]},
                created_at=attempted_at.isoformat(),
                return_existing=True,
            )
            raise
        execution_budget = min(
            float(job.timeout_seconds),
            self.settings.runtime.scan_timeout_seconds,
        )
        if job.deadline is not None:
            execution_budget = min(
                execution_budget,
                (job.deadline - attempted_at).total_seconds(),
            )
        execution_deadline = started_monotonic + max(0.0, execution_budget)
        scan_logger = (
            self.logger.bind(
                scan_id=job.scan_id,
                endpoint_id=job.endpoint_id,
                scanner_version=self.settings.scanner_version,
                authorization_scope_id=job.authorization.scope_id,
            )
            if self.logger
            else None
        )
        try:
            job_payload = job.model_dump(mode="json", exclude_none=True)
            job_payload.update(
                {
                    "status": OverallStatus.QUEUED.value,
                    "initiator": job.initiated_by,
                }
            )
            self.storage.create_scan_job(job_payload)
            existing = self.storage.get_normalized_result(job.scan_id)
            if existing is not None:
                result = ScanResult.model_validate(existing["payload"])
                # Reconcile artifacts/outbox after a crash from an older release.
                try:
                    self.report_writer.write(job.scan_id, result)
                    with self.storage.transaction():
                        change = self.storage.get_snapshot_change_for_scan(job.scan_id)
                        self._queue_result(job, result, change)
                        self._queue_terminal_status(job, result.status, result=result)
                        self.storage.update_scan_job(
                            job.scan_id,
                            "COMPLETED",
                            completed_at=(
                                result.finished_at.isoformat()
                                if result.finished_at
                                else None
                            ),
                            result_status=result.status.value,
                        )
                except Exception as exc:
                    # The normalized result is already authoritative.  Surface
                    # reconciliation failure to the caller without rewriting a
                    # completed scan as FAILED or emitting a contradictory
                    # terminal status.
                    raise _CompletedScanReconciliationError(
                        str(sanitize_for_log(exc))[:2048]
                    ) from exc
                if scan_logger:
                    scan_logger.info("scan_duplicate_reused", status=result.status.value)
                return result

            self.maintain_storage(now=attempted_at)

            started_at = attempted_at
            persisted_job = self.storage.get_scan_job(job.scan_id)
            persisted_started_at = persisted_job.get("started_at") if persisted_job else None
            if persisted_started_at:
                try:
                    parsed_started_at = datetime.fromisoformat(
                        str(persisted_started_at).replace("Z", "+00:00")
                    )
                    if parsed_started_at.tzinfo is not None:
                        started_at = parsed_started_at.astimezone(UTC)
                except ValueError:
                    pass
            with self.storage.transaction():
                self.storage.update_scan_job(
                    job.scan_id, "RUNNING", started_at=started_at.isoformat()
                )
                self.storage.record_audit_event(
                    "SCAN_STARTED",
                    "SUCCESS",
                    event_id=_event_id("scan-started", job.scan_id),
                    actor=job.initiated_by,
                    resource_type="domain" if job.target else "endpoint",
                    resource_id=job.target or job.endpoint_id,
                    scan_id=job.scan_id,
                    endpoint_id=job.endpoint_id,
                    authorization_scope_id=job.authorization.scope_id,
                    details={"scan_type": job.scan_type.value, "policy_id": job.policy_id},
                    created_at=started_at.isoformat(),
                    return_existing=True,
                )
            if scan_logger:
                scan_logger.info(
                    "scan_started",
                    status=OverallStatus.RUNNING.value,
                    scan_type=job.scan_type.value,
                )
            bundle = self.collectors.collect(job, deadline_at=execution_deadline)
            self._require_execution_time(execution_deadline)
            observed_at = self.clock()
            for collector in bundle.collectors.values():
                self.metrics.collector_finished(
                    collector.name,
                    collector.status.value,
                    collector.duration_seconds or 0.0,
                )
            result = self._analyze(
                job,
                bundle,
                policy,
                started_at,
                observed_at,
                execution_deadline,
            )
            self._require_execution_time(execution_deadline)
            finished_at = self.clock()
            endpoint = result.endpoint
            if endpoint is not None:
                endpoint = endpoint.model_copy(update={"last_seen_at": finished_at})
            result = result.model_copy(
                update={
                    "timestamp": finished_at,
                    "finished_at": finished_at,
                    "endpoint": endpoint,
                }
            )
            payload = result.model_dump(mode="json", exclude_none=True)
            report_path = self.report_writer.write(job.scan_id, result)
            self._require_execution_time(execution_deadline)
            with self.storage.transaction():
                if result.endpoint is not None and job.endpoint_id:
                    self.storage.upsert_endpoint(
                        job.endpoint_id,
                        result.endpoint.model_dump(mode="json", exclude_none=True),
                        last_seen_at=finished_at.isoformat(),
                    )
                change = self.storage.save_scan_result(
                    job.scan_id, job.endpoint_id, payload, target=job.target
                )
                self._queue_result(job, result, change)
                self._queue_terminal_status(job, result.status, result=result)
                self.storage.update_scan_job(
                    job.scan_id,
                    "COMPLETED",
                    completed_at=finished_at.isoformat(),
                    result_status=result.status.value,
                )
                self.storage.record_audit_event(
                    "SCAN_COMPLETED",
                    result.status.value,
                    event_id=_event_id("scan-completed", job.scan_id),
                    actor=job.initiated_by,
                    resource_type="domain" if job.target else "endpoint",
                    resource_id=job.target or job.endpoint_id,
                    scan_id=job.scan_id,
                    endpoint_id=job.endpoint_id,
                    authorization_scope_id=job.authorization.scope_id,
                    details={
                        "duration_seconds": max(
                            0.0, (finished_at - started_at).total_seconds()
                        ),
                        "policy_version": policy.policy_version,
                        "policy_checksum": _policy_checksum(policy),
                        "tools": bundle.tool_versions,
                        "collectors": {
                            name: collector.status.value
                            for name, collector in result.collectors.items()
                        },
                        "report": report_path.name,
                        "target": job.target,
                    },
                    created_at=finished_at.isoformat(),
                )
                # Keep the complete persistence/outbox unit inside the scan's
                # execution budget; an overrun rolls this transaction back.
                self._require_execution_time(execution_deadline)
            duration = max(0.0, (finished_at - started_at).total_seconds())
            self.metrics.scan_finished(result.status.value, duration)
            self.metrics.queue_size(self.storage.queue_stats().active)
            if scan_logger:
                scan_logger.info(
                    "scan_completed",
                    status=result.status.value,
                    duration_seconds=duration,
                    finding_count=len(result.findings),
                    queue_size=self.storage.queue_stats().active,
                )
            return result
        except _CompletedScanReconciliationError as exc:
            safe_error = str(sanitize_for_log(exc))[:2048]
            if scan_logger:
                scan_logger.error(
                    "scan_duplicate_reconciliation_failed",
                    status="COMPLETED",
                    error_type=(
                        type(exc.__cause__).__name__
                        if exc.__cause__
                        else type(exc).__name__
                    ),
                    error_message=safe_error,
                )
            raise ScanExecutionError(
                f"completed scan {job.scan_id} reconciliation failed: {safe_error}"
            ) from exc
        except Exception as exc:
            safe_error = str(sanitize_for_log(exc))[:2048]
            completed_at = self.clock()
            duration = max(0.0, (completed_at - started_at).total_seconds())
            failure_persisted = False
            try:
                with self.storage.transaction():
                    self.storage.update_scan_job(
                        job.scan_id,
                        "FAILED",
                        completed_at=completed_at.isoformat(),
                        result_status=OverallStatus.FAILED.value,
                        error=safe_error,
                    )
                    self.storage.record_audit_event(
                        "SCAN_FAILED",
                        "FAILED",
                        event_id=_event_id("scan-failed", job.scan_id),
                        actor=job.initiated_by,
                        resource_type="domain" if job.target else "endpoint",
                        resource_id=job.target or job.endpoint_id,
                        scan_id=job.scan_id,
                        endpoint_id=job.endpoint_id,
                        authorization_scope_id=job.authorization.scope_id,
                        details={"error": safe_error, "target": job.target},
                        created_at=completed_at.isoformat(),
                        return_existing=True,
                    )
                failure_persisted = True
            except Exception as persistence_exc:
                # Preserve the original lifecycle exception if persistence itself failed.
                if scan_logger:
                    scan_logger.warning(
                        "scan_failure_persistence_failed",
                        error_type=type(persistence_exc).__name__,
                    )
            if failure_persisted:
                try:
                    self._queue_terminal_status(job, OverallStatus.FAILED)
                except Exception as outbox_exc:
                    if scan_logger:
                        scan_logger.warning(
                            "scan_failure_status_queue_failed",
                            error_type=type(outbox_exc).__name__,
                        )
            self.metrics.scan_finished(OverallStatus.FAILED.value, duration)
            if scan_logger:
                scan_logger.error(
                    "scan_failed",
                    status=OverallStatus.FAILED.value,
                    duration_seconds=duration,
                    error_type=type(exc).__name__,
                    error_message=safe_error,
                )
            raise ScanExecutionError(f"scan {job.scan_id} failed: {safe_error}") from exc

    @staticmethod
    def _require_execution_time(deadline_at: float) -> None:
        if time.monotonic() >= deadline_at:
            raise TimeoutError("scan execution deadline exceeded")

    def _analyze(
        self,
        job: ScanJob,
        bundle: CollectionBundle,
        policy: PolicyBundle,
        started_at: datetime,
        finished_at: datetime,
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
        if job.endpoint_id and isinstance(inventory.get("security"), SecurityPosture):
            latest = self.storage.get_latest_snapshot(job.endpoint_id)
            if latest is not None:
                posture = inventory["security"]
                assert isinstance(posture, SecurityPosture)
                scan_age_days: float | None = None
                try:
                    previous_time = datetime.fromisoformat(
                        str(latest["created_at"]).replace("Z", "+00:00")
                    )
                    if previous_time.tzinfo is not None:
                        scan_age_days = max(
                            0.0,
                            (finished_at - previous_time.astimezone(UTC)).total_seconds()
                            / 86_400,
                        )
                except (KeyError, ValueError):
                    pass
                inventory["security"] = posture.model_copy(
                    update={
                        "scan_age_days": scan_age_days,
                        "scan_stale": (
                            scan_age_days > self.settings.analysis.stale_scan_after_days
                            if scan_age_days is not None
                            else None
                        ),
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
                last_seen_at=finished_at,
            )

        result_values: dict[str, Any] = {
            "schema_version": self.settings.schema_version,
            "scanner_version": self.settings.scanner_version,
            "scan_id": job.scan_id,
            "endpoint_id": job.endpoint_id,
            "scan_type": job.scan_type,
            "timestamp": finished_at,
            "started_at": started_at,
            "finished_at": finished_at,
            "status": overall_status(bundle.collectors.values()),
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "policy_checksum": _policy_checksum(policy),
            "authorization_scope_id": job.authorization.scope_id,
            "endpoint": endpoint,
            "collectors": bundle.collectors,
            "metadata": {
                "warnings": [str(item)[:2048] for item in bundle.warnings[:1000]],
                "tool_versions": bundle.tool_versions,
                "authorized_target": job.target,
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
            detected_at=finished_at,
            platform=preliminary.os.family if preliminary.os else None,
            scan_type=job.scan_type,
        )
        evaluated_findings = self.policy_engine.evaluate(
            policy,
            preliminary,
            context,
            deadline_at=execution_deadline,
            max_operations=self.settings.runtime.max_policy_operations,
        )
        findings = []
        for finding in evaluated_findings:
            historical = self.storage.get_finding_first_seen(finding.finding_id)
            first_seen = finding.first_seen_at
            if historical:
                try:
                    parsed = datetime.fromisoformat(historical.replace("Z", "+00:00"))
                    if parsed.tzinfo is not None and parsed <= finding.detected_at:
                        first_seen = parsed.astimezone(UTC)
                except ValueError:
                    pass
            findings.append(finding.model_copy(update={"first_seen_at": first_seen}))
        exposure = (
            1.0
            if job.target or any(port.exposed for port in preliminary.listening_ports)
            else 0.3
        )
        risk = self.risk_engine.calculate(
            findings,
            scan_id=job.scan_id,
            asset_criticality=asset_criticality,
            exposure=exposure,
            now=finished_at,
            policy_version=policy.policy_version,
            scanner_version=self.settings.scanner_version,
        )
        return preliminary.model_copy(update={"findings": findings, "risk": risk})

    def _queue_result(
        self, job: ScanJob, result: ScanResult, change: SnapshotChange | None
    ) -> None:
        serialized = result.model_dump(mode="json", exclude_none=True)
        if change is None:
            upload: Mapping[str, Any] = serialized
            snapshot_key = "attack-surface"
        else:
            inventory_sync = self.storage.snapshot_upload_payload(change.snapshot_id)
            sbom = build_cyclonedx_sbom(result)
            sbom_sha256 = hashlib.sha256(
                canonical_json(sbom).encode("utf-8")
            ).hexdigest()
            summary_fields = {
                "schema_version",
                "scanner_version",
                "scan_id",
                "endpoint_id",
                "scan_type",
                "timestamp",
                "started_at",
                "finished_at",
                "status",
                "policy_id",
                "policy_version",
                "policy_checksum",
                "authorization_scope_id",
                "findings",
                "risk",
                "collectors",
                "metadata",
            }
            upload = {
                "evidence_envelope_version": "1.0",
                "result": {
                    key: value for key, value in serialized.items() if key in summary_fields
                },
                "inventory_sync": inventory_sync,
                "sbom": sbom,
                "sbom_sha256": sbom_sha256,
            }
            snapshot_key = change.snapshot_hash
        idempotency_digest = hashlib.sha256(
            f"{job.scan_id}:{snapshot_key}".encode()
        ).hexdigest()
        payload = serialize_report(upload, max_bytes=self.settings.cloud.max_request_bytes)
        self.storage.enqueue_upload(
            "scan_result",
            payload,
            f"scan-result:{idempotency_digest}",
            self.settings.cloud.routes.scan_submit_path,
            metadata={
                "scan_id": job.scan_id,
                "endpoint_id": job.endpoint_id,
                "authorization_scope_id": job.authorization.scope_id,
            },
        )

    def _queue_terminal_status(
        self,
        job: ScanJob,
        status: OverallStatus,
        *,
        result: ScanResult | None = None,
    ) -> None:
        terminal_status = status
        if result is not None:
            if result.scan_id != job.scan_id or result.status is not status:
                raise ValueError("terminal status result does not match the scan lifecycle")
            policy_id = result.policy_id
            policy_version = result.policy_version
            policy_checksum = result.policy_checksum
        else:
            try:
                policy = self.resolve_policy(job)
            except ValueError:
                policy = None
            policy_id = policy.policy_id if policy else job.policy_id
            policy_version = policy.policy_version if policy else job.policy_version
            policy_checksum = _policy_checksum(policy) if policy else None
        payload = {
            "schema_version": self.settings.schema_version,
            "scanner_version": self.settings.scanner_version,
            "scan_id": job.scan_id,
            "endpoint_id": job.endpoint_id,
            "target": job.target,
            "authorization_scope_id": job.authorization.scope_id,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "policy_checksum": policy_checksum,
            "status": terminal_status.value,
            "requested_at": job.requested_at.isoformat(),
        }
        digest = hashlib.sha256(
            f"{job.scan_id}:{terminal_status.value}".encode()
        ).hexdigest()
        encoded = serialize_report(
            payload,
            max_bytes=self.settings.cloud.max_request_bytes,
        )
        self.storage.enqueue_upload(
            "scan_status",
            encoded,
            f"scan-status:{digest}",
            self.settings.cloud.routes.scan_status_path,
            metadata={
                "scan_id": job.scan_id,
                "endpoint_id": job.endpoint_id,
                "terminal_status": terminal_status.value,
            },
        )
        self.storage.append_scan_history(
            job.scan_id,
            "TERMINAL_STATUS_QUEUED",
            status=terminal_status.value,
            details={"endpoint": self.settings.cloud.routes.scan_status_path},
            idempotency_key=f"terminal-status-queued:{digest}",
        )


def load_orchestrator(config: ScannerSettings | None = None) -> ScannerOrchestrator:
    return ScannerOrchestrator.from_settings(config or ScannerSettings.from_env())
