"""Long-running service loop for cloud-triggered and scheduled job retrieval."""

from __future__ import annotations

import hashlib
import json
import random
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from app.enrollment import CredentialError
from app.models import ScanResult
from app.observability import ScannerMetrics, StructuredLogger
from app.policies import PolicySyncError
from app.scheduling import CooperativeScanScheduler
from app.storage import SQLiteStorage
from app.transport import (
    CloudApiClient,
    ProtocolError,
    TransportError,
    UploadRunStats,
    UploadWorker,
)

from .job_loader import JobValidationError, load_job_json
from .scanner import ScannerOrchestrator


@dataclass(frozen=True, slots=True)
class AgentRunResult:
    online: bool
    scan: ScanResult | None
    uploads: UploadRunStats


class CloudJobSource:
    """Fetch one bounded job through an authenticated cloud client."""

    def __init__(
        self,
        client: CloudApiClient,
        endpoint_id: str,
        *,
        audit_storage: SQLiteStorage | None = None,
    ) -> None:
        if not endpoint_id or len(endpoint_id) > 128:
            raise ValueError("endpoint_id is invalid")
        self.client = client
        self.endpoint_id = endpoint_id
        self.audit_storage = audit_storage
        client_config = getattr(client, "config", None)
        routes = getattr(client_config, "routes", None)
        self._next_scan_path_template = str(
            getattr(routes, "next_scan_path_template", "/api/v1/scans/next/{endpoint_id}")
        )
        self._scan_rejections_path = str(
            getattr(routes, "scan_rejections_path", "/api/v1/scans/rejections")
        )
        self._rejected_fingerprints: dict[str, None] = {}

    @staticmethod
    def _safe_scan_id(document: object) -> str | None:
        if not isinstance(document, dict):
            return None
        value = document.get("scan_id")
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= 128
            or not value[0].isalnum()
            or any(not (character.isalnum() or character in "._:-") for character in value)
        ):
            return None
        return value

    def _reject(self, body: bytes, reason: str, document: object = None) -> None:
        fingerprint = hashlib.sha256(body).hexdigest()
        if fingerprint in self._rejected_fingerprints:
            return
        scan_id = self._safe_scan_id(document)
        payload = {
            "endpoint_id": self.endpoint_id,
            "scan_id": scan_id,
            "reason": reason,
            "document_sha256": fingerprint,
        }
        if self.audit_storage is None:
            self.client.post_json(
                self._scan_rejections_path,
                payload,
                idempotency_key=f"job-rejection:{fingerprint}",
            )
        else:
            with self.audit_storage.transaction():
                queued = self.audit_storage.enqueue_upload(
                    "scan_rejection",
                    payload,
                    f"job-rejection:{fingerprint}",
                    self._scan_rejections_path,
                    metadata={
                        "endpoint_id": self.endpoint_id,
                        "remote_scan_id": scan_id,
                    },
                )
                # The outbox idempotency key persists across process restarts.
                # Only its creating transaction writes the companion audit row;
                # otherwise a different implicit timestamp would conflict with
                # the deterministic audit event identifier.
                if queued.created:
                    self.audit_storage.record_audit_event(
                        "SCAN_JOB_REJECTED",
                        "REJECTED",
                        event_id=f"cloud-job-rejected:{fingerprint[:32]}",
                        resource_type="endpoint",
                        resource_id=self.endpoint_id,
                        endpoint_id=self.endpoint_id,
                        details={
                            "reason": reason,
                            "document_sha256": fingerprint,
                            "remote_scan_id": scan_id,
                        },
                    )
        self._rejected_fingerprints[fingerprint] = None
        if len(self._rejected_fingerprints) > 1_024:
            self._rejected_fingerprints.pop(next(iter(self._rejected_fingerprints)))

    def fetch(self) -> Any:
        encoded_endpoint = quote(self.endpoint_id, safe="")
        path = self._next_scan_path_template.format(endpoint_id=encoded_endpoint)
        response = self.client.request("GET", path)
        if response.status_code == 204 or not response.body:
            return None
        try:
            document = response.json()
        except ProtocolError:
            self._reject(response.body, "INVALID_JSON")
            return None
        try:
            encoded = json.dumps(
                document,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode()
            job = load_job_json(encoded)
            if job.endpoint_id is not None and job.endpoint_id != self.endpoint_id:
                raise JobValidationError("cloud returned a job for a different endpoint")
        except (JobValidationError, TypeError, ValueError):
            self._reject(response.body, "INVALID_OR_UNAUTHORIZED_JOB", document)
            return None
        return job


class ScannerAgent:
    """Cooperative service; the OS service manager handles process supervision."""

    def __init__(
        self,
        orchestrator: ScannerOrchestrator,
        job_source: CloudJobSource,
        upload_worker: UploadWorker,
        *,
        poll_interval_seconds: float = 60.0,
        jitter_ratio: float = 0.10,
        logger: StructuredLogger | None = None,
        metrics: ScannerMetrics | None = None,
        random_source: random.Random | None = None,
        scheduler: CooperativeScanScheduler | None = None,
        credential_maintenance: Callable[[], bool] | None = None,
        policy_maintenance: Callable[[], bool] | None = None,
    ) -> None:
        if not 5 <= poll_interval_seconds <= 3600:
            raise ValueError("poll interval must be between 5 and 3600 seconds")
        if not 0 <= jitter_ratio <= 0.5:
            raise ValueError("jitter_ratio must be between 0 and 0.5")
        self.orchestrator = orchestrator
        self.job_source = job_source
        self.upload_worker = upload_worker
        self.poll_interval_seconds = poll_interval_seconds
        self.jitter_ratio = jitter_ratio
        self.logger = logger
        self.metrics = metrics or ScannerMetrics()
        self.random_source = random_source or random.SystemRandom()
        self.scheduler = scheduler
        self.credential_maintenance = credential_maintenance
        self.policy_maintenance = policy_maintenance
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def request_policy_scan(self) -> bool:
        if self.scheduler is None:
            return False
        self.scheduler.request_policy_scan()
        return True

    def run_once(self) -> AgentRunResult:
        if self.credential_maintenance is not None:
            try:
                rotated = self.credential_maintenance()
                if rotated and self.logger:
                    self.logger.info("cloud_credential_rotated")
            # Credential lifecycle boundary; the current token may remain valid.
            except Exception as exc:
                if self.logger:
                    self.logger.warning(
                        "cloud_credential_rotation_failed",
                        error_type=type(exc).__name__,
                    )
        uploads = self.upload_worker.run_once()
        self.metrics.queue_size(self.orchestrator.storage.queue_stats().active)
        online = True
        if self.policy_maintenance is not None:
            try:
                activated = self.policy_maintenance()
                if activated and self.logger:
                    self.logger.info(
                        "cloud_policy_activated",
                        policy_id=self.orchestrator.policy.policy_id,
                        policy_version=self.orchestrator.policy.policy_version,
                    )
                if activated and self.scheduler is not None:
                    self.scheduler.request_policy_scan()
            except PolicySyncError as exc:
                if self.logger:
                    self.logger.warning(
                        "cloud_policy_rejected",
                        error_type=type(exc).__name__,
                    )
            except (CredentialError, TransportError) as exc:
                online = False
                if self.logger:
                    self.logger.warning(
                        "cloud_policy_sync_offline",
                        error_type=type(exc).__name__,
                    )
        try:
            job = self.job_source.fetch() if online else None
        except (CredentialError, TransportError) as exc:
            online = False
            if self.logger:
                self.logger.warning(
                    "cloud_offline",
                    error_type=type(exc).__name__,
                    queue_size=self.orchestrator.storage.queue_stats().active,
                )
            job = None
        if job is None and self.scheduler is not None:
            job = self.scheduler.poll()
        if job is None:
            return AgentRunResult(online=online, scan=None, uploads=uploads)
        result = self.orchestrator.execute(job)
        # Attempt immediate delivery; failure remains durably scheduled in SQLite.
        delivered = self.upload_worker.run_once()
        combined = UploadRunStats(
            claimed=uploads.claimed + delivered.claimed,
            succeeded=uploads.succeeded + delivered.succeeded,
            retried=uploads.retried + delivered.retried,
            dead=uploads.dead + delivered.dead,
        )
        return AgentRunResult(online=online, scan=result, uploads=combined)

    def run(self) -> None:
        """Run immediately at startup, then periodically with fleet-safe jitter."""

        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:
                if self.logger:
                    self.logger.exception("agent_iteration_failed", exc)
            spread = self.poll_interval_seconds * self.jitter_ratio
            delay = self.poll_interval_seconds + self.random_source.uniform(-spread, spread)
            if self._stop.wait(max(1.0, delay)):
                return
