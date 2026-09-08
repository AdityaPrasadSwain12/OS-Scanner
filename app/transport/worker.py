"""Worker that drains durable uploads while preserving at-least-once delivery."""

from __future__ import annotations

import time
from dataclasses import dataclass
from random import Random, SystemRandom
from typing import Any

from app.storage import RetryPolicy, SQLiteStorage, StorageError, UploadStatus

from .client import CloudApiClient
from .errors import CloudApiError, TransportError


@dataclass(frozen=True, slots=True)
class UploadRunStats:
    claimed: int = 0
    succeeded: int = 0
    retried: int = 0
    dead: int = 0


class UploadWorker:
    def __init__(
        self,
        storage: SQLiteStorage,
        client: CloudApiClient,
        *,
        retry_policy: RetryPolicy | None = None,
        lease_seconds: float = 60.0,
        metrics: Any = None,
        logger: Any = None,
        clock: Any = time.time,
        random_source: Random | None = None,
    ) -> None:
        self.storage = storage
        self.client = client
        self.retry_policy = retry_policy or RetryPolicy()
        self.lease_seconds = lease_seconds
        self.metrics = metrics
        self.logger = logger
        self.clock = clock
        self.random_source = random_source or SystemRandom()

    def _effective_lease_seconds(self) -> float:
        """Keep a lease valid for the client's complete in-request retry budget."""

        config = self.client.config
        attempts = int(config.max_attempts)
        request_budget = (
            attempts
            * (config.effective_connect_timeout_seconds + config.effective_read_timeout_seconds)
            + max(0, attempts - 1) * float(config.backoff_max_seconds)
            + 5.0
        )
        lease = max(float(self.lease_seconds), request_budget)
        if not 1 <= lease <= 86_400:
            raise ValueError("upload request retry budget exceeds the maximum queue lease")
        return lease

    def _metric(self, name: str, value: float = 1, **attributes: object) -> None:
        if self.metrics is not None:
            try:
                self.metrics.increment(name, value, attributes=attributes)
            except Exception:
                # Optional exporters are outside the durable delivery state
                # machine and cannot be allowed to strand a queue lease.
                self.metrics = None
                return

    def _log(self, level: str, event: str, **fields: object) -> None:
        if self.logger is not None:
            try:
                getattr(self.logger, level)(event, **fields)
            except Exception:
                # Logging failure is not an upload failure and must not alter
                # retry/dead-letter transitions that already committed.
                self.logger = None
                return

    def run_once(self, *, limit: int = 10) -> UploadRunStats:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        lease_seconds = self._effective_lease_seconds()
        claimed = 0
        succeeded = retried = dead = 0
        # Claim immediately before delivery.  This avoids leasing a batch whose
        # later entries sit idle while an earlier HTTP request consumes its
        # complete retry budget.
        while claimed < limit:
            uploads = self.storage.claim_uploads(
                limit=1,
                lease_seconds=lease_seconds,
                now=float(self.clock()),
            )
            if not uploads:
                break
            upload = uploads[0]
            claimed += 1
            try:
                self.client.request(
                    upload.method,
                    upload.endpoint,
                    body=upload.payload,
                    content_type=upload.content_type,
                    idempotency_key=upload.idempotency_key,
                    request_id=upload.request_id,
                )
            except CloudApiError as exc:
                is_conflict = exc.status_code in {409, 412}
                is_recovery = bool(upload.metadata.get("causal_recovery"))
                if is_conflict and not is_recovery:
                    try:
                        recovery = self.storage.schedule_full_resync(
                            upload.upload_id,
                            upload.lease_token,
                            exc,
                            now=float(self.clock()),
                        )
                    except StorageError as recovery_error:
                        status = self.storage.mark_upload_failed(
                            upload.upload_id,
                            upload.lease_token,
                            recovery_error,
                            permanent=True,
                            retry_policy=self.retry_policy,
                            random_source=self.random_source,
                            now=float(self.clock()),
                        )
                        dead += 1
                        self._metric(
                            "scanner_upload_failures_total",
                            kind=upload.kind,
                            terminal=True,
                        )
                        self._log(
                            "error",
                            "upload_full_resync_unavailable",
                            upload_id=upload.upload_id,
                            request_id=upload.request_id,
                            error_type=type(recovery_error).__name__,
                        )
                    else:
                        retried += 1
                        self._metric(
                            "scanner_upload_rebases_total",
                            kind=upload.kind,
                        )
                        self._log(
                            "warning",
                            "upload_rebased_to_full_snapshot",
                            upload_id=upload.upload_id,
                            recovery_upload_id=recovery.upload_id,
                            request_id=upload.request_id,
                            http_status=exc.status_code,
                        )
                    continue
                status = self.storage.mark_upload_failed(
                    upload.upload_id,
                    upload.lease_token,
                    exc,
                    permanent=not exc.retryable,
                    retry_after_seconds=exc.retry_after_seconds,
                    retry_policy=self.retry_policy,
                    random_source=self.random_source,
                    now=float(self.clock()),
                )
                if status == UploadStatus.DEAD:
                    dead += 1
                else:
                    retried += 1
                self._metric(
                    "scanner_upload_failures_total",
                    kind=upload.kind,
                    terminal=status == UploadStatus.DEAD,
                )
                self._log(
                    "warning",
                    "upload_failed",
                    upload_id=upload.upload_id,
                    request_id=upload.request_id,
                    attempt=upload.attempt_count,
                    terminal=status == UploadStatus.DEAD,
                    error_type=type(exc).__name__,
                )
            except TransportError as exc:
                status = self.storage.mark_upload_failed(
                    upload.upload_id,
                    upload.lease_token,
                    exc,
                    permanent=not exc.retryable,
                    retry_policy=self.retry_policy,
                    random_source=self.random_source,
                    now=float(self.clock()),
                )
                dead += status == UploadStatus.DEAD
                retried += status != UploadStatus.DEAD
                self._metric(
                    "scanner_upload_failures_total",
                    kind=upload.kind,
                    terminal=status == UploadStatus.DEAD,
                )
                self._log(
                    "warning",
                    "upload_failed",
                    upload_id=upload.upload_id,
                    request_id=upload.request_id,
                    attempt=upload.attempt_count,
                    terminal=status == UploadStatus.DEAD,
                    error_type=type(exc).__name__,
                )
            except Exception as exc:  # queue survives unexpected adapter failures
                status = self.storage.mark_upload_failed(
                    upload.upload_id,
                    upload.lease_token,
                    type(exc).__name__,
                    retry_policy=self.retry_policy,
                    random_source=self.random_source,
                    now=float(self.clock()),
                )
                dead += status == UploadStatus.DEAD
                retried += status != UploadStatus.DEAD
                self._metric(
                    "scanner_upload_failures_total",
                    kind=upload.kind,
                    terminal=status == UploadStatus.DEAD,
                )
                self._log(
                    "error",
                    "upload_worker_error",
                    upload_id=upload.upload_id,
                    request_id=upload.request_id,
                    error_type=type(exc).__name__,
                )
            else:
                if self.storage.mark_upload_succeeded(upload.upload_id, upload.lease_token):
                    succeeded += 1
                    self._metric("scanner_uploads_total", kind=upload.kind)
                    self._log(
                        "info",
                        "upload_succeeded",
                        upload_id=upload.upload_id,
                        request_id=upload.request_id,
                        attempt=upload.attempt_count,
                    )
        queue_size = self.storage.queue_stats().active
        if self.metrics is not None:
            try:
                self.metrics.set_gauge("scanner_upload_queue_size", queue_size)
            except Exception:
                self.metrics = None
        return UploadRunStats(claimed, succeeded, retried, dead)
