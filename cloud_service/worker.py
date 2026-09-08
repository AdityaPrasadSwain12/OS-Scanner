"""Durable cloud analysis worker with bounded retries and optional notifications.

PostgreSQL (through ``AnalysisRepository``) is always the queue source of truth.
Redis or another notifier may only wake an idle worker; no task is acknowledged or
constructed from a notification message.
"""

from __future__ import annotations

import asyncio
import math
import os
import random
import signal
import socket
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, cast

from app.security.redaction import redact_text

from .analysis import (
    AnalysisInputError,
    CloudAnalysisEngine,
    CloudScanInput,
    PermanentAnalysisError,
    RetryableAnalysisError,
    coerce_scan_input,
)

ToolKind = Literal["OSV", "DEPSCAN"]


class AnalysisTaskRecord(Protocol):
    @property
    def task_id(self) -> str: ...

    @property
    def tenant_id(self) -> str: ...

    @property
    def endpoint_id(self) -> str: ...

    @property
    def scan_id(self) -> str: ...

    @property
    def kind(self) -> ToolKind: ...

    @property
    def state(self) -> str: ...

    @property
    def attempts(self) -> int: ...

    @property
    def payload(self) -> Mapping[str, Any]: ...


class AnalysisRepository(Protocol):
    """Exact durable repository surface required by ``AnalysisWorker``."""

    async def claim_analysis_task(
        self, kind: ToolKind, worker_id: str, lease_seconds: int
    ) -> AnalysisTaskRecord | None: ...

    async def complete_analysis_task(
        self,
        task_id: str,
        worker_id: str,
        result: dict[str, Any],
    ) -> None: ...

    async def fail_analysis_task(
        self,
        task_id: str,
        worker_id: str,
        error: str,
        retry_at: datetime,
        dead_letter: bool,
    ) -> None: ...

    async def get_scan_analysis_input(self, scan_id: str) -> object | None: ...

    async def list_scan_analysis_results(self, scan_id: str) -> dict[str, dict[str, Any]]: ...

    async def next_scan_ready_for_finalization(self) -> str | None: ...

    async def finalize_scan_report(self, scan_id: str, report: dict[str, Any]) -> None: ...

    async def finalize_scan_report_failure(self, scan_id: str, error: str) -> None: ...


class AnalysisNotification(Protocol):
    """Optional Redis-compatible wake-up and status publication boundary."""

    async def wait(self, timeout_seconds: float) -> None: ...

    async def publish(self, event: str, payload: Mapping[str, Any]) -> None: ...


@dataclass(frozen=True, slots=True)
class WorkerSettings:
    worker_id: str = "cloud-analysis-worker"
    kinds: tuple[ToolKind, ...] = ("OSV", "DEPSCAN")
    lease_seconds: int = 1_200
    max_attempts: int = 5
    base_backoff_seconds: float = 2.0
    max_backoff_seconds: float = 300.0
    jitter_fraction: float = 0.2
    idle_poll_seconds: float = 2.0

    def __post_init__(self) -> None:
        if not self.worker_id or len(self.worker_id) > 128:
            raise ValueError("worker_id must contain 1 to 128 characters")
        normalized = tuple(str(kind).upper() for kind in self.kinds)
        if not normalized or len(set(normalized)) != len(normalized):
            raise ValueError("worker kinds must be non-empty and unique")
        if any(kind not in {"OSV", "DEPSCAN"} for kind in normalized):
            raise ValueError("worker kind is unsupported")
        object.__setattr__(self, "kinds", cast(tuple[ToolKind, ...], normalized))
        if not 10 <= self.lease_seconds <= 3_600:
            raise ValueError("lease_seconds must be between 10 and 3600")
        if not 1 <= self.max_attempts <= 20:
            raise ValueError("max_attempts must be between 1 and 20")
        if not 0.1 <= self.base_backoff_seconds <= 3_600:
            raise ValueError("base backoff must be between 0.1 and 3600 seconds")
        if not self.base_backoff_seconds <= self.max_backoff_seconds <= 86_400:
            raise ValueError("maximum backoff is invalid")
        if not 0 <= self.jitter_fraction <= 1:
            raise ValueError("jitter fraction must be between 0 and 1")
        if not 0.05 <= self.idle_poll_seconds <= 300:
            raise ValueError("idle poll must be between 0.05 and 300 seconds")


@dataclass(frozen=True, slots=True)
class WorkerOutcome:
    processed: bool
    task_id: str | None = None
    kind: str | None = None
    task_status: str | None = None
    finalized: bool = False
    error: str | None = None


class AnalysisWorker:
    """Claim, execute, persist, and finalize cloud analysis tasks."""

    def __init__(
        self,
        repository: AnalysisRepository,
        engine: CloudAnalysisEngine,
        *,
        settings: WorkerSettings | None = None,
        notification: AnalysisNotification | None = None,
        clock: Callable[[], datetime] | None = None,
        random_value: Callable[[], float] | None = None,
    ) -> None:
        self.repository = repository
        self.engine = engine
        self.settings = settings or WorkerSettings()
        self.notification = notification
        self._next_kind_index = 0
        self._clock = clock or (lambda: datetime.now(UTC))
        self._random = random_value or random.random
        longest_tool = max(
            engine.limits.osv_timeout_seconds,
            engine.limits.depscan_timeout_seconds,
        )
        if self.settings.lease_seconds < math.ceil(longest_tool) + 30:
            raise ValueError("worker lease must exceed the longest tool timeout by 30 seconds")

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("worker clock must return a timezone-aware timestamp")
        return value.astimezone(UTC)

    def _backoff(self, attempts: int) -> float:
        exponent = max(0, min(attempts - 1, 30))
        base = min(
            self.settings.max_backoff_seconds,
            self.settings.base_backoff_seconds * (2**exponent),
        )
        spread = base * self.settings.jitter_fraction
        centered = (min(1.0, max(0.0, self._random())) * 2.0) - 1.0
        return float(max(0.0, base + centered * spread))

    async def _publish(self, event: str, payload: Mapping[str, Any]) -> None:
        if self.notification is None:
            return
        try:
            await self.notification.publish(event, payload)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Notifications are advisory. Durable repository state has already won.
            return

    async def _load_scan_input(self, task: AnalysisTaskRecord) -> CloudScanInput:
        raw = await self.repository.get_scan_analysis_input(task.scan_id)
        return coerce_scan_input(
            raw,
            tenant_id=task.tenant_id,
            endpoint_id=task.endpoint_id,
            scan_id=task.scan_id,
        )

    async def finalize_ready_scan(
        self,
        scan_id: str,
        *,
        scan_input: CloudScanInput | None = None,
    ) -> bool:
        """Idempotently finalize a scan only when every expected result is persisted."""

        if scan_input is None:
            raw = await self.repository.get_scan_analysis_input(scan_id)
            scan_input = coerce_scan_input(raw, scan_id=scan_id)
        results = await self.repository.list_scan_analysis_results(scan_id)
        if any(kind not in results for kind in scan_input.expected_tools):
            return False
        report = await asyncio.to_thread(self.engine.build_final_report, scan_input, results)
        await self.repository.finalize_scan_report(scan_id, report)
        await self._publish(
            "scan.report.finalized",
            {
                "tenant_id": scan_input.tenant_id,
                "endpoint_id": scan_input.endpoint_id,
                "scan_id": scan_input.scan_id,
                "status": report["status"],
            },
        )
        return True

    async def _fail_task(
        self,
        task: AnalysisTaskRecord,
        error: BaseException,
    ) -> WorkerOutcome:
        message = redact_text(str(error), max_length=2_048).strip() or type(error).__name__
        permanent = isinstance(error, (PermanentAnalysisError, AnalysisInputError))
        dead_letter = permanent or task.attempts >= self.settings.max_attempts
        retry_at = self._now() + timedelta(
            seconds=0 if dead_letter else self._backoff(task.attempts)
        )
        await self.repository.fail_analysis_task(
            task.task_id,
            self.settings.worker_id,
            message,
            retry_at,
            dead_letter,
        )
        await self._publish(
            "scan.analysis.failed" if dead_letter else "scan.analysis.retry",
            {
                "tenant_id": task.tenant_id,
                "endpoint_id": task.endpoint_id,
                "scan_id": task.scan_id,
                "task_id": task.task_id,
                "kind": task.kind,
                "attempts": task.attempts,
                "dead_letter": dead_letter,
            },
        )
        if dead_letter:
            # The repository exposes a synthetic terminal result for dead letters,
            # allowing the report to finish as PARTIAL instead of hanging forever.
            with suppress(
                PermanentAnalysisError,
                RetryableAnalysisError,
                RuntimeError,
                ValueError,
            ):
                await self.finalize_ready_scan(task.scan_id)
        return WorkerOutcome(
            processed=True,
            task_id=task.task_id,
            kind=task.kind,
            task_status="FAILED" if dead_letter else "RETRY",
            error=message,
        )

    async def _process(self, task: AnalysisTaskRecord) -> WorkerOutcome:
        try:
            scan_input = await self._load_scan_input(task)
            result = await asyncio.to_thread(
                self.engine.analyze_tool,
                task.kind,
                scan_input,
            )
            tool_status = str(result.get("status") or "FAILED").upper()
            if tool_status in {"FAILED", "TIMEOUT", "UNAVAILABLE"}:
                raise RetryableAnalysisError(
                    f"{task.kind} analysis returned retryable status {tool_status}"
                )
            await self.repository.complete_analysis_task(
                task.task_id,
                self.settings.worker_id,
                result,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return await self._fail_task(task, exc)

        await self._publish(
            "scan.analysis.completed",
            {
                "tenant_id": task.tenant_id,
                "endpoint_id": task.endpoint_id,
                "scan_id": task.scan_id,
                "task_id": task.task_id,
                "kind": task.kind,
                "status": result["status"],
            },
        )
        finalized = False
        finalization_error: str | None = None
        try:
            finalized = await self.finalize_ready_scan(task.scan_id, scan_input=scan_input)
        except asyncio.CancelledError:
            raise
        except PermanentAnalysisError as exc:
            await self.repository.finalize_scan_report_failure(task.scan_id, str(exc))
            finalized = True
            finalization_error = redact_text(str(exc), max_length=2_048)
        except (RetryableAnalysisError, RuntimeError, ValueError) as exc:
            # The tool outcome is already durable. ``finalize_ready_scan`` is public
            # and safe to retry from another worker or a reconciliation process.
            finalization_error = redact_text(str(exc), max_length=2_048)
        return WorkerOutcome(
            processed=True,
            task_id=task.task_id,
            kind=task.kind,
            task_status="SUCCEEDED",
            finalized=finalized,
            error=finalization_error,
        )

    async def run_once(self) -> WorkerOutcome:
        """Process one fair tool task or reconcile one terminal unfinalized scan."""

        kind_count = len(self.settings.kinds)
        for offset in range(kind_count):
            index = (self._next_kind_index + offset) % kind_count
            kind = self.settings.kinds[index]
            task = await self.repository.claim_analysis_task(
                kind,
                self.settings.worker_id,
                self.settings.lease_seconds,
            )
            if task is not None:
                self._next_kind_index = (index + 1) % kind_count
                return await self._process(task)
        scan_id = await self.repository.next_scan_ready_for_finalization()
        if scan_id is not None:
            try:
                finalized = await self.finalize_ready_scan(scan_id)
            except asyncio.CancelledError:
                raise
            except PermanentAnalysisError as exc:
                await self.repository.finalize_scan_report_failure(scan_id, str(exc))
                return WorkerOutcome(
                    processed=True,
                    kind="REPORT",
                    task_status="FAILED",
                    finalized=True,
                    error=redact_text(str(exc), max_length=2_048),
                )
            except (RetryableAnalysisError, RuntimeError, ValueError) as exc:
                # Terminal tool results remain durable. Returning processed=False
                # applies the normal idle delay before the next reconciliation.
                return WorkerOutcome(
                    processed=False,
                    kind="REPORT",
                    task_status="RETRY",
                    error=redact_text(str(exc), max_length=2_048),
                )
            return WorkerOutcome(
                processed=True,
                kind="REPORT",
                task_status="SUCCEEDED",
                finalized=finalized,
            )
        return WorkerOutcome(processed=False)

    async def _idle_wait(self, stop_event: asyncio.Event) -> None:
        async def wait_source() -> None:
            if self.notification is not None:
                try:
                    await self.notification.wait(self.settings.idle_poll_seconds)
                    return
                except asyncio.CancelledError:
                    raise
                except Exception:
                    await asyncio.sleep(self.settings.idle_poll_seconds)
                    return
            await asyncio.sleep(self.settings.idle_poll_seconds)

        source = asyncio.create_task(wait_source())
        stopped = asyncio.create_task(stop_event.wait())
        done, pending = await asyncio.wait({source, stopped}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            await task

    async def run_forever(self, stop_event: asyncio.Event) -> None:
        """Run until requested to stop; an empty Redis signal never skips the DB poll."""

        while not stop_event.is_set():
            outcome = await self.run_once()
            if not outcome.processed and not stop_event.is_set():
                await self._idle_wait(stop_event)

    def health(self) -> dict[str, Any]:
        engine_health = self.engine.health()
        return {
            "worker_id": self.settings.worker_id,
            "kinds": list(self.settings.kinds),
            "lease_seconds": self.settings.lease_seconds,
            "max_attempts": self.settings.max_attempts,
            "engine": engine_health,
        }


def _environment_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().casefold()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise ValueError(f"{name} must be true or false")


async def _run_from_environment() -> None:
    """Construct the worker without loading API credential-issuance secrets."""

    from .postgres import PostgresRepository

    environment = os.getenv("SCANNER_ENVIRONMENT", "development").strip().casefold()
    if environment not in {"development", "test", "production"}:
        raise ValueError("SCANNER_ENVIRONMENT is invalid")
    database_url = os.getenv("SCANNER_DATABASE_URL") or None
    if database_url is None:
        raise ValueError("SCANNER_DATABASE_URL is required for the analysis worker")
    if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        raise ValueError("SCANNER_DATABASE_URL must be a PostgreSQL URL")
    fixture_mode = _environment_flag("SCANNER_ANALYSIS_FIXTURE_MODE")
    if fixture_mode and environment == "production":
        raise ValueError("fixture analysis is forbidden in production")
    osv_executable = os.getenv("SCANNER_OSV_EXECUTABLE") or None
    depscan_executable = os.getenv("SCANNER_DEPSCAN_EXECUTABLE") or None
    engine = CloudAnalysisEngine(
        osv_executable=None if fixture_mode else osv_executable,
        depscan_executable=None if fixture_mode else depscan_executable,
        fixture_mode=fixture_mode,
    )
    host = socket.gethostname().strip()[:80] or "unknown-host"
    worker_id = os.getenv("SCANNER_ANALYSIS_WORKER_ID", f"analysis-{host}-{os.getpid()}")
    raw_kinds = os.getenv("SCANNER_ANALYSIS_KINDS", "OSV,DEPSCAN")
    kinds = cast(
        tuple[ToolKind, ...],
        tuple(item.strip().upper() for item in raw_kinds.split(",") if item.strip()),
    )
    settings = WorkerSettings(
        worker_id=worker_id,
        kinds=kinds,
        lease_seconds=int(os.getenv("SCANNER_ANALYSIS_LEASE_SECONDS", "1200")),
        max_attempts=int(os.getenv("SCANNER_ANALYSIS_MAX_ATTEMPTS", "5")),
        base_backoff_seconds=float(os.getenv("SCANNER_ANALYSIS_BASE_BACKOFF_SECONDS", "2")),
        max_backoff_seconds=float(os.getenv("SCANNER_ANALYSIS_MAX_BACKOFF_SECONDS", "300")),
        jitter_fraction=float(os.getenv("SCANNER_ANALYSIS_JITTER_FRACTION", "0.2")),
        idle_poll_seconds=float(os.getenv("SCANNER_ANALYSIS_POLL_SECONDS", "2")),
    )
    repository = PostgresRepository(
        database_url,
        run_migrations=_environment_flag("SCANNER_RUN_MIGRATIONS", default=False),
    )
    worker = AnalysisWorker(repository, engine, settings=settings)
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop_event.set)
        except (NotImplementedError, RuntimeError):
            # Windows and embedded event loops may not support signal callbacks.
            continue
    await repository.startup()
    try:
        await worker.run_forever(stop_event)
    finally:
        await repository.shutdown()


def main() -> int:
    """CLI entry point used by the dedicated cloud worker container."""

    try:
        asyncio.run(_run_from_environment())
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        message = redact_text(str(exc), max_length=2_048)
        print(f"cloud analysis worker failed: {message}")
        return 1
    return 0


__all__ = [
    "AnalysisNotification",
    "AnalysisRepository",
    "AnalysisTaskRecord",
    "AnalysisWorker",
    "WorkerOutcome",
    "WorkerSettings",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
