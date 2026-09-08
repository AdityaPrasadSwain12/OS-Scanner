from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest

from cloud_service.analysis import CloudAnalysisEngine
from cloud_service.repository import AnalysisTask, InMemoryRepository, ScanRecord
from cloud_service.worker import AnalysisWorker, WorkerSettings

NOW = datetime(2026, 9, 2, tzinfo=UTC)


def _upload() -> dict[str, Any]:
    return {
        "result": {
            "schema_version": "1.0",
            "scanner_version": "1.1.0",
            "scan_id": "scan-1",
            "endpoint_id": "endpoint-1",
            "status": "SUCCESS",
        },
        "inventory_sync": {"mode": "full", "snapshot": {}},
        "sbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [],
        },
    }


@dataclass
class _Task:
    task_id: str
    kind: str
    tenant_id: str = "tenant-1"
    endpoint_id: str = "endpoint-1"
    scan_id: str = "scan-1"
    state: str = "RUNNING"
    attempts: int = 1
    payload: dict[str, Any] | None = None


class _Repo:
    def __init__(self, tasks: list[_Task], *, scan_input: object | None = None) -> None:
        self.tasks = tasks
        self.scan_input = scan_input if scan_input is not None else {
            "tenant_id": "tenant-1",
            "endpoint_id": "endpoint-1",
            "scan_id": "scan-1",
            "upload": _upload(),
            "expected_kinds": ["OSV", "DEPSCAN"],
        }
        self.results: dict[str, dict[str, Any]] = {}
        self.failures: list[tuple[str, bool, datetime]] = []
        self.final_report: dict[str, Any] | None = None
        self.finalization_failures = 0

    async def claim_analysis_task(
        self, kind: str, worker_id: str, lease_seconds: int
    ) -> _Task | None:
        for index, task in enumerate(self.tasks):
            if task.kind == kind:
                return self.tasks.pop(index)
        return None

    async def complete_analysis_task(
        self, task_id: str, worker_id: str, result: dict[str, Any]
    ) -> None:
        self.results[result["tool"]] = result

    async def fail_analysis_task(
        self,
        task_id: str,
        worker_id: str,
        error: str,
        retry_at: datetime,
        dead_letter: bool,
    ) -> None:
        self.failures.append((error, dead_letter, retry_at))

    async def get_scan_analysis_input(self, scan_id: str) -> object | None:
        return self.scan_input

    async def list_scan_analysis_results(self, scan_id: str) -> dict[str, dict[str, Any]]:
        return dict(self.results)

    async def next_scan_ready_for_finalization(self) -> str | None:
        if self.final_report is None and set(self.results) == {"OSV", "DEPSCAN"}:
            return "scan-1"
        return None

    async def finalize_scan_report(self, scan_id: str, report: dict[str, Any]) -> None:
        if self.finalization_failures:
            self.finalization_failures -= 1
            raise RuntimeError("temporary final report persistence failure")
        self.final_report = report

    async def finalize_scan_report_failure(self, scan_id: str, error: str) -> None:
        self.final_report = {"status": "FAILED", "error": error}


def _settings(**changes: Any) -> WorkerSettings:
    values = {
        "worker_id": "worker-1",
        "lease_seconds": 100,
        "max_attempts": 3,
        "base_backoff_seconds": 2.0,
        "max_backoff_seconds": 30.0,
        "jitter_fraction": 0.0,
        "idle_poll_seconds": 0.05,
    }
    values.update(changes)
    return WorkerSettings(**values)


def _engine() -> CloudAnalysisEngine:
    from cloud_service.analysis import AnalysisLimits

    return CloudAnalysisEngine(
        fixture_mode=True,
        limits=AnalysisLimits(osv_timeout_seconds=10, depscan_timeout_seconds=10),
    )


def test_worker_persists_each_tool_then_finalizes_from_durable_results() -> None:
    repository = _Repo([_Task("task-osv", "OSV"), _Task("task-depscan", "DEPSCAN")])
    worker = AnalysisWorker(repository, _engine(), settings=_settings(), clock=lambda: NOW)

    async def exercise() -> tuple[Any, Any]:
        return await worker.run_once(), await worker.run_once()

    first, second = asyncio.run(exercise())

    assert first.processed is True and first.finalized is False
    assert second.processed is True and second.finalized is True
    assert set(repository.results) == {"OSV", "DEPSCAN"}
    assert repository.final_report is not None
    assert repository.final_report["status"] == "FIXTURE"


def test_worker_reconciles_report_after_last_task_finalization_failure() -> None:
    repository = _Repo([_Task("task-osv", "OSV"), _Task("task-depscan", "DEPSCAN")])
    repository.finalization_failures = 1
    worker = AnalysisWorker(repository, _engine(), settings=_settings(), clock=lambda: NOW)

    async def exercise() -> tuple[Any, Any, Any]:
        return await worker.run_once(), await worker.run_once(), await worker.run_once()

    first, second, reconciled = asyncio.run(exercise())

    assert first.finalized is False
    assert second.task_status == "SUCCEEDED" and second.error is not None
    assert reconciled.kind == "REPORT" and reconciled.finalized is True
    assert repository.final_report is not None


def test_worker_round_robins_tool_kinds_under_backlog() -> None:
    repository = _Repo(
        [
            _Task("task-osv-1", "OSV"),
            _Task("task-osv-2", "OSV"),
            _Task("task-depscan", "DEPSCAN"),
        ]
    )
    worker = AnalysisWorker(repository, _engine(), settings=_settings(), clock=lambda: NOW)

    async def exercise() -> tuple[Any, Any]:
        return await worker.run_once(), await worker.run_once()

    first, second = asyncio.run(exercise())

    assert (first.kind, second.kind) == ("OSV", "DEPSCAN")


def test_missing_durable_input_retries_with_exponential_backoff() -> None:
    repository = _Repo([_Task("task-osv", "OSV", attempts=2)], scan_input=None)
    repository.scan_input = None
    worker = AnalysisWorker(repository, _engine(), settings=_settings(), clock=lambda: NOW)

    outcome = asyncio.run(worker.run_once())

    assert outcome.task_status == "RETRY"
    assert repository.failures[0][1] is False
    assert (repository.failures[0][2] - NOW).total_seconds() == 4


def test_malformed_input_dead_letters_without_wasting_retry_budget() -> None:
    bad_input = {
        "tenant_id": "tenant-1",
        "endpoint_id": "endpoint-1",
        "scan_id": "scan-1",
        "upload": {**_upload(), "sbom": {"bomFormat": "SPDX"}},
    }
    repository = _Repo([_Task("task-osv", "OSV")], scan_input=bad_input)
    worker = AnalysisWorker(repository, _engine(), settings=_settings(), clock=lambda: NOW)

    outcome = asyncio.run(worker.run_once())

    assert outcome.task_status == "FAILED"
    assert repository.failures[0][1] is True


@pytest.mark.parametrize(("attempts", "expected"), [(1, "RETRY"), (3, "FAILED")])
def test_transient_tool_status_uses_worker_retry_budget(
    monkeypatch: pytest.MonkeyPatch, attempts: int, expected: str
) -> None:
    repository = _Repo([_Task("task-osv", "OSV", attempts=attempts)])
    engine = _engine()
    monkeypatch.setattr(
        engine,
        "analyze_tool",
        lambda *_args, **_kwargs: {"tool": "osv", "status": "TIMEOUT"},
    )
    worker = AnalysisWorker(repository, engine, settings=_settings(), clock=lambda: NOW)

    outcome = asyncio.run(worker.run_once())

    assert outcome.task_status == expected
    assert repository.failures[0][1] is (expected == "FAILED")


def test_worker_lease_must_cover_tool_deadline() -> None:
    with pytest.raises(ValueError, match="lease"):
        AnalysisWorker(_Repo([]), _engine(), settings=_settings(lease_seconds=39))


def test_worker_matches_the_durable_repository_contract_end_to_end() -> None:
    repository = InMemoryRepository()
    repository_now = datetime.now(UTC)
    repository.scans["scan-1"] = ScanRecord(
        tenant_id="tenant-1",
        endpoint_id="endpoint-1",
        scan_id="scan-1",
        job_id="job-1",
        state="ANALYZING",
        job_document={},
        created_at=repository_now,
        updated_at=repository_now,
        upload=_upload(),
    )
    for kind in ("OSV", "DEPSCAN"):
        task = AnalysisTask(
            task_id=f"task-{kind.casefold()}",
            tenant_id="tenant-1",
            endpoint_id="endpoint-1",
            scan_id="scan-1",
            kind=kind,
            state="PENDING",
            attempts=0,
            payload={},
            created_at=repository_now,
            updated_at=repository_now,
            available_at=repository_now,
        )
        repository.tasks[task.task_id] = task
    worker = AnalysisWorker(repository, _engine(), settings=_settings(), clock=lambda: NOW)

    async def exercise() -> None:
        await worker.run_once()
        await worker.run_once()

    asyncio.run(exercise())

    stored = repository.scans["scan-1"]
    assert stored.state == "COMPLETE"
    assert stored.final_report is not None
    assert stored.final_report["status"] == "FIXTURE"
