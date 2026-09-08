from __future__ import annotations

import hashlib
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.enrollment import CredentialExpiredError
from app.orchestrator import CloudJobSource, ScannerAgent
from app.storage import QueueStats, SQLiteStorage
from app.transport import CloudApiRoutes, NetworkError, ProtocolError, UploadRunStats


def _job_document(endpoint_id: str = "endpoint-1") -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "scan_id": "scan-1",
        "scan_type": "QUICK",
        "endpoint_id": endpoint_id,
        "authorization": {
            "scope_id": "scope-1",
            "authorized": True,
            "authorization_reference": "ticket-1",
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "allowed_endpoint_ids": [endpoint_id],
        },
    }


class ResponseClient:
    def __init__(self, response: object) -> None:
        self.response = response
        self.endpoint = ""
        self.posts: list[tuple[str, object, str]] = []
        self.config = SimpleNamespace(routes=CloudApiRoutes())

    def request(self, method: str, endpoint: str) -> object:
        assert method == "GET"
        self.endpoint = endpoint
        return self.response

    def post_json(
        self, endpoint: str, payload: object, *, idempotency_key: str
    ) -> object:
        self.posts.append((endpoint, payload, idempotency_key))
        return FakeResponse(202)


class FakeResponse:
    def __init__(self, status_code: int, document: object | None = None) -> None:
        self.status_code = status_code
        self.document = document
        self.body = b"" if document is None else json.dumps(document).encode()

    def json(self) -> object:
        return self.document


def test_cloud_job_source_validates_endpoint_and_handles_empty_response() -> None:
    with pytest.raises(ValueError, match="endpoint_id"):
        CloudJobSource(ResponseClient(FakeResponse(204)), "")  # type: ignore[arg-type]

    client = ResponseClient(FakeResponse(204))
    source = CloudJobSource(client, "endpoint / one")  # type: ignore[arg-type]
    assert source.fetch() is None
    assert client.endpoint.endswith("endpoint%20%2F%20one")


def test_cloud_job_source_uses_configured_fetch_and_rejection_routes() -> None:
    mismatch_document = _job_document("endpoint-2")
    mismatch_document["authorization"]["allowed_endpoint_ids"] = [
        "endpoint-1",
        "endpoint-2",
    ]
    client = ResponseClient(FakeResponse(200, mismatch_document))
    client.config = SimpleNamespace(
        routes=CloudApiRoutes(
            next_scan_path_template="/tenant/jobs/{endpoint_id}/next",
            scan_rejections_path="/tenant/jobs/rejected",
        )
    )

    assert CloudJobSource(client, "endpoint / one").fetch() is None  # type: ignore[arg-type]

    assert client.endpoint == "/tenant/jobs/endpoint%20%2F%20one/next"
    assert len(client.posts) == 1
    assert client.posts[0][0] == "/tenant/jobs/rejected"


def test_cloud_job_source_parses_bounded_job_and_rejects_endpoint_mismatch() -> None:
    client = ResponseClient(FakeResponse(200, _job_document()))
    job = CloudJobSource(client, "endpoint-1").fetch()  # type: ignore[arg-type]
    assert job is not None and job.scan_id == "scan-1"

    mismatch_document = _job_document("endpoint-2")
    mismatch_document["authorization"]["allowed_endpoint_ids"] = [  # type: ignore[index]
        "endpoint-1",
        "endpoint-2",
    ]
    mismatch_client = ResponseClient(FakeResponse(200, mismatch_document))
    mismatch = CloudJobSource(mismatch_client, "endpoint-1")  # type: ignore[arg-type]

    assert mismatch.fetch() is None
    assert mismatch.fetch() is None
    assert len(mismatch_client.posts) == 1
    endpoint, payload, idempotency_key = mismatch_client.posts[0]
    assert endpoint == "/api/v1/scans/rejections"
    assert isinstance(payload, dict)
    assert payload == {
        "endpoint_id": "endpoint-1",
        "scan_id": "scan-1",
        "reason": "INVALID_OR_UNAUTHORIZED_JOB",
        "document_sha256": hashlib.sha256(
            json.dumps(mismatch_document).encode()
        ).hexdigest(),
    }
    assert idempotency_key == f"job-rejection:{payload['document_sha256']}"
    assert "authorization" not in json.dumps(payload)
    assert "ticket-1" not in json.dumps(payload)


def test_malformed_cloud_job_is_suppressed_and_audited_once(
    tmp_path: Path,
) -> None:
    class InvalidJsonResponse(FakeResponse):
        def __init__(self) -> None:
            super().__init__(200)
            self.body = b'{"scan_id":"secret-raw-job","token":"must-not-audit"'

        def json(self) -> object:
            raise ProtocolError("invalid JSON")

    storage = SQLiteStorage(tmp_path / "agent.sqlite3")
    client = ResponseClient(InvalidJsonResponse())
    source = CloudJobSource(  # type: ignore[arg-type]
        client,
        "endpoint-1",
        audit_storage=storage,
    )
    try:
        assert source.fetch() is None
        assert source.fetch() is None

        # A storage-backed source never relies on a direct network call. A new
        # source instance models a restart and must deduplicate durably as well.
        restarted = CloudJobSource(  # type: ignore[arg-type]
            client,
            "endpoint-1",
            audit_storage=storage,
        )
        assert restarted.fetch() is None
        assert client.posts == []

        queued = storage.claim_uploads(limit=10, now=10_000_000_000)
        assert len(queued) == 1
        rejection = queued[0]
        assert rejection.kind == "scan_rejection"
        assert rejection.endpoint == "/api/v1/scans/rejections"
        payload = json.loads(rejection.payload)
        assert payload["scan_id"] is None
        assert payload["reason"] == "INVALID_JSON"
        assert rejection.idempotency_key == f"job-rejection:{payload['document_sha256']}"
        assert rejection.metadata == {
            "endpoint_id": "endpoint-1",
            "remote_scan_id": None,
        }
        assert "must-not-audit" not in json.dumps(payload)
        with storage.transaction() as connection:
            audit_rows = connection.execute(
                "SELECT details_json FROM audit_log WHERE event_type='SCAN_JOB_REJECTED'"
            ).fetchall()
        assert len(audit_rows) == 1
        assert "must-not-audit" not in audit_rows[0]["details_json"]
    finally:
        storage.close()


class FakeStorage:
    def __init__(self, active: int = 2) -> None:
        self.active = active

    def queue_stats(self) -> QueueStats:
        return QueueStats(pending=self.active)


class FakeOrchestrator:
    def __init__(self) -> None:
        self.storage = FakeStorage()
        self.jobs: list[object] = []

    def execute(self, job: object) -> object:
        self.jobs.append(job)
        return SimpleNamespace(scan_id="scan-1")


class SequencedWorker:
    def __init__(self, values: list[UploadRunStats]) -> None:
        self.values = iter(values)
        self.calls = 0

    def run_once(self) -> UploadRunStats:
        self.calls += 1
        return next(self.values)


class Metrics:
    def __init__(self) -> None:
        self.values: list[int] = []

    def queue_size(self, value: int) -> None:
        self.values.append(value)


class Logger:
    def __init__(self) -> None:
        self.infos: list[tuple[str, dict[str, object]]] = []
        self.warnings: list[tuple[str, dict[str, object]]] = []
        self.exceptions: list[tuple[str, str]] = []
        self.on_exception: Any = None

    def info(self, event: str, **fields: object) -> None:
        self.infos.append((event, fields))

    def warning(self, event: str, **fields: object) -> None:
        self.warnings.append((event, fields))

    def exception(self, event: str, error: Exception) -> None:
        self.exceptions.append((event, type(error).__name__))
        if self.on_exception:
            self.on_exception()


class Source:
    def __init__(self, value: object = None, *, error: Exception | None = None) -> None:
        self.value = value
        self.error = error

    def fetch(self) -> object:
        if self.error:
            raise self.error
        return self.value


@pytest.mark.parametrize(
    ("poll", "jitter", "message"),
    [
        (4.9, 0.1, "poll interval"),
        (3_601, 0.1, "poll interval"),
        (60, -0.1, "jitter"),
        (60, 0.6, "jitter"),
    ],
)
def test_agent_rejects_unsafe_scheduling_bounds(
    poll: float, jitter: float, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        ScannerAgent(
            FakeOrchestrator(),  # type: ignore[arg-type]
            Source(),  # type: ignore[arg-type]
            SequencedWorker([]),  # type: ignore[arg-type]
            poll_interval_seconds=poll,
            jitter_ratio=jitter,
        )


def test_agent_drains_queue_and_reports_cloud_offline_without_losing_work() -> None:
    orchestrator = FakeOrchestrator()
    worker = SequencedWorker([UploadRunStats(claimed=1, retried=1)])
    metrics = Metrics()
    logger = Logger()
    agent = ScannerAgent(
        orchestrator,  # type: ignore[arg-type]
        Source(error=NetworkError("offline")),  # type: ignore[arg-type]
        worker,  # type: ignore[arg-type]
        logger=logger,  # type: ignore[arg-type]
        metrics=metrics,  # type: ignore[arg-type]
    )

    result = agent.run_once()

    assert result.online is False
    assert result.uploads.retried == 1
    assert orchestrator.jobs == []
    assert metrics.values == [2]
    assert logger.warnings[0][0] == "cloud_offline"
    assert logger.warnings[0][1]["error_type"] == "NetworkError"


def test_agent_executes_job_then_attempts_immediate_delivery() -> None:
    job = object()
    orchestrator = FakeOrchestrator()
    worker = SequencedWorker(
        [
            UploadRunStats(claimed=1, succeeded=1),
            UploadRunStats(claimed=2, succeeded=1, retried=1),
        ]
    )
    agent = ScannerAgent(
        orchestrator,  # type: ignore[arg-type]
        Source(job),  # type: ignore[arg-type]
        worker,  # type: ignore[arg-type]
    )

    result = agent.run_once()

    assert result.online is True
    assert result.scan is not None
    assert result.uploads == UploadRunStats(claimed=3, succeeded=2, retried=1)
    assert orchestrator.jobs == [job]
    assert worker.calls == 2


def test_agent_runs_credential_maintenance_before_network_work() -> None:
    events: list[str] = []
    logger = Logger()

    class OrderedWorker:
        def run_once(self) -> UploadRunStats:
            events.append("upload")
            return UploadRunStats()

    class OrderedSource:
        def fetch(self) -> None:
            events.append("fetch")
            return None

    def maintain() -> bool:
        events.append("maintain")
        return True

    result = ScannerAgent(
        FakeOrchestrator(),  # type: ignore[arg-type]
        OrderedSource(),  # type: ignore[arg-type]
        OrderedWorker(),  # type: ignore[arg-type]
        logger=logger,  # type: ignore[arg-type]
        credential_maintenance=maintain,
    ).run_once()

    assert result.scan is None
    assert events == ["maintain", "upload", "fetch"]
    assert logger.infos == [("cloud_credential_rotated", {})]


def test_policy_activation_coalesces_a_policy_scan_before_cloud_job_fetch() -> None:
    events: list[str] = []
    policy_job = object()
    orchestrator = FakeOrchestrator()
    worker = SequencedWorker([UploadRunStats(), UploadRunStats()])

    class OrderedSource:
        def fetch(self) -> None:
            events.append("fetch")
            return None

    class PolicyScheduler:
        def __init__(self) -> None:
            self.pending = False
            self.requests = 0

        def request_policy_scan(self) -> None:
            events.append("policy-request")
            self.pending = True
            self.requests += 1

        def poll(self) -> object | None:
            events.append("poll")
            if not self.pending:
                return None
            self.pending = False
            return policy_job

    scheduler = PolicyScheduler()

    def sync_policy() -> bool:
        events.append("policy-sync")
        return True

    result = ScannerAgent(
        orchestrator,  # type: ignore[arg-type]
        OrderedSource(),  # type: ignore[arg-type]
        worker,  # type: ignore[arg-type]
        scheduler=scheduler,  # type: ignore[arg-type]
        policy_maintenance=sync_policy,
    ).run_once()

    assert result.scan is not None
    assert scheduler.requests == 1
    assert orchestrator.jobs == [policy_job]
    assert events == ["policy-sync", "policy-request", "fetch", "poll"]


def test_expired_cloud_credential_does_not_block_offline_scheduled_scan() -> None:
    job = object()
    orchestrator = FakeOrchestrator()
    worker = SequencedWorker([UploadRunStats(), UploadRunStats()])
    logger = Logger()

    class Scheduler:
        def poll(self) -> object:
            return job

        def request_policy_scan(self) -> None:
            pass

    def expired_maintenance() -> bool:
        raise CredentialExpiredError("re-enrollment required")

    agent = ScannerAgent(
        orchestrator,  # type: ignore[arg-type]
        Source(error=CredentialExpiredError("expired")),  # type: ignore[arg-type]
        worker,  # type: ignore[arg-type]
        logger=logger,  # type: ignore[arg-type]
        scheduler=Scheduler(),  # type: ignore[arg-type]
        credential_maintenance=expired_maintenance,
    )

    result = agent.run_once()

    assert result.online is False
    assert result.scan is not None
    assert orchestrator.jobs == [job]
    assert worker.calls == 2
    assert [event for event, _ in logger.warnings] == [
        "cloud_credential_rotation_failed",
        "cloud_offline",
    ]


def test_agent_idle_iteration_does_not_attempt_second_upload() -> None:
    worker = SequencedWorker([UploadRunStats()])
    result = ScannerAgent(
        FakeOrchestrator(),  # type: ignore[arg-type]
        Source(),  # type: ignore[arg-type]
        worker,  # type: ignore[arg-type]
    ).run_once()
    assert result.online is True
    assert result.scan is None
    assert worker.calls == 1


def test_agent_run_contains_unexpected_iteration_failure_and_stops() -> None:
    logger = Logger()
    agent = ScannerAgent(
        FakeOrchestrator(),  # type: ignore[arg-type]
        Source(error=ValueError("bad job")),  # type: ignore[arg-type]
        SequencedWorker([UploadRunStats()]),  # type: ignore[arg-type]
        poll_interval_seconds=5,
        jitter_ratio=0,
        logger=logger,  # type: ignore[arg-type]
        random_source=random.Random(1),  # noqa: S311 - deterministic unit test
    )
    logger.on_exception = agent.stop

    agent.run()

    assert logger.exceptions == [("agent_iteration_failed", "ValueError")]
