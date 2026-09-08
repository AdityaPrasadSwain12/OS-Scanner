from __future__ import annotations

import json
import ssl
from pathlib import Path

from app.observability import InMemoryMetrics
from app.storage import SQLiteStorage
from app.transport import (
    CloudApiClient,
    CloudApiConfig,
    HttpRequest,
    HttpResponse,
    UploadWorker,
)


class RecordingExecutor:
    def __init__(self) -> None:
        self.requests: list[HttpRequest] = []

    def send(
        self,
        request: HttpRequest,
        *,
        timeout_seconds: float,
        ssl_context: ssl.SSLContext,
        max_response_bytes: int,
    ) -> HttpResponse:
        del timeout_seconds, ssl_context, max_response_bytes
        self.requests.append(request)
        return HttpResponse(202, {"content-type": "application/json"}, b'{"accepted":true}')


def test_normalize_store_close_reopen_and_upload_pipeline(tmp_path: Path) -> None:
    database_path = tmp_path / "scanner.db"
    result = {
        "schema_version": "1.0",
        "scanner_version": "1.0.0",
        "scan_id": "scan-1",
        "endpoint_id": "endpoint-1",
        "scan_type": "FULL",
        "status": "SUCCESS",
        "software": [{"name": "Browser", "version": "1"}],
        "findings": [],
        "collectors": {"osquery": {"status": "SUCCESS", "records_collected": 1}},
    }
    with SQLiteStorage(database_path) as storage:
        snapshot = storage.save_scan_result("scan-1", "endpoint-1", result)
        assert snapshot is not None
        sync_payload = storage.snapshot_upload_payload(snapshot.snapshot_id)
        storage.enqueue_upload(
            "inventory-snapshot",
            sync_payload,
            "snapshot:scan-1",
            "/api/v1/scans",
        )

    executor = RecordingExecutor()
    client = CloudApiClient(
        CloudApiConfig(
            "https://scanner.example.test",
            max_attempts=1,
            compress_requests=False,
        ),
        executor=executor,
    )
    metrics = InMemoryMetrics()
    with SQLiteStorage(database_path) as reopened:
        stats = UploadWorker(reopened, client, metrics=metrics).run_once()
        assert stats.succeeded == 1
        assert reopened.queue_stats().succeeded == 1
        assert reopened.get_normalized_result("scan-1")["payload"] == result

    sent = json.loads((executor.requests[0].body or b"").decode("utf-8"))
    assert sent["mode"] == "full"
    assert sent["snapshot"]["software"][0]["version"] == "1"
    assert executor.requests[0].headers["Idempotency-Key"] == "snapshot:scan-1"
    gauges = metrics.snapshot()["gauges"]
    assert gauges[0]["name"] == "scanner_upload_queue_size"
    assert gauges[0]["value"] == 0
