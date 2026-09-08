from __future__ import annotations

import gzip
import json
import ssl
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from app.storage import RetryPolicy, SQLiteStorage
from app.transport import (
    BearerTokenAuthProvider,
    CloudApiClient,
    CloudApiConfig,
    CloudApiError,
    CloudApiRoutes,
    HttpRequest,
    HttpResponse,
    ResponseTooLargeError,
    TLSVerificationError,
    TransportConfigurationError,
    UploadWorker,
)


class FakeExecutor:
    def __init__(self, responses: Iterable[HttpResponse | Exception]) -> None:
        self.responses = iter(responses)
        self.requests: list[HttpRequest] = []
        self.options: list[dict[str, Any]] = []

    def send(
        self,
        request: HttpRequest,
        *,
        timeout_seconds: float,
        ssl_context: ssl.SSLContext,
        max_response_bytes: int,
    ) -> HttpResponse:
        self.requests.append(request)
        self.options.append(
            {
                "timeout": timeout_seconds,
                "verify_mode": ssl_context.verify_mode,
                "check_hostname": ssl_context.check_hostname,
                "max_response_bytes": max_response_bytes,
            }
        )
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def _client(
    executor: FakeExecutor,
    **overrides: Any,
) -> CloudApiClient:
    values = {"base_url": "https://scanner.example.test", "max_attempts": 1, **overrides}
    return CloudApiClient(
        CloudApiConfig(**values),
        BearerTokenAuthProvider("test-access-token"),
        executor=executor,
        sleep=lambda _: None,
    )


def test_https_and_certificate_verification_are_mandatory() -> None:
    with pytest.raises(TransportConfigurationError, match="HTTPS"):
        CloudApiConfig("http://scanner.example.test")

    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    with pytest.raises(TransportConfigurationError, match="cannot be disabled"):
        CloudApiClient(CloudApiConfig("https://scanner.example.test"), ssl_context=insecure)


def test_explicit_loopback_http_is_available_only_for_local_development() -> None:
    config = CloudApiConfig(
        "http://127.0.0.1:8080",
        allow_insecure_loopback_http=True,
    )
    executor = FakeExecutor([HttpResponse(200, {}, b"{}")])
    client = CloudApiClient(config, executor=executor)

    client.request("GET", "/healthz")

    assert executor.requests[0].url == "http://127.0.0.1:8080/healthz"
    with pytest.raises(TransportConfigurationError, match="HTTPS"):
        CloudApiConfig(
            "http://192.0.2.1:8080",
            allow_insecure_loopback_http=True,
        )


def test_base_url_path_prefix_is_preserved_for_api_requests() -> None:
    executor = FakeExecutor([HttpResponse(200, {}, b"{}")])
    client = _client(executor, base_url="https://scanner.example.test/control-plane/")

    client.request("GET", "/api/v1/policies", request_id="prefix-request")

    assert executor.requests[0].url == (
        "https://scanner.example.test/control-plane/api/v1/policies"
    )


def test_cloud_client_helpers_use_every_configured_route_and_encode_identifiers() -> None:
    executor = FakeExecutor([HttpResponse(200, {}, b"{}") for _ in range(6)])
    routes = CloudApiRoutes(
        enrollment_path="/tenant/enroll",
        scan_submit_path="/tenant/results",
        scan_lookup_path_template="/tenant/results/{scan_id}",
        policies_path="/tenant/policy-bundles",
        heartbeat_path="/tenant/endpoint-heartbeats",
        attack_surface_jobs_path="/tenant/discovery-results",
    )
    client = _client(executor, routes=routes)

    client.enroll({"hostname": "host-1"}, BearerTokenAuthProvider("enrollment-token"))
    client.submit_scan({"scan_id": "scan-1"}, idempotency_key="result:scan-1")
    client.get_scan("scan / one")
    client.fetch_policies()
    client.heartbeat({"endpoint_id": "endpoint-1"}, idempotency_key="heartbeat:1")
    client.submit_attack_surface_job(
        {"scan_id": "surface-1"}, idempotency_key="surface:1"
    )

    assert [request.url for request in executor.requests] == [
        "https://scanner.example.test/tenant/enroll",
        "https://scanner.example.test/tenant/results",
        "https://scanner.example.test/tenant/results/scan%20%2F%20one",
        "https://scanner.example.test/tenant/policy-bundles",
        "https://scanner.example.test/tenant/endpoint-heartbeats",
        "https://scanner.example.test/tenant/discovery-results",
    ]


@pytest.mark.parametrize(
    "base_url",
    (
        "https://user:password@scanner.example.test/control-plane",
        "https://scanner.example.test/control-plane?tenant=one",
        "https://scanner.example.test/control-plane#fragment",
        "https://scanner.example.test/control\\plane",
        "https://scanner.example.test/control\x01plane",
        "https://scanner.example.test/control/./plane",
        "https://scanner.example.test/control/../admin",
        "https://scanner.example.test/control/%2e%2e/admin",
    ),
)
def test_base_url_rejects_ambiguous_or_traversing_paths(base_url: str) -> None:
    with pytest.raises(TransportConfigurationError):
        CloudApiConfig(base_url)


def test_authenticated_json_request_uses_gzip_and_bounded_response() -> None:
    payload = {"inventory": "x" * 256}
    encoded_response = gzip.compress(b'{"accepted":true}', mtime=0)
    executor = FakeExecutor([HttpResponse(202, {"Content-Encoding": "gzip"}, encoded_response)])
    client = _client(
        executor,
        compression_threshold_bytes=1,
        max_response_bytes=1024,
    )

    assert client.post_json(
        "/api/v1/scans", payload, idempotency_key="scan:1", request_id="request-1"
    ) == {"accepted": True}
    request = executor.requests[0]
    assert request.url == "https://scanner.example.test/api/v1/scans"
    assert request.headers["Authorization"] == "Bearer test-access-token"
    assert request.headers["Idempotency-Key"] == "scan:1"
    assert request.headers["X-Request-ID"] == "request-1"
    assert request.headers["Content-Encoding"] == "gzip"
    assert gzip.decompress(request.body or b"").startswith(b'{"inventory"')
    assert executor.options[0]["verify_mode"] == ssl.CERT_REQUIRED
    assert executor.options[0]["check_hostname"] is True


def test_retryable_request_preserves_identifiers() -> None:
    executor = FakeExecutor(
        [HttpResponse(503, {"retry-after": "0"}, b""), HttpResponse(200, {}, b"{}")]
    )
    sleeps: list[float] = []
    client = CloudApiClient(
        CloudApiConfig("https://scanner.example.test", max_attempts=2),
        executor=executor,
        sleep=sleeps.append,
    )
    client.post_json(
        "/api/v1/scans", {"scan_id": "scan-1"}, idempotency_key="scan:1", request_id="r1"
    )
    assert len(executor.requests) == 2
    assert {request.headers["X-Request-ID"] for request in executor.requests} == {"r1"}
    assert {request.headers["Idempotency-Key"] for request in executor.requests} == {"scan:1"}
    assert sleeps == [0]


def test_non_idempotent_post_is_not_retried() -> None:
    executor = FakeExecutor([HttpResponse(503, {}, b""), HttpResponse(200, {}, b"ok")])
    client = CloudApiClient(
        CloudApiConfig("https://scanner.example.test", max_attempts=2),
        executor=executor,
        sleep=lambda _: None,
    )
    with pytest.raises(CloudApiError) as error:
        client.request("POST", "/api/v1/scans", body=b"{}")
    assert error.value.retryable is True
    assert len(executor.requests) == 1


def test_oversized_and_gzip_bomb_responses_are_rejected() -> None:
    oversized = FakeExecutor([HttpResponse(200, {}, b"x" * 11)])
    with pytest.raises(ResponseTooLargeError):
        _client(oversized, max_response_bytes=10).request("GET", "/api/v1/policies")

    bomb = FakeExecutor(
        [HttpResponse(200, {"content-encoding": "gzip"}, gzip.compress(b"x" * 1000))]
    )
    with pytest.raises(ResponseTooLargeError):
        _client(bomb, max_response_bytes=100).request("GET", "/api/v1/policies")


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://evil.test/api",
        "//evil.test/api",
        "/api/../admin",
        "/api/%2e%2e/admin",
        "/api/./admin",
        "/api/%2e/admin",
        "/api\\admin",
        "/api/\x01admin",
    ],
)
def test_endpoint_origin_and_path_traversal_are_rejected(endpoint: str) -> None:
    client = _client(FakeExecutor([]))
    with pytest.raises(TransportConfigurationError):
        client.request("GET", endpoint)


def test_upload_worker_retries_persistent_item_then_completes(tmp_path: Path) -> None:
    storage = SQLiteStorage(tmp_path / "scanner.db")
    storage.enqueue_upload(
        "scan-result",
        {"scan_id": "scan-1"},
        "scan:1",
        "/api/v1/scans",
        max_attempts=3,
        not_before=100,
    )
    executor = FakeExecutor([HttpResponse(503, {}, b""), HttpResponse(202, {}, b"{}")])
    client = _client(executor)

    class Clock:
        value = 100.0

        def __call__(self) -> float:
            return self.value

    clock = Clock()
    worker = UploadWorker(
        storage,
        client,
        retry_policy=RetryPolicy(base_delay_seconds=1, jitter_ratio=0),
        clock=clock,
    )
    first = worker.run_once()
    assert first.retried == 1
    assert storage.queue_stats().pending == 1
    storage.close()

    storage = SQLiteStorage(tmp_path / "scanner.db")
    worker.storage = storage
    clock.value = 101
    second = worker.run_once()
    assert second.succeeded == 1
    assert storage.queue_stats().succeeded == 1
    storage.close()


def _enqueue_differential_and_status(storage: SQLiteStorage) -> tuple[int, int]:
    storage.store_snapshot(
        "endpoint-1",
        "scan-base",
        {"software": [{"name": "browser", "version": "1"}]},
        "1.0",
    )
    changed = storage.store_snapshot(
        "endpoint-1",
        "scan-change",
        {"software": [{"name": "browser", "version": "2"}]},
        "1.0",
    )
    differential = storage.snapshot_upload_payload(changed.snapshot_id)
    result = storage.enqueue_upload(
        "scan_result",
        {"result": {"scan_id": "scan-change"}, "inventory_sync": differential},
        "delta-scan-change",
        "/api/v1/scans",
        metadata={"scan_id": "scan-change", "endpoint_id": "endpoint-1"},
        max_attempts=2,
        not_before=0,
    )
    status = storage.enqueue_upload(
        "scan_status",
        {"scan_id": "scan-change", "endpoint_id": "endpoint-1", "status": "SUCCESS"},
        "status-scan-change",
        "/api/v1/scans/status",
        metadata={"scan_id": "scan-change", "endpoint_id": "endpoint-1"},
        max_attempts=2,
        not_before=0,
    )
    return result.upload_id, status.upload_id


def test_conflicted_delta_queues_one_full_resync_before_downstream_status(
    tmp_path: Path,
) -> None:
    with SQLiteStorage(tmp_path / "scanner.db") as storage:
        result_id, status_id = _enqueue_differential_and_status(storage)
        executor = FakeExecutor(
            [
                HttpResponse(409, {}, b""),
                HttpResponse(202, {}, b"{}"),
                HttpResponse(202, {}, b"{}"),
            ]
        )
        worker = UploadWorker(storage, _client(executor), clock=lambda: 100.0)

        first = worker.run_once(limit=1)
        assert first.retried == 1
        original = storage.get_upload(result_id)
        assert original is not None and original["status"] == "DEAD"
        recovery_id = original["superseded_by_upload_id"]
        recovery = storage.get_upload(recovery_id)
        assert recovery is not None and recovery["status"] == "PENDING"
        assert recovery["metadata"]["causal_recovery"] is True
        assert storage.get_upload(status_id)["status"] == "PENDING"

        assert worker.run_once(limit=1).succeeded == 1
        recovery_payload = json.loads(executor.requests[1].body or b"{}")
        assert recovery_payload["inventory_sync"]["mode"] == "full"
        assert recovery_payload["inventory_sync"]["previous_hash"] is None
        assert recovery_payload["inventory_sync"]["snapshot"]["software"][0]["version"] == "2"
        assert storage.get_upload(status_id)["status"] == "PENDING"

        assert worker.run_once(limit=1).succeeded == 1
        assert storage.get_upload(status_id)["status"] == "SUCCEEDED"
        with storage.transaction() as connection:
            recoveries = connection.execute(
                "SELECT COUNT(*) FROM upload_queue "
                "WHERE json_extract(metadata_json,'$.causal_recovery')=1"
            ).fetchone()[0]
        assert recoveries == 1
        resolved_stats = storage.queue_stats()
        assert resolved_stats.dead == 0
        assert resolved_stats.succeeded == 2
        assert storage.purge_succeeded_uploads(
            older_than="9999-01-01T00:00:00+00:00", limit=10
        ) == 3
        assert storage.queue_stats().succeeded == 0
        assert storage.get_upload(result_id) is None
        assert storage.get_upload(recovery_id) is None
        assert storage.get_upload(status_id) is None


def test_conflict_on_full_resync_does_not_create_recursive_recovery(
    tmp_path: Path,
) -> None:
    with SQLiteStorage(tmp_path / "scanner.db") as storage:
        _result_id, status_id = _enqueue_differential_and_status(storage)
        executor = FakeExecutor(
            [HttpResponse(412, {}, b""), HttpResponse(409, {}, b"")]
        )
        worker = UploadWorker(storage, _client(executor), clock=lambda: 100.0)

        assert worker.run_once(limit=1).retried == 1
        second = worker.run_once(limit=1)

        assert second.dead == 1
        assert storage.queue_stats().dead == 2
        assert storage.get_upload(status_id)["status"] == "PENDING"
        with storage.transaction() as connection:
            rows = connection.execute(
                "SELECT COUNT(*) FROM upload_queue "
                "WHERE json_extract(metadata_json,'$.causal_recovery')=1"
            ).fetchone()[0]
        assert rows == 1
        assert storage.purge_succeeded_uploads(
            older_than="9999-01-01T00:00:00+00:00", limit=10
        ) == 0
        assert storage.queue_stats().dead == 2
        assert storage.get_upload(status_id)["status"] == "PENDING"


@pytest.mark.parametrize(
    "responses",
    (
        (HttpResponse(401, {}, b""), HttpResponse(401, {}, b"")),
        (
            TLSVerificationError("certificate verification failed"),
            TLSVerificationError("certificate verification failed"),
        ),
    ),
)
def test_authentication_and_tls_failures_retry_durably_until_queue_bound(
    tmp_path: Path,
    responses: tuple[HttpResponse | Exception, HttpResponse | Exception],
) -> None:
    storage = SQLiteStorage(tmp_path / "scanner.db")
    try:
        upload = storage.enqueue_upload(
            "artifact",
            {"scan_id": "scan-auth-tls"},
            "bounded-auth-tls",
            "/api/v1/artifacts",
            max_attempts=2,
            not_before=100,
        )
        executor = FakeExecutor(responses)
        clock_value = [100.0]
        worker = UploadWorker(
            storage,
            _client(executor),
            retry_policy=RetryPolicy(base_delay_seconds=1, jitter_ratio=0),
            clock=lambda: clock_value[0],
        )

        first = worker.run_once(limit=1)
        assert first.retried == 1
        assert storage.get_upload(upload.upload_id)["status"] == "PENDING"

        clock_value[0] = 101.0
        second = worker.run_once(limit=1)
        assert second.dead == 1
        assert storage.get_upload(upload.upload_id)["status"] == "DEAD"
    finally:
        storage.close()


def test_worker_lease_covers_the_clients_complete_retry_budget() -> None:
    client = _client(
        FakeExecutor([]),
        max_attempts=3,
        timeout_seconds=20,
        backoff_max_seconds=10,
    )
    with SQLiteStorage(":memory:") as storage:
        worker = UploadWorker(storage, client, lease_seconds=30)

        expected_retry_budget = 3 * (20 + 20) + 2 * 10 + 5
        assert worker._effective_lease_seconds() == expected_retry_budget
