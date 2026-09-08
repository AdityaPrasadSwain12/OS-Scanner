from __future__ import annotations

import ssl
from collections.abc import Mapping
from pathlib import Path

import pytest

from app.enrollment import CredentialStorageError, ProtectedFileCredentialStore
from app.storage import SQLiteStorage
from app.transport import (
    CloudApiClient,
    CloudApiConfig,
    CloudApiError,
    HttpRequest,
    HttpResponse,
    ProtocolError,
    RequestAuthContext,
    TransportConfigurationError,
)


class OneResponseExecutor:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response

    def send(
        self,
        request: HttpRequest,
        *,
        timeout_seconds: float,
        ssl_context: ssl.SSLContext,
        max_response_bytes: int,
    ) -> HttpResponse:
        del request, timeout_seconds, ssl_context, max_response_bytes
        return self.response


class MaliciousAuthProvider:
    def authorization_headers(self, context: RequestAuthContext) -> Mapping[str, str]:
        del context
        return {"Authorization": "Bearer valid\r\nX-Injected: yes"}


class RejectingProtector:
    def protect(self, plaintext: bytes) -> bytes:
        return plaintext

    def unprotect(self, ciphertext: bytes) -> bytes:
        raise ValueError("invalid protected value")


def test_cloud_config_rejects_credentials_query_and_header_injection() -> None:
    with pytest.raises(TransportConfigurationError):
        CloudApiConfig("https://user:password@scanner.example.test")
    with pytest.raises(TransportConfigurationError):
        CloudApiConfig("https://scanner.example.test?token=secret")

    client = CloudApiClient(
        CloudApiConfig("https://scanner.example.test", max_attempts=1),
        auth_provider=MaliciousAuthProvider(),
        executor=OneResponseExecutor(HttpResponse(200, {}, b"{}")),
    )
    with pytest.raises(TransportConfigurationError):
        client.request("GET", "/api/v1/policies")
    with pytest.raises(TransportConfigurationError):
        client.request(
            "GET", "/api/v1/policies", headers={"Authorization": "Bearer override"}
        )


def test_cloud_errors_do_not_echo_server_body_secrets() -> None:
    executor = OneResponseExecutor(
        HttpResponse(500, {"content-type": "application/json"}, b'{"token":"server-secret"}')
    )
    client = CloudApiClient(
        CloudApiConfig("https://scanner.example.test", max_attempts=1), executor=executor
    )
    with pytest.raises(CloudApiError) as captured:
        client.request("GET", "/api/v1/policies")
    assert "server-secret" not in str(captured.value)


def test_non_json_response_declaration_is_rejected() -> None:
    executor = OneResponseExecutor(
        HttpResponse(200, {"content-type": "text/html"}, b"<html>not json</html>")
    )
    client = CloudApiClient(
        CloudApiConfig("https://scanner.example.test", max_attempts=1), executor=executor
    )
    with pytest.raises(ProtocolError, match="non-JSON"):
        client.request_json("GET", "/api/v1/policies")


def test_queue_failure_diagnostics_are_redacted_and_single_line() -> None:
    with SQLiteStorage(":memory:") as storage:
        queued = storage.enqueue_upload("scan", {}, "scan:1", "/api/v1/scans", not_before=1)
        claim = storage.claim_uploads(now=1)[0]
        storage.mark_upload_failed(
            claim.upload_id,
            claim.lease_token,
            "Authorization: Bearer top-secret\r\nforged=true",
            permanent=True,
            now=1,
        )
        record = storage.get_upload(queued.upload_id)
        assert record is not None
        assert "top-secret" not in record["last_error"]
        assert "\n" not in record["last_error"]


def test_audit_chain_detects_local_record_tampering() -> None:
    with SQLiteStorage(":memory:") as storage:
        storage.record_audit_event("scan.started", "SUCCESS", event_id="event-1")
        storage.record_audit_event("scan.finished", "SUCCESS", event_id="event-2")
        with storage.transaction() as connection:
            connection.execute(
                "UPDATE audit_log SET outcome='FAILED' WHERE event_id='event-1'"
            )
        assert storage.verify_audit_chain() is False


def test_corrupted_protected_credential_record_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    path.write_text('{"version":1,"records":{"endpoint-1":"aW52YWxpZA=="}}', encoding="utf-8")
    store = ProtectedFileCredentialStore(path, RejectingProtector())
    with pytest.raises(CredentialStorageError):
        store.load("endpoint-1")
