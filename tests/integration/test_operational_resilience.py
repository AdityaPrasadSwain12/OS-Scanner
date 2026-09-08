from __future__ import annotations

import ssl
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.storage import DatabaseIntegrityError, SQLiteStorage
from app.transport import CloudApiClient, CloudApiConfig, TLSVerificationError

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures"
TLS_CERTIFICATE = FIXTURE_ROOT / "tls_wronghost_cert.pem"
TLS_PRIVATE_KEY = FIXTURE_ROOT / "tls_wronghost_key.pem"


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        payload = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _QuietTlsServer(ThreadingHTTPServer):
    def handle_error(self, _request: object, _client_address: object) -> None:
        return


@pytest.fixture
def local_wronghost_tls_server() -> Iterator[str]:
    server = _QuietTlsServer(("127.0.0.1", 0), _HealthHandler)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(TLS_CERTIFICATE, TLS_PRIVATE_KEY)
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_live_https_rejects_an_untrusted_certificate_chain(
    local_wronghost_tls_server: str,
) -> None:
    client = CloudApiClient(
        CloudApiConfig(
            local_wronghost_tls_server,
            connect_timeout_seconds=2,
            read_timeout_seconds=2,
            max_attempts=1,
        )
    )

    with pytest.raises(TLSVerificationError, match="certificate verification"):
        client.request("GET", "/health", request_id="untrusted-chain")


def test_live_https_rejects_a_trusted_certificate_with_wrong_hostname(
    local_wronghost_tls_server: str,
) -> None:
    trusted_context = ssl.create_default_context(cafile=str(TLS_CERTIFICATE))
    client = CloudApiClient(
        CloudApiConfig(
            local_wronghost_tls_server,
            connect_timeout_seconds=2,
            read_timeout_seconds=2,
            max_attempts=1,
        ),
        ssl_context=trusted_context,
    )

    with pytest.raises(TLSVerificationError, match="certificate verification"):
        client.request("GET", "/health", request_id="hostname-mismatch")


def test_corrupt_sqlite_database_fails_closed_without_replacing_evidence(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "scanner.sqlite3"
    original = b"not-a-sqlite-database\x00preserve-for-forensics"
    database_path.write_bytes(original)

    with pytest.raises(DatabaseIntegrityError):
        SQLiteStorage(database_path)

    assert database_path.read_bytes() == original
