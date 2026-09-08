"""Secure cloud API client with bounded I/O and idempotent retries."""

from __future__ import annotations

import gzip
import http.client
import json
import re
import socket
import ssl
import threading
import time
import urllib.parse
import zlib
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from random import Random, SystemRandom
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4

from app.security.url_paths import (
    ApiPathValidationError,
    validate_api_path,
    validate_base_url_path,
)

from .auth import AnonymousAuthProvider, AuthProvider, RequestAuthContext
from .errors import (
    AuthenticationError,
    CloudApiError,
    NetworkError,
    ProtocolError,
    ResponseTooLargeError,
    TLSVerificationError,
    TransportConfigurationError,
    TransportError,
)

_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
_RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
_RESERVED_HEADERS = frozenset(
    {
        "authorization",
        "host",
        "content-length",
        "transfer-encoding",
        "x-request-id",
        "idempotency-key",
        "accept-encoding",
        "content-encoding",
    }
)


@dataclass(frozen=True, slots=True)
class CloudApiRoutes:
    enrollment_path: str = "/api/v1/endpoint/enroll"
    credential_rotation_path_template: str = (
        "/api/v1/endpoints/{endpoint_id}/credentials/rotate"
    )
    scan_submit_path: str = "/api/v1/scans"
    scan_status_path: str = "/api/v1/scans/status"
    scan_lookup_path_template: str = "/api/v1/scans/{scan_id}"
    next_scan_path_template: str = "/api/v1/scans/next/{endpoint_id}"
    policies_path: str = "/api/v1/policies"
    heartbeat_path: str = "/api/v1/heartbeat"
    attack_surface_jobs_path: str = "/api/v1/attack-surface/jobs"
    scan_rejections_path: str = "/api/v1/scans/rejections"

    def __post_init__(self) -> None:
        templates = {
            "credential_rotation_path_template": frozenset({"endpoint_id"}),
            "scan_lookup_path_template": frozenset({"scan_id"}),
            "next_scan_path_template": frozenset({"endpoint_id"}),
        }
        for name in self.__dataclass_fields__:
            expected = templates.get(name, frozenset())
            try:
                validate_api_path(
                    getattr(self, name), expected_placeholders=expected
                )
            except ApiPathValidationError as exc:
                if exc.kind == "placeholder":
                    raise TransportConfigurationError(
                        f"cloud API route {name} has invalid placeholders"
                    ) from exc
                raise TransportConfigurationError(
                    f"cloud API route {name} is not a safe absolute path"
                ) from exc


@dataclass(frozen=True, slots=True)
class CloudApiConfig:
    base_url: str
    allow_insecure_loopback_http: bool = False
    # Retained as the backwards-compatible timeout used by injected executors.
    # The standard executor uses the distinct effective values below.
    timeout_seconds: float = 20.0
    connect_timeout_seconds: float | None = None
    read_timeout_seconds: float | None = None
    max_response_bytes: int = 8 * 1024 * 1024
    max_request_bytes: int = 32 * 1024 * 1024
    max_attempts: int = 3
    backoff_base_seconds: float = 0.5
    backoff_max_seconds: float = 10.0
    jitter_ratio: float = 0.20
    compress_requests: bool = True
    compression_threshold_bytes: int = 1024
    user_agent: str = "endpoint-security-scanner"
    routes: CloudApiRoutes = field(default_factory=CloudApiRoutes)

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlsplit(self.base_url)
        scheme = parsed.scheme.lower()
        loopback_http = (
            scheme == "http"
            and self.allow_insecure_loopback_http
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        )
        if scheme != "https" and not loopback_http:
            raise TransportConfigurationError(
                "cloud API base URL must use HTTPS unless loopback HTTP is explicitly enabled"
            )
        if not parsed.hostname or parsed.username or parsed.password:
            raise TransportConfigurationError("cloud API base URL is invalid")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise TransportConfigurationError("cloud API base URL has an invalid port") from exc
        if parsed.query or parsed.fragment:
            raise TransportConfigurationError("cloud API base URL cannot include query or fragment")
        if "?" in self.base_url or "#" in self.base_url:
            raise TransportConfigurationError(
                "cloud API base URL cannot include query or fragment"
            )
        try:
            validate_base_url_path(parsed.path)
        except ApiPathValidationError as exc:
            raise TransportConfigurationError(
                "cloud API base URL contains an invalid path"
            ) from exc
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.connect_timeout_seconds is not None and self.connect_timeout_seconds <= 0:
            raise ValueError("connect_timeout_seconds must be positive")
        if self.read_timeout_seconds is not None and self.read_timeout_seconds <= 0:
            raise ValueError("read_timeout_seconds must be positive")
        if not 1 <= self.max_response_bytes <= 512 * 1024 * 1024:
            raise ValueError("max_response_bytes is outside the supported range")
        if not 1 <= self.max_request_bytes <= 512 * 1024 * 1024:
            raise ValueError("max_request_bytes is outside the supported range")
        if not 1 <= self.max_attempts <= 10:
            raise ValueError("max_attempts must be between 1 and 10")
        if self.backoff_base_seconds <= 0 or self.backoff_max_seconds < self.backoff_base_seconds:
            raise ValueError("invalid backoff bounds")
        if not 0 <= self.jitter_ratio <= 1:
            raise ValueError("jitter_ratio must be between 0 and 1")
        if self.compression_threshold_bytes < 0:
            raise ValueError("compression_threshold_bytes cannot be negative")
        _validate_header_value(self.user_agent, "user_agent")

    @property
    def effective_connect_timeout_seconds(self) -> float:
        return float(self.connect_timeout_seconds or self.timeout_seconds)

    @property
    def effective_read_timeout_seconds(self) -> float:
        return float(self.read_timeout_seconds or self.timeout_seconds)


@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes | None
    connect_timeout_seconds: float | None = None
    read_timeout_seconds: float | None = None


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True, slots=True)
class CloudResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes
    request_id: str

    def json(self) -> Any:
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("cloud API returned invalid JSON") from exc


@runtime_checkable
class HttpExecutor(Protocol):
    def send(
        self,
        request: HttpRequest,
        *,
        timeout_seconds: float,
        ssl_context: ssl.SSLContext,
        max_response_bytes: int,
    ) -> HttpResponse: ...


def _read_bounded(
    stream: Any,
    maximum: int,
    *,
    deadline_at: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> bytes:
    result = bytearray()
    reader = getattr(stream, "read1", None)
    if not callable(reader):
        reader = stream.read
    while True:
        if deadline_at is not None and clock() >= deadline_at:
            raise NetworkError("cloud response read deadline exceeded")
        try:
            chunk = reader(min(64 * 1024, maximum + 1 - len(result)))
        except TimeoutError as exc:
            raise NetworkError("cloud response read timed out") from exc
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > maximum:
            raise ResponseTooLargeError(f"cloud response exceeded the {maximum}-byte limit")


class UrllibHttpExecutor:
    """Standard-library HTTP(S) executor with distinct, absolute I/O deadlines.

    The historical class name is retained as part of the public API.  Direct
    ``http.client`` use prevents implicit redirects and lets the connection
    socket switch from a connect timeout to a read timeout before response
    headers are consumed.
    """

    def send(
        self,
        request: HttpRequest,
        *,
        timeout_seconds: float,
        ssl_context: ssl.SSLContext,
        max_response_bytes: int,
    ) -> HttpResponse:
        parsed = urllib.parse.urlsplit(request.url)
        scheme = parsed.scheme.lower()
        if not parsed.hostname or (
            scheme != "https"
            and not (
                scheme == "http"
                and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            )
        ):
            raise TransportConfigurationError(
                "HTTP executor requires HTTPS or an explicitly configured loopback URL"
            )
        connect_timeout = float(request.connect_timeout_seconds or timeout_seconds)
        read_timeout = float(request.read_timeout_seconds or timeout_seconds)
        if connect_timeout <= 0 or read_timeout <= 0:
            raise TransportConfigurationError("HTTP timeouts must be positive")
        try:
            port = parsed.port
        except ValueError as exc:
            raise TransportConfigurationError("cloud API URL has an invalid port") from exc
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection: http.client.HTTPConnection
        if scheme == "https":
            connection = http.client.HTTPSConnection(
                parsed.hostname,
                port,
                timeout=connect_timeout,
                context=ssl_context,
            )
        else:
            connection = http.client.HTTPConnection(
                parsed.hostname,
                port,
                timeout=connect_timeout,
            )
        deadline_expired = threading.Event()
        deadline_timer: threading.Timer | None = None

        def expire_read() -> None:
            deadline_expired.set()
            connected_socket = connection.sock
            if connected_socket is None:
                return
            with suppress(OSError):
                connected_socket.shutdown(socket.SHUT_RDWR)

        try:
            connection.connect()
            connection.request(
                request.method,
                path,
                body=request.body,
                headers=dict(request.headers),
            )
            if connection.sock is None:
                raise NetworkError("cloud connection closed before response")
            connection.sock.settimeout(read_timeout)
            read_deadline = time.monotonic() + read_timeout
            deadline_timer = threading.Timer(read_timeout, expire_read)
            deadline_timer.daemon = True
            deadline_timer.start()
            response = connection.getresponse()
            try:
                return HttpResponse(
                    status_code=int(response.status),
                    headers={str(key).lower(): str(value) for key, value in response.getheaders()},
                    body=_read_bounded(
                        response,
                        max_response_bytes,
                        deadline_at=read_deadline,
                    ),
                )
            finally:
                response.close()
        except (ssl.SSLCertVerificationError, ssl.CertificateError) as exc:
            if deadline_expired.is_set():
                raise NetworkError("cloud response read deadline exceeded") from exc
            raise TLSVerificationError("cloud TLS certificate verification failed") from exc
        except ssl.SSLError as exc:
            if deadline_expired.is_set():
                raise NetworkError("cloud response read deadline exceeded") from exc
            raise TLSVerificationError("cloud TLS negotiation failed") from exc
        except TimeoutError as exc:
            message = (
                "cloud response read deadline exceeded"
                if deadline_expired.is_set()
                else "cloud network request timed out"
            )
            raise NetworkError(message) from exc
        except http.client.HTTPException as exc:
            message = (
                "cloud response read deadline exceeded"
                if deadline_expired.is_set()
                else f"cloud HTTP protocol failed: {type(exc).__name__}"
            )
            raise NetworkError(message) from exc
        except OSError as exc:
            if deadline_expired.is_set():
                raise NetworkError("cloud response read deadline exceeded") from exc
            raise NetworkError(f"cloud network request failed: {type(exc).__name__}") from exc
        finally:
            if deadline_timer is not None:
                deadline_timer.cancel()
            connection.close()


def _validate_header_value(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise TransportConfigurationError(f"{field} must be a non-empty string")
    if len(value) > 16_384 or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise TransportConfigurationError(f"{field} contains invalid characters")
    return value


def _strict_json_bytes(payload: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TransportConfigurationError("request payload is not strict JSON") from exc


def _decode_gzip_bounded(payload: bytes, maximum: int) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        decoded = decoder.decompress(payload, maximum + 1)
        if len(decoded) > maximum or decoder.unconsumed_tail:
            raise ResponseTooLargeError(
                f"decompressed cloud response exceeded the {maximum}-byte limit"
            )
        remaining = maximum + 1 - len(decoded)
        decoded += decoder.flush(remaining)
    except zlib.error as exc:
        raise ProtocolError("cloud API returned invalid gzip data") from exc
    if len(decoded) > maximum or not decoder.eof:
        if len(decoded) > maximum:
            raise ResponseTooLargeError(
                f"decompressed cloud response exceeded the {maximum}-byte limit"
            )
        raise ProtocolError("cloud API returned truncated gzip data")
    return decoded


class CloudApiClient:
    def __init__(
        self,
        config: CloudApiConfig,
        auth_provider: AuthProvider | None = None,
        *,
        executor: HttpExecutor | None = None,
        ssl_context: ssl.SSLContext | None = None,
        sleep: Callable[[float], None] = time.sleep,
        random_source: Random | None = None,
    ) -> None:
        self.config = config
        self.auth_provider = auth_provider or AnonymousAuthProvider()
        self.executor = executor or UrllibHttpExecutor()
        self.ssl_context = ssl_context or ssl.create_default_context()
        if self.ssl_context.verify_mode != ssl.CERT_REQUIRED or not self.ssl_context.check_hostname:
            raise TransportConfigurationError(
                "TLS certificate and hostname verification cannot be disabled"
            )
        if hasattr(ssl, "TLSVersion"):
            minimum = self.ssl_context.minimum_version
            if minimum < ssl.TLSVersion.TLSv1_2:
                self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._sleep = sleep
        self._random = random_source or SystemRandom()
        self._parsed_base = urllib.parse.urlsplit(config.base_url.rstrip("/"))

    def _url(self, endpoint: str) -> str:
        try:
            # Identifiers are encoded by scanner-owned helpers before this
            # boundary, so encoded spaces/path delimiters may be data.  Raw URL
            # syntax, nested escapes, braces, controls, and traversal remain
            # forbidden.
            validate_api_path(endpoint, allow_encoded_path_data=True)
        except ApiPathValidationError as exc:
            raise TransportConfigurationError("API endpoint is not a safe absolute path") from exc
        parsed = urllib.parse.urlsplit(endpoint)
        base_path = self._parsed_base.path.rstrip("/")
        final_path = f"{base_path}{parsed.path}"
        return urllib.parse.urlunsplit(
            (
                self._parsed_base.scheme,
                self._parsed_base.netloc,
                final_path,
                "",
                "",
            )
        )

    @staticmethod
    def _request_identifier(value: str | None, field: str) -> str:
        candidate = value or str(uuid4())
        if (
            len(candidate) > 256
            or not candidate
            or any(ord(character) < 33 or ord(character) == 127 for character in candidate)
        ):
            raise TransportConfigurationError(f"{field} contains invalid characters")
        return candidate

    def _headers(
        self,
        *,
        method: str,
        url: str,
        request_id: str,
        idempotency_key: str | None,
        content_type: str | None,
        content_encoding: str | None,
        headers: Mapping[str, str] | None,
        auth_provider: AuthProvider | None,
    ) -> dict[str, str]:
        result = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "User-Agent": self.config.user_agent,
            "X-Request-ID": request_id,
        }
        if content_type:
            result["Content-Type"] = _validate_header_value(content_type, "content_type")
        if content_encoding:
            result["Content-Encoding"] = content_encoding
        if idempotency_key:
            result["Idempotency-Key"] = idempotency_key
        for name, value in (headers or {}).items():
            if not _HEADER_NAME.fullmatch(name):
                raise TransportConfigurationError("request contains an invalid header name")
            if name.lower() in _RESERVED_HEADERS:
                raise TransportConfigurationError(f"request cannot override reserved header {name}")
            result[name] = _validate_header_value(value, f"header {name}")
        provider = auth_provider or self.auth_provider
        context = RequestAuthContext(method=method, url=url, request_id=request_id)
        for name, value in provider.authorization_headers(context).items():
            if name.lower() not in {"authorization", "x-api-key"} or not _HEADER_NAME.fullmatch(
                name
            ):
                raise TransportConfigurationError(
                    "authentication provider returned an unsafe header"
                )
            result[name] = _validate_header_value(value, "authentication header")
        return result

    def _retry_delay(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(self.config.backoff_max_seconds, max(0.0, retry_after))
        base = min(
            self.config.backoff_max_seconds,
            self.config.backoff_base_seconds * (2 ** min(attempt - 1, 16)),
        )
        jitter = base * self.config.jitter_ratio
        return float(
            max(
                0.0,
                min(
                    self.config.backoff_max_seconds,
                    base + float(self._random.uniform(-jitter, jitter)),
                ),
            )
        )

    @staticmethod
    def _retry_after(headers: Mapping[str, str]) -> float | None:
        value = next((v for key, v in headers.items() if key.lower() == "retry-after"), None)
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            try:
                parsed = parsedate_to_datetime(value)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=UTC)
                return max(0.0, (parsed - datetime.now(UTC)).total_seconds())
            except (TypeError, ValueError, OverflowError):
                return None

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        body: bytes | None = None,
        content_type: str | None = None,
        headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        request_id: str | None = None,
        auth_provider: AuthProvider | None = None,
    ) -> CloudResponse:
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise TransportConfigurationError("unsupported HTTP method")
        url = self._url(endpoint)
        request_id = self._request_identifier(request_id, "request_id")
        if idempotency_key is not None:
            idempotency_key = self._request_identifier(idempotency_key, "idempotency_key")
        if body is not None and len(body) > self.config.max_request_bytes:
            raise TransportConfigurationError("request body exceeds configured size limit")
        wire_body = body
        content_encoding = None
        if (
            body is not None
            and self.config.compress_requests
            and len(body) >= self.config.compression_threshold_bytes
        ):
            wire_body = gzip.compress(body, compresslevel=6, mtime=0)
            content_encoding = "gzip"
        request_headers = self._headers(
            method=method,
            url=url,
            request_id=request_id,
            idempotency_key=idempotency_key,
            content_type=content_type,
            content_encoding=content_encoding,
            headers=headers,
            auth_provider=auth_provider,
        )
        retry_allowed = method in _IDEMPOTENT_METHODS or idempotency_key is not None
        for attempt in range(1, self.config.max_attempts + 1):
            request = HttpRequest(
                method,
                url,
                request_headers,
                wire_body,
                connect_timeout_seconds=self.config.effective_connect_timeout_seconds,
                read_timeout_seconds=self.config.effective_read_timeout_seconds,
            )
            try:
                response = self.executor.send(
                    request,
                    timeout_seconds=max(
                        self.config.effective_connect_timeout_seconds,
                        self.config.effective_read_timeout_seconds,
                    ),
                    ssl_context=self.ssl_context,
                    max_response_bytes=self.config.max_response_bytes,
                )
            except TransportError as exc:
                if exc.retryable and retry_allowed and attempt < self.config.max_attempts:
                    self._sleep(self._retry_delay(attempt, None))
                    continue
                raise
            normalized_headers = {
                str(key).lower(): str(value) for key, value in response.headers.items()
            }
            encoding = normalized_headers.get("content-encoding", "identity").lower().strip()
            if encoding in {"", "identity"}:
                decoded_body = response.body
            elif encoding == "gzip":
                decoded_body = _decode_gzip_bounded(response.body, self.config.max_response_bytes)
            else:
                raise ProtocolError(f"cloud API returned unsupported content encoding: {encoding}")
            if len(decoded_body) > self.config.max_response_bytes:
                raise ResponseTooLargeError("cloud response exceeded configured size limit")
            if 200 <= response.status_code < 300:
                return CloudResponse(
                    response.status_code, normalized_headers, decoded_body, request_id
                )
            if response.status_code in {401, 403}:
                raise AuthenticationError(response.status_code, request_id=request_id)
            retry_after = self._retry_after(normalized_headers)
            retryable = response.status_code in _RETRYABLE_STATUSES
            error = CloudApiError(
                response.status_code,
                request_id=request_id,
                retryable=retryable,
                retry_after_seconds=retry_after,
            )
            if retryable and retry_allowed and attempt < self.config.max_attempts:
                self._sleep(self._retry_delay(attempt, retry_after))
                continue
            raise error
        raise AssertionError("unreachable retry state")

    def request_json(
        self,
        method: str,
        endpoint: str,
        *,
        payload: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        request_id: str | None = None,
        auth_provider: AuthProvider | None = None,
    ) -> Any:
        body = _strict_json_bytes(payload) if payload is not None else None
        response = self.request(
            method,
            endpoint,
            body=body,
            content_type="application/json" if body is not None else None,
            idempotency_key=idempotency_key,
            request_id=request_id,
            auth_provider=auth_provider,
        )
        content_type = response.headers.get("content-type")
        if response.body and content_type:
            media_type = content_type.partition(";")[0].strip().lower()
            if media_type != "application/json" and not media_type.endswith("+json"):
                raise ProtocolError("cloud API declared a non-JSON response")
        return response.json()

    def post_json(
        self,
        endpoint: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str | None = None,
        request_id: str | None = None,
        auth_provider: AuthProvider | None = None,
    ) -> Any:
        return self.request_json(
            "POST",
            endpoint,
            payload=payload,
            idempotency_key=idempotency_key or str(uuid4()),
            request_id=request_id,
            auth_provider=auth_provider,
        )

    def enroll(self, endpoint: Mapping[str, Any], enrollment_auth: AuthProvider) -> Any:
        return self.post_json(
            self.config.routes.enrollment_path,
            endpoint,
            auth_provider=enrollment_auth,
        )

    def submit_scan(self, result: Mapping[str, Any], *, idempotency_key: str) -> Any:
        return self.post_json(
            self.config.routes.scan_submit_path,
            result,
            idempotency_key=idempotency_key,
        )

    def get_scan(self, scan_id: str) -> Any:
        safe_id = urllib.parse.quote(scan_id, safe="")
        path = self.config.routes.scan_lookup_path_template.format(scan_id=safe_id)
        return self.request_json("GET", path)

    def fetch_policies(self) -> Any:
        return self.request_json("GET", self.config.routes.policies_path)

    def heartbeat(self, payload: Mapping[str, Any], *, idempotency_key: str) -> Any:
        return self.post_json(
            self.config.routes.heartbeat_path,
            payload,
            idempotency_key=idempotency_key,
        )

    def submit_attack_surface_job(self, payload: Mapping[str, Any], *, idempotency_key: str) -> Any:
        return self.post_json(
            self.config.routes.attack_surface_jobs_path,
            payload,
            idempotency_key=idempotency_key,
        )
