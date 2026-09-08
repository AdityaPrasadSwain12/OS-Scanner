"""Transport failure taxonomy used to make safe retry decisions."""

from __future__ import annotations


class TransportError(RuntimeError):
    retryable = False


class TransportConfigurationError(TransportError):
    """The configured URL, TLS context, or request violates security policy."""


class NetworkError(TransportError):
    retryable = True


class TLSVerificationError(TransportError):
    # Certificate rotation, trust-store repair, and clock correction can make a
    # later outbox attempt succeed.  Retries remain bounded by both the HTTP
    # client and the durable queue.
    retryable = True


class ResponseTooLargeError(TransportError):
    retryable = False


class ProtocolError(TransportError):
    retryable = False


class CloudApiError(TransportError):
    def __init__(
        self,
        status_code: int,
        *,
        request_id: str,
        retryable: bool = False,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(f"cloud API returned HTTP {status_code} (request {request_id})")
        self.status_code = status_code
        self.request_id = request_id
        self.retryable = retryable
        self.retry_after_seconds = retry_after_seconds


class AuthenticationError(CloudApiError):
    def __init__(self, status_code: int, *, request_id: str) -> None:
        # Do not retry immediately in CloudApiClient with the same credential.
        # The outbox worker will retry later, allowing the agent's credential
        # rotation path to refresh the authentication material first.
        super().__init__(status_code, request_id=request_id, retryable=True)
