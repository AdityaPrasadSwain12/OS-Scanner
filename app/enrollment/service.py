"""Temporary-token enrollment and proactive credential rotation."""

from __future__ import annotations

import time
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import uuid4

from app.security.url_paths import ApiPathValidationError, validate_api_path
from app.transport import AuthProvider, BearerTokenAuthProvider, RequestAuthContext

from .credentials import CredentialStore, EndpointCredential
from .errors import CredentialExpiredError, EnrollmentError, MissingCredentialError


class _CloudEnrollmentApi(Protocol):
    def post_json(
        self,
        endpoint: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str | None = None,
        request_id: str | None = None,
        auth_provider: AuthProvider | None = None,
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class EnrollmentConfig:
    enrollment_path: str = "/api/v1/endpoint/enroll"
    rotation_path_template: str = "/api/v1/endpoints/{endpoint_id}/credentials/rotate"
    rotation_margin_seconds: float = 24 * 60 * 60

    def __post_init__(self) -> None:
        paths: tuple[tuple[str, frozenset[str]], ...] = (
            (self.enrollment_path, frozenset()),
            (self.rotation_path_template, frozenset({"endpoint_id"})),
        )
        for value, expected_placeholders in paths:
            try:
                validate_api_path(
                    value, expected_placeholders=expected_placeholders
                )
            except ApiPathValidationError as exc:
                if exc.kind == "placeholder":
                    raise ValueError(
                        "enrollment API path placeholders are invalid"
                    ) from exc
                raise ValueError(
                    "enrollment API paths must be safe absolute paths"
                ) from exc
        if self.rotation_margin_seconds < 0:
            raise ValueError("rotation_margin_seconds cannot be negative")


class StoredCredentialAuthProvider:
    def __init__(
        self,
        store: CredentialStore,
        endpoint_id: str,
        *,
        expiration_margin_seconds: float = 0,
        clock: Any = time.time,
    ) -> None:
        self.store = store
        self.endpoint_id = endpoint_id
        self.expiration_margin_seconds = expiration_margin_seconds
        self.clock = clock

    def authorization_headers(self, context: RequestAuthContext) -> Mapping[str, str]:
        del context
        credential = self.store.load(self.endpoint_id)
        if credential is None:
            raise MissingCredentialError(
                f"no cloud credential is stored for endpoint {self.endpoint_id}"
            )
        now = datetime.fromtimestamp(float(self.clock()), tz=UTC)
        if credential.is_expired(now=now, margin_seconds=self.expiration_margin_seconds):
            raise CredentialExpiredError(
                f"cloud credential is expired for endpoint {self.endpoint_id}"
            )
        return {"Authorization": f"Bearer {credential.access_token}"}


class EnrollmentService:
    def __init__(
        self,
        api: _CloudEnrollmentApi,
        credential_store: CredentialStore,
        config: EnrollmentConfig | None = None,
        *,
        clock: Any = time.time,
    ) -> None:
        self.api = api
        self.credential_store = credential_store
        self.config = config or EnrollmentConfig()
        self.clock = clock

    @staticmethod
    def _response_credential(
        response: Any, *, expected_endpoint_id: str | None = None
    ) -> EndpointCredential:
        if not isinstance(response, Mapping):
            raise EnrollmentError("enrollment API response must be a JSON object")
        value = response.get("credential", response)
        if not isinstance(value, Mapping):
            raise EnrollmentError("enrollment API response is missing credential")
        try:
            return EndpointCredential.from_mapping(value, expected_endpoint_id=expected_endpoint_id)
        except (TypeError, ValueError) as exc:
            raise EnrollmentError("enrollment API returned an invalid credential") from exc

    def enroll(
        self,
        temporary_token: str,
        endpoint_metadata: Mapping[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> EndpointCredential:
        """Exchange an ephemeral token; the token is never persisted or put in JSON."""

        authentication = BearerTokenAuthProvider(temporary_token)
        response = self.api.post_json(
            self.config.enrollment_path,
            endpoint_metadata,
            idempotency_key=idempotency_key or str(uuid4()),
            auth_provider=authentication,
        )
        credential = self._response_credential(response)
        self.credential_store.save(credential)
        return credential

    def rotate(
        self,
        endpoint_id: str,
        *,
        idempotency_key: str | None = None,
    ) -> EndpointCredential:
        current = self.credential_store.load(endpoint_id)
        if current is None:
            raise MissingCredentialError(
                f"no cloud credential is stored for endpoint {endpoint_id}"
            )
        now = datetime.fromtimestamp(float(self.clock()), tz=UTC)
        if current.is_expired(now=now):
            raise CredentialExpiredError(
                f"cannot rotate expired credential for endpoint {endpoint_id}; re-enroll"
            )
        if not current.credential_id:
            raise EnrollmentError(
                "stored credential has no credential_id and cannot be rotated safely; re-enroll"
            )
        path = self.config.rotation_path_template.format(
            endpoint_id=urllib.parse.quote(endpoint_id, safe="")
        )
        payload: dict[str, Any] = {
            "endpoint_id": endpoint_id,
            "generation": current.generation,
            "credential_id": current.credential_id,
        }
        response = self.api.post_json(
            path,
            payload,
            idempotency_key=idempotency_key or str(uuid4()),
            auth_provider=BearerTokenAuthProvider(current.access_token),
        )
        rotated = self._response_credential(response, expected_endpoint_id=endpoint_id)
        if rotated.generation <= current.generation:
            raise EnrollmentError("rotated credential generation did not advance")
        self.credential_store.save(rotated)
        return rotated

    def needs_rotation(self, endpoint_id: str) -> bool:
        credential = self.credential_store.load(endpoint_id)
        if credential is None:
            raise MissingCredentialError(
                f"no cloud credential is stored for endpoint {endpoint_id}"
            )
        now = datetime.fromtimestamp(float(self.clock()), tz=UTC)
        return credential.is_expired(now=now, margin_seconds=self.config.rotation_margin_seconds)

    def auth_provider(self, endpoint_id: str) -> StoredCredentialAuthProvider:
        return StoredCredentialAuthProvider(self.credential_store, endpoint_id, clock=self.clock)
