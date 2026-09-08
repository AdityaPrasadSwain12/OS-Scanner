from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.enrollment import (
    CredentialExpiredError,
    CredentialStorageError,
    EndpointCredential,
    EnrollmentConfig,
    EnrollmentService,
    InMemoryCredentialStore,
    OSKeyringCredentialStore,
    ProtectedFileCredentialStore,
    StoredCredentialAuthProvider,
)
from app.transport import RequestAuthContext


class FakeProtector:
    def protect(self, plaintext: bytes) -> bytes:
        return b"protected:" + plaintext[::-1]

    def unprotect(self, ciphertext: bytes) -> bytes:
        if not ciphertext.startswith(b"protected:"):
            raise ValueError("invalid ciphertext")
        return ciphertext[len(b"protected:") :][::-1]


class FakeEnrollmentApi:
    def __init__(self, responses: list[Mapping[str, Any]]) -> None:
        self.responses = iter(responses)
        self.calls: list[dict[str, Any]] = []

    def post_json(
        self,
        endpoint: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str | None = None,
        request_id: str | None = None,
        auth_provider: Any = None,
    ) -> Any:
        headers = auth_provider.authorization_headers(
            RequestAuthContext("POST", f"https://cloud.test{endpoint}", request_id or "r1")
        )
        self.calls.append(
            {
                "endpoint": endpoint,
                "payload": dict(payload),
                "idempotency_key": idempotency_key,
                "headers": headers,
            }
        )
        return next(self.responses)


def _credential_payload(*, generation: int = 1, access_value: str | None = None) -> dict[str, Any]:
    access_value = access_value or "access-one"
    return {
        "endpoint_id": "endpoint-1",
        "access_token": access_value,
        "refresh_token": f"refresh-{generation}",
        "credential_id": f"credential-{generation}",
        "generation": generation,
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2027-01-01T00:00:00Z",
    }


def test_enrollment_token_is_ephemeral_and_credential_is_stored() -> None:
    api = FakeEnrollmentApi([{"credential": _credential_payload()}])
    store = InMemoryCredentialStore()
    service = EnrollmentService(api, store)

    credential = service.enroll(
        "temporary-enrollment-token",
        {"hostname": "host-1", "platform": "linux"},
        idempotency_key="enroll:host-1",
    )

    assert credential.endpoint_id == "endpoint-1"
    assert store.load("endpoint-1") == credential
    assert api.calls[0]["headers"] == {"Authorization": "Bearer temporary-enrollment-token"}
    assert "temporary-enrollment-token" not in json.dumps(api.calls[0]["payload"])


def test_protected_file_store_never_writes_plaintext_secret(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    store = ProtectedFileCredentialStore(path, FakeProtector())
    credential = EndpointCredential.from_mapping(_credential_payload())
    store.save(credential)

    raw = path.read_bytes()
    assert b"access-one" not in raw
    assert b"refresh-1" not in raw
    assert store.load("endpoint-1") == credential
    replacement = EndpointCredential.from_mapping(
        _credential_payload(generation=2, access_value="access-two")
    )
    store.save(replacement)
    assert store.load("endpoint-1") == replacement
    assert store.delete("endpoint-1") is True
    assert store.load("endpoint-1") is None


def test_rotation_authenticates_with_current_credential_and_advances_generation() -> None:
    store = InMemoryCredentialStore()
    store.save(EndpointCredential.from_mapping(_credential_payload()))
    api = FakeEnrollmentApi(
        [{"credential": _credential_payload(generation=2, access_value="access-two")}]
    )
    service = EnrollmentService(api, store, clock=lambda: 1_780_000_000)

    rotated = service.rotate("endpoint-1", idempotency_key="rotate:1")
    assert rotated.generation == 2
    assert api.calls[0]["headers"] == {"Authorization": "Bearer access-one"}
    assert api.calls[0]["payload"] == {
        "endpoint_id": "endpoint-1",
        "generation": 1,
        "credential_id": "credential-1",
    }
    assert store.load("endpoint-1") == rotated


def test_enrollment_service_uses_custom_enrollment_and_rotation_routes() -> None:
    api = FakeEnrollmentApi(
        [
            {"credential": _credential_payload()},
            {"credential": _credential_payload(generation=2, access_value="access-two")},
        ]
    )
    store = InMemoryCredentialStore()
    service = EnrollmentService(
        api,
        store,
        EnrollmentConfig(
            enrollment_path="/tenant/enroll",
            rotation_path_template="/tenant/endpoints/{endpoint_id}/rotate",
        ),
        clock=lambda: 1_780_000_000,
    )

    service.enroll("temporary-enrollment-token", {"hostname": "host-1"})
    service.rotate("endpoint-1")

    assert [call["endpoint"] for call in api.calls] == [
        "/tenant/enroll",
        "/tenant/endpoints/endpoint-1/rotate",
    ]


def test_stored_auth_provider_rejects_expired_credentials() -> None:
    now = datetime.now(UTC)
    expired = EndpointCredential(
        endpoint_id="endpoint-1",
        access_token="expired-access-token",
        issued_at=now - timedelta(days=2),
        expires_at=now - timedelta(days=1),
    )
    store = InMemoryCredentialStore()
    store.save(expired)
    provider = StoredCredentialAuthProvider(store, "endpoint-1", clock=lambda: now.timestamp())
    with pytest.raises(CredentialExpiredError):
        provider.authorization_headers(
            RequestAuthContext("GET", "https://cloud.test/api/v1/policies", "r1")
        )


class FakeSecureBackend:
    priority = 1

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        del self.values[(service, username)]


def test_os_keyring_store_round_trips_and_deletes_credentials() -> None:
    backend = FakeSecureBackend()
    store = OSKeyringCredentialStore(backend=backend)
    credential = EndpointCredential.from_mapping(_credential_payload())

    assert store.load("endpoint-1") is None
    store.save(credential)
    assert store.load("endpoint-1") == credential
    assert store.delete("missing") is False
    assert store.delete("endpoint-1") is True
    assert store.load("endpoint-1") is None


@pytest.mark.parametrize("name", ["NullBackend", "PlaintextBackend", "FailBackend"])
def test_os_keyring_store_rejects_insecure_backend_names(name: str) -> None:
    backend_type = type(name, (FakeSecureBackend,), {})
    with pytest.raises(CredentialStorageError, match="no secure"):
        OSKeyringCredentialStore(backend=backend_type())


def test_os_keyring_store_rejects_invalid_service_backend_and_records() -> None:
    with pytest.raises(ValueError, match="service name"):
        OSKeyringCredentialStore(service_name="")

    backend = FakeSecureBackend()
    backend.priority = "invalid"  # type: ignore[assignment]
    with pytest.raises(CredentialStorageError, match="backend is invalid"):
        OSKeyringCredentialStore(backend=backend)

    backend = FakeSecureBackend()
    backend.values[("endpoint-security-scanner", "endpoint-1")] = "not-json"
    store = OSKeyringCredentialStore(backend=backend)
    with pytest.raises(CredentialStorageError, match="data is invalid"):
        store.load("endpoint-1")
    with pytest.raises(ValueError, match="endpoint_id"):
        store.load("bad endpoint")


class BrokenSecureBackend(FakeSecureBackend):
    def get_password(self, service: str, username: str) -> str | None:
        del service, username
        raise RuntimeError("keyring unavailable")

    def set_password(self, service: str, username: str, password: str) -> None:
        del service, username, password
        raise RuntimeError("keyring unavailable")


def test_os_keyring_store_wraps_backend_failures_without_leaking_secret() -> None:
    store = OSKeyringCredentialStore(backend=BrokenSecureBackend())
    with pytest.raises(CredentialStorageError, match="cannot be read") as read_error:
        store.load("endpoint-1")
    with pytest.raises(CredentialStorageError, match="cannot be stored") as write_error:
        store.save(EndpointCredential.from_mapping(_credential_payload()))
    assert "access-one" not in str(read_error.value)
    assert "access-one" not in str(write_error.value)
