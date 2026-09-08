"""Credential value objects and protected persistence implementations."""

from __future__ import annotations

import base64
import ctypes
import importlib
import json
import os
import sys
import tempfile
import threading
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, Protocol, runtime_checkable

from .errors import CredentialStorageError


def _utc_datetime(value: object, field_name: str) -> datetime:
    if isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(float(value), tz=UTC)
    elif isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"{field_name} is not a valid ISO-8601 timestamp") from exc
    else:
        raise TypeError(f"{field_name} must be a timestamp")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _validate_secret(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must not be empty")
    if len(value) > 16_384:
        raise ValueError(f"{field_name} is unexpectedly large")
    if any(ord(character) < 33 or ord(character) == 127 for character in value):
        raise ValueError(f"{field_name} contains invalid characters")
    return value


@dataclass(frozen=True, slots=True)
class EndpointCredential:
    endpoint_id: str
    access_token: str = field(repr=False)
    issued_at: datetime
    expires_at: datetime
    refresh_token: str | None = field(default=None, repr=False)
    credential_id: str | None = None
    generation: int = 1

    def __post_init__(self) -> None:
        if (
            not self.endpoint_id
            or len(self.endpoint_id) > 256
            or any(ord(character) < 33 or ord(character) == 127 for character in self.endpoint_id)
        ):
            raise ValueError("endpoint_id is invalid")
        _validate_secret(self.access_token, "access_token")
        if self.refresh_token is not None:
            _validate_secret(self.refresh_token, "refresh_token")
        issued = _utc_datetime(self.issued_at, "issued_at")
        expires = _utc_datetime(self.expires_at, "expires_at")
        if expires <= issued:
            raise ValueError("credential expiration must follow issue time")
        if not 1 <= self.generation <= 2_147_483_647:
            raise ValueError("credential generation is invalid")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any], *, expected_endpoint_id: str | None = None
    ) -> EndpointCredential:
        endpoint_id = value.get("endpoint_id") or expected_endpoint_id
        if not isinstance(endpoint_id, str):
            raise ValueError("credential response is missing endpoint_id")
        if expected_endpoint_id and endpoint_id != expected_endpoint_id:
            raise ValueError("credential response endpoint_id does not match request")
        return cls(
            endpoint_id=endpoint_id,
            access_token=_validate_secret(
                value.get("access_token", value.get("token")), "access_token"
            ),
            refresh_token=(
                _validate_secret(value["refresh_token"], "refresh_token")
                if value.get("refresh_token") is not None
                else None
            ),
            issued_at=_utc_datetime(value.get("issued_at"), "issued_at"),
            expires_at=_utc_datetime(value.get("expires_at"), "expires_at"),
            credential_id=(str(value["credential_id"]) if value.get("credential_id") else None),
            generation=int(value.get("generation", 1)),
        )

    def as_mapping(self) -> dict[str, Any]:
        value = asdict(self)
        value["issued_at"] = self.issued_at.isoformat().replace("+00:00", "Z")
        value["expires_at"] = self.expires_at.isoformat().replace("+00:00", "Z")
        return value

    def is_expired(self, *, now: datetime | None = None, margin_seconds: float = 0) -> bool:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        return current.timestamp() + margin_seconds >= self.expires_at.timestamp()


@runtime_checkable
class CredentialStore(Protocol):
    def load(self, endpoint_id: str) -> EndpointCredential | None: ...

    def save(self, credential: EndpointCredential) -> None: ...

    def delete(self, endpoint_id: str) -> bool: ...


@runtime_checkable
class SecretProtector(Protocol):
    """Boundary for DPAPI, Keychain, libsecret, HSM, or enterprise vaults."""

    def protect(self, plaintext: bytes) -> bytes: ...

    def unprotect(self, ciphertext: bytes) -> bytes: ...


class InMemoryCredentialStore:
    """Ephemeral store useful for short-lived agents and tests."""

    def __init__(self) -> None:
        self._credentials: dict[str, EndpointCredential] = {}
        self._lock = threading.RLock()

    def load(self, endpoint_id: str) -> EndpointCredential | None:
        with self._lock:
            return self._credentials.get(endpoint_id)

    def save(self, credential: EndpointCredential) -> None:
        with self._lock:
            self._credentials[credential.endpoint_id] = credential

    def delete(self, endpoint_id: str) -> bool:
        with self._lock:
            return self._credentials.pop(endpoint_id, None) is not None


class OSKeyringCredentialStore:
    """Store credentials in the service account's native OS keyring.

    The required ``keyring`` package selects Windows Credential Locker, macOS
    Keychain, Secret Service, or KWallet. Backends that report no usable
    priority—or whose name indicates a null/plaintext backend—are rejected so
    deployment errors cannot silently downgrade credential protection.
    """

    def __init__(
        self,
        *,
        service_name: str = "endpoint-security-scanner",
        backend: Any | None = None,
    ) -> None:
        if not service_name or len(service_name) > 256:
            raise ValueError("keyring service name is invalid")
        try:
            keyring = importlib.import_module("keyring")
            selected = backend or keyring.get_keyring()
        except Exception as exc:
            raise CredentialStorageError("operating-system keyring is unavailable") from exc
        backend_name = f"{type(selected).__module__}.{type(selected).__name__}".casefold()
        try:
            priority = float(getattr(selected, "priority", 0))
        except (TypeError, ValueError) as exc:
            raise CredentialStorageError("operating-system keyring backend is invalid") from exc
        forbidden_backends = ("fail", "null", "plaintext")
        if priority <= 0 or any(name in backend_name for name in forbidden_backends):
            raise CredentialStorageError("no secure operating-system keyring backend is active")
        self.service_name = service_name
        self._backend = selected
        self._lock = threading.RLock()

    @staticmethod
    def _endpoint_id(value: str) -> str:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 256
            or any(ord(character) < 33 or ord(character) == 127 for character in value)
        ):
            raise ValueError("endpoint_id is invalid")
        return value

    def load(self, endpoint_id: str) -> EndpointCredential | None:
        endpoint_id = self._endpoint_id(endpoint_id)
        try:
            with self._lock:
                encoded = self._backend.get_password(self.service_name, endpoint_id)
        except Exception as exc:
            raise CredentialStorageError("credential cannot be read from the OS keyring") from exc
        if encoded is None:
            return None
        if not isinstance(encoded, str) or len(encoded) > 128 * 1024:
            raise CredentialStorageError("OS keyring returned invalid credential data")
        try:
            value = json.loads(encoded)
            if not isinstance(value, Mapping):
                raise TypeError("credential entry is not an object")
            return EndpointCredential.from_mapping(value, expected_endpoint_id=endpoint_id)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CredentialStorageError("OS keyring credential data is invalid") from exc

    def save(self, credential: EndpointCredential) -> None:
        encoded = json.dumps(
            credential.as_mapping(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        try:
            with self._lock:
                self._backend.set_password(
                    self.service_name,
                    credential.endpoint_id,
                    encoded,
                )
        except Exception as exc:
            raise CredentialStorageError("credential cannot be stored in the OS keyring") from exc

    def delete(self, endpoint_id: str) -> bool:
        endpoint_id = self._endpoint_id(endpoint_id)
        try:
            with self._lock:
                if self._backend.get_password(self.service_name, endpoint_id) is None:
                    return False
                self._backend.delete_password(self.service_name, endpoint_id)
        except Exception as exc:
            raise CredentialStorageError(
                "credential cannot be deleted from the OS keyring"
            ) from exc
        return True


class ProtectedFileCredentialStore:
    """Atomic credential file whose records must be protected by an OS/vault provider.

    There is intentionally no plaintext protector and no generated local key that
    would merely sit beside the ciphertext. On Windows, ``WindowsDPAPIProtector``
    provides a standard-library-only production implementation. Linux/macOS
    deployments should inject their service-account secret-store adapter.
    """

    _MAX_FILE_BYTES = 4 * 1024 * 1024

    def __init__(self, path: str | os.PathLike[str], protector: SecretProtector) -> None:
        if not isinstance(protector, SecretProtector):
            raise TypeError("protector must implement SecretProtector")
        # Keep the final path component unresolved so a symlink can be rejected.
        self.path = Path(path).expanduser().absolute()
        self.protector = protector
        self._lock = threading.RLock()

    def _read_container(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        if self.path.is_symlink():
            raise CredentialStorageError("credential path cannot be a symbolic link")
        try:
            size = self.path.stat().st_size
            if size > self._MAX_FILE_BYTES:
                raise CredentialStorageError("credential store exceeds size limit")
            raw = self.path.read_bytes()
            document = json.loads(raw.decode("utf-8"))
            if document.get("version") != 1 or not isinstance(document.get("records"), dict):
                raise CredentialStorageError("credential store format is invalid")
            return {str(key): str(value) for key, value in document["records"].items()}
        except CredentialStorageError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
            raise CredentialStorageError("credential store cannot be read") from exc

    def _write_container(self, records: Mapping[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.is_symlink():
            raise CredentialStorageError("credential path cannot be a symbolic link")
        data = json.dumps(
            {"version": 1, "records": records},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        temporary_name: str | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
            )
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            except Exception:
                with suppress(OSError):
                    os.close(descriptor)
                raise
            os.replace(temporary_name, self.path)
            temporary_name = None
            if os.name != "nt":
                self.path.chmod(0o600)
        except OSError as exc:
            raise CredentialStorageError("credential store cannot be written") from exc
        finally:
            self._remove_temporary(temporary_name)

    @staticmethod
    def _remove_temporary(temporary_name: str | None) -> None:
        if temporary_name is not None:
            with suppress(OSError):
                os.unlink(temporary_name)

    def load(self, endpoint_id: str) -> EndpointCredential | None:
        with self._lock:
            encoded = self._read_container().get(endpoint_id)
            if encoded is None:
                return None
            try:
                ciphertext = base64.b64decode(encoded, validate=True)
                plaintext = self.protector.unprotect(ciphertext)
                value = json.loads(plaintext.decode("utf-8"))
                credential = EndpointCredential.from_mapping(
                    value, expected_endpoint_id=endpoint_id
                )
            except Exception as exc:
                raise CredentialStorageError("stored credential cannot be decrypted") from exc
            return credential

    def save(self, credential: EndpointCredential) -> None:
        plaintext = json.dumps(
            credential.as_mapping(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            protected = self.protector.protect(plaintext)
            if not isinstance(protected, bytes) or not protected:
                raise CredentialStorageError("protector returned invalid ciphertext")
        except CredentialStorageError:
            raise
        except Exception as exc:
            raise CredentialStorageError("credential cannot be encrypted") from exc
        with self._lock:
            records = self._read_container()
            records[credential.endpoint_id] = base64.b64encode(protected).decode("ascii")
            self._write_container(records)

    def delete(self, endpoint_id: str) -> bool:
        with self._lock:
            records = self._read_container()
            if endpoint_id not in records:
                return False
            del records[endpoint_id]
            self._write_container(records)
            return True


class WindowsDPAPIProtector:
    """Protect secrets to the Windows service/user identity using DPAPI."""

    _CRYPTPROTECT_UI_FORBIDDEN = 0x1

    class _DataBlob(ctypes.Structure):
        _fields_: ClassVar[list[tuple[str, Any]]] = [
            ("cbData", ctypes.c_ulong),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    def __init__(self, *, description: str = "Endpoint Scanner Credential") -> None:
        if sys.platform != "win32":
            raise CredentialStorageError("Windows DPAPI is unavailable on this platform")
        self.description = description
        self._crypt32 = ctypes.windll.crypt32
        self._kernel32 = ctypes.windll.kernel32
        blob_pointer = ctypes.POINTER(self._DataBlob)
        self._crypt32.CryptProtectData.argtypes = [
            blob_pointer,
            ctypes.c_wchar_p,
            blob_pointer,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
            blob_pointer,
        ]
        self._crypt32.CryptProtectData.restype = ctypes.c_int
        self._crypt32.CryptUnprotectData.argtypes = [
            blob_pointer,
            ctypes.POINTER(ctypes.c_wchar_p),
            blob_pointer,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
            blob_pointer,
        ]
        self._crypt32.CryptUnprotectData.restype = ctypes.c_int
        self._kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self._kernel32.LocalFree.restype = ctypes.c_void_p

    @classmethod
    def _blob(cls, value: bytes) -> tuple[WindowsDPAPIProtector._DataBlob, Any]:
        buffer = ctypes.create_string_buffer(value, len(value))
        blob = cls._DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
        return blob, buffer

    def _transform(self, value: bytes, *, protect: bool) -> bytes:
        if not value:
            raise CredentialStorageError("DPAPI input cannot be empty")
        input_blob, keepalive = self._blob(value)
        output_blob = self._DataBlob()
        if protect:
            success = self._crypt32.CryptProtectData(
                ctypes.byref(input_blob),
                self.description,
                None,
                None,
                None,
                self._CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
        else:
            success = self._crypt32.CryptUnprotectData(
                ctypes.byref(input_blob),
                None,
                None,
                None,
                None,
                self._CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
        # Keep the input buffer alive until CryptProtectData/UnprotectData returns.
        del keepalive
        if not success:
            raise CredentialStorageError("Windows DPAPI operation failed")
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            self._kernel32.LocalFree(ctypes.cast(output_blob.pbData, ctypes.c_void_p))

    def protect(self, plaintext: bytes) -> bytes:
        return self._transform(plaintext, protect=True)

    def unprotect(self, ciphertext: bytes) -> bytes:
        return self._transform(ciphertext, protect=False)
