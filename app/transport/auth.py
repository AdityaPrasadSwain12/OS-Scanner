"""Authentication-provider boundary; credentials never live in client config."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .errors import TransportConfigurationError


@dataclass(frozen=True, slots=True)
class RequestAuthContext:
    method: str
    url: str
    request_id: str


@runtime_checkable
class AuthProvider(Protocol):
    def authorization_headers(self, context: RequestAuthContext) -> Mapping[str, str]: ...


class AnonymousAuthProvider:
    def authorization_headers(self, context: RequestAuthContext) -> Mapping[str, str]:
        del context
        return {}


class BearerTokenAuthProvider:
    """Bearer authentication backed by a value or a just-in-time token callback."""

    def __init__(self, token: str | Callable[[], str]) -> None:
        self._token = token
        if isinstance(token, str):
            self._validate(token)

    @staticmethod
    def _validate(token: object) -> str:
        if not isinstance(token, str) or not token:
            raise TransportConfigurationError("authentication token is empty")
        if len(token) > 16_384:
            raise TransportConfigurationError("authentication token is unexpectedly large")
        if any(ord(character) < 33 or ord(character) == 127 for character in token):
            raise TransportConfigurationError("authentication token contains invalid characters")
        return token

    def authorization_headers(self, context: RequestAuthContext) -> Mapping[str, str]:
        del context
        value = self._token() if callable(self._token) else self._token
        return {"Authorization": f"Bearer {self._validate(value)}"}
