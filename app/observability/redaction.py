"""Bounded recursive redaction for logs, errors, and command metadata."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "proxy_authorization",
        "password",
        "passwd",
        "password_hash",
        "secret",
        "client_secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "session_token",
        "enrollment_token",
        "credential",
        "credentials",
        "cookie",
        "cookies",
        "set_cookie",
        "private_key",
    }
)

_AUTH_PATTERN = re.compile(
    r"(?i)\b(authorization|proxy-authorization)\s*[:=]\s*(?:bearer\s+|basic\s+)?[^\s,;]+"
)
_QUERY_PATTERN = re.compile(
    r"(?i)([?&](?:access_token|refresh_token|token|api_key|apikey|password|secret)=)[^&#\s]*"
)
_ARGUMENT_PATTERN = re.compile(
    r"(?i)(--?(?:password|passwd|token|api-key|apikey|secret)(?:=|\s+))(?:\"[^\"]*\"|'[^']*'|\S+)"
)
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(password|passwd|access_token|refresh_token|api_key|client_secret)\s*=\s*[^\s,;]+"
)
_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


@dataclass(frozen=True, slots=True)
class RedactionConfig:
    replacement: str = "[REDACTED]"
    max_string_length: int = 4096
    max_collection_items: int = 100
    max_depth: int = 12

    def __post_init__(self) -> None:
        if not 64 <= self.max_string_length <= 1_000_000:
            raise ValueError("max_string_length is outside the supported range")
        if not 1 <= self.max_collection_items <= 10_000:
            raise ValueError("max_collection_items is outside the supported range")
        if not 1 <= self.max_depth <= 100:
            raise ValueError("max_depth is outside the supported range")


def _normalized_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")


def _sensitive_key(value: object) -> bool:
    key = _normalized_key(value)
    return (
        key in _SENSITIVE_KEYS
        or key.endswith("_token")
        or key.endswith("_secret")
        or key.endswith("_password")
        or key.endswith("_private_key")
    )


class Redactor:
    def __init__(self, config: RedactionConfig | None = None) -> None:
        self.config = config or RedactionConfig()

    def text(self, value: object) -> str:
        text = str(value)
        replacement = self.config.replacement
        text = _PRIVATE_KEY_PATTERN.sub(replacement, text)
        text = _AUTH_PATTERN.sub(lambda match: f"{match.group(1)}={replacement}", text)
        text = _QUERY_PATTERN.sub(lambda match: f"{match.group(1)}{replacement}", text)
        text = _ARGUMENT_PATTERN.sub(lambda match: f"{match.group(1)}{replacement}", text)
        text = _ASSIGNMENT_PATTERN.sub(lambda match: f"{match.group(1)}={replacement}", text)
        text = _JWT_PATTERN.sub(replacement, text)
        # A JSON formatter escapes these too, but canonical single-line values
        # protect non-JSON handlers and log forwarders from injection.
        text = text.replace("\r", "\\r").replace("\n", "\\n")
        text = text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
        text = "".join(
            character if ord(character) >= 32 and ord(character) != 127 else "?"
            for character in text
        )
        if len(text) > self.config.max_string_length:
            text = f"{text[: self.config.max_string_length]}...[TRUNCATED]"
        return text

    def value(self, value: Any) -> Any:
        return self._value(value, depth=0, seen=set())

    def _value(self, value: Any, *, depth: int, seen: set[int]) -> Any:
        if depth >= self.config.max_depth:
            return "[MAX_DEPTH]"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, bytes):
            return f"[BINARY {len(value)} bytes]"
        if isinstance(value, (Enum, Path)):
            return self.text(value.value if isinstance(value, Enum) else value)
        model_dump = getattr(value, "model_dump", None)
        if callable(model_dump):
            value = model_dump(mode="json")
        if not isinstance(value, type) and dataclasses.is_dataclass(value):
            value = dataclasses.asdict(value)
        track_identity = isinstance(value, (Mapping, list, tuple, set, frozenset))
        identity = id(value)
        if track_identity and identity in seen:
            return "[CYCLE]"
        if track_identity:
            seen.add(identity)
        try:
            if isinstance(value, Mapping):
                mapped_result: dict[str, Any] = {}
                items = list(value.items())
                for key, item in items[: self.config.max_collection_items]:
                    clean_key = self.text(key)
                    mapped_result[clean_key] = (
                        self.config.replacement
                        if _sensitive_key(key)
                        else self._value(item, depth=depth + 1, seen=seen)
                    )
                if len(items) > self.config.max_collection_items:
                    mapped_result["_truncated_items"] = (
                        len(items) - self.config.max_collection_items
                    )
                return mapped_result
            if isinstance(value, (list, tuple, set, frozenset)):
                items = list(value)
                sequence_result = [
                    self._value(item, depth=depth + 1, seen=seen)
                    for item in items[: self.config.max_collection_items]
                ]
                if len(items) > self.config.max_collection_items:
                    sequence_result.append(
                        f"[TRUNCATED {len(items) - self.config.max_collection_items} ITEMS]"
                    )
                return sequence_result
            return self.text(value)
        finally:
            if track_identity:
                seen.discard(identity)


_DEFAULT_REDACTOR = Redactor()


def redact(value: Any) -> Any:
    return _DEFAULT_REDACTOR.value(value)
