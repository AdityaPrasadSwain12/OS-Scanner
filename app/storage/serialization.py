"""Deterministic and strict JSON helpers used by durable records."""

from __future__ import annotations

import base64
import dataclasses
import json
import re
from datetime import UTC, date, datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

_ERROR_SECRET = re.compile(
    r"(?i)(\b(?:authorization|password|passwd|token|api[_-]?key|client[_-]?secret)"
    r"\b\s*[:=]\s*)(?:bearer\s+|basic\s+)?[^\s,;]+"
)
_ERROR_BEARER = re.compile(r"(?i)(\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+")
_ERROR_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)


def _json_default(value: Any) -> Any:
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json")
    if not isinstance(value, type) and dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, (Enum, UUID, Path)):
        return str(value.value if isinstance(value, Enum) else value)
    if isinstance(value, bytes):
        return {"$binary": base64.b64encode(value).decode("ascii")}
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def canonical_json(value: Any) -> str:
    """Return stable JSON and reject non-standard NaN/Infinity values."""

    return json.dumps(
        value,
        default=_json_default,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def parse_json(value: str | bytes | bytearray) -> Any:
    return json.loads(value)


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def clean_identifier(value: object, field: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    candidate = value.strip()
    if not candidate:
        raise ValueError(f"{field} must not be empty")
    if len(candidate) > max_length:
        raise ValueError(f"{field} is longer than {max_length} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
        raise ValueError(f"{field} contains control characters")
    return candidate


def clean_error(value: object, *, max_length: int = 1024) -> str:
    """Keep queue diagnostics single-line and bounded."""

    text = str(value)
    text = _ERROR_SECRET.sub(r"\1[REDACTED]", text)
    text = _ERROR_BEARER.sub(r"\1[REDACTED]", text)
    text = _ERROR_JWT.sub("[REDACTED]", text)
    text = text.replace("\r", " ").replace("\n", " ")
    text = "".join(character if ord(character) >= 32 else " " for character in text)
    return text[:max_length]
