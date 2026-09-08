"""Bounded, duplicate-key-safe job ingestion for the cloud/CLI boundary."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.models import ScanJob


class JobValidationError(ValueError):
    """A job is malformed, oversized, ambiguous, or unauthorized."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JobValidationError(f"duplicate JSON property: {key}")
        result[key] = value
    return result


def load_job_json(document: str | bytes, *, max_bytes: int = 1024 * 1024) -> ScanJob:
    if max_bytes < 1024:
        raise ValueError("max_bytes must be at least 1024")
    encoded = document.encode("utf-8") if isinstance(document, str) else document
    if len(encoded) > max_bytes:
        raise JobValidationError("scan job exceeds the maximum accepted size")
    try:
        text = encoded.decode("utf-8", errors="strict")
        payload = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                JobValidationError(f"non-finite JSON number is forbidden: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise JobValidationError("scan job is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise JobValidationError("scan job must be a JSON object")
    try:
        return ScanJob.model_validate(payload)
    except ValidationError as exc:
        raise JobValidationError(f"scan job validation failed: {exc.errors()[0]['msg']}") from exc


def load_job_file(path: Path, *, max_bytes: int = 1024 * 1024) -> ScanJob:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file() or resolved.stat().st_size > max_bytes:
        raise JobValidationError("job path is not a bounded regular file")
    return load_job_json(resolved.read_bytes(), max_bytes=max_bytes)

