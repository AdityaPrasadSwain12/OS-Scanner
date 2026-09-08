"""Deterministic and size-bounded JSON reporting."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol


class ModelDumpable(Protocol):
    """Subset of Pydantic's serialization API needed by the reporter."""

    def model_dump(self, *, mode: str = "python", exclude_none: bool = False) -> dict[str, Any]: ...


class ReportTooLargeError(ValueError):
    """Raised before a report larger than the configured limit is persisted."""


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def _as_mapping(report: ModelDumpable | Mapping[str, Any]) -> Mapping[str, Any]:
    if hasattr(report, "model_dump"):
        return report.model_dump(mode="json", exclude_none=True)
    return report


def serialize_report(
    report: ModelDumpable | Mapping[str, Any],
    *,
    max_bytes: int = 50 * 1024 * 1024,
    redactor: Callable[[Any], Any] | None = None,
) -> bytes:
    """Serialize a report predictably, applying a final privacy redaction hook."""

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    payload: Any = dict(_as_mapping(report))
    if redactor is not None:
        payload = redactor(payload)
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > max_bytes:
        raise ReportTooLargeError(f"report is {len(encoded)} bytes; maximum is {max_bytes}")
    return encoded


class AtomicReportWriter:
    """Write local reports atomically with owner-only permissions where supported."""

    def __init__(self, directory: Path, *, max_bytes: int = 50 * 1024 * 1024) -> None:
        self.directory = directory.resolve()
        self.max_bytes = max_bytes

    @staticmethod
    def filename_for(scan_id: str) -> str:
        readable_name = _SAFE_NAME.sub("_", scan_id)[:48]
        if not readable_name or readable_name in {".", ".."}:
            raise ValueError("invalid scan_id for report filename")
        # The digest makes the mapping collision-resistant even when two valid
        # identifiers sanitize to the same human-readable prefix (for example,
        # ``scan:1`` and ``scan_1``).
        digest = hashlib.sha256(scan_id.encode("utf-8")).hexdigest()
        return f"{readable_name}--{digest}.json"

    def write(
        self,
        scan_id: str,
        report: ModelDumpable | Mapping[str, Any],
        *,
        redactor: Callable[[Any], Any] | None = None,
    ) -> Path:
        filename = self.filename_for(scan_id)
        safe_name = filename.removesuffix(".json")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination = self.directory / filename
        body = serialize_report(report, max_bytes=self.max_bytes, redactor=redactor)

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{safe_name}.", suffix=".tmp", dir=self.directory
        )
        temporary = Path(temporary_name)
        try:
            os.chmod(temporary, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
        return destination
