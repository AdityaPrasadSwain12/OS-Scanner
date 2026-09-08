"""Canonical JSON serialization for endpoint assessment artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.models.assessment import CanonicalAssessmentReport

from .json_report import serialize_report

_MAX_REPORT_BYTES = 100 * 1024 * 1024
_UNORDERED_ARRAY_KEYS = frozenset({"aliases", "groups", "tags"})


@dataclass(frozen=True, slots=True)
class SerializedAssessment:
    """The exact JSON bytes and digest consumed by downstream renderers."""

    content: bytes
    sha256: str


def _canonicalize_unordered_arrays(
    value: Any,
    *,
    parent_key: str | None = None,
) -> Any:
    if isinstance(value, dict):
        return {
            key: _canonicalize_unordered_arrays(child, parent_key=key)
            for key, child in value.items()
        }
    if isinstance(value, list):
        children = [_canonicalize_unordered_arrays(child) for child in value]
        if parent_key in _UNORDERED_ARRAY_KEYS:
            return sorted(
                children,
                key=lambda item: json.dumps(
                    item,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
        return children
    return value


def validate_canonical_assessment(
    report: CanonicalAssessmentReport | object,
) -> CanonicalAssessmentReport:
    """Revalidate copied or decoded data before it crosses a report boundary."""

    payload: object
    if isinstance(report, CanonicalAssessmentReport):
        payload = report.model_dump(mode="python", exclude_none=False)
    else:
        payload = report
    return CanonicalAssessmentReport.model_validate(payload)


def serialize_canonical_assessment(
    report: CanonicalAssessmentReport | object,
    *,
    max_bytes: int = _MAX_REPORT_BYTES,
) -> SerializedAssessment:
    """Serialize the strict model once; JSON, PDF, and integrity checks share it."""

    validated = validate_canonical_assessment(report)
    payload = _canonicalize_unordered_arrays(
        validated.model_dump(mode="json", exclude_none=True)
    )
    content = serialize_report(payload, max_bytes=max_bytes)
    return SerializedAssessment(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


class CanonicalAssessmentJsonWriter:
    """Atomically persist a validated canonical assessment with owner-only access."""

    def __init__(self, *, max_bytes: int = _MAX_REPORT_BYTES) -> None:
        if max_bytes < 1 or max_bytes > 1024 * 1024 * 1024:
            raise ValueError("max_bytes must be between 1 byte and 1 GiB")
        self.max_bytes = max_bytes

    @staticmethod
    def validate_destination(output_path: str | os.PathLike[str]) -> Path:
        raw = os.fspath(output_path)
        if not raw or "\x00" in raw:
            raise ValueError("assessment output path is invalid")
        candidate = Path(raw).expanduser()
        if candidate.suffix.casefold() != ".json":
            raise ValueError("assessment output must use a .json extension")
        if len(candidate.name) > 240 or candidate.name in {".json", "..json"}:
            raise ValueError("assessment output filename is invalid")
        return candidate.parent.resolve(strict=False) / candidate.name

    def write(
        self,
        report: CanonicalAssessmentReport | object,
        output_path: str | os.PathLike[str],
    ) -> Path:
        destination = self.validate_destination(output_path)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.is_symlink():
            raise ValueError("assessment output cannot replace a symbolic link")
        if destination.exists() and not destination.is_file():
            raise ValueError("assessment output destination is not a regular file")
        artifact = serialize_canonical_assessment(report, max_bytes=self.max_bytes)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.stem}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary = Path(temporary_name)
        try:
            os.chmod(temporary, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(artifact.content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
            if os.name != "nt":
                directory_descriptor = os.open(destination.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
        return destination


def write_canonical_assessment_json(
    report: CanonicalAssessmentReport | object,
    output_path: str | os.PathLike[str],
    *,
    max_bytes: int = _MAX_REPORT_BYTES,
) -> Path:
    return CanonicalAssessmentJsonWriter(max_bytes=max_bytes).write(report, output_path)


__all__ = [
    "CanonicalAssessmentJsonWriter",
    "SerializedAssessment",
    "serialize_canonical_assessment",
    "validate_canonical_assessment",
    "write_canonical_assessment_json",
]
