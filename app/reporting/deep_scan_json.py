"""Atomic JSON-only persistence for a combined deep-scan assessment."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from app.models.deep_scan import DeepScanReport
from app.security.redaction import redact_text, redact_value

from .json_report import serialize_report

_UNORDERED_ARRAY_KEYS = frozenset({"aliases", "groups", "tags"})


def _canonicalize_unordered_arrays(value: object, *, parent_key: str | None = None) -> object:
    if isinstance(value, dict):
        return {
            key: _canonicalize_unordered_arrays(child, parent_key=key)
            for key, child in value.items()
        }
    if isinstance(value, list):
        children = [_canonicalize_unordered_arrays(child, parent_key=None) for child in value]
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


def _redact_report(value: object) -> object:
    # Deep endpoint inventories can legitimately exceed the generic telemetry
    # redactor's small default node budget.  Collection and report byte limits
    # remain the primary resource bounds here.
    redacted = redact_value(value, max_depth=24, max_nodes=2_000_000)
    # The generic redactor correctly treats arbitrary ``authorization`` keys as
    # sensitive, but these exact fields are bounded report-model identifiers,
    # not bearer credentials. Restore their already validated and text-redacted
    # values so the persisted evidence remains auditable.
    if isinstance(value, dict) and isinstance(redacted, dict):
        _restore_authorization_audit_fields(value, redacted)
    return _canonicalize_unordered_arrays(redacted)


def _restore_text_field(
    source: dict[object, object],
    destination: dict[object, object],
    key: str,
    *,
    max_length: int,
) -> None:
    raw = source.get(key)
    if isinstance(raw, str):
        destination[key] = redact_text(raw, max_length=max_length)


def _restore_authorization_audit_fields(
    source: dict[object, object],
    destination: dict[object, object],
) -> None:
    _restore_text_field(source, destination, "authorization_scope_id", max_length=128)
    source_audit = source.get("audit_context")
    destination_audit = destination.get("audit_context")
    if isinstance(source_audit, dict) and isinstance(destination_audit, dict):
        _restore_text_field(
            source_audit,
            destination_audit,
            "authorization_scope_id",
            max_length=128,
        )
        _restore_text_field(
            source_audit,
            destination_audit,
            "authorization_reference",
            max_length=512,
        )
    source_endpoint = source.get("endpoint_scan")
    destination_endpoint = destination.get("endpoint_scan")
    if isinstance(source_endpoint, dict) and isinstance(destination_endpoint, dict):
        _restore_text_field(
            source_endpoint,
            destination_endpoint,
            "authorization_scope_id",
            max_length=128,
        )
    source_attacks = source.get("attack_surface_scans")
    destination_attacks = destination.get("attack_surface_scans")
    if isinstance(source_attacks, list) and isinstance(destination_attacks, list):
        for source_scan, destination_scan in zip(
            source_attacks,
            destination_attacks,
            strict=True,
        ):
            if isinstance(source_scan, dict) and isinstance(destination_scan, dict):
                _restore_text_field(
                    source_scan,
                    destination_scan,
                    "authorization_scope_id",
                    max_length=128,
                )


class DeepScanJsonWriter:
    """Write exactly one bounded UTF-8 JSON report using atomic replacement."""

    def __init__(self, *, max_bytes: int = 50 * 1024 * 1024) -> None:
        if max_bytes < 1 or max_bytes > 1024 * 1024 * 1024:
            raise ValueError("max_bytes must be between 1 byte and 1 GiB")
        self.max_bytes = max_bytes

    @staticmethod
    def validate_destination(output_path: str | os.PathLike[str]) -> Path:
        raw = os.fspath(output_path)
        if not raw or "\x00" in raw:
            raise ValueError("deep-scan output path is invalid")
        candidate = Path(raw).expanduser()
        if candidate.suffix.casefold() != ".json":
            raise ValueError("deep-scan output must use a .json extension")
        if len(candidate.name) > 240 or candidate.name in {".json", "..json"}:
            raise ValueError("deep-scan output filename is invalid")
        parent = candidate.parent.resolve(strict=False)
        return parent / candidate.name

    def write(
        self,
        report: DeepScanReport,
        output_path: str | os.PathLike[str],
    ) -> Path:
        destination = self.validate_destination(output_path)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.is_symlink():
            raise ValueError("deep-scan output cannot replace a symbolic link")
        if destination.exists() and not destination.is_file():
            raise ValueError("deep-scan output destination is not a regular file")

        body = serialize_report(
            report,
            max_bytes=self.max_bytes,
            redactor=_redact_report,
        )
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
                handle.write(body)
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


def write_deep_scan_json(
    report: DeepScanReport,
    output_path: str | os.PathLike[str],
    *,
    max_bytes: int = 50 * 1024 * 1024,
) -> Path:
    """Convenience API used by local commands and future service integrations."""

    return DeepScanJsonWriter(max_bytes=max_bytes).write(report, output_path)


__all__ = ["DeepScanJsonWriter", "write_deep_scan_json"]
