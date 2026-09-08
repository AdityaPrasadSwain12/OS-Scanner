"""Small validation helpers shared by tool adapters."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value: object, *, maximum: int = 4096) -> str:
    text = str(value) if value is not None else ""
    text = _CONTROL_CHARACTERS.sub("", text).replace("\r", " ").replace("\n", " ").strip()
    return text[:maximum]


def parse_json_document(output: str, *, max_chars: int = 10 * 1024 * 1024) -> Any:
    if len(output) > max_chars:
        raise ValueError("JSON response exceeds the adapter limit")
    try:
        return json.loads(output)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("tool returned invalid JSON") from exc


def read_bounded_text(
    path: Path,
    *,
    max_bytes: int,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> str:
    """Read at most ``max_bytes`` from an external-tool-owned result file."""

    if not 1_024 <= max_bytes <= 100 * 1024 * 1024:
        raise ValueError("text file limit must be between 1 KiB and 100 MiB")
    if not path.is_file():
        raise ValueError("tool result is not a regular file")
    with path.open("rb") as handle:
        payload = handle.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError("tool result exceeds the configured size limit")
    return payload.decode(encoding, errors=errors)


def approved_local_path(
    source: str | Path,
    approved_roots: tuple[Path, ...],
    *,
    require_file: bool = False,
) -> Path:
    if not approved_roots:
        raise PermissionError("no local source roots have been approved")
    raw = Path(source).expanduser()
    try:
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("source does not resolve to an existing local path") from exc
    if require_file and not resolved.is_file():
        raise ValueError("source must be a regular file")
    if not require_file and not (resolved.is_file() or resolved.is_dir()):
        raise ValueError("source must be a regular file or directory")
    if not any(resolved == root or resolved.is_relative_to(root) for root in approved_roots):
        raise PermissionError("source is outside the approved local roots")
    return resolved
