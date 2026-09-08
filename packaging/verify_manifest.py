"""Verify release artifacts against a trusted, externally signed manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any

_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate manifest property: {key}")
        result[key] = value
    return result


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _relative_path(value: Any) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("manifest path is not a bounded portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise ValueError(f"unsafe manifest path: {value}")
    return path


def _artifact_paths(root: Path, manifest: Path) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    for candidate in sorted(root.rglob("*")):
        if candidate == manifest:
            continue
        if candidate.is_symlink():
            relative_path = candidate.relative_to(root)
            raise ValueError(f"release tree contains a symbolic link: {relative_path}")
        mode = candidate.stat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            relative_path = candidate.relative_to(root)
            raise ValueError(f"release tree contains a non-regular file: {relative_path}")
        relative_name = candidate.relative_to(root).as_posix()
        artifacts[relative_name] = candidate
    return artifacts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", type=Path)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        root = args.artifacts.resolve(strict=True)
        manifest_input = args.manifest.expanduser().absolute()
        if manifest_input.is_symlink():
            raise ValueError("manifest cannot be a symbolic link")
        manifest = manifest_input.resolve(strict=True)
        if not root.is_dir() or not manifest.is_file():
            raise ValueError("artifact root and manifest must be regular filesystem objects")
        if manifest.stat().st_size > _MAX_MANIFEST_BYTES:
            raise ValueError("manifest exceeds the size limit")
        raw: Any = json.loads(
            manifest.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite manifest number is forbidden: {value}")
            ),
        )
        if (
            not isinstance(raw, dict)
            or set(raw) != {"algorithm", "files"}
            or raw.get("algorithm") != "sha256"
            or not isinstance(raw.get("files"), list)
            or not raw["files"]
        ):
            raise ValueError("manifest must contain a non-empty sha256 file list")
        if len(raw["files"]) > 100_000:
            raise ValueError("manifest contains too many files")

        expected: dict[str, str] = {}
        for item in raw["files"]:
            if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
                raise ValueError("manifest file entries require only path and sha256")
            relative = _relative_path(item["path"]).as_posix()
            checksum = item["sha256"]
            if relative in expected:
                raise ValueError(f"duplicate manifest path: {relative}")
            if not isinstance(checksum, str) or not _SHA256.fullmatch(checksum):
                raise ValueError(f"invalid SHA-256 digest: {relative}")
            expected[relative] = checksum

        actual = _artifact_paths(root, manifest)
        missing = sorted(actual.keys() - expected.keys())
        unlisted = sorted(expected.keys() - actual.keys())
        if missing or unlisted:
            raise ValueError(
                "manifest artifact set mismatch: "
                f"unlisted_artifacts={missing[:10]}, absent_artifacts={unlisted[:10]}"
            )
        for relative, checksum in expected.items():
            if digest(actual[relative]) != checksum:
                raise ValueError(f"digest mismatch: {relative}")
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise SystemExit(f"manifest verification failed: {exc}") from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
