"""Verify and stage pre-approved native endpoint package inputs.

The verifier deliberately has no network capability.  A release pipeline supplies the
expected hash of a reviewed manifest, and the manifest pins every vendor binary and its
license text.  Only files copied into the new staging directory may be packaged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
_MAX_LICENSE_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TARGET = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
_COMPONENT = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$")
_INSTALL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_LICENSE_EXPRESSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.()+ -]{0,127}$")
_MANIFEST_KEYS = frozenset({"schema_version", "target", "artifacts"})
_ARTIFACT_KEYS = frozenset(
    {
        "component",
        "version",
        "source_path",
        "install_name",
        "sha256",
        "size_bytes",
        "license_path",
        "license_sha256",
        "license_size_bytes",
        "license_expression",
    }
)


class VerificationError(ValueError):
    """Raised when an input cannot safely enter a package."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _sha256_file(path: Path, *, maximum_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            if size > maximum_bytes:
                raise VerificationError(f"input exceeds the size limit: {path.name}")
            digest.update(chunk)
    return digest.hexdigest(), size


def _trusted_sha256(value: str, label: str) -> str:
    normalized = value.casefold()
    if not _SHA256.fullmatch(normalized) or normalized == "0" * 64:
        raise VerificationError(f"{label} must be a non-placeholder SHA-256")
    return normalized


def _safe_relative_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise VerificationError(f"{label} must be a bounded relative path")
    if "\\" in value or ":" in value or value.startswith("/"):
        raise VerificationError(f"{label} must use portable relative path syntax")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise VerificationError(f"{label} contains an unsafe path segment")
    return Path(*parts)


def _regular_file_beneath(root: Path, relative: Path, label: str) -> Path:
    root = root.resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        raise VerificationError("artifact root must be a real directory")
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise VerificationError(f"{label} must not traverse a symbolic link")
    resolved = cursor.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise VerificationError(f"{label} escapes the artifact root") from exc
    if not resolved.is_file():
        raise VerificationError(f"{label} is not a regular file")
    return resolved


def _strict_string(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise VerificationError(f"invalid {label}")
    return value


def _strict_size(value: Any, maximum: int, label: str) -> int:
    if type(value) is not int or value <= 0 or value > maximum:
        raise VerificationError(f"invalid {label}")
    return value


def _copy_verified(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str,
    expected_size: int,
    maximum_bytes: int,
) -> None:
    source_hash, source_size = _sha256_file(source, maximum_bytes=maximum_bytes)
    if source_hash != expected_sha256 or source_size != expected_size:
        raise VerificationError(f"approved digest or size does not match: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_handle, destination.open("xb") as output_handle:
        shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
        output_handle.flush()
        os.fsync(output_handle.fileno())
    copied_hash, copied_size = _sha256_file(destination, maximum_bytes=maximum_bytes)
    if copied_hash != expected_sha256 or copied_size != expected_size:
        raise VerificationError(f"staged input verification failed: {destination.name}")


def verify_and_stage(
    manifest_path: Path,
    artifact_root: Path,
    stage_dir: Path,
    *,
    manifest_sha256: str,
    expected_target: str,
    required_components: frozenset[str],
) -> dict[str, Any]:
    """Verify an immutable input set and copy it into a new staging directory."""

    trusted_manifest_hash = _trusted_sha256(manifest_sha256, "manifest hash")
    actual_manifest_hash, manifest_size = _sha256_file(
        manifest_path, maximum_bytes=_MAX_MANIFEST_BYTES
    )
    if actual_manifest_hash != trusted_manifest_hash:
        raise VerificationError("manifest does not match the approved SHA-256")
    try:
        document = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError("manifest is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != _MANIFEST_KEYS:
        raise VerificationError("manifest fields do not match schema version 1")
    if document["schema_version"] != 1 or type(document["schema_version"]) is not int:
        raise VerificationError("unsupported manifest schema version")
    target = _strict_string(document["target"], _TARGET, "target")
    expected = _strict_string(expected_target, _TARGET, "expected target")
    if target != expected:
        raise VerificationError("manifest target does not match this package build")
    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 16:
        raise VerificationError("manifest must contain 1 to 16 artifacts")
    if stage_dir.exists():
        raise VerificationError("staging directory must not already exist")

    parsed: list[dict[str, Any]] = []
    components: set[str] = set()
    source_paths: set[str] = set()
    total_bytes = 0
    for index, item in enumerate(artifacts):
        if not isinstance(item, dict) or set(item) != _ARTIFACT_KEYS:
            raise VerificationError(f"artifact {index} fields do not match the schema")
        component = _strict_string(item["component"], _COMPONENT, "component")
        if component in components:
            raise VerificationError(f"duplicate component: {component}")
        components.add(component)
        version = _strict_string(item["version"], _VERSION, "component version")
        install_name = _strict_string(
            item["install_name"], _INSTALL_NAME, "install name"
        )
        source_relative = _safe_relative_path(item["source_path"], "source path")
        license_relative = _safe_relative_path(item["license_path"], "license path")
        for relative in (source_relative, license_relative):
            normalized = relative.as_posix().casefold()
            if normalized in source_paths:
                raise VerificationError("manifest paths must be unique")
            source_paths.add(normalized)
        size_bytes = _strict_size(
            item["size_bytes"], _MAX_ARTIFACT_BYTES, "artifact size"
        )
        license_size_bytes = _strict_size(
            item["license_size_bytes"], _MAX_LICENSE_BYTES, "license size"
        )
        total_bytes += size_bytes + license_size_bytes
        if total_bytes > _MAX_TOTAL_BYTES:
            raise VerificationError("total package inputs exceed the size limit")
        parsed.append(
            {
                "component": component,
                "version": version,
                "install_name": install_name,
                "source_relative": source_relative,
                "source_sha256": _trusted_sha256(
                    item["sha256"], f"{component} artifact hash"
                ),
                "source_size": size_bytes,
                "license_relative": license_relative,
                "license_sha256": _trusted_sha256(
                    item["license_sha256"], f"{component} license hash"
                ),
                "license_size": license_size_bytes,
                "license_expression": _strict_string(
                    item["license_expression"],
                    _LICENSE_EXPRESSION,
                    "license expression",
                ),
            }
        )
    if components != set(required_components):
        raise VerificationError(
            "manifest components do not exactly match the required package inputs"
        )

    artifact_root = artifact_root.resolve(strict=True)
    staged_records: list[dict[str, Any]] = []
    stage_dir.mkdir(parents=True, exist_ok=False)
    try:
        for item in parsed:
            component = item["component"]
            source = _regular_file_beneath(
                artifact_root, item["source_relative"], f"{component} source"
            )
            license_source = _regular_file_beneath(
                artifact_root, item["license_relative"], f"{component} license"
            )
            installed_relative = Path("components", component, item["install_name"])
            license_destination = Path("licenses", f"{component}.txt")
            _copy_verified(
                source,
                stage_dir / installed_relative,
                expected_sha256=item["source_sha256"],
                expected_size=item["source_size"],
                maximum_bytes=_MAX_ARTIFACT_BYTES,
            )
            _copy_verified(
                license_source,
                stage_dir / license_destination,
                expected_sha256=item["license_sha256"],
                expected_size=item["license_size"],
                maximum_bytes=_MAX_LICENSE_BYTES,
            )
            staged_records.append(
                {
                    "component": component,
                    "version": item["version"],
                    "license_expression": item["license_expression"],
                    "file": installed_relative.as_posix(),
                    "sha256": item["source_sha256"],
                    "size_bytes": item["source_size"],
                    "license_file": license_destination.as_posix(),
                    "license_sha256": item["license_sha256"],
                    "license_size_bytes": item["license_size"],
                }
            )
        receipt = {
            "schema_version": 1,
            "target": target,
            "manifest_sha256": actual_manifest_hash,
            "manifest_size_bytes": manifest_size,
            "artifacts": sorted(staged_records, key=lambda value: value["component"]),
        }
        receipt_path = stage_dir / "verified-inputs.json"
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return receipt
    except Exception:
        # Keep the uniquely created, incomplete stage for forensic review.  The
        # caller must select a new stage directory for the next attempt.
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify and stage offline native endpoint package inputs"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--stage-dir", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--require-component", action="append", required=True, dest="components"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        receipt = verify_and_stage(
            args.manifest,
            args.artifact_root,
            args.stage_dir,
            manifest_sha256=args.manifest_sha256,
            expected_target=args.target,
            required_components=frozenset(args.components),
        )
    except (OSError, VerificationError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "VERIFIED",
                "target": receipt["target"],
                "components": [item["component"] for item in receipt["artifacts"]],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
