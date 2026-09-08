"""Allowlisted local release artifacts for the development control plane.

The HTTP API resolves an opaque artifact identifier through this module.  A
request can never provide a filesystem path.  Production deployments can
replace this local store with authenticated object storage while retaining the
same catalog contract.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 1024 * 1024
_CHUNK_BYTES = 1024 * 1024


class UnknownArtifactError(LookupError):
    """The opaque artifact identifier is not in the server allowlist."""


class ArtifactUnavailableError(RuntimeError):
    """A configured artifact is absent or failed integrity validation."""


@dataclass(frozen=True, slots=True)
class InstallerDefinition:
    artifact_id: str
    platform: str
    architecture: str
    package_type: str
    version: str
    filename: str
    manifest_path: str
    media_type: str
    magic: bytes


WINDOWS_X86_64_PORTABLE = InstallerDefinition(
    artifact_id="windows-x86_64-portable",
    platform="WINDOWS",
    architecture="x86_64",
    package_type="PORTABLE_EXECUTABLE",
    version="1.1.0",
    filename="endpoint-scanner.exe",
    manifest_path="endpoint/endpoint-scanner.exe",
    media_type="application/vnd.microsoft.portable-executable",
    magic=b"MZ",
)

INSTALLER_DEFINITIONS: tuple[InstallerDefinition, ...] = (WINDOWS_X86_64_PORTABLE,)


@dataclass(frozen=True, slots=True)
class InstallerArtifact:
    definition: InstallerDefinition
    size_bytes: int
    sha256: str

    def catalog_document(self) -> dict[str, Any]:
        definition = self.definition
        return {
            "artifact_id": definition.artifact_id,
            "display_name": "Windows endpoint scanner (developer portable build)",
            "platform": definition.platform,
            "architecture": definition.architecture,
            "package_type": definition.package_type,
            "version": definition.version,
            "filename": definition.filename,
            "media_type": definition.media_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "available": True,
            "delivery_mode": "DEVELOPMENT_PORTABLE",
            "managed_installer": False,
            "requires_elevation": True,
            "includes_cloud_analysis_tools": False,
            "download_url": (
                f"/api/v1/platform/installers/{definition.artifact_id}/download"
            ),
        }


@dataclass(slots=True)
class OpenInstallerArtifact:
    artifact: InstallerArtifact
    stream: BinaryIO

    def chunks(self) -> Iterator[bytes]:
        try:
            while chunk := self.stream.read(_CHUNK_BYTES):
                yield chunk
        finally:
            self.stream.close()


class LocalInstallerArtifactStore:
    """Read-only, manifest-verified artifacts addressed by opaque identifiers."""

    def __init__(self, root: str | Path, manifest: str | Path, max_bytes: int) -> None:
        self._root = Path(root).resolve(strict=False)
        self._manifest = Path(manifest).resolve(strict=False)
        self._max_bytes = max_bytes
        self._definitions = {value.artifact_id: value for value in INSTALLER_DEFINITIONS}

    def catalog(self) -> list[dict[str, Any]]:
        documents: list[dict[str, Any]] = []
        for definition in INSTALLER_DEFINITIONS:
            try:
                artifact = self.inspect(definition.artifact_id)
            except ArtifactUnavailableError:
                documents.append(
                    {
                        "artifact_id": definition.artifact_id,
                        "display_name": (
                            "Windows endpoint scanner (developer portable build)"
                        ),
                        "platform": definition.platform,
                        "architecture": definition.architecture,
                        "package_type": definition.package_type,
                        "version": definition.version,
                        "filename": definition.filename,
                        "media_type": definition.media_type,
                        "size_bytes": None,
                        "sha256": None,
                        "available": False,
                        "delivery_mode": "DEVELOPMENT_PORTABLE",
                        "managed_installer": False,
                        "requires_elevation": True,
                        "includes_cloud_analysis_tools": False,
                        "download_url": None,
                    }
                )
            else:
                documents.append(artifact.catalog_document())
        return documents

    def inspect(self, artifact_id: str) -> InstallerArtifact:
        opened = self.open(artifact_id)
        try:
            return opened.artifact
        finally:
            opened.stream.close()

    def open(self, artifact_id: str) -> OpenInstallerArtifact:
        definition = self._definitions.get(artifact_id)
        if definition is None:
            raise UnknownArtifactError(artifact_id)
        expected_hashes = self._load_manifest()
        expected = expected_hashes.get(definition.manifest_path)
        if expected is None:
            raise ArtifactUnavailableError("release manifest does not contain the artifact")

        candidate = (self._root / definition.filename).resolve(strict=False)
        if not candidate.is_relative_to(self._root):
            raise ArtifactUnavailableError("artifact path is outside the configured root")
        if candidate.name != definition.filename or candidate.suffix.casefold() != ".exe":
            raise ArtifactUnavailableError("artifact filename is invalid")
        if candidate.is_symlink() or not candidate.is_file():
            raise ArtifactUnavailableError("artifact file is unavailable")

        stream: BinaryIO | None = None
        try:
            stream = candidate.open("rb")
            before = os.fstat(stream.fileno())
            if not 1 <= before.st_size <= self._max_bytes:
                raise ArtifactUnavailableError("artifact size is outside the allowed range")
            if stream.read(len(definition.magic)) != definition.magic:
                raise ArtifactUnavailableError("artifact content does not match its package type")
            stream.seek(0)
            digest = hashlib.sha256()
            while chunk := stream.read(_CHUNK_BYTES):
                digest.update(chunk)
            after = os.fstat(stream.fileno())
            if (
                before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ino != after.st_ino
            ):
                raise ArtifactUnavailableError("artifact changed during integrity validation")
            sha256 = digest.hexdigest()
            if sha256 != expected:
                raise ArtifactUnavailableError("artifact SHA-256 does not match release manifest")
            stream.seek(0)
            return OpenInstallerArtifact(
                InstallerArtifact(definition, before.st_size, sha256), stream
            )
        except OSError as exc:
            raise ArtifactUnavailableError("artifact could not be read") from exc
        except Exception:
            if stream is not None:
                stream.close()
            raise

    def _load_manifest(self) -> dict[str, str]:
        try:
            if self._manifest.is_symlink() or not self._manifest.is_file():
                raise ArtifactUnavailableError("release manifest is unavailable")
            size = self._manifest.stat().st_size
            if not 1 <= size <= _MAX_MANIFEST_BYTES:
                raise ArtifactUnavailableError("release manifest size is invalid")
            raw = self._manifest.read_bytes()
            if len(raw) != size:
                raise ArtifactUnavailableError("release manifest changed while being read")
            document = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ArtifactUnavailableError("release manifest is invalid") from exc
        if not isinstance(document, dict) or document.get("algorithm") != "sha256":
            raise ArtifactUnavailableError("release manifest algorithm is invalid")
        files = document.get("files")
        if not isinstance(files, list) or len(files) > 128:
            raise ArtifactUnavailableError("release manifest file list is invalid")
        result: dict[str, str] = {}
        for entry in files:
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
                raise ArtifactUnavailableError("release manifest entry is invalid")
            path, digest = entry["path"], entry["sha256"]
            if (
                not isinstance(path, str)
                or not isinstance(digest, str)
                or _SHA256.fullmatch(digest) is None
                or path in result
            ):
                raise ArtifactUnavailableError("release manifest entry is invalid")
            result[path] = digest
        return result
