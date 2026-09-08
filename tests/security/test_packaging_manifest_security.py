from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_script(name: str) -> ModuleType:
    path = PROJECT_ROOT / "packaging" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"packaging_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _generate(
    monkeypatch: pytest.MonkeyPatch, artifacts: Path, manifest: Path
) -> ModuleType:
    module = _load_script("generate_manifest")
    monkeypatch.setattr(
        sys,
        "argv",
        ["generate_manifest.py", str(artifacts), "--output", str(manifest)],
    )
    assert module.main() == 0
    return module


def _verify(monkeypatch: pytest.MonkeyPatch, artifacts: Path, manifest: Path) -> int:
    module = _load_script("verify_manifest")
    monkeypatch.setattr(
        sys,
        "argv",
        ["verify_manifest.py", str(artifacts), str(manifest)],
    )
    return module.main()


def test_manifest_round_trip_and_tamper_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    artifact = artifacts / "scanner.whl"
    artifact.write_bytes(b"signed release payload")
    manifest = tmp_path / "SHA256SUMS.json"
    _generate(monkeypatch, artifacts, manifest)

    assert _verify(monkeypatch, artifacts, manifest) == 0

    artifact.write_bytes(b"tampered payload")
    with pytest.raises(SystemExit, match="digest mismatch"):
        _verify(monkeypatch, artifacts, manifest)


def test_verifier_rejects_unlisted_release_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "scanner.whl").write_bytes(b"wheel")
    manifest = tmp_path / "SHA256SUMS.json"
    _generate(monkeypatch, artifacts, manifest)
    (artifacts / "unlisted-installer.exe").write_bytes(b"untrusted")

    with pytest.raises(SystemExit, match="unlisted"):
        _verify(monkeypatch, artifacts, manifest)


def test_verifier_rejects_duplicate_manifest_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "scanner.whl").write_bytes(b"wheel")
    manifest = tmp_path / "SHA256SUMS.json"
    _generate(monkeypatch, artifacts, manifest)
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["files"].append(document["files"][0])
    manifest.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SystemExit, match="duplicate"):
        _verify(monkeypatch, artifacts, manifest)


@pytest.mark.parametrize(
    "document",
    (
        {"algorithm": "sha256"},
        {"algorithm": "sha256", "files": {}},
        {"algorithm": "sha256", "files": [{"path": "scanner.whl"}]},
        {
            "algorithm": "sha256",
            "files": [{"path": "scanner.whl", "sha256": "not-a-sha256"}],
        },
    ),
)
def test_verifier_rejects_malformed_manifest_documents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    document: object,
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "scanner.whl").write_bytes(b"wheel")
    manifest = tmp_path / "SHA256SUMS.json"
    manifest.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SystemExit, match="manifest"):
        _verify(monkeypatch, artifacts, manifest)


def test_verifier_rejects_paths_outside_artifact_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    digest = _load_script("verify_manifest").digest(outside)
    manifest = tmp_path / "SHA256SUMS.json"
    manifest.write_text(
        json.dumps(
            {
                "algorithm": "sha256",
                "files": [{"path": "../outside.bin", "sha256": digest}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="unsafe manifest path"):
        _verify(monkeypatch, artifacts, manifest)
