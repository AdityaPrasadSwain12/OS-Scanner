from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from app.config_loader import load_settings_file

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = PROJECT_ROOT / "packaging" / "endpoint"
VERIFY = PACKAGE_ROOT / "tools" / "verify_inputs.py"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _manifest(root: Path, *, source_path: str = "native/osqueryi") -> Path:
    binary = b"approved osquery binary"
    license_text = b"approved license text\n"
    (root / "native").mkdir()
    (root / "licenses").mkdir()
    (root / "native" / "osqueryi").write_bytes(binary)
    (root / "licenses" / "osquery.txt").write_bytes(license_text)
    document = {
        "schema_version": 1,
        "target": "linux-x86_64",
        "artifacts": [
            {
                "component": "osquery",
                "version": "1.2.3",
                "source_path": source_path,
                "install_name": "osqueryi",
                "sha256": _sha256(binary),
                "size_bytes": len(binary),
                "license_path": "licenses/osquery.txt",
                "license_sha256": _sha256(license_text),
                "license_size_bytes": len(license_text),
                "license_expression": "Apache-2.0",
            }
        ],
    }
    path = root / "manifest.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _verify(manifest: Path, artifact_root: Path, stage: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter and local test utility
        [
            sys.executable,
            str(VERIFY),
            "--manifest",
            str(manifest),
            "--manifest-sha256",
            _sha256(manifest.read_bytes()),
            "--artifact-root",
            str(artifact_root),
            "--stage-dir",
            str(stage),
            "--target",
            "linux-x86_64",
            "--require-component",
            "osquery",
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_verified_inputs_are_staged_with_a_receipt(tmp_path: Path) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    manifest = _manifest(inputs)
    stage = tmp_path / "stage"

    result = _verify(manifest, inputs, stage)

    assert result.returncode == 0, result.stderr
    assert (stage / "components" / "osquery" / "osqueryi").read_bytes() == (
        b"approved osquery binary"
    )
    receipt = json.loads((stage / "verified-inputs.json").read_text(encoding="utf-8"))
    assert receipt["manifest_sha256"] == _sha256(manifest.read_bytes())
    assert receipt["artifacts"][0]["component"] == "osquery"
    assert not any(
        str(inputs.resolve()) in value
        for value in receipt.values()
        if isinstance(value, str)
    )


def test_verifier_rejects_tampered_artifact(tmp_path: Path) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    manifest = _manifest(inputs)
    (inputs / "native" / "osqueryi").write_bytes(b"tampered")

    result = _verify(manifest, inputs, tmp_path / "stage")

    assert result.returncode == 2
    assert "does not match" in result.stderr


def test_verifier_rejects_path_traversal(tmp_path: Path) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    manifest = _manifest(inputs)
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["artifacts"][0]["source_path"] = "../outside/osqueryi"
    manifest.write_text(json.dumps(document), encoding="utf-8")

    result = _verify(manifest, inputs, tmp_path / "stage")

    assert result.returncode == 2
    assert "unsafe path" in result.stderr


def test_verifier_rejects_unapproved_manifest_hash(tmp_path: Path) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    manifest = _manifest(inputs)
    result = subprocess.run(  # noqa: S603 - fixed interpreter and local test utility
        [
            sys.executable,
            str(VERIFY),
            "--manifest",
            str(manifest),
            "--manifest-sha256",
            "1" * 64,
            "--artifact-root",
            str(inputs),
            "--stage-dir",
            str(tmp_path / "stage"),
            "--target",
            "linux-x86_64",
            "--require-component",
            "osquery",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "approved SHA-256" in result.stderr


@pytest.mark.parametrize("platform_name", ["windows", "linux", "macos"])
def test_managed_configs_are_cloud_offload_and_secret_free(platform_name: str) -> None:
    config_path = PACKAGE_ROOT / "config" / f"{platform_name}.yaml"
    settings = load_settings_file(config_path)
    text = config_path.read_text(encoding="utf-8")

    assert settings.cloud.offload_vulnerability_analysis is True
    assert settings.cloud.allow_insecure_loopback_http is False
    assert settings.tools.osquery_executable is not None
    assert settings.tools.osv_scanner_executable is None
    assert settings.tools.depscan_executable is None
    assert settings.tools.amass_executable is None
    assert not re.search(r"(?im)^\s*(access_token|refresh_token|api_token|password)\s*:", text)


def test_package_scripts_have_no_network_download_implementation() -> None:
    patterns = re.compile(
        r"(?i)(invoke-webrequest|start-bitstransfer|\bcurl\b|\bwget\b|urlopen\(|requests\.)"
    )
    suffixes = {".ps1", ".sh", ".iss", ".py"}
    scripts = [path for path in PACKAGE_ROOT.rglob("*") if path.suffix in suffixes]

    assert scripts
    for script in scripts:
        assert patterns.search(script.read_text(encoding="utf-8")) is None, script


def test_services_cannot_auto_start_before_enrollment() -> None:
    windows = (PACKAGE_ROOT / "windows" / "EndpointScannerService.xml").read_text(
        encoding="utf-8"
    )
    linux = (PACKAGE_ROOT / "linux" / "endpoint-scanner.service").read_text(
        encoding="utf-8"
    )
    linux_postinst = (PACKAGE_ROOT / "linux" / "postinst").read_text(encoding="utf-8")
    macos = (PACKAGE_ROOT / "macos" / "com.enterprise.endpoint-scanner.plist").read_text(
        encoding="utf-8"
    )
    macos_postinstall = (PACKAGE_ROOT / "macos" / "postinstall").read_text(
        encoding="utf-8"
    )

    assert "<startmode>Manual</startmode>" in windows
    assert "ConditionPathExists=/var/lib/endpoint-scanner/enrolled" in linux
    assert not re.search(r"^systemctl\s+(enable|start|restart)", linux_postinst, re.MULTILINE)
    assert "<key>Disabled</key>" in macos and "<true/>" in macos
    assert "launchctl enable" not in macos_postinstall
    assert "launchctl bootstrap" not in macos_postinstall


def test_windows_powershell_files_parse() -> None:
    files = list((PACKAGE_ROOT / "windows").glob("*.ps1"))
    quoted = ",".join("'" + str(path).replace("'", "''") + "'" for path in files)
    command = (
        "$failed=$false; foreach($path in @(" + quoted + ")) {"
        "$tokens=$null; $errors=$null; "
        "[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)"
        " | Out-Null; if($errors.Count -gt 0){$errors|Out-String|Write-Error;$failed=$true}};"
        "if($failed){exit 1}"
    )
    powershell = shutil.which("powershell")
    assert powershell is not None
    result = subprocess.run(  # noqa: S603 - resolved system PowerShell parser
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
