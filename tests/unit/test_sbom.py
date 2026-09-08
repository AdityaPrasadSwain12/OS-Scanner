from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from app.models import OverallStatus, ScanResult, ScanType, Software
from app.reporting import ReportTooLargeError
from app.sbom import (
    AtomicCycloneDxWriter,
    SbomLimitError,
    build_cyclonedx_sbom,
    serialize_cyclonedx_sbom,
)


def _result(software: list[Software]) -> ScanResult:
    observed = datetime(2026, 9, 2, 8, 30, tzinfo=UTC)
    return ScanResult(
        scan_id="scan-sbom-1",
        endpoint_id="endpoint-1",
        scan_type=ScanType.FULL,
        timestamp=observed,
        started_at=observed,
        finished_at=observed,
        status=OverallStatus.SUCCESS,
        authorization_scope_id="scope-1",
        software=software,
        metadata={
            "observed_inventory_sections": ["software"],
            "unobserved_inventory_sections": ["vulnerabilities"],
        },
    )


def test_cyclonedx_export_is_deterministic_deduplicated_and_omits_local_paths() -> None:
    first = Software(
        name="Example App",
        version="2.0",
        vendor="Example Corp",
        installation_path="C:/Users/private/App",
        installation_date=date(2026, 1, 2),
        package_manager="winget",
        architecture="x64",
        source="native",
    )
    second = Software(name="Alpha", version="1.0")
    result = _result([first, second, first.model_copy()])

    left = serialize_cyclonedx_sbom(result)
    right = serialize_cyclonedx_sbom(result.model_copy(update={"software": [second, first]}))

    assert left == right
    document = json.loads(left)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert [item["name"] for item in document["components"]] == ["Alpha", "Example App"]
    assert len(document["components"]) == 2
    assert "C:/Users/private/App" not in left.decode("utf-8")
    properties = {item["name"]: item["value"] for item in document["metadata"]["properties"]}
    assert properties["com.endpoint-scanner.software-completeness"] == "observed"
    assert properties["com.endpoint-scanner.scan-id"] == "scan-sbom-1"


def test_cyclonedx_export_redacts_secrets_and_bounds_components() -> None:
    result = _result([Software(name="token=do-not-leak", version="1")])
    encoded = serialize_cyclonedx_sbom(result)

    assert b"do-not-leak" not in encoded
    assert b"<redacted>" in encoded
    with pytest.raises(ValueError, match="max_components"):
        build_cyclonedx_sbom(result, max_components=0)  # invalid setting is rejected first


def test_cyclonedx_adds_purl_only_for_known_versioned_package_ecosystems() -> None:
    result = _result(
        [
            Software(
                name="openssl",
                version="3.0.17-1~deb12u2",
                package_manager="dpkg",
                architecture="amd64",
            ),
            Software(name="Unmapped Desktop App", version="4.2", package_manager="winget"),
        ]
    )

    components = build_cyclonedx_sbom(result)["components"]
    by_name = {component["name"]: component for component in components}
    assert by_name["openssl"]["purl"] == (
        "pkg:deb/openssl@3.0.17-1~deb12u2?arch=amd64"
    )
    assert by_name["openssl"]["type"] == "library"
    assert "purl" not in by_name["Unmapped Desktop App"]


def test_cyclonedx_component_limit_and_serialized_size_fail_closed() -> None:
    result = _result([Software(name="one"), Software(name="two")])

    with pytest.raises(SbomLimitError):
        build_cyclonedx_sbom(result, max_components=1)
    with pytest.raises(ReportTooLargeError):
        serialize_cyclonedx_sbom(result, max_bytes=16)


def test_atomic_cyclonedx_writer_writes_valid_json_and_cleans_oversized_temp(
    tmp_path: Path,
) -> None:
    result = _result([Software(name="Example", version="1.0")])
    directory = tmp_path / "sbom"
    destination = AtomicCycloneDxWriter(directory).write(result)

    assert destination.parent == directory.resolve()
    assert destination.name.endswith(".json")
    assert json.loads(destination.read_text(encoding="utf-8"))["components"][0]["name"] == "Example"

    oversized_directory = tmp_path / "oversized"
    with pytest.raises(ReportTooLargeError):
        AtomicCycloneDxWriter(oversized_directory, max_bytes=16).write(result)
    assert not list(oversized_directory.glob("*.tmp"))
    assert not list(oversized_directory.glob("*.json"))
