from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.tools.base import ToolExecution, ToolHealth, ToolState
from cloud_service.analysis import (
    AnalysisInputError,
    CloudAnalysisEngine,
    CloudScanInput,
    coerce_scan_input,
)
from cloud_service.repository import ScanAnalysisInput

NOW = datetime(2026, 9, 2, tzinfo=UTC)


def _sbom() -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg:pypi/demo@1.0",
                "type": "library",
                "name": "demo",
                "version": "1.0",
                "purl": "pkg:pypi/demo@1.0",
            }
        ],
    }


def _scan(*, checksum: str | None = None) -> CloudScanInput:
    return CloudScanInput(
        tenant_id="tenant-1",
        endpoint_id="endpoint-1",
        scan_id="scan-1",
        result={
            "schema_version": "1.0",
            "scanner_version": "1.1.0",
            "scan_id": "scan-1",
            "endpoint_id": "endpoint-1",
            "status": "SUCCESS",
            "metadata": {"inventory_complete": True},
        },
        inventory_sync={"mode": "full", "snapshot": {"software": []}},
        sbom=_sbom(),
        sbom_sha256=checksum,
    )


def _osv_record() -> dict[str, Any]:
    return {
        "vulnerability_id": "OSV-2026-DEMO",
        "aliases": ["CVE-2026-0001"],
        "package": {"name": "demo", "version": "1.0", "ecosystem": "PyPI"},
        "severity": "HIGH",
        "fixed_versions": ["1.1"],
        "summary": "demo advisory",
    }


def _depscan_record() -> dict[str, Any]:
    return {
        "vulnerability_id": "CVE-2026-0001",
        "aliases": ["OSV-2026-DEMO"],
        "package": {"name": "demo", "version": "1.0", "ecosystem": "PyPI"},
        "severity": "CRITICAL",
        "fixed_versions": ["1.2"],
        "summary": "more complete demo advisory",
    }


def test_fixture_mode_is_deterministic_and_cannot_claim_production_completeness() -> None:
    engine = CloudAnalysisEngine(
        fixture_mode=True,
        fixture_records={"OSV": [_osv_record()], "DEPSCAN": [_depscan_record()]},
    )

    osv = engine.analyze_tool("OSV", _scan())
    depscan = engine.analyze_tool("DEPSCAN", _scan())
    assert osv == engine.analyze_tool("OSV", _scan())

    report = engine.build_final_report(_scan(), {"OSV": osv, "DEPSCAN": depscan})

    assert report["status"] == "FIXTURE"
    assert report["completeness"]["complete"] is False
    assert report["completeness"]["fixture_mode"] is True
    assert report["summary"]["vulnerability_count"] == 1
    vulnerability = report["cloud_analysis"]["vulnerabilities"][0]
    assert vulnerability["severity"] == "CRITICAL"
    assert vulnerability["fixed_versions"] == ["1.1", "1.2"]
    assert set(vulnerability["evidence"]["sources"]) == {
        "osv-scanner",
        "owasp-dep-scan",
    }


def test_unconfigured_tools_are_explicit_and_preserve_endpoint_evidence() -> None:
    engine = CloudAnalysisEngine(clock=lambda: NOW)
    osv = engine.analyze_tool("OSV", _scan())
    depscan = engine.analyze_tool("DEPSCAN", _scan())

    report = engine.build_final_report(_scan(), {"OSV": osv, "DEPSCAN": depscan})

    assert osv["status"] == "UNAVAILABLE"
    assert depscan["status"] == "UNAVAILABLE"
    assert report["status"] == "PARTIAL"
    assert report["endpoint_evidence"]["result"]["scan_id"] == "scan-1"
    assert report["summary"]["degraded_tools"] == ["DEPSCAN", "OSV"]


def test_checksum_mismatch_is_rejected_before_tool_execution() -> None:
    engine = CloudAnalysisEngine(clock=lambda: NOW)
    with pytest.raises(AnalysisInputError, match="checksum"):
        engine.analyze_tool("OSV", _scan(checksum="0" * 64))


def test_missing_optional_sbom_finishes_as_partial_instead_of_hanging_tasks() -> None:
    source = _scan()
    scan = CloudScanInput(
        tenant_id=source.tenant_id,
        endpoint_id=source.endpoint_id,
        scan_id=source.scan_id,
        result=source.result,
        inventory_sync=source.inventory_sync,
        sbom={},
    )
    engine = CloudAnalysisEngine(clock=lambda: NOW)
    results = {tool: engine.analyze_tool(tool, scan) for tool in engine.expected_tools}

    report = engine.build_final_report(scan, results)

    assert {result["status"] for result in results.values()} == {"SKIPPED"}
    assert report["status"] == "PARTIAL"
    assert report["completeness"]["sbom_received"] is False


class _InspectingOsv:
    def __init__(self, root: Path, paths: list[Path]) -> None:
        self.root = root
        self.paths = paths

    def health(self) -> ToolHealth:
        return ToolHealth("osv-scanner", ToolState.SUCCESS, version="2.0")

    def execute(
        self,
        value: Any,
        *,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> ToolExecution[list[dict[str, Any]]]:
        assert value.source.parent == self.root
        assert value.source.is_file()
        assert json.loads(value.source.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"
        self.paths.append(value.source)
        return ToolExecution(
            "osv-scanner",
            ToolState.SUCCESS,
            payload=[_osv_record()],
            version="2.0",
        )


class _FailedDepScan:
    def health(self) -> ToolHealth:
        return ToolHealth("depscan", ToolState.SUCCESS, version="6.0")

    def execute(
        self,
        value: Any,
        *,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> ToolExecution[list[dict[str, Any]]]:
        return ToolExecution(
            "depscan",
            ToolState.FAILED,
            version="6.0",
            error="isolated dep-scan failure",
        )


def test_tool_receives_only_private_temporary_sbom_and_workspace_is_removed() -> None:
    paths: list[Path] = []
    engine = CloudAnalysisEngine(
        osv_factory=lambda root: _InspectingOsv(root, paths),
        clock=lambda: NOW,
    )

    result = engine.analyze_tool("OSV", _scan())

    assert result["status"] == "SUCCESS"
    assert len(paths) == 1
    assert not paths[0].exists()
    expected = hashlib.sha256(
        json.dumps(
            _sbom(), ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    assert result["provenance"]["sbom_sha256"] == expected


def test_cloud_depscan_factory_passes_explicit_persistent_cache_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("VDB_HOME", str(cache / "vdb"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    engine = CloudAnalysisEngine(depscan_executable=str(tmp_path / "depscan"))

    adapter = engine._default_depscan_factory(tmp_path)
    environment = adapter._runner.environment  # type: ignore[attr-defined]

    assert environment["VDB_HOME"] == str((cache / "vdb").resolve())
    assert environment["XDG_CACHE_HOME"] == str(cache.resolve())


def test_one_tool_failure_does_not_discard_other_tool_vulnerability_evidence() -> None:
    engine = CloudAnalysisEngine(
        osv_factory=lambda root: _InspectingOsv(root, []),
        depscan_factory=lambda root: _FailedDepScan(),
        clock=lambda: NOW,
    )

    osv = engine.analyze_tool("OSV", _scan())
    depscan = engine.analyze_tool("DEPSCAN", _scan())
    report = engine.build_final_report(_scan(), {"OSV": osv, "DEPSCAN": depscan})

    assert depscan["status"] == "FAILED"
    assert report["status"] == "PARTIAL"
    assert report["summary"]["vulnerability_count"] == 1
    assert report["cloud_analysis"]["vulnerabilities"][0]["vulnerability_id"] == (
        "CVE-2026-0001"
    )


def test_partial_tool_is_usable_but_degraded_and_never_complete() -> None:
    engine = CloudAnalysisEngine(clock=lambda: NOW)
    common = {
        "scan_id": "scan-1",
        "endpoint_id": "endpoint-1",
        "vulnerabilities": [],
    }

    report = engine.build_final_report(
        _scan(),
        {
            "OSV": {**common, "status": "PARTIAL", "warnings": ["bounded warning"]},
            "DEPSCAN": {**common, "status": "SUCCESS"},
        },
    )

    assert report["status"] == "PARTIAL"
    assert report["completeness"]["complete"] is False
    assert report["summary"]["successful_tools"] == ["DEPSCAN"]
    assert report["summary"]["usable_tools"] == ["DEPSCAN", "OSV"]
    assert report["summary"]["degraded_tools"] == ["OSV"]
    assert "OSV analysis status is PARTIAL" in report["completeness"]["gaps"]


def test_repository_upload_envelope_is_coerced_without_persistence_import_coupling() -> None:
    source = _scan()
    aggregate = ScanAnalysisInput(
        tenant_id=source.tenant_id,
        endpoint_id=source.endpoint_id,
        scan_id=source.scan_id,
        upload={
            "result": dict(source.result),
            "inventory_sync": dict(source.inventory_sync),
            "sbom": dict(source.sbom),
        },
    )

    coerced = coerce_scan_input(aggregate)

    assert coerced.scan_id == "scan-1"
    assert coerced.expected_tools == ("OSV", "DEPSCAN")


def test_reconstructed_delta_is_reported_as_full_inventory_evidence() -> None:
    source = _scan()
    scan = CloudScanInput(
        tenant_id=source.tenant_id,
        endpoint_id=source.endpoint_id,
        scan_id=source.scan_id,
        result=source.result,
        inventory_sync={
            "mode": "delta",
            "snapshot_hash": "a" * 64,
            "previous_hash": "b" * 64,
            "changes": {"software": {"replacements": [], "removed": []}},
            "reconstructed_snapshot": {"software": [{"name": "requests"}]},
        },
        sbom=source.sbom,
    )
    engine = CloudAnalysisEngine(clock=lambda: NOW)
    results = {tool: engine.analyze_tool(tool, scan) for tool in engine.expected_tools}

    report = engine.build_final_report(scan, results)

    assert report["completeness"]["full_inventory_available"] is True
    assert report["endpoint_evidence"]["inventory_sync"]["reconstructed_snapshot"] == {
        "software": [{"name": "requests"}]
    }


def test_secret_shaped_endpoint_fields_are_redacted_in_final_report() -> None:
    scan = _scan()
    secret_scan = CloudScanInput(
        tenant_id=scan.tenant_id,
        endpoint_id=scan.endpoint_id,
        scan_id=scan.scan_id,
        result={**scan.result, "api_token": "must-not-survive"},
        inventory_sync=scan.inventory_sync,
        sbom=scan.sbom,
    )
    engine = CloudAnalysisEngine(clock=lambda: NOW)
    results = {
        tool: engine.analyze_tool(tool, secret_scan) for tool in engine.expected_tools
    }

    report = engine.build_final_report(secret_scan, results)

    assert report["endpoint_evidence"]["result"]["api_token"] == "<redacted>"
