from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.core.config import ScannerSettings, ToolSettings
from app.models import AuthorizationScope, CollectorState, ScanJob, ScanType
from app.orchestrator.deep_scan import create_stateless_orchestrator
from app.tools import (
    AmassAdapter,
    AmassRequest,
    DepScanAdapter,
    OpenScapAdapter,
    OpenScapRequest,
    OsqueryAdapter,
    OsvScannerAdapter,
    OsvScanRequest,
    ToolState,
)

pytestmark = pytest.mark.integration


def _require_live_tools() -> None:
    if os.environ.get("SCANNER_RUN_LIVE_TOOLS") != "1":
        pytest.skip("set SCANNER_RUN_LIVE_TOOLS=1 to run installed-tool smoke tests")


def _configured_executable(variable: str, tool_name: str) -> Path:
    raw_path = os.environ.get(variable)
    if not raw_path:
        pytest.skip(f"set {variable} to an approved absolute {tool_name} executable path")
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        pytest.fail(f"{variable} must be an absolute path")
    try:
        executable = candidate.resolve(strict=True)
    except OSError as exc:
        pytest.fail(f"{variable} does not resolve to an installed executable: {exc}")
    if not executable.is_file():
        pytest.fail(f"{variable} must resolve to a regular file")
    return executable


def test_live_osquery_smoke() -> None:
    _require_live_tools()
    adapter = OsqueryAdapter(max_concurrency=1)
    if not adapter.is_available():
        pytest.skip("osqueryi is not installed")

    execution = adapter.execute("os_info", timeout_seconds=10)

    assert execution.status is ToolState.SUCCESS
    assert execution.payload
    assert execution.payload[0].get("name")


def test_live_osv_scanner_on_safe_local_manifest(tmp_path: Path) -> None:
    _require_live_tools()
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("", encoding="utf-8")
    adapter = OsvScannerAdapter(approved_roots=(tmp_path,))
    if not adapter.is_available():
        pytest.skip("osv-scanner is not installed")

    execution = adapter.execute(
        OsvScanRequest(manifest, recursive=False),
        timeout_seconds=30,
    )

    assert execution.status is ToolState.SUCCESS
    assert execution.payload == []


def test_live_depscan_configured_executable_health_smoke() -> None:
    """Exercise only dep-scan's bounded version probe, not endpoint collection."""

    _require_live_tools()
    executable = _configured_executable(
        "SCANNER_LIVE_DEPSCAN_EXECUTABLE",
        "OWASP dep-scan",
    )
    adapter = DepScanAdapter(executable=str(executable))

    health = adapter.health()

    assert health.status is ToolState.SUCCESS
    assert health.version
    assert health.executable is not None
    assert Path(health.executable).resolve(strict=True) == executable


def test_live_depscan_stateless_endpoint_orchestration(tmp_path: Path) -> None:
    """Qualify live-OS integration in memory after explicit endpoint authorization.

    This deliberately calls ``StatelessScanner.execute`` instead of ``run_deep_scan``:
    no combined report, child report, queue, or database is persisted by the test.
    No domain-discovery job is constructed.
    """

    _require_live_tools()
    if os.environ.get("SCANNER_RUN_LIVE_ENDPOINT_ORCHESTRATION") != "1":
        pytest.skip(
            "set SCANNER_RUN_LIVE_ENDPOINT_ORCHESTRATION=1 to run the in-memory "
            "endpoint orchestration smoke test"
        )
    if os.environ.get("SCANNER_LIVE_ENDPOINT_AUTHORIZED") != "1":
        pytest.skip(
            "set SCANNER_LIVE_ENDPOINT_AUTHORIZED=1 only when this endpoint is "
            "explicitly authorized for a live scan"
        )
    executable = _configured_executable(
        "SCANNER_LIVE_DEPSCAN_EXECUTABLE",
        "OWASP dep-scan",
    )
    data_directory = tmp_path / "must-not-be-created"
    settings = ScannerSettings(
        environment="test",
        data_directory=data_directory,
        tools=ToolSettings(depscan_executable=executable),
    )
    now = datetime.now(UTC)
    endpoint_id = "live-depscan-qualification-endpoint"

    with create_stateless_orchestrator(settings) as resources:
        job = ScanJob(
            job_id="job-live-depscan-qualification",
            scan_id="scan-live-depscan-qualification",
            scan_type=ScanType.FULL,
            authorization=AuthorizationScope(
                scope_id="scope-live-depscan-qualification",
                authorized=True,
                authorization_reference="operator-approved-live-test",
                authorized_by="live-test-operator",
                purpose="local dep-scan orchestration compatibility qualification",
                valid_from=now - timedelta(minutes=1),
                expires_at=now + timedelta(minutes=30),
                allowed_endpoint_ids=frozenset({endpoint_id}),
            ),
            endpoint_id=endpoint_id,
            policy_id=resources.scanner.policy.policy_id,
            policy_version=resources.scanner.policy.policy_version,
            initiated_by="live-test-operator",
            requested_at=now,
            deadline=now + timedelta(minutes=20),
            timeout_seconds=900,
        )

        result = resources.scanner.execute(job)

    depscan = result.collectors.get("depscan.live-os")
    assert depscan is not None
    assert depscan.status in {CollectorState.SUCCESS, CollectorState.PARTIAL}
    assert result.endpoint_id == endpoint_id
    assert result.scan_type is ScanType.FULL
    assert result.metadata.get("persistence_mode") == "STATELESS"
    assert not data_directory.exists()
    assert not list(tmp_path.rglob("*.json"))
    assert not list(tmp_path.rglob("*.sqlite*"))


def test_live_openscap_with_operator_supplied_local_fixture() -> None:
    _require_live_tools()
    raw_content = os.environ.get("SCANNER_LIVE_SCAP_CONTENT")
    profile = os.environ.get("SCANNER_LIVE_SCAP_PROFILE")
    if not raw_content or not profile:
        pytest.skip(
            "set SCANNER_LIVE_SCAP_CONTENT and SCANNER_LIVE_SCAP_PROFILE "
            "to an approved local benchmark"
        )
    content = Path(raw_content).expanduser().resolve(strict=True)
    adapter = OpenScapAdapter(approved_roots=(content.parent,))
    if not adapter.is_available():
        pytest.skip("oscap is not installed")

    execution = adapter.execute(
        OpenScapRequest(content, profile),
        timeout_seconds=120,
    )

    assert execution.status is ToolState.SUCCESS
    assert execution.payload


def test_live_amass_requires_operator_authorized_domain() -> None:
    _require_live_tools()
    domain = os.environ.get("SCANNER_LIVE_AMASS_DOMAIN")
    if not domain:
        pytest.skip(
            "set SCANNER_LIVE_AMASS_DOMAIN only for a domain explicitly authorized for discovery"
        )
    adapter = AmassAdapter(
        maximum_timeout_seconds=60,
        maximum_dns_concurrency=1,
        maximum_dns_queries_per_second=1,
    )
    if not adapter.is_available():
        pytest.skip("amass is not installed")

    execution = adapter.execute(
        AmassRequest(
            target=domain,
            authorized_domains=(domain,),
            authorization_id="live-smoke-operator-approval",
            authorized=True,
            max_dns_concurrency=1,
            max_dns_queries_per_second=1,
            timeout_seconds=30,
            max_assets=1_000,
        )
    )

    assert execution.status in {ToolState.SUCCESS, ToolState.PARTIAL}
    assert all(
        item["hostname"] == domain or item["hostname"].endswith(f".{domain}")
        for item in execution.payload or []
    )
