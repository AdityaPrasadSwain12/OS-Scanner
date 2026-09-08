from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.core import (
    CloudAPISettings,
    DiscoverySettings,
    RuntimeLimits,
    ScannerSettings,
    ToolSettings,
)
from app.models import (
    AuthorizationScope,
    CollectorState,
    CollectorStatus,
    OperatingSystemFamily,
    ScanJob,
    ScanType,
    Software,
)
from app.orchestrator import CollectionBundle, CollectorPipeline
from app.tools import DepScanMode, DepScanRequest, ToolExecution, ToolState
from app.tools.osquery.queries import DEFAULT_QUERY_REGISTRY


def _authorization(*, domain: bool = False) -> AuthorizationScope:
    now = datetime.now(UTC)
    return AuthorizationScope(
        scope_id="scope-1",
        authorized=True,
        authorization_reference="ticket-1",
        valid_from=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        allowed_domains={"example.test"} if domain else set(),
        allowed_endpoint_ids=set() if domain else {"endpoint-1"},
        excluded_domains={"excluded.example.test"} if domain else set(),
    )


def _job(
    scan_type: ScanType = ScanType.QUICK,
    *,
    collectors: set[str] | None = None,
    sources: tuple[str, ...] = (),
) -> ScanJob:
    return ScanJob(
        scan_id=f"scan-{scan_type.value.casefold()}",
        scan_type=scan_type,
        endpoint_id="endpoint-1",
        authorization=_authorization(),
        approved_collectors=collectors or set(),
        approved_sources=sources,
    )


class FakeNativeCollector:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[str, object]] = []

    def collect(self, scan_type: str, selected: object = None) -> object:
        self.calls.append((scan_type, selected))
        if self.fail:
            raise OSError("password=must-not-leak")
        return SimpleNamespace(
            platform="linux",
            data={
                "posture": {"firewall": {"status": "Status: active"}},
                "patches": {},
                "persistence": {},
            },
            statuses=(
                SimpleNamespace(
                    name="firewall",
                    category="posture",
                    status=ToolState.SUCCESS,
                    duration_seconds=0.01,
                    count=1,
                    error=None,
                    metadata={},
                ),
            ),
        )


class MixedNativeCollector:
    def collect(self, scan_type: str, selected: object = None) -> object:
        del scan_type, selected
        return SimpleNamespace(
            platform="linux",
            data={
                "posture": {"firewall": {"status": "Status: active"}},
                "patches": {},
                "persistence": {},
            },
            statuses=(
                SimpleNamespace(
                    name="firewall",
                    category="posture",
                    status=ToolState.SUCCESS,
                    duration_seconds=0.01,
                    count=1,
                    error=None,
                    metadata={},
                ),
                SimpleNamespace(
                    name="disk_encryption",
                    category="posture",
                    status=ToolState.FAILED,
                    duration_seconds=0.01,
                    count=0,
                    error="permission denied",
                    metadata={},
                ),
            ),
        )


class MalformedInventoryCollector:
    def collect(self, scan_type: str, selected: object = None) -> object:
        del scan_type, selected
        return SimpleNamespace(
            platform="windows",
            data={"inventory": {"software": [{"not_name": "malformed"}]}},
            statuses=(
                SimpleNamespace(
                    name="software",
                    category="inventory",
                    status=ToolState.SUCCESS,
                    duration_seconds=0.01,
                    count=1,
                    error=None,
                    metadata={},
                ),
            ),
        )


class OptionalLinuxCapabilityCollector:
    def collect(self, scan_type: str, selected: object = None) -> object:
        del scan_type, selected
        return SimpleNamespace(
            platform="linux",
            data={
                "posture": {
                    "disk_encryption": {"root_volume_encrypted": False},
                }
            },
            statuses=(
                SimpleNamespace(
                    name="firewall_ufw",
                    category="posture",
                    status=ToolState.UNAVAILABLE,
                    duration_seconds=0.0,
                    count=0,
                    error=None,
                    metadata={},
                ),
                SimpleNamespace(
                    name="disk_encryption",
                    category="posture",
                    status=ToolState.SUCCESS,
                    duration_seconds=0.01,
                    count=1,
                    error=None,
                    metadata={},
                ),
            ),
        )


class FakeOsquery:
    def __init__(
        self,
        *,
        states: dict[str, ToolState] | None = None,
        registry: tuple[str, ...] = (
            "os_info",
            "system_info",
            "uptime",
            "software",
            "interfaces",
            "listening_ports",
        ),
    ) -> None:
        self._queries = dict.fromkeys(registry, "SELECT 1")
        self.states = states or {}
        self.selected: tuple[str, ...] = ()

    def version(self) -> str:
        return "5.15.0"

    def run_registered(
        self, selected: tuple[str, ...]
    ) -> dict[str, ToolExecution[list[dict[str, str]]]]:
        self.selected = selected
        executions: dict[str, ToolExecution[list[dict[str, str]]]] = {}
        for name in selected:
            payload: list[dict[str, str]] = []
            if name == "os_info":
                payload = [{"name": "Example Linux", "version": "1", "platform": "linux"}]
            elif name == "system_info":
                payload = [{"hostname": "host-1", "cpu_brand": "Example CPU"}]
            executions[name] = ToolExecution(
                tool="osquery",
                status=self.states.get(name, ToolState.SUCCESS),
                payload=payload,
                duration_seconds=0.01,
            )
        return executions


class FakeOpenScap:
    def version(self) -> str:
        return "1.3.10"

    def evaluate(self, content: Path, profile: str) -> ToolExecution[list[dict[str, Any]]]:
        del content, profile
        return ToolExecution(
            tool="openscap",
            status=ToolState.SUCCESS,
            payload=[
                {
                    "rule_id": "xccdf-rule-1",
                    "title": "Rule one",
                    "status": "FAILED",
                    "severity": "HIGH",
                }
            ],
        )


class FakeOsv:
    def __init__(self) -> None:
        self.sources: list[Path] = []

    def version(self) -> str:
        return "2.0.0"

    def scan(self, source: Path) -> ToolExecution[list[dict[str, Any]]]:
        self.sources.append(source)
        return ToolExecution(
            tool="osv-scanner",
            status=ToolState.SUCCESS,
            payload=[
                {
                    "vulnerability_id": "CVE-2026-0001",
                    "package": {"name": "example", "version": "1", "ecosystem": "PyPI"},
                    "severity": "CRITICAL",
                }
            ],
        )


class MixedOsv(FakeOsv):
    def scan(self, source: Path) -> ToolExecution[list[dict[str, Any]]]:
        if source.name == "failed.lock":
            self.sources.append(source)
            return ToolExecution(
                tool="osv-scanner",
                status=ToolState.FAILED,
                error="source could not be scanned",
            )
        return super().scan(source)


class FakeDepScan:
    def __init__(self) -> None:
        self.requests: list[DepScanRequest] = []

    def version(self) -> str:
        return "6.1.0"

    def execute(
        self, request: DepScanRequest
    ) -> ToolExecution[list[dict[str, Any]]]:
        self.requests.append(request)
        return ToolExecution(
            tool="depscan",
            status=ToolState.SUCCESS,
            payload=[
                {
                    "vulnerability_id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": ["CVE-2026-0001"],
                    "package": {
                        "name": "example",
                        "version": "1",
                        "ecosystem": "PyPI",
                    },
                    "severity": "HIGH",
                }
            ],
        )


class FakeAmass:
    def __init__(self, state: ToolState = ToolState.SUCCESS) -> None:
        self.state = state
        self.arguments: dict[str, Any] = {}

    def version(self) -> str:
        return "4.2.0"

    def discover(self, target: str, **kwargs: Any) -> ToolExecution[list[dict[str, Any]]]:
        self.arguments = {"target": target, **kwargs}
        return ToolExecution(
            tool="amass",
            status=self.state,
            payload=[{"hostname": "api.example.test", "addresses": ["192.0.2.10"]}],
        )


class RaisingOpenScap(FakeOpenScap):
    def evaluate(self, content: Path, profile: str) -> ToolExecution[list[dict[str, Any]]]:
        del content, profile
        raise RuntimeError("OpenSCAP adapter crashed")


class VersionRaisingOpenScap(FakeOpenScap):
    def version(self) -> str:
        raise RuntimeError("OpenSCAP version probe crashed")


class FirstSourceRaisingOsv(FakeOsv):
    def scan(self, source: Path) -> ToolExecution[list[dict[str, Any]]]:
        if not self.sources:
            self.sources.append(source)
            raise RuntimeError("OSV-Scanner adapter crashed")
        return super().scan(source)


class LiveOsRaisingDepScan(FakeDepScan):
    def execute(
        self, request: DepScanRequest
    ) -> ToolExecution[list[dict[str, Any]]]:
        if request.mode is DepScanMode.LIVE_OS:
            self.requests.append(request)
            raise RuntimeError("dep-scan adapter crashed")
        return super().execute(request)


class RaisingAmass(FakeAmass):
    def discover(self, target: str, **kwargs: Any) -> ToolExecution[list[dict[str, Any]]]:
        del target, kwargs
        raise RuntimeError("Amass adapter crashed")


class ControlFlowRaisingOsv(FakeOsv):
    def __init__(self, exception: BaseException) -> None:
        super().__init__()
        self.exception = exception

    def scan(self, source: Path) -> ToolExecution[list[dict[str, Any]]]:
        del source
        raise self.exception


def _pipeline(
    settings: ScannerSettings,
    *,
    native: FakeNativeCollector | None = None,
    osquery: FakeOsquery | None = None,
    openscap: FakeOpenScap | None = None,
    osv: FakeOsv | None = None,
    depscan: FakeDepScan | None = None,
    amass: FakeAmass | None = None,
) -> CollectorPipeline:
    native = native or FakeNativeCollector()
    return CollectorPipeline(
        settings,
        native_factory=lambda: native,  # type: ignore[arg-type,return-value]
        osquery=osquery or FakeOsquery(),  # type: ignore[arg-type]
        openscap=openscap or FakeOpenScap(),  # type: ignore[arg-type]
        osv_scanner=osv or FakeOsv(),  # type: ignore[arg-type]
        depscan=depscan,  # type: ignore[arg-type]
        amass=amass or FakeAmass(),  # type: ignore[arg-type]
    )


def test_quick_pipeline_collects_only_controlled_queries_and_aggregates_partial() -> None:
    osquery = FakeOsquery(states={"software": ToolState.TIMEOUT})
    pipeline = _pipeline(ScannerSettings(environment="test"), osquery=osquery)

    bundle = pipeline.collect(_job())

    assert set(osquery.selected) == set(osquery._queries)
    assert bundle.inventory["os"].name == "Example Linux"
    assert bundle.inventory["security"].firewall_enabled is True
    assert bundle.collectors["osquery"].status is CollectorState.PARTIAL
    assert bundle.tool_versions["osquery"] == "5.15.0"


def test_on_demand_selection_rejects_unknown_or_locally_disabled_query() -> None:
    settings = ScannerSettings(
        environment="test",
        tools=ToolSettings(enabled_osquery_queries={"os_info"}),
    )
    pipeline = _pipeline(settings)

    unknown = pipeline.collect(_job(ScanType.ON_DEMAND, collectors={"not_registered"}))
    forbidden = pipeline.collect(_job(ScanType.ON_DEMAND, collectors={"system_info"}))

    assert unknown.collectors["osquery"].status is CollectorState.FAILED
    assert unknown.collectors["osquery"].error_code == "OSQUERY_PIPELINE_FAILED"
    assert forbidden.collectors["osquery"].status is CollectorState.FAILED


@pytest.mark.parametrize(
    ("family", "expected", "excluded"),
    (
        (
            OperatingSystemFamily.WINDOWS,
            {"software", "services", "logical_drives", "interfaces_windows"},
            {"packages", "services_linux", "mounts", "dns_resolvers", "software_macos"},
        ),
        (
            OperatingSystemFamily.LINUX,
            {"packages", "packages_rpm", "services_linux", "mounts", "dns_resolvers"},
            {"software", "services", "logical_drives", "services_macos", "software_macos"},
        ),
        (
            OperatingSystemFamily.MACOS,
            {
                "software_macos",
                "packages_homebrew",
                "services_macos",
                "mounts",
                "browser_extensions_safari",
            },
            {"software", "packages", "services", "services_linux", "logical_drives"},
        ),
    ),
)
def test_full_query_selection_is_strictly_platform_compatible(
    family: OperatingSystemFamily, expected: set[str], excluded: set[str]
) -> None:
    osquery = FakeOsquery()
    osquery._queries = dict(DEFAULT_QUERY_REGISTRY)
    pipeline = _pipeline(ScannerSettings(environment="test"), osquery=osquery)

    selected = set(pipeline._selected_queries(_job(ScanType.FULL), family))

    assert expected <= selected
    assert selected.isdisjoint(excluded)


def test_on_demand_selection_rejects_a_registered_query_for_another_platform() -> None:
    osquery = FakeOsquery()
    osquery._queries = dict(DEFAULT_QUERY_REGISTRY)
    pipeline = _pipeline(ScannerSettings(environment="test"), osquery=osquery)

    with pytest.raises(PermissionError, match="incompatible"):
        pipeline._selected_queries(
            _job(ScanType.ON_DEMAND, collectors={"services"}),
            OperatingSystemFamily.LINUX,
        )


def test_native_boundary_is_failure_isolated_and_on_demand_can_skip_native() -> None:
    failed_native = FakeNativeCollector(fail=True)
    failed = _pipeline(
        ScannerSettings(environment="test"), native=failed_native
    ).collect(_job())
    assert failed.collectors["native"].status is CollectorState.FAILED
    assert "must-not-leak" not in (failed.collectors["native"].error_message or "")

    native = FakeNativeCollector()
    pipeline = _pipeline(ScannerSettings(environment="test"), native=native)
    pipeline.collect(_job(ScanType.ON_DEMAND, collectors={"os_info"}))
    assert native.calls == []


def test_mixed_native_result_normalizes_successful_components_and_reports_failure() -> None:
    pipeline = _pipeline(
        ScannerSettings(environment="test"),
        native=MixedNativeCollector(),  # type: ignore[arg-type]
    )

    bundle = pipeline.collect(_job())

    assert bundle.inventory["security"].firewall_enabled is True
    assert bundle.inventory["security"].disk_encryption_enabled is None
    assert bundle.collectors["native.firewall"].status is CollectorState.SUCCESS
    assert bundle.collectors["native.disk_encryption"].status is CollectorState.FAILED
    assert bundle.collectors["native.disk_encryption"].error_message == "permission denied"
    assert "security" not in bundle.observed_inventory_sections
    assert "security" in bundle.incomplete_inventory_sections


def test_malformed_native_rows_make_section_partial_and_non_authoritative() -> None:
    pipeline = CollectorPipeline(
        ScannerSettings(environment="test"),
        native_factory=lambda: MalformedInventoryCollector(),  # type: ignore[arg-type,return-value]
    )

    bundle = pipeline.collect(_job())

    assert bundle.inventory["software"] == []
    assert bundle.collectors["native.software"].status is CollectorState.PARTIAL
    assert (
        bundle.collectors["native.software"].error_code
        == "NATIVE_NORMALIZATION_PARTIAL"
    )
    assert "software" not in bundle.observed_inventory_sections


def test_unavailable_optional_linux_capability_is_skipped_not_failed() -> None:
    pipeline = CollectorPipeline(
        ScannerSettings(environment="test"),
        native_factory=lambda: OptionalLinuxCapabilityCollector(),  # type: ignore[arg-type,return-value]
    )

    bundle = pipeline.collect(_job())

    assert bundle.collectors["native.firewall_ufw"].status is CollectorState.SKIPPED
    assert bundle.collectors["native.disk_encryption"].status is CollectorState.SUCCESS
    assert "security" in bundle.observed_inventory_sections
    assert "security" not in bundle.incomplete_inventory_sections


def test_full_pipeline_runs_linux_openscap_and_osv_when_configured(tmp_path: Path) -> None:
    content = tmp_path / "baseline.xml"
    content.write_text("<Benchmark/>", encoding="utf-8")
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("example==1", encoding="utf-8")
    osv = FakeOsv()
    settings = ScannerSettings(
        environment="test",
        tools=ToolSettings(
            approved_scap_content_roots=(tmp_path,),
            default_scap_content=content,
            default_scap_profile="profile-1",
        ),
    )
    pipeline = _pipeline(settings, osv=osv)

    bundle = pipeline.collect(_job(ScanType.FULL, sources=(str(manifest),)))

    assert bundle.collectors["openscap"].status is CollectorState.SUCCESS
    assert bundle.inventory["compliance"][0].rule_id == "xccdf-rule-1"
    assert bundle.inventory["vulnerabilities"][0].vulnerability_id == "CVE-2026-0001"
    assert osv.sources == [manifest]


def test_openscap_exception_is_terminal_and_later_tools_continue(tmp_path: Path) -> None:
    content = tmp_path / "baseline.xml"
    content.write_text("<Benchmark/>", encoding="utf-8")
    settings = ScannerSettings(
        environment="test",
        tools=ToolSettings(
            approved_scap_content_roots=(tmp_path,),
            default_scap_content=content,
            default_scap_profile="profile-1",
        ),
    )

    bundle = _pipeline(settings, openscap=RaisingOpenScap()).collect(
        _job(ScanType.FULL)
    )

    assert bundle.collectors["openscap"].status is CollectorState.FAILED
    assert bundle.collectors["openscap"].error_code == "OPENSCAP_PIPELINE_FAILED"
    assert bundle.collectors["depscan"].status is CollectorState.SKIPPED
    assert "compliance" in bundle.incomplete_inventory_sections


def test_openscap_version_exception_does_not_discard_evaluation(tmp_path: Path) -> None:
    content = tmp_path / "baseline.xml"
    content.write_text("<Benchmark/>", encoding="utf-8")
    settings = ScannerSettings(
        environment="test",
        tools=ToolSettings(
            approved_scap_content_roots=(tmp_path,),
            default_scap_content=content,
            default_scap_profile="profile-1",
        ),
    )

    bundle = _pipeline(settings, openscap=VersionRaisingOpenScap()).collect(
        _job(ScanType.FULL)
    )

    assert bundle.collectors["openscap.version"].status is CollectorState.FAILED
    assert bundle.collectors["openscap"].status is CollectorState.SUCCESS
    assert "compliance" in bundle.observed_inventory_sections


def test_mixed_osv_sources_keep_successes_without_marking_section_fully_observed(
    tmp_path: Path,
) -> None:
    good = tmp_path / "good.lock"
    failed = tmp_path / "failed.lock"
    good.write_text("example==1", encoding="utf-8")
    failed.write_text("broken", encoding="utf-8")
    osv = MixedOsv()
    pipeline = _pipeline(ScannerSettings(environment="test"), osv=osv)

    bundle = pipeline.collect(
        _job(ScanType.VULNERABILITY, sources=(str(good), str(failed)))
    )

    assert [item.vulnerability_id for item in bundle.inventory["vulnerabilities"]] == [
        "CVE-2026-0001"
    ]
    assert bundle.collectors["osv-scanner.1"].status is CollectorState.SUCCESS
    assert bundle.collectors["osv-scanner.2"].status is CollectorState.FAILED
    assert "vulnerabilities" not in bundle.observed_inventory_sections
    assert osv.sources == [good, failed]


def test_osv_exception_is_isolated_per_source_and_later_source_continues(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.lock"
    second = tmp_path / "second.lock"
    first.write_text("broken", encoding="utf-8")
    second.write_text("example==1", encoding="utf-8")
    osv = FirstSourceRaisingOsv()

    bundle = _pipeline(ScannerSettings(environment="test"), osv=osv).collect(
        _job(ScanType.VULNERABILITY, sources=(str(first), str(second)))
    )

    assert bundle.collectors["osv-scanner.1"].status is CollectorState.FAILED
    assert (
        bundle.collectors["osv-scanner.1"].error_code
        == "OSV_SCANNER_PIPELINE_FAILED"
    )
    assert bundle.collectors["osv-scanner.2"].status is CollectorState.SUCCESS
    assert [item.vulnerability_id for item in bundle.inventory["vulnerabilities"]] == [
        "CVE-2026-0001"
    ]
    assert "vulnerabilities" in bundle.incomplete_inventory_sections


def test_full_pipeline_runs_depscan_live_os_and_merges_source_evidence(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()
    (source / "requirements.txt").write_text("example==1", encoding="utf-8")
    depscan = FakeDepScan()
    pipeline = _pipeline(
        ScannerSettings(environment="test"),
        osv=FakeOsv(),
        depscan=depscan,
    )

    bundle = pipeline.collect(
        _job(ScanType.FULL, sources=(str(source),))
    )

    assert [request.mode for request in depscan.requests] == [
        DepScanMode.LIVE_OS,
        DepScanMode.SOURCE,
    ]
    assert bundle.collectors["depscan.live-os"].status is CollectorState.SUCCESS
    assert bundle.collectors["depscan.source.1"].status is CollectorState.SUCCESS
    assert len(bundle.inventory["vulnerabilities"]) == 1
    assert bundle.inventory["vulnerabilities"][0].evidence["sources"] == [
        "osv-scanner",
        "owasp-dep-scan",
    ]
    assert "vulnerabilities" in bundle.observed_inventory_sections


def test_depscan_exception_is_isolated_per_request_and_source_continues(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()
    (source / "requirements.txt").write_text("example==1", encoding="utf-8")
    depscan = LiveOsRaisingDepScan()

    bundle = _pipeline(
        ScannerSettings(environment="test"),
        osv=FakeOsv(),
        depscan=depscan,
    ).collect(_job(ScanType.FULL, sources=(str(source),)))

    assert bundle.collectors["depscan.live-os"].status is CollectorState.FAILED
    assert (
        bundle.collectors["depscan.live-os"].error_code
        == "DEPSCAN_PIPELINE_FAILED"
    )
    assert bundle.collectors["depscan.source.1"].status is CollectorState.SUCCESS
    assert [request.mode for request in depscan.requests] == [
        DepScanMode.LIVE_OS,
        DepScanMode.SOURCE,
    ]
    assert "vulnerabilities" in bundle.incomplete_inventory_sections


def test_full_pipeline_skips_unconfigured_optional_scap_and_osv_enrichment() -> None:
    bundle = _pipeline(ScannerSettings(environment="test")).collect(_job(ScanType.FULL))

    assert bundle.collectors["openscap"].status is CollectorState.SKIPPED
    assert bundle.collectors["osv-scanner"].status is CollectorState.SKIPPED
    assert bundle.collectors["depscan"].status is CollectorState.SKIPPED


def test_cloud_offload_never_invokes_endpoint_vulnerability_tools() -> None:
    osv = FakeOsv()
    depscan = FakeDepScan()
    settings = ScannerSettings(
        environment="test",
        cloud=CloudAPISettings(offload_vulnerability_analysis=True),
    )

    bundle = _pipeline(settings, osv=osv, depscan=depscan).collect(
        _job(ScanType.FULL)
    )

    assert osv.sources == []
    assert depscan.requests == []
    assert bundle.collectors["osv-scanner.cloud"].status is CollectorState.SKIPPED
    assert bundle.collectors["depscan.cloud"].status is CollectorState.SKIPPED
    assert (
        bundle.collectors["osv-scanner.cloud"].metadata["execution_location"]
        == "cloud"
    )


def test_null_openscap_executable_disables_path_discovery(tmp_path: Path) -> None:
    content = tmp_path / "baseline.xml"
    content.write_text("<Benchmark/>", encoding="utf-8")
    settings = ScannerSettings(
        environment="test",
        tools=ToolSettings(
            openscap_executable=None,
            approved_scap_content_roots=(tmp_path,),
            default_scap_content=content,
            default_scap_profile="profile-1",
        ),
    )
    pipeline = CollectorPipeline(
        settings,
        native_factory=lambda: FakeNativeCollector(),  # type: ignore[arg-type,return-value]
        osquery=FakeOsquery(),  # type: ignore[arg-type]
    )

    bundle = pipeline.collect(_job(ScanType.FULL))

    assert bundle.collectors["openscap"].status is CollectorState.SKIPPED
    assert "not enabled" in (bundle.collectors["openscap"].error_message or "")


def test_unconfigured_osquery_is_disabled_even_if_a_binary_could_be_discovered() -> None:
    native = FakeNativeCollector()
    pipeline = CollectorPipeline(
        ScannerSettings(environment="test"),
        native_factory=lambda: native,  # type: ignore[arg-type,return-value]
    )

    bundle = pipeline.collect(_job(ScanType.QUICK))

    assert native.calls == [("QUICK", None)]
    assert bundle.collectors["osquery"].status is CollectorState.SKIPPED
    assert "not enabled" in (bundle.collectors["osquery"].error_message or "")
    assert not any(name.startswith("osquery.") for name in bundle.collectors)


def test_attack_surface_requires_local_enablement_and_passes_bounded_scope() -> None:
    job = ScanJob(
        scan_id="scan-domain",
        scan_type=ScanType.ATTACK_SURFACE,
        target="example.test",
        authorization=_authorization(domain=True),
        timeout_seconds=30,
        parameters={"scope": ["api.example.test"]},
    )
    disabled = _pipeline(ScannerSettings(environment="test")).collect(job)
    assert disabled.collectors["amass"].error_code == "DISCOVERY_DISABLED"

    amass = FakeAmass()
    settings = ScannerSettings(
        environment="test",
        discovery=DiscoverySettings(
            enabled=True,
            authorized_domains={"example.test"},
            max_dns_concurrency=3,
            max_dns_queries_per_second=5,
            timeout_seconds=20,
        ),
    )
    enabled = _pipeline(settings, amass=amass).collect(job)
    assert enabled.inventory["attack_surface"][0].hostname == "api.example.test"
    assert amass.arguments["target"] == "example.test"
    assert amass.arguments["scope"] == ("api.example.test",)
    assert amass.arguments["exclusions"] == ("excluded.example.test",)
    assert amass.arguments["max_dns_concurrency"] == 3
    assert amass.arguments["max_dns_queries_per_second"] == 5
    assert amass.arguments["timeout_seconds"] == 20


def test_amass_exception_becomes_terminal_failed_attack_surface_result() -> None:
    job = ScanJob(
        scan_id="scan-amass-failure",
        scan_type=ScanType.ATTACK_SURFACE,
        target="example.test",
        authorization=_authorization(domain=True),
        timeout_seconds=30,
    )
    settings = ScannerSettings(
        environment="test",
        discovery=DiscoverySettings(
            enabled=True,
            authorized_domains={"example.test"},
        ),
    )

    bundle = _pipeline(settings, amass=RaisingAmass()).collect(job)

    assert bundle.collectors["amass"].status is CollectorState.FAILED
    assert bundle.collectors["amass"].error_code == "AMASS_PIPELINE_FAILED"
    assert bundle.inventory["attack_surface"] == []


def test_null_amass_executable_disables_path_discovery() -> None:
    job = ScanJob(
        scan_id="scan-amass-disabled",
        scan_type=ScanType.ATTACK_SURFACE,
        target="example.test",
        authorization=_authorization(domain=True),
        timeout_seconds=30,
    )
    settings = ScannerSettings(
        environment="test",
        discovery=DiscoverySettings(
            enabled=True,
            authorized_domains={"example.test"},
        ),
        tools=ToolSettings(amass_executable=None),
    )

    bundle = CollectorPipeline(settings).collect(job)

    assert bundle.collectors["amass"].status is CollectorState.SKIPPED
    assert "not enabled" in (bundle.collectors["amass"].error_message or "")
    assert bundle.inventory["attack_surface"] == []


@pytest.mark.parametrize("exception", [KeyboardInterrupt(), SystemExit(2)])
def test_external_tool_boundary_preserves_process_control_exceptions(
    tmp_path: Path,
    exception: BaseException,
) -> None:
    source = tmp_path / "requirements.txt"
    source.write_text("example==1", encoding="utf-8")
    pipeline = _pipeline(
        ScannerSettings(environment="test"),
        osv=ControlFlowRaisingOsv(exception),
    )

    with pytest.raises(type(exception)):
        pipeline.collect(
            _job(ScanType.VULNERABILITY, sources=(str(source),))
        )


def test_attack_surface_cannot_escape_local_discovery_allowlist() -> None:
    job = ScanJob(
        scan_id="scan-local-scope",
        scan_type=ScanType.ATTACK_SURFACE,
        target="example.test",
        authorization=_authorization(domain=True),
        timeout_seconds=30,
    )
    settings = ScannerSettings(
        environment="test",
        discovery=DiscoverySettings(
            enabled=True,
            authorized_domains={"customer.example.test"},
        ),
    )

    with pytest.raises(PermissionError, match="locally administered discovery allowlist"):
        _pipeline(settings, amass=FakeAmass()).collect(job)


def test_collection_bundle_renames_duplicate_collector_statuses() -> None:
    bundle = CollectionBundle(inventory={})
    for _ in range(3):
        bundle.add_status(
            CollectorStatus(name="same", status=CollectorState.SUCCESS)
        )
    assert set(bundle.collectors) == {"same", "same.2", "same.3"}


def test_normalized_inventory_record_limit_is_enforced() -> None:
    pipeline = _pipeline(
        ScannerSettings(
            environment="test",
            runtime=RuntimeLimits(max_inventory_records=100),
        )
    )
    bundle = CollectionBundle(
        inventory={"software": [Software(name=f"package-{index}") for index in range(101)]}
    )

    with pytest.raises(ValueError, match=r"inventory exceeds.*record limit"):
        pipeline._enforce_inventory_limit(bundle)
