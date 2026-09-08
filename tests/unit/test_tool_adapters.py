from __future__ import annotations

import json
from pathlib import Path
from threading import Event, Lock

import pytest

from app.models import ComplianceStatus
from app.normalization import normalize_openscap, normalize_osv
from app.tools import (
    AmassAdapter,
    AmassRequest,
    CommandResult,
    OpenScapAdapter,
    OpenScapRequest,
    OsqueryAdapter,
    OsvScannerAdapter,
    OsvScanRequest,
    ToolState,
)
from app.tools.osquery.queries import QueryDefinition


def command_result(
    stdout: str = "",
    *,
    returncode: int = 0,
    timed_out: bool = False,
    stdout_truncated: bool = False,
) -> CommandResult:
    return CommandResult(
        executable="mock-tool",
        arguments=(),
        returncode=returncode,
        stdout=stdout,
        stderr="mock failure" if returncode else "",
        duration_seconds=0.01,
        timed_out=timed_out,
        stdout_truncated=stdout_truncated,
    )


class FakeRunner:
    def __init__(self, outputs: dict[str, str] | None = None, *, available: bool = True) -> None:
        self.outputs = outputs or {}
        self.available = available
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def is_available(self, executable: str | Path) -> bool:
        return self.available

    def resolve(self, executable: str | Path) -> Path | None:
        return Path(f"/mock/{Path(executable).name}") if self.available else None

    def run(
        self,
        executable: str | Path,
        arguments: tuple[str, ...] = (),
        *,
        timeout_seconds: float | None = None,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        del timeout_seconds, cwd
        executable_text = str(executable)
        self.calls.append((executable_text, tuple(arguments)))
        if "--version" in arguments or arguments == ("version",):
            return command_result("mock 1.2.3")
        return command_result(self.outputs.get(executable_text, "[]"))


class FakeOpenScapRunner(FakeRunner):
    def __init__(self, result_xml: str) -> None:
        super().__init__()
        self.result_xml = result_xml

    def run(
        self,
        executable: str | Path,
        arguments: tuple[str, ...] = (),
        *,
        timeout_seconds: float | None = None,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        del timeout_seconds, cwd
        self.calls.append((str(executable), tuple(arguments)))
        result_path = Path(arguments[arguments.index("--results") + 1])
        result_path.write_text(self.result_xml, encoding="utf-8")
        return command_result(returncode=2)


def test_osquery_executes_only_registered_query() -> None:
    runner = FakeRunner({"osqueryi": '[{"name":"Linux","version":"1"}]'})
    adapter = OsqueryAdapter(runner=runner)  # type: ignore[arg-type]

    execution = adapter.execute("os_info")

    assert execution.status == ToolState.SUCCESS
    assert execution.payload == [{"name": "Linux", "version": "1"}]
    assert runner.calls[0][1][0] == "--json"
    assert runner.calls[0][1][1].startswith("SELECT ")
    with pytest.raises(ValueError):
        adapter.validate_input("SELECT * FROM processes;")


def test_osquery_rejects_truncated_output_and_excess_rows() -> None:
    registry = {
        "bounded": QueryDefinition(
            identifier="bounded",
            category="test",
            sql="SELECT 1 AS value;",
            maximum_rows=1,
        )
    }
    too_many = OsqueryAdapter(
        runner=FakeRunner({"osqueryi": '[{"value":1},{"value":2}]'}),  # type: ignore[arg-type]
        query_registry=registry,
    )

    class TruncatingRunner(FakeRunner):
        def run(
            self,
            executable: str | Path,
            arguments: tuple[str, ...] = (),
            *,
            timeout_seconds: float | None = None,
            cwd: str | Path | None = None,
        ) -> CommandResult:
            del executable, arguments, timeout_seconds, cwd
            return command_result("[]", stdout_truncated=True)

    truncated = OsqueryAdapter(
        runner=TruncatingRunner(),  # type: ignore[arg-type]
        query_registry=registry,
    )

    row_outcome = too_many.execute("bounded")
    truncation_outcome = truncated.execute("bounded")

    assert row_outcome.status is ToolState.FAILED
    assert row_outcome.error == "osquery row limit exceeded"
    assert truncation_outcome.status is ToolState.FAILED
    assert truncation_outcome.error == "osquery output exceeded the size limit"


def test_osquery_queued_query_uses_remaining_absolute_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 1.0}
    release_running_queries = Event()
    runner_lock = Lock()

    class DeadlineRunner(FakeRunner):
        def __init__(self) -> None:
            super().__init__()
            self.timeouts: list[float | None] = []
            self.started = 0

        def run(
            self,
            executable: str | Path,
            arguments: tuple[str, ...] = (),
            *,
            timeout_seconds: float | None = None,
            cwd: str | Path | None = None,
        ) -> CommandResult:
            del cwd
            with runner_lock:
                self.calls.append((str(executable), tuple(arguments)))
                self.timeouts.append(timeout_seconds)
                self.started += 1
                if self.started == 2:
                    clock["now"] = 11.0
                    release_running_queries.set()
            assert release_running_queries.wait(timeout=5.0)
            return command_result("[]")

    registry = {
        identifier: QueryDefinition(
            identifier=identifier,
            category="test",
            sql=f"SELECT '{identifier}' AS value;",
            maximum_rows=1,
        )
        for identifier in ("first", "second", "queued")
    }
    runner = DeadlineRunner()
    adapter = OsqueryAdapter(
        runner=runner,  # type: ignore[arg-type]
        query_registry=registry,
        max_concurrency=2,
    )
    monkeypatch.setattr("app.tools.osquery.adapter.time.monotonic", lambda: clock["now"])

    outcomes = adapter.run_registered(
        ("first", "second", "queued"),
        timeout_seconds=30.0,
        deadline_at=10.0,
    )

    assert outcomes["first"].status is ToolState.SUCCESS
    assert outcomes["second"].status is ToolState.SUCCESS
    assert outcomes["queued"].status is ToolState.TIMEOUT
    assert outcomes["queued"].error == "scan deadline exhausted before osquery query started"
    assert runner.timeouts == [9.0, 9.0]
    assert len(runner.calls) == 2


def test_osquery_scalar_batch_attributes_each_query_exactly() -> None:
    registry = {
        "first": QueryDefinition(
            "first",
            "test",
            "SELECT 'alpha' AS value;",
            maximum_rows=1,
            batch_columns=("value",),
        ),
        "second": QueryDefinition(
            "second",
            "test",
            "SELECT 'beta' AS value;",
            maximum_rows=1,
            batch_columns=("value",),
        ),
    }
    combined = json.dumps(
        [
            {
                "__scanner_count_0": 1,
                "__scanner_value_0_0": "alpha",
                "__scanner_count_1": 1,
                "__scanner_value_1_0": "beta",
            }
        ]
    )
    runner = FakeRunner({"osqueryi": combined})
    adapter = OsqueryAdapter(
        runner=runner,  # type: ignore[arg-type]
        query_registry=registry,
        max_concurrency=1,
    )

    outcomes = adapter.run_registered(("first", "second"))

    assert outcomes["first"].payload == [{"value": "alpha"}]
    assert outcomes["second"].payload == [{"value": "beta"}]
    assert outcomes["first"].metadata["batched"] is True
    assert outcomes["second"].metadata["batch_size"] == 2
    assert len(runner.calls) == 1


def test_osquery_invalid_scalar_batch_falls_back_to_individual_queries() -> None:
    registry = {
        "first": QueryDefinition(
            "first",
            "test",
            "SELECT 'alpha' AS first_value;",
            maximum_rows=1,
            batch_columns=("first_value",),
        ),
        "second": QueryDefinition(
            "second",
            "test",
            "SELECT 'beta' AS second_value;",
            maximum_rows=1,
            batch_columns=("second_value",),
        ),
    }

    class FallbackRunner(FakeRunner):
        def run(
            self,
            executable: str | Path,
            arguments: tuple[str, ...] = (),
            *,
            timeout_seconds: float | None = None,
            cwd: str | Path | None = None,
        ) -> CommandResult:
            del timeout_seconds, cwd
            self.calls.append((str(executable), tuple(arguments)))
            sql = arguments[1]
            if sql.startswith("WITH "):
                return command_result("[]")
            if "first_value" in sql:
                return command_result('[{"first_value":"alpha"}]')
            return command_result('[{"second_value":"beta"}]')

    runner = FallbackRunner()
    adapter = OsqueryAdapter(
        runner=runner,  # type: ignore[arg-type]
        query_registry=registry,
        max_concurrency=1,
    )

    outcomes = adapter.run_registered(("first", "second"))

    assert outcomes["first"].payload == [{"first_value": "alpha"}]
    assert outcomes["second"].payload == [{"second_value": "beta"}]
    assert outcomes["first"].metadata["batch_fallback"] is True
    assert outcomes["second"].metadata["batch_fallback"] is True
    assert len(runner.calls) == 3


def test_osquery_ttl_cache_returns_hits_as_copy_safe_payloads() -> None:
    registry = {
        "cached": QueryDefinition(
            "cached",
            "hardware",
            "SELECT value FROM cached_hardware;",
            maximum_rows=10,
            cache_ttl_seconds=300,
        )
    }
    runner = FakeRunner({"osqueryi": '[{"value":"original"}]'})
    adapter = OsqueryAdapter(
        runner=runner,  # type: ignore[arg-type]
        query_registry=registry,
        max_concurrency=1,
    )

    first = adapter.run_registered(("cached",))["cached"]
    assert first.payload is not None
    first.payload[0]["value"] = "mutated-by-caller"
    first.metadata["caller"] = "mutation"
    second = adapter.run_registered(("cached",))["cached"]
    assert second.payload == [{"value": "original"}]
    assert second.metadata["cache_hit"] is True
    assert "caller" not in second.metadata
    assert second.payload is not None
    second.payload[0]["value"] = "mutated-again"
    third = adapter.run_registered(("cached",))["cached"]
    assert third.payload == [{"value": "original"}]
    assert len(runner.calls) == 1


def test_openscap_parses_rule_results_and_is_fail_soft(tmp_path: Path) -> None:
    content = tmp_path / "baseline.xml"
    content.write_text("<Benchmark/>", encoding="utf-8")
    unavailable = OpenScapAdapter(
        approved_roots=(tmp_path,), runner=FakeRunner(available=False)  # type: ignore[arg-type]
    )
    outcome = unavailable.execute(OpenScapRequest(content, "xccdf_org.example_profile_standard"))
    assert outcome.status == ToolState.UNAVAILABLE

    parsed = unavailable.parse(
        "<Benchmark xmlns='urn:xccdf'><TestResult>"
        "<rule-result idref='rule-1' severity='high'><result>fail</result>"
        "<message>disabled</message></rule-result></TestResult></Benchmark>"
    )
    assert parsed[0]["rule_id"] == "rule-1"
    assert parsed[0]["status"] == "FAILED"
    assert parsed[0]["severity"] == "HIGH"


def test_openscap_preserves_rule_metadata_and_explicit_statuses(tmp_path: Path) -> None:
    content = tmp_path / "enterprise-baseline.xml"
    content.write_text(
        "<Benchmark xmlns='urn:xccdf'><Rule id='rule-1'>"
        "<title>Ensure secure configuration</title>"
        "<reference href='https://example.test/control-1'>Control 1</reference>"
        "<fix>Enable the secure configuration.</fix></Rule></Benchmark>",
        encoding="utf-8",
    )
    result_xml = (
        "<Benchmark xmlns='urn:xccdf'><TestResult>"
        "<rule-result idref='rule-1' severity='high'><result>fail</result>"
        "<message>configuration disabled</message></rule-result>"
        "<rule-result idref='rule-2'><result>notchecked</result></rule-result>"
        "<rule-result idref='rule-3'><result>notselected</result></rule-result>"
        "<rule-result idref='rule-4'><result>informational</result></rule-result>"
        "<rule-result idref='rule-5'><result>fixed</result></rule-result>"
        "</TestResult></Benchmark>"
    )
    adapter = OpenScapAdapter(
        approved_roots=(tmp_path,),
        runner=FakeOpenScapRunner(result_xml),  # type: ignore[arg-type]
    )

    outcome = adapter.execute(OpenScapRequest(content, "enterprise_standard"))

    assert outcome.status is ToolState.SUCCESS
    assert outcome.payload is not None
    assert [item["status"] for item in outcome.payload] == [
        "FAILED",
        "NOT_CHECKED",
        "NOT_SELECTED",
        "INFORMATIONAL",
        "FIXED",
    ]
    failed = outcome.payload[0]
    assert failed["title"] == "Ensure secure configuration"
    assert failed["remediation"] == "Enable the secure configuration."
    assert failed["references"] == ["https://example.test/control-1"]
    assert failed["evidence"] == {
        "messages": ["configuration disabled"],
        "raw_result": "fail",
    }

    normalized, warnings = normalize_openscap(
        outcome.payload,
        scan_id="scan-openscap",
        endpoint_id="endpoint-1",
        profile_id="enterprise_standard",
    )
    assert warnings == []
    assert normalized[0].status is ComplianceStatus.FAIL
    assert normalized[0].title == "Ensure secure configuration"
    assert normalized[0].remediation == "Enable the secure configuration."
    assert normalized[0].references == ["https://example.test/control-1"]
    assert normalized[1].status is ComplianceStatus.UNKNOWN
    assert normalized[4].status is ComplianceStatus.PASS


def test_osv_normalizes_current_result_shape(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("sample==1.0", encoding="utf-8")
    raw = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "sample", "version": "1.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-aaaa-bbbb-cccc",
                                "aliases": ["CVE-2026-0001"],
                                "summary": "Example issue",
                                "database_specific": {
                                    "cvss_score": 9.8,
                                    "known_exploited": True,
                                },
                                "ecosystem_specific": {"exploitability_score": 8.0},
                                "severity": [
                                    {
                                        "type": "CVSS_V3",
                                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    }
                                ],
                                "affected": [
                                    {
                                        "versions": ["1.0", "0.9"],
                                        "ranges": [
                                            {"events": [{"introduced": "0"}, {"fixed": "1.1"}]}
                                        ]
                                    }
                                ],
                                "references": [{"url": "https://osv.dev/example"}],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    runner = FakeRunner({"osv-scanner": json.dumps(raw)})
    adapter = OsvScannerAdapter(approved_roots=(tmp_path,), runner=runner)  # type: ignore[arg-type]

    outcome = adapter.execute(OsvScanRequest(manifest))

    assert outcome.status == ToolState.SUCCESS
    assert outcome.payload is not None
    assert outcome.payload[0]["vulnerability_id"] == "GHSA-aaaa-bbbb-cccc"
    assert outcome.payload[0]["fixed_versions"] == ["1.1"]
    assert outcome.payload[0]["affected_versions"] == ["0.9", "1.0"]
    assert outcome.payload[0]["severity"] == "CRITICAL"
    assert outcome.payload[0]["cvss_score"] == 9.8
    assert outcome.payload[0]["known_exploited"] is True
    assert outcome.payload[0]["exploitability"] == 0.8
    assert outcome.payload[0]["severity_scores"] == [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    ]

    vulnerabilities, warnings = normalize_osv(
        outcome.payload,
        scan_id="scan-osv",
        endpoint_id="endpoint-1",
    )
    assert warnings == []
    assert vulnerabilities[0].affected_versions == ["0.9", "1.0"]
    assert vulnerabilities[0].cvss_score == 9.8
    assert vulnerabilities[0].known_exploited is True
    assert vulnerabilities[0].evidence["severity_scores"] == outcome.payload[0][
        "severity_scores"
    ]


def test_osv_vector_only_cvss_drives_normalized_severity(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("sample==1.0", encoding="utf-8")
    raw = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "sample", "version": "1.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "CVE-2026-9999",
                                "severity": [
                                    {
                                        "type": "CVSS_V3",
                                        "score": (
                                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                        ),
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    adapter = OsvScannerAdapter(
        approved_roots=(tmp_path,),
        runner=FakeRunner({"osv-scanner": json.dumps(raw)}),  # type: ignore[arg-type]
    )

    outcome = adapter.execute(OsvScanRequest(manifest))

    assert outcome.status is ToolState.SUCCESS
    assert outcome.payload is not None
    assert outcome.payload[0]["cvss_score"] == 9.8
    assert outcome.payload[0]["severity"] == "CRITICAL"


def test_osv_cvss_v2_vector_uses_case_insensitive_authentication_metric(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("legacy==1.0", encoding="utf-8")
    raw = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "legacy", "version": "1.0"},
                        "vulnerabilities": [
                            {
                                "id": "CVE-2026-0002",
                                "severity": [
                                    {
                                        "type": "CVSS_V2",
                                        "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ]
    }
    adapter = OsvScannerAdapter(
        approved_roots=(tmp_path,),
        runner=FakeRunner({"osv-scanner": json.dumps(raw)}),  # type: ignore[arg-type]
    )

    outcome = adapter.execute(OsvScanRequest(manifest))

    assert outcome.status is ToolState.SUCCESS
    assert outcome.payload is not None
    assert outcome.payload[0]["cvss_score"] == 10.0
    assert outcome.payload[0]["severity"] == "CRITICAL"


class FakeAmassRunner(FakeRunner):
    def run(
        self,
        executable: str | Path,
        arguments: tuple[str, ...] = (),
        *,
        timeout_seconds: float | None = None,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        del timeout_seconds, cwd
        self.calls.append((str(executable), tuple(arguments)))
        output_path = Path(arguments[arguments.index("-json") + 1])
        output_path.write_text(
            '\n'.join(
                (
                    json.dumps(
                        {
                            "name": "api.corp.example.com",
                            "addresses": [{"ip": "192.0.2.1"}],
                        }
                    ),
                    json.dumps({"name": "excluded.corp.example.com"}),
                    json.dumps({"name": "outside.example.net"}),
                )
            ),
            encoding="utf-8",
        )
        return command_result()


def test_amass_executes_passive_discovery_and_filters_results() -> None:
    runner = FakeAmassRunner()
    adapter = AmassAdapter(runner=runner)  # type: ignore[arg-type]
    request = AmassRequest(
        target="corp.example.com",
        authorized_domains=("corp.example.com",),
        authorization_id="scope-123",
        authorized=True,
        exclusions=("excluded.corp.example.com",),
        max_dns_concurrency=7,
        max_dns_queries_per_second=11,
    )

    outcome = adapter.execute(request)

    assert outcome.status == ToolState.SUCCESS
    assert [item["hostname"] for item in outcome.payload or []] == ["api.corp.example.com"]
    arguments = runner.calls[0][1]
    assert "-passive" in arguments
    assert arguments[arguments.index("-d") + 1] == "corp.example.com"
    assert "example.com" not in arguments
    assert "-active" not in arguments
    assert arguments[arguments.index("-max-dns-queries") + 1] == "7"
    assert arguments[arguments.index("-dns-qps") + 1] == "11"
    assert arguments[arguments.index("-bl") + 1] == "excluded.corp.example.com"


def test_explicit_null_amass_executable_never_probes_runner_or_path() -> None:
    class ProbeMustNotRun(FakeRunner):
        def is_available(self, executable: str | Path) -> bool:
            del executable
            raise AssertionError("disabled Amass attempted executable discovery")

    adapter = AmassAdapter(
        executable=None,
        runner=ProbeMustNotRun(),  # type: ignore[arg-type]
    )
    request = AmassRequest(
        target="corp.example.com",
        authorized_domains=("corp.example.com",),
        authorization_id="scope-disabled",
        authorized=True,
    )

    outcome = adapter.execute(request)

    assert adapter.is_available() is False
    assert adapter.executable_path() is None
    assert outcome.status is ToolState.UNAVAILABLE


def test_unexpected_amass_runner_exception_returns_failed_execution() -> None:
    class RaisingRunner(FakeRunner):
        def run(
            self,
            executable: str | Path,
            arguments: tuple[str, ...] = (),
            *,
            timeout_seconds: float | None = None,
            cwd: str | Path | None = None,
        ) -> CommandResult:
            del executable, arguments, timeout_seconds, cwd
            raise RuntimeError("unexpected runner failure")

    adapter = AmassAdapter(runner=RaisingRunner())  # type: ignore[arg-type]
    request = AmassRequest(
        target="corp.example.com",
        authorized_domains=("corp.example.com",),
        authorization_id="scope-failure",
        authorized=True,
    )

    outcome = adapter.execute(request)

    assert outcome.status is ToolState.FAILED
    assert outcome.error == "unexpected runner failure"
