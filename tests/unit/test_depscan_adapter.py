from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.normalization import normalize_depscan
from app.tools import (
    CommandResult,
    DepScanAdapter,
    DepScanMode,
    DepScanRequest,
    ToolState,
)


def _command_result(
    *,
    returncode: int | None = 0,
    timed_out: bool = False,
    stdout_truncated: bool = False,
    stderr_truncated: bool = False,
    stderr: str = "",
) -> CommandResult:
    return CommandResult(
        executable="depscan",
        arguments=(),
        returncode=returncode,
        stdout="",
        stderr=stderr,
        duration_seconds=0.25,
        timed_out=timed_out,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
    )


def _sbom() -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg:pypi/sample@1.0.0",
                "type": "library",
                "name": "sample",
                "version": "1.0.0",
                "purl": "pkg:pypi/sample@1.0.0",
            }
        ],
    }


def _vdr(*, vulnerabilities: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    document = _sbom()
    document.update(
        {
            "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
            "metadata": {
                "timestamp": "2026-09-02T00:00:00Z",
                "component": {
                    "name": "endpoint-packages",
                    "version": "1",
                    "purl": "pkg:generic/endpoint-packages@1",
                },
                "tools": {
                    "components": [
                        {"vendor": "OWASP", "name": "dep-scan", "version": "6.0.0"}
                    ]
                },
            },
            "vulnerabilities": vulnerabilities
            if vulnerabilities is not None
            else [
                {
                    "bom-ref": (
                        "GHSA-aaaa-bbbb-cccc/pkg:pypi/sample@1.0.0"
                    ),
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "source": {
                        "name": "OSV",
                        "url": "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc",
                    },
                    "references": [
                        {
                            "id": "CVE-2026-1000",
                            "source": {
                                "name": "NVD",
                                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1000",
                            },
                        }
                    ],
                    "ratings": [
                        {
                            "method": "CVSSv31",
                            "score": 9.1,
                            "severity": "critical",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "source": {"name": "NVD"},
                        }
                    ],
                    "description": "A bounded example dependency issue.",
                    "cwes": [400, "CWE-770"],
                    "published": "2026-09-01T00:00:00Z",
                    "advisories": [
                        {"url": "https://example.test/advisories/GHSA-aaaa-bbbb-cccc"},
                        {"url": "http://insecure.example.test/not-preserved"},
                    ],
                    "affects": [
                        {
                            "ref": "pkg:pypi/sample@1.0.0",
                            "versions": [
                                {"version": "1.0.0", "status": "affected"},
                                {"version": "1.1.0", "status": "unaffected"},
                            ],
                        }
                    ],
                    "analysis": {
                        "state": "in_triage",
                        "detail": (
                            'Dependency Tree: ["pkg:pypi/root@1", '
                            '"pkg:pypi/sample@1.0.0"]'
                        ),
                        "response": ["update"],
                    },
                    "properties": [
                        {"name": "depscan:insights", "value": "Reachable\nKnown Exploits"},
                        {"name": "depscan:prioritized", "value": "true"},
                    ],
                    "recommendation": "Upgrade sample to 1.1.0.",
                }
            ],
        }
    )
    return document


class FakeDepScanRunner:
    def __init__(
        self,
        document: dict[str, Any] | None = None,
        *,
        available: bool = True,
        command_result: CommandResult | None = None,
        oversized_side_file: bool = False,
    ) -> None:
        self.document = _vdr(vulnerabilities=[]) if document is None else document
        self.available = available
        self.command_result = command_result or _command_result()
        self.oversized_side_file = oversized_side_file
        self.calls: list[tuple[str, tuple[str, ...], float | None, Path | None]] = []
        self.live_input_was_private_and_empty = False

    def is_available(self, executable: str | Path) -> bool:
        del executable
        return self.available

    def resolve(self, executable: str | Path) -> Path | None:
        return Path("C:/trusted") / str(executable) if self.available else None

    def run(
        self,
        executable: str | Path,
        arguments: tuple[str, ...] = (),
        *,
        timeout_seconds: float | None = None,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        cwd_path = Path(cwd) if cwd is not None else None
        self.calls.append((str(executable), tuple(arguments), timeout_seconds, cwd_path))
        if "--version" in arguments:
            return CommandResult(
                executable="depscan",
                arguments=arguments,
                returncode=0,
                stdout="OWASP dep-scan 6.0.0",
                stderr="",
                duration_seconds=0.01,
            )
        if self.command_result.timed_out or self.command_result.returncode != 0:
            return self.command_result
        report_root = Path(arguments[arguments.index("--reports-dir") + 1])
        report_root.mkdir(parents=True, exist_ok=True)
        source = Path(arguments[arguments.index("--src") + 1]) if "--src" in arguments else None
        if "--type" in arguments and arguments[arguments.index("--type") + 1] == "os":
            assert source is not None
            assert cwd_path is not None
            self.live_input_was_private_and_empty = (
                source.parent == cwd_path and source.is_dir() and not any(source.iterdir())
            )
        (report_root / "endpoint.vdr.json").write_text(
            json.dumps(self.document), encoding="utf-8"
        )
        (report_root / "sbom-os.cdx.json").write_text(
            json.dumps(_sbom()), encoding="utf-8"
        )
        if self.oversized_side_file:
            (report_root / "oversized.bin").write_bytes(b"x" * 2048)
        return self.command_result


def _write_sbom(path: Path) -> Path:
    path.write_text(json.dumps(_sbom()), encoding="utf-8")
    return path


def test_depscan_parses_vdr_and_preserves_bounded_provenance(tmp_path: Path) -> None:
    sbom = _write_sbom(tmp_path / "input.cdx.json")
    runner = FakeDepScanRunner(_vdr())
    adapter = DepScanAdapter(
        approved_roots=(tmp_path,), runner=runner  # type: ignore[arg-type]
    )

    outcome = adapter.execute(
        DepScanRequest(mode=DepScanMode.SBOM, source=sbom, deep=True)
    )

    assert outcome.status is ToolState.SUCCESS
    assert outcome.payload is not None
    assert len(outcome.payload) == 1
    record = outcome.payload[0]
    assert record["vulnerability_id"] == "GHSA-aaaa-bbbb-cccc"
    assert record["package"] == {
        "name": "sample",
        "version": "1.0.0",
        "ecosystem": "pypi",
        "purl": "pkg:pypi/sample@1.0.0",
        "bom_ref": "pkg:pypi/sample@1.0.0",
        "group": "",
        "type": "library",
    }
    assert record["severity"] == "CRITICAL"
    assert record["cvss_score"] == 9.1
    assert record["affected_versions"] == ["1.0.0"]
    assert record["fixed_versions"] == ["1.1.0"]
    assert record["prioritized"] is True
    assert record["known_exploited"] is True
    assert record["cwes"] == ["CWE-400", "CWE-770"]
    assert record["timestamps"] == {"published": "2026-09-01T00:00:00Z"}
    assert record["insights"] == ["Reachable", "Known Exploits"]
    assert "http://insecure.example.test/not-preserved" not in record["references"]
    assert len(record["provenance"]["report_sha256"]) == 64
    assert record["provenance"]["tools"] == [
        {"vendor": "OWASP", "name": "dep-scan", "version": "6.0.0"}
    ]
    artifacts = outcome.metadata["artifacts"]
    assert [artifact["kind"] for artifact in artifacts] == ["vdr", "sbom"]
    assert artifacts[1]["cyclonedx"]["component_count"] == 1
    assert len(artifacts[1]["sha256"]) == 64

    vulnerabilities, warnings = normalize_depscan(
        outcome.payload,
        scan_id="scan-depscan",
        endpoint_id="endpoint-1",
    )
    assert warnings == []
    assert vulnerabilities[0].package_name == "sample"
    assert vulnerabilities[0].installed_version == "1.0.0"
    assert vulnerabilities[0].cvss_score == 9.1
    assert vulnerabilities[0].known_exploited is True
    assert vulnerabilities[0].evidence["source_tool"] == "owasp-dep-scan"
    assert vulnerabilities[0].evidence["prioritized"] is True


def test_depscan_sbom_uses_fixed_argv_and_keeps_hostile_path_one_argument(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "input with spaces; still-one-argument"
    source_root.mkdir()
    sbom = _write_sbom(source_root / "bom.cdx.json")
    runner = FakeDepScanRunner()
    adapter = DepScanAdapter(
        approved_roots=(source_root,), runner=runner  # type: ignore[arg-type]
    )

    outcome = adapter.execute(DepScanRequest(mode=DepScanMode.SBOM, source=sbom))

    assert outcome.status is ToolState.SUCCESS
    arguments = runner.calls[0][1]
    assert arguments[arguments.index("--bom") + 1] == str(sbom.resolve())
    assert arguments.count(str(sbom.resolve())) == 1
    assert "--src" not in arguments
    assert "--deep" not in arguments
    assert "--vulnerability-analyzer" in arguments
    assert arguments[arguments.index("--vulnerability-analyzer") + 1] == "VDRAnalyzer"
    assert arguments[arguments.index("--reachability-analyzer") + 1] == "off"
    assert "--fail-on-error" in arguments
    assert "--no-vuln-table" in arguments
    assert "--quiet" in arguments


def test_depscan_live_os_uses_private_empty_source_and_fixed_deep_os_mode() -> None:
    runner = FakeDepScanRunner()
    adapter = DepScanAdapter(runner=runner)  # type: ignore[arg-type]

    outcome = adapter.execute(DepScanRequest(mode=DepScanMode.LIVE_OS))

    assert outcome.status is ToolState.SUCCESS
    assert runner.live_input_was_private_and_empty is True
    arguments = runner.calls[0][1]
    assert arguments[arguments.index("--type") + 1] == "os"
    assert "--deep" in arguments
    assert "--src" in arguments
    assert "--bom" not in arguments
    assert outcome.metadata["source"] == "live_os"
    assert outcome.metadata["input_kind"] == "live_os"


def test_depscan_source_mode_requires_approved_directory_and_adds_deep(
    tmp_path: Path,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    (approved / "requirements.txt").write_text("sample==1.0.0", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "requirements.txt").write_text("outside==1", encoding="utf-8")
    runner = FakeDepScanRunner()
    adapter = DepScanAdapter(
        approved_roots=(approved,), runner=runner  # type: ignore[arg-type]
    )

    accepted = adapter.execute(
        DepScanRequest(mode=DepScanMode.SOURCE, source=approved, deep=True)
    )
    rejected = adapter.execute(
        DepScanRequest(mode=DepScanMode.SOURCE, source=outside, deep=True)
    )

    assert accepted.status is ToolState.SUCCESS
    assert "--deep" in runner.calls[0][1]
    assert rejected.status is ToolState.FAILED
    assert rejected.error == "source is outside the approved local roots"
    assert len(runner.calls) == 1


def test_depscan_is_fail_soft_for_unavailable_timeout_and_bad_live_request(
    tmp_path: Path,
) -> None:
    unavailable = DepScanAdapter(
        runner=FakeDepScanRunner(available=False)  # type: ignore[arg-type]
    )
    timed_out = DepScanAdapter(
        runner=FakeDepScanRunner(  # type: ignore[arg-type]
            command_result=_command_result(returncode=-9, timed_out=True)
        )
    )

    assert unavailable.execute(
        DepScanRequest(mode=DepScanMode.LIVE_OS)
    ).status is ToolState.UNAVAILABLE
    assert timed_out.execute(
        DepScanRequest(mode=DepScanMode.LIVE_OS)
    ).status is ToolState.TIMEOUT
    bad_request = unavailable.execute(
        DepScanRequest(mode=DepScanMode.LIVE_OS, source=tmp_path)
    )
    assert bad_request.status is ToolState.FAILED
    assert bad_request.error == "live OS dep-scan does not accept a caller-selected source"


def test_depscan_enforces_report_and_record_limits(tmp_path: Path) -> None:
    sbom = _write_sbom(tmp_path / "input.cdx.json")
    oversized = DepScanAdapter(
        approved_roots=(tmp_path,),
        max_report_bytes=1024,
        runner=FakeDepScanRunner(oversized_side_file=True),  # type: ignore[arg-type]
    )
    too_many = DepScanAdapter(
        approved_roots=(tmp_path,),
        max_vulnerabilities=1,
        runner=FakeDepScanRunner(  # type: ignore[arg-type]
            _vdr(
                vulnerabilities=[
                    {"id": "GHSA-aaaa-bbbb-0001"},
                    {"id": "GHSA-aaaa-bbbb-0002"},
                ]
            )
        ),
    )

    oversized_outcome = oversized.execute(
        DepScanRequest(mode=DepScanMode.SBOM, source=sbom)
    )
    too_many_outcome = too_many.execute(
        DepScanRequest(mode=DepScanMode.SBOM, source=sbom)
    )

    assert oversized_outcome.status is ToolState.FAILED
    assert oversized_outcome.error == "dep-scan temporary output exceeded the byte-size limit"
    assert too_many_outcome.status is ToolState.FAILED
    assert too_many_outcome.error == "dep-scan produced no valid CycloneDX VDR reports"
    assert any("too many vulnerabilities" in warning for warning in too_many_outcome.warnings)


def test_depscan_rejects_non_cyclonedx_input_and_malformed_vdr(tmp_path: Path) -> None:
    invalid_input = tmp_path / "input.json"
    invalid_input.write_text('{"format":"not-cyclonedx"}', encoding="utf-8")
    runner = FakeDepScanRunner()
    adapter = DepScanAdapter(
        approved_roots=(tmp_path,), runner=runner  # type: ignore[arg-type]
    )

    outcome = adapter.execute(
        DepScanRequest(mode=DepScanMode.SBOM, source=invalid_input)
    )

    assert outcome.status is ToolState.FAILED
    assert outcome.error == "dep-scan file input must be a CycloneDX JSON SBOM"
    assert runner.calls == []
    with pytest.raises(ValueError, match="vulnerabilities must be an array"):
        adapter.parse(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "vulnerabilities": {},
                }
            )
        )
