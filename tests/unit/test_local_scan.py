from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import ValidationError

import app.orchestrator.scanner as scanner_module
from app.core import ScannerSettings
from app.local_scan import (
    LocalScanRequest,
    build_local_scan_job,
    default_local_endpoint_id,
    run_local_scan,
)
from app.models import OverallStatus, ScanResult, ScanType
from app.orchestrator import ScannerOrchestrator
from app.reporting import AtomicReportWriter


class FakeStorage:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeScanner:
    def __init__(self, report_directory: Path, *, fail: bool = False) -> None:
        self.policy = SimpleNamespace(policy_id="enterprise-default", policy_version="1.0.0")
        self.report_writer = AtomicReportWriter(report_directory)
        self.storage = FakeStorage()
        self.fail = fail
        self.jobs: list[Any] = []

    def execute(self, job: Any) -> ScanResult:
        self.jobs.append(job)
        if self.fail:
            raise RuntimeError("controlled failure")
        result = ScanResult(
            scan_id=job.scan_id,
            endpoint_id=job.endpoint_id,
            scan_type=job.scan_type,
            started_at=job.requested_at,
            finished_at=job.requested_at,
            status=OverallStatus.SUCCESS,
            policy_id=job.policy_id,
            policy_version=job.policy_version,
            policy_checksum="a" * 64,
            authorization_scope_id=job.authorization.scope_id,
        )
        self.report_writer.write(result.scan_id, result)
        return result


def test_local_scan_request_fails_closed_without_consent_or_valid_scope() -> None:
    with pytest.raises(ValidationError):
        LocalScanRequest(authorized=False)
    with pytest.raises(ValidationError, match="QUICK or FULL"):
        LocalScanRequest(authorized=True, scan_type=ScanType.COMPLIANCE)
    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        LocalScanRequest(authorized=True, endpoint_id="bad/id")


def test_local_scan_job_has_short_lived_explicit_authorization(tmp_path: Path) -> None:
    scanner = FakeScanner(tmp_path)
    request = LocalScanRequest(
        authorized=True,
        scan_type=ScanType.FULL,
        endpoint_id="powershell-device-1",
        timeout_seconds=300,
        authorization_reference="powershell-owner-consent",
    )

    first = build_local_scan_job(scanner, request)  # type: ignore[arg-type]
    second = build_local_scan_job(scanner, request)  # type: ignore[arg-type]

    assert first.scan_type is ScanType.FULL
    assert first.endpoint_id == "powershell-device-1"
    assert first.authorization.allowed_endpoint_ids == frozenset({"powershell-device-1"})
    assert first.authorization.authorization_reference == "powershell-owner-consent"
    assert first.authorization.authorized is True
    assert first.deadline is not None
    assert first.deadline > first.requested_at
    assert first.scan_id != second.scan_id


def test_run_local_scan_returns_absolute_existing_report_and_closes(tmp_path: Path) -> None:
    scanner = FakeScanner(tmp_path / "reports")
    settings = ScannerSettings(environment="test", data_directory=tmp_path)

    outcome = run_local_scan(
        settings,
        LocalScanRequest(authorized=True, endpoint_id="powershell-device-1"),
        orchestrator_factory=lambda _: cast(ScannerOrchestrator, scanner),
    )

    assert outcome.report_path.is_absolute()
    assert outcome.report_path.is_file()
    assert outcome.result.status is OverallStatus.SUCCESS
    assert scanner.storage.closed is True


def test_run_local_scan_closes_storage_when_execution_fails(tmp_path: Path) -> None:
    scanner = FakeScanner(tmp_path / "reports", fail=True)

    with pytest.raises(RuntimeError, match="controlled failure"):
        run_local_scan(
            ScannerSettings(environment="test", data_directory=tmp_path),
            LocalScanRequest(authorized=True, endpoint_id="powershell-device-1"),
            orchestrator_factory=lambda _: cast(ScannerOrchestrator, scanner),
        )

    assert scanner.storage.closed is True


def test_default_local_endpoint_identifier_is_stable_and_valid() -> None:
    first = default_local_endpoint_id()

    assert first == default_local_endpoint_id()
    assert first.startswith("local-")
    assert 1 <= len(first) <= 128


def test_orchestrator_factory_closes_database_when_initialization_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    storage = FakeStorage()
    monkeypatch.setattr(scanner_module, "SQLiteStorage", lambda _: storage)

    def fail_after_open(cls: type[ScannerOrchestrator], *_: object) -> ScannerOrchestrator:
        del cls
        raise RuntimeError("initialization failed")

    monkeypatch.setattr(
        ScannerOrchestrator,
        "_from_loaded_settings",
        classmethod(fail_after_open),
    )

    with pytest.raises(RuntimeError, match="initialization failed"):
        ScannerOrchestrator.from_settings(
            ScannerSettings(environment="test", data_directory=tmp_path)
        )

    assert storage.closed is True
