from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import app.cli as cli
from app.core import CloudAPISettings, CloudRouteSettings, ScannerSettings, SchedulingSettings
from app.enrollment import EndpointCredential
from app.orchestrator.deep_scan import DeepScanRequest
from app.reporting import AtomicReportWriter
from app.scheduling import TriggerType
from app.storage import QueueStats
from app.tools import ToolHealth, ToolState
from app.transport import CloudApiRoutes, UploadRunStats


class FakeStorage:
    def __init__(self) -> None:
        self.closed = False
        self.endpoint_ids: list[str] = []
        self.endpoint_list_calls: list[tuple[bool, int]] = []
        self.integrity = True
        self.audit_chain = True
        self.queue = QueueStats(pending=1, succeeded=2)
        self.schema_version = 8

    def close(self) -> None:
        self.closed = True

    def check_integrity(self, *, quick: bool) -> bool:
        assert quick is True
        return self.integrity

    def verify_audit_chain(self) -> bool:
        return self.audit_chain

    def queue_stats(self) -> QueueStats:
        return self.queue

    def list_endpoint_ids(self, *, enrolled_only: bool, limit: int) -> list[str]:
        self.endpoint_list_calls.append((enrolled_only, limit))
        return self.endpoint_ids[:limit]


class FakeScanner:
    def __init__(self, settings: ScannerSettings) -> None:
        self.settings = settings
        self.storage = FakeStorage()
        self.logger = None
        self.metrics = SimpleNamespace(sink=object())
        health = lambda name: SimpleNamespace(  # noqa: E731
            health=lambda: ToolHealth(name=name, status=ToolState.UNAVAILABLE)
        )
        self.collectors = SimpleNamespace(
            osquery=health("osquery"),
            openscap=health("openscap"),
            osv_scanner=health("osv-scanner"),
            depscan=health("depscan"),
            amass=health("amass"),
        )
        self.policy = SimpleNamespace(
            policy_id="enterprise-default", policy_version="1.0.0", rules=[1, 2]
        )
        self.policy_checksum = "a" * 64
        self.capacity = SimpleNamespace(
            local_bytes=1024,
            free_bytes=settings.retention.minimum_free_disk_bytes + 1,
        )
        self.storage_maintenance = SimpleNamespace(
            inspect_capacity=lambda: self.capacity
        )
        self.result_status = "SUCCESS"
        self.executed_jobs: list[object] = []
        self.reconcile_limits: list[int] = []
        self.policy_installs: list[tuple[object, ...]] = []
        self.policy_rejections: list[tuple[str, str]] = []

    def execute(self, job: object) -> object:
        self.executed_jobs.append(job)
        return SimpleNamespace(
            scan_id="scan-1",
            status=SimpleNamespace(value=self.result_status),
            findings=[1],
            risk=SimpleNamespace(score=91.0),
        )

    def reconcile_terminal_statuses(self, *, limit: int) -> int:
        self.reconcile_limits.append(limit)
        return 0

    def install_policy_assignment(self, *values: object) -> bool:
        self.policy_installs.append(values)
        return True

    def record_policy_sync_rejection(self, fingerprint: str, reason: str) -> None:
        self.policy_rejections.append((fingerprint, reason))


def _settings(tmp_path: Path) -> ScannerSettings:
    return ScannerSettings(environment="test", data_directory=tmp_path)


def _credential(endpoint_id: str = "endpoint-1", generation: int = 1) -> EndpointCredential:
    now = datetime.now(UTC)
    return EndpointCredential(
        endpoint_id=endpoint_id,
        access_token="valid-access-token",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
        generation=generation,
    )


def test_parser_exposes_operational_commands_and_bounds_upload_batch() -> None:
    parser = cli.build_parser()
    assert parser.parse_args(["validate-job", "--job", "job.json"]).command == "validate-job"
    assert parser.parse_args(["scan", "--job", "job.json"]).command == "scan"
    local = parser.parse_args(["local-scan", "--authorized"])
    assert local.command == "local-scan"
    assert local.scan_type == "FULL"
    deep = parser.parse_args(["deep-scan", "--authorized"])
    assert deep.command == "deep-scan"
    assert deep.output == Path("deep-scan-report.json")
    assert deep.timeout == 1_800
    assert parser.parse_args(["health"]).command == "health"
    assert parser.parse_args(["enroll"]).token_env == "SCANNER_ENROLLMENT_TOKEN"
    assert parser.parse_args(["rotate-credential", "--endpoint-id", "one"]).command
    repair = parser.parse_args(
        [
            "requeue-upload",
            "--upload-id",
            "42",
            "--actor",
            "operator",
            "--reason",
            "incident-42",
        ]
    )
    assert repair.upload_id == 42
    assert parser.parse_args(["agent", "--endpoint-id", "one"]).poll_interval == 60.0
    with pytest.raises(SystemExit):
        parser.parse_args(["upload", "--limit", "101"])
    with pytest.raises(SystemExit):
        parser.parse_args(["local-scan"])
    with pytest.raises(SystemExit):
        parser.parse_args(["deep-scan"])


def test_client_requires_cloud_origin_and_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    with pytest.raises(ValueError, match="base_url"):
        cli._client(settings)

    configured = settings.model_copy(
        update={"cloud": CloudAPISettings(base_url="https://scanner.example.test")}
    )
    monkeypatch.delenv(configured.cloud.credential_env_var, raising=False)
    with pytest.raises(ValueError, match="credential is unavailable"):
        cli._client(configured)
    assert cli._client(configured, allow_anonymous=True) is not None

    monkeypatch.setenv(configured.cloud.credential_env_var, "valid-access-token")
    assert cli._client(configured) is not None


def test_cli_wires_custom_cloud_routes_into_transport_and_enrollment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    routes = CloudRouteSettings(
        enrollment_path="/tenant/enroll",
        credential_rotation_path_template="/tenant/endpoints/{endpoint_id}/rotate",
        scan_submit_path="/tenant/results",
        scan_status_path="/tenant/results/status",
        scan_lookup_path_template="/tenant/results/{scan_id}",
        next_scan_path_template="/tenant/jobs/{endpoint_id}/next",
        policies_path="/tenant/policies",
        heartbeat_path="/tenant/heartbeat",
        attack_surface_jobs_path="/tenant/discovery",
        scan_rejections_path="/tenant/jobs/rejections",
    )
    settings = ScannerSettings(
        environment="test",
        data_directory=tmp_path,
        cloud=CloudAPISettings(
            base_url="https://scanner.example.test/control-plane",
            routes=routes,
        ),
    )
    monkeypatch.setenv(settings.cloud.credential_env_var, "valid-access-token")

    client = cli._client(settings)
    enrollment = cli._enrollment_config(settings)

    assert client.config.routes == CloudApiRoutes(**routes.model_dump(mode="python"))
    assert enrollment.enrollment_path == "/tenant/enroll"
    assert enrollment.rotation_path_template == "/tenant/endpoints/{endpoint_id}/rotate"


def test_validate_job_command_prints_minimal_identity(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    job = SimpleNamespace(
        scan_id="scan-1",
        scan_type=SimpleNamespace(value="QUICK"),
        validate_for_execution=lambda: None,
    )
    monkeypatch.setattr(cli, "load_job_file", lambda _: job)

    assert cli._cmd_validate_job(argparse.Namespace(job=Path("job.json"))) == 0
    assert json.loads(capsys.readouterr().out) == {
        "valid": True,
        "scan_id": "scan-1",
        "scan_type": "QUICK",
    }


@pytest.mark.parametrize(("status", "exit_code"), [("SUCCESS", 0), ("PARTIAL", 0), ("FAILED", 1)])
def test_scan_command_reports_result_and_always_closes_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: str,
    exit_code: int,
) -> None:
    settings = _settings(tmp_path)
    scanner = FakeScanner(settings)
    scanner.result_status = status
    monkeypatch.setattr(cli, "_settings", lambda _: settings)
    monkeypatch.setattr(
        cli.ScannerOrchestrator, "from_settings", lambda _: scanner
    )
    monkeypatch.setattr(cli, "load_job_file", lambda _: object())

    result = cli._cmd_scan(argparse.Namespace(config=None, job=Path("job.json")))

    payload = json.loads(capsys.readouterr().out)
    assert result == exit_code
    assert payload["scan_id"] == "scan-1"
    assert payload["risk_score"] == 91.0
    assert payload["report"] == str(
        settings.report_directory / AtomicReportWriter.filename_for("scan-1")
    )
    assert scanner.storage.closed is True


def test_local_scan_builds_an_explicitly_authorized_job_without_a_job_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(tmp_path)
    scanner = FakeScanner(settings)
    monkeypatch.setattr(cli, "_settings", lambda _: settings)
    monkeypatch.setattr(cli.ScannerOrchestrator, "from_settings", lambda _: scanner)
    monkeypatch.setattr(cli, "_default_local_endpoint_id", lambda: "local-device-1")
    args = argparse.Namespace(
        authorized=True,
        authorization_reference="owner-consent",
        config=None,
        endpoint_id=None,
        scan_type="FULL",
        timeout=300,
    )

    assert cli._cmd_local_scan(args) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "SUCCESS"
    assert len(scanner.executed_jobs) == 1
    job = scanner.executed_jobs[0]
    assert job.endpoint_id == "local-device-1"
    assert job.scan_type.value == "FULL"
    assert job.authorization.authorized is True
    assert job.authorization.authorization_reference == "owner-consent"
    assert job.authorization.allowed_endpoint_ids == frozenset({"local-device-1"})
    assert scanner.storage.closed is True


def test_local_scan_refuses_direct_invocation_without_consent(tmp_path: Path) -> None:
    with pytest.raises(PermissionError, match="explicit --authorized"):
        cli._cmd_local_scan(argparse.Namespace(authorized=False, config=None))


def _deep_scan_outcome(
    tmp_path: Path, *, endpoint_status: str = "SUCCESS"
) -> SimpleNamespace:
    summary_values = {
        field: index for index, field in enumerate(cli._DEEP_SCAN_COUNT_FIELDS, start=1)
    }
    summary = SimpleNamespace(
        status=SimpleNamespace(value="PARTIAL"),
        **summary_values,
    )
    readiness = SimpleNamespace(
        name="osquery",
        configured=True,
        scheduled=True,
        status=SimpleNamespace(value="SUCCESS"),
        version="5.18.1",
        records_collected=12,
        detail=None,
    )
    report = SimpleNamespace(
        report_id="deep-report-1",
        endpoint_scan=SimpleNamespace(
            scan_id="endpoint-scan-1",
            status=SimpleNamespace(value=endpoint_status),
        ),
        summary=summary,
        completeness=SimpleNamespace(
            complete=False,
            unobserved_endpoint_sections=("compliance",),
            degraded_collectors=("endpoint:openscap",),
            unobserved_attack_surface_domains=("missing.example",),
        ),
        tool_readiness=(readiness,),
    )
    return SimpleNamespace(
        report=report,
        report_path=(tmp_path / "deep-report.json").resolve(),
    )


@pytest.mark.parametrize(("endpoint_status", "exit_code"), [("SUCCESS", 0), ("FAILED", 1)])
def test_deep_scan_command_writes_machine_readable_summary_and_wires_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    endpoint_status: str,
    exit_code: int,
) -> None:
    settings = _settings(tmp_path)
    outcome = _deep_scan_outcome(tmp_path, endpoint_status=endpoint_status)
    captured: dict[str, object] = {}

    def run(config: ScannerSettings, request: object) -> object:
        captured["settings"] = config
        captured["request"] = request
        return outcome

    monkeypatch.setattr(cli, "_settings", lambda _: settings)
    monkeypatch.setattr(cli, "run_deep_scan", run)
    source = tmp_path / "approved-project"
    args = argparse.Namespace(
        authorized=True,
        config=None,
        endpoint_id="endpoint-1",
        dependency_source=[source],
        domain=["Example.COM", "api.example.com"],
        timeout=600,
        authorization_reference="ticket-123",
        output=tmp_path / "deep-report.json",
    )

    assert cli._cmd_deep_scan(args) == exit_code

    payload = json.loads(capsys.readouterr().out)
    assert payload["report"] == str(outcome.report_path)
    assert payload["report_id"] == "deep-report-1"
    assert payload["scan_id"] == "endpoint-scan-1"
    assert payload["status"] == "PARTIAL"
    assert payload["completeness"] == {
        "complete": False,
        "degraded_collectors": ["endpoint:openscap"],
        "unobserved_attack_surface_domains": ["missing.example"],
        "unobserved_endpoint_sections": ["compliance"],
    }
    assert payload["counts"]["software_count"] == 3
    assert payload["counts"]["vulnerability_count"] == 14
    assert payload["tool_readiness"]["osquery"] == {
        "configured": True,
        "detail": None,
        "records_collected": 12,
        "scheduled": True,
        "status": "SUCCESS",
        "version": "5.18.1",
    }
    request = captured["request"]
    assert captured["settings"] is settings
    assert isinstance(request, DeepScanRequest)
    assert request.authorized is True
    assert request.endpoint_id == "endpoint-1"
    assert request.dependency_sources == (source.resolve(),)
    assert request.authorized_domains == ("api.example.com", "example.com")
    assert request.timeout_seconds == 600
    assert request.authorization_reference == "ticket-123"
    assert request.output_path == (tmp_path / "deep-report.json").resolve()
    assert not settings.database_path.exists()


def test_deep_scan_refuses_direct_invocation_without_consent() -> None:
    with pytest.raises(PermissionError, match="explicit --authorized"):
        cli._cmd_deep_scan(argparse.Namespace(authorized=False))


def test_health_command_reports_database_policy_queue_and_tool_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(tmp_path)
    scanner = FakeScanner(settings)
    monkeypatch.setattr(cli, "_settings", lambda _: settings)
    monkeypatch.setattr(cli.ScannerOrchestrator, "from_settings", lambda _: scanner)

    assert cli._cmd_health(argparse.Namespace(config=None)) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "HEALTHY"
    assert payload["database_schema_version"] == 8
    assert payload["database_integrity"] is True
    assert payload["audit_chain_valid"] is True
    assert payload["queue"]["pending"] == 1
    assert payload["policy"]["rules"] == 2
    assert payload["policy"]["checksum"] == "a" * 64
    assert payload["storage"]["within_capacity"] is True
    assert payload["tools"]["amass"]["status"] == "UNAVAILABLE"
    assert scanner.storage.closed is True


@pytest.mark.parametrize(
    "degradation",
    ("database", "audit", "dead_queue", "high_water", "free_space"),
)
def test_health_command_returns_degraded_for_operational_integrity_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    degradation: str,
) -> None:
    settings = _settings(tmp_path)
    scanner = FakeScanner(settings)
    if degradation == "database":
        scanner.storage.integrity = False
    elif degradation == "audit":
        scanner.storage.audit_chain = False
    elif degradation == "dead_queue":
        scanner.storage.queue = QueueStats(dead=1)
    elif degradation == "high_water":
        scanner.capacity = SimpleNamespace(
            local_bytes=settings.retention.max_local_storage_bytes + 1,
            free_bytes=settings.retention.minimum_free_disk_bytes + 1,
        )
    else:
        scanner.capacity = SimpleNamespace(
            local_bytes=0,
            free_bytes=settings.retention.minimum_free_disk_bytes - 1,
        )
    monkeypatch.setattr(cli, "_settings", lambda _: settings)
    monkeypatch.setattr(cli.ScannerOrchestrator, "from_settings", lambda _: scanner)

    assert cli._cmd_health(argparse.Namespace(config=None)) == 1

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "DEGRADED"
    assert scanner.storage.closed is True


def test_upload_command_reports_dead_items_as_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(tmp_path)
    scanner = FakeScanner(settings)
    monkeypatch.setattr(cli, "_settings", lambda _: settings)
    monkeypatch.setattr(cli.ScannerOrchestrator, "from_settings", lambda _: scanner)
    monkeypatch.setattr(cli, "_client", lambda *_args, **_kwargs: object())

    class Worker:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run_once(self, *, limit: int) -> UploadRunStats:
            assert limit == 3
            return UploadRunStats(claimed=1, dead=1)

    monkeypatch.setattr(cli, "UploadWorker", Worker)
    result = cli._cmd_upload(
        argparse.Namespace(config=None, endpoint_id="endpoint-1", limit=3)
    )
    assert result == 1
    assert json.loads(capsys.readouterr().out)["dead"] == 1
    assert scanner.reconcile_limits == [100]
    assert scanner.storage.closed is True


def test_requeue_upload_command_emits_only_recovery_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(tmp_path)
    scanner = FakeScanner(settings)
    calls: list[tuple[object, ...]] = []

    def requeue(
        upload_id: int,
        *,
        actor: str,
        reason: str,
        max_attempts: int | None,
    ) -> dict[str, object]:
        calls.append((upload_id, actor, reason, max_attempts))
        return {
            "upload_id": upload_id,
            "status": "PENDING",
            "audit_event_id": "audit-1",
        }

    scanner.storage.requeue_dead_upload = requeue
    monkeypatch.setattr(cli, "_settings", lambda _: settings)
    monkeypatch.setattr(cli.ScannerOrchestrator, "from_settings", lambda _: scanner)

    result = cli._cmd_requeue_upload(
        argparse.Namespace(
            config=None,
            upload_id=42,
            actor="security-operator",
            reason="approved incident INC-42",
            max_attempts=5,
        )
    )

    assert result == 0
    assert calls == [(42, "security-operator", "approved incident INC-42", 5)]
    assert json.loads(capsys.readouterr().out) == {
        "audit_event_id": "audit-1",
        "status": "PENDING",
        "upload_id": 42,
    }
    assert scanner.storage.closed is True


def test_enroll_and_rotate_commands_emit_no_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(tmp_path)
    calls: list[tuple[str, object]] = []

    class Service:
        def __init__(self, *_args: object) -> None:
            pass

        def enroll(self, token: str, identity: object) -> EndpointCredential:
            calls.append((token, identity))
            return _credential()

        def rotate(self, endpoint_id: str) -> EndpointCredential:
            calls.append(("rotate", endpoint_id))
            return _credential(endpoint_id, generation=2)

    monkeypatch.setattr(cli, "_settings", lambda _: settings)
    monkeypatch.setattr(cli, "_client", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "_credential_store", lambda _: object())
    monkeypatch.setattr(cli, "EnrollmentService", Service)

    monkeypatch.delenv("TEMP_ENROLL_TOKEN", raising=False)
    with pytest.raises(ValueError, match="temporary enrollment token"):
        cli._cmd_enroll(argparse.Namespace(config=None, token_env="TEMP_ENROLL_TOKEN"))

    monkeypatch.setenv("TEMP_ENROLL_TOKEN", "temporary-secret")
    assert cli._cmd_enroll(
        argparse.Namespace(config=None, token_env="TEMP_ENROLL_TOKEN")
    ) == 0
    enrollment_output = capsys.readouterr().out
    assert "temporary-secret" not in enrollment_output
    assert "valid-access-token" not in enrollment_output

    assert cli._cmd_rotate(
        argparse.Namespace(config=None, endpoint_id="endpoint-1")
    ) == 0
    rotation = json.loads(capsys.readouterr().out)
    assert rotation == {
        "endpoint_id": "endpoint-1",
        "expires_at": rotation["expires_at"],
        "generation": 2,
    }
    assert calls[0][0] == "temporary-secret"


def test_agent_command_requires_identity_runs_loop_and_closes_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    scanner = FakeScanner(settings)
    monkeypatch.setattr(cli, "_settings", lambda _: settings)
    monkeypatch.setattr(cli.ScannerOrchestrator, "from_settings", lambda _: scanner)
    client_endpoint_ids: list[str | None] = []

    def client(*_args: object, endpoint_id: str | None = None, **_kwargs: object) -> object:
        client_endpoint_ids.append(endpoint_id)
        return object()

    monkeypatch.setattr(cli, "_client", client)
    monkeypatch.setattr(
        cli,
        "_credential_store",
        lambda _: SimpleNamespace(load=lambda _endpoint_id: None),
    )
    monkeypatch.setattr(cli, "UploadWorker", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "CloudJobSource", lambda *_args, **_kwargs: object())
    registered_signals: list[Any] = []
    monkeypatch.setattr(cli.signal, "signal", lambda *args: registered_signals.append(args))
    ran: list[bool] = []
    schedulers: list[object | None] = []

    class Agent:
        def __init__(self, *_args: object, **kwargs: object) -> None:
            schedulers.append(kwargs.get("scheduler"))

        def run(self) -> None:
            ran.append(True)

        def stop(self) -> None:
            ran.append(False)

    monkeypatch.setattr(cli, "ScannerAgent", Agent)
    monkeypatch.delenv("SCANNER_ENDPOINT_ID", raising=False)
    with pytest.raises(ValueError, match="endpoint-id"):
        cli._cmd_agent(
            argparse.Namespace(
                config=None, endpoint_id=None, poll_interval=60.0, jitter=0.1
            )
        )

    scanner.storage.endpoint_ids = ["endpoint-from-storage", "endpoint-second"]
    with pytest.raises(ValueError, match="multiple enrolled"):
        cli._cmd_agent(
            argparse.Namespace(
                config=None, endpoint_id=None, poll_interval=60.0, jitter=0.1
            )
        )

    scanner.storage.endpoint_ids = ["endpoint-from-storage"]
    assert cli._cmd_agent(
        argparse.Namespace(
            config=None, endpoint_id=None, poll_interval=60.0, jitter=0.1
        )
    ) == 0
    assert ran == [True]
    assert client_endpoint_ids == ["endpoint-from-storage"]
    assert scanner.storage.endpoint_list_calls == [(True, 2), (True, 2), (True, 2)]
    assert scanner.reconcile_limits == [100]
    assert registered_signals
    assert schedulers == [None]
    assert scanner.storage.closed is True


def test_agent_once_runs_one_iteration_and_emits_machine_readable_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(tmp_path)
    scanner = FakeScanner(settings)
    scanner.storage.endpoint_ids = ["endpoint-once"]
    monkeypatch.setattr(cli, "_settings", lambda _: settings)
    monkeypatch.setattr(cli.ScannerOrchestrator, "from_settings", lambda _: scanner)
    monkeypatch.setattr(cli, "_client", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        cli,
        "_credential_store",
        lambda _: SimpleNamespace(load=lambda _endpoint_id: None),
    )
    monkeypatch.setattr(cli, "UploadWorker", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "CloudJobSource", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli.signal, "signal", lambda *_args: None)
    loop_runs: list[bool] = []

    class Agent:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run_once(self) -> SimpleNamespace:
            return SimpleNamespace(
                online=True,
                scan=SimpleNamespace(
                    scan_id="scan-once",
                    status=SimpleNamespace(value="SUCCESS"),
                    findings=[1, 2],
                ),
                uploads=UploadRunStats(claimed=2, succeeded=2),
            )

        def run(self) -> None:
            loop_runs.append(True)

        def stop(self) -> None:
            pass

        def request_policy_scan(self) -> bool:
            return False

    monkeypatch.setattr(cli, "ScannerAgent", Agent)

    assert cli._cmd_agent(
        argparse.Namespace(
            config=None,
            endpoint_id=None,
            poll_interval=60.0,
            jitter=0.1,
            once=True,
        )
    ) == 0

    assert loop_runs == []
    assert json.loads(capsys.readouterr().out) == {
        "online": True,
        "queue": {
            "dead": 0,
            "in_flight": 0,
            "pending": 1,
            "succeeded": 2,
        },
        "scan": {"findings": 2, "scan_id": "scan-once", "status": "SUCCESS"},
        "uploads": {"claimed": 2, "dead": 0, "retried": 0, "succeeded": 2},
    }
    assert scanner.storage.closed is True


def test_agent_wires_authorized_scheduled_jobs_and_proactive_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = ScannerSettings(
        environment="test",
        data_directory=tmp_path,
        scheduling=SchedulingSettings(
            enabled=True,
            startup_scan=True,
            periodic_interval_seconds=None,
            scan_type="FULL",
            timeout_seconds=600,
        ),
    )
    scanner = FakeScanner(settings)
    scanner.storage.endpoint_ids = ["endpoint-scheduled"]
    credential = _credential("endpoint-scheduled")
    rotations: list[str] = []
    captured: dict[str, object] = {}
    policy_sync_calls: list[str] = []

    class Store:
        def load(self, endpoint_id: str) -> EndpointCredential | None:
            assert endpoint_id == "endpoint-scheduled"
            return credential

    class Service:
        def __init__(self, _client: object, _store: object, _config: object) -> None:
            pass

        def needs_rotation(self, endpoint_id: str) -> bool:
            assert endpoint_id == "endpoint-scheduled"
            return True

        def rotate(self, endpoint_id: str) -> EndpointCredential:
            rotations.append(endpoint_id)
            return _credential(endpoint_id, generation=2)

    class Agent:
        def __init__(self, *_args: object, **kwargs: object) -> None:
            captured.update(kwargs)

        def run(self) -> None:
            pass

        def stop(self) -> None:
            pass

        def request_policy_scan(self) -> bool:
            return True

    class PolicySynchronizer:
        def __init__(
            self,
            client: object,
            loader: object,
            installer: object,
            rejection_recorder: object,
        ) -> None:
            assert client is cloud_client
            assert loader.__class__.__name__ == "PolicyLoader"
            assert installer == scanner.install_policy_assignment
            assert rejection_recorder == scanner.record_policy_sync_rejection

        def sync(self) -> bool:
            policy_sync_calls.append("sync")
            return True

    cloud_client = object()
    monkeypatch.setattr(cli, "_settings", lambda _: settings)
    monkeypatch.setattr(cli.ScannerOrchestrator, "from_settings", lambda _: scanner)
    monkeypatch.setattr(cli, "_client", lambda *_args, **_kwargs: cloud_client)
    monkeypatch.setattr(cli, "_credential_store", lambda _: Store())
    monkeypatch.setattr(cli, "EnrollmentService", Service)
    monkeypatch.setattr(cli, "UploadWorker", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "CloudJobSource", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "CloudPolicySynchronizer", PolicySynchronizer)
    monkeypatch.setattr(cli, "ScannerAgent", Agent)
    monkeypatch.setattr(cli.signal, "signal", lambda *_args: None)
    monkeypatch.delenv("SCANNER_ENDPOINT_ID", raising=False)

    assert cli._cmd_agent(
        argparse.Namespace(config=None, endpoint_id=None, poll_interval=60.0, jitter=0.1)
    ) == 0

    maintenance = captured["credential_maintenance"]
    assert callable(maintenance)
    assert maintenance() is True
    assert rotations == ["endpoint-scheduled"]
    policy_maintenance = captured["policy_maintenance"]
    assert callable(policy_maintenance)
    assert policy_maintenance() is True
    assert policy_sync_calls == ["sync"]

    scheduler = captured["scheduler"]
    assert scheduler is not None
    startup = scheduler.poll()  # type: ignore[union-attr]
    requested_at = datetime.now(UTC)
    periodic = scheduler.job_factory(  # type: ignore[union-attr]
        TriggerType.PERIODIC, requested_at
    )
    scheduler.request_policy_scan()  # type: ignore[union-attr]
    policy = scheduler.poll()  # type: ignore[union-attr]

    assert startup.scan_type.value == "FULL"
    assert periodic.scan_type.value == "FULL"
    assert policy.scan_type.value == "COMPLIANCE"
    for job in (startup, periodic, policy):
        assert job.endpoint_id == "endpoint-scheduled"
        assert job.authorization.authorized is True
        assert job.authorization.allowed_endpoint_ids == frozenset({"endpoint-scheduled"})
        assert job.policy_id == "enterprise-default"
        assert job.policy_version == "1.0.0"
        assert (job.deadline - job.requested_at).total_seconds() == 600
        job.validate_for_execution(job.requested_at)
    assert scanner.reconcile_limits == [100]


def test_main_returns_sanitized_machine_readable_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(_args: argparse.Namespace) -> int:
        raise ValueError("Authorization: Bearer top-secret\r\nforged=true")

    monkeypatch.setattr(cli, "_cmd_health", fail)

    assert cli.main(["health"]) == 2
    error = capsys.readouterr().err
    payload = json.loads(error)
    assert payload["status"] == "ERROR"
    assert "top-secret" not in error
    assert "forged=true" in payload["error"]
    assert "\n" not in payload["error"]
