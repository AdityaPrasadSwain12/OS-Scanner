from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core import (
    AnalysisSettings,
    CloudAPISettings,
    CloudRouteSettings,
    PolicySettings,
    RetentionSettings,
    ScannerSettings,
)
from app.models import (
    AttackSurfaceAsset,
    AuthorizationScope,
    CollectorState,
    CollectorStatus,
    OperatingSystem,
    OperatingSystemFamily,
    Process,
    ScanJob,
    ScanType,
    SecurityPosture,
)
from app.orchestrator import CollectionBundle, ScanExecutionError, ScannerOrchestrator
from app.policies import (
    CloudPolicySynchronizer,
    PolicyBundle,
    PolicyCondition,
    PolicyLoader,
    PolicyRule,
    PolicySyncError,
    ValidatedPolicyDocument,
    canonical_policy_bytes,
    canonical_policy_document,
)
from app.reporting import AtomicReportWriter
from app.sbom import build_cyclonedx_sbom
from app.storage import QueuedUpload, SQLiteStorage
from app.storage.serialization import canonical_json


def policy() -> PolicyBundle:
    return PolicyBundle(
        policy_id="enterprise-default",
        policy_version="1.0.0",
        rules=[
            PolicyRule(
                rule_id="FIREWALL-TEST",
                title="Firewall disabled",
                severity="HIGH",
                category="endpoint_security",
                description="The host firewall is disabled.",
                condition=PolicyCondition(
                    field="security.firewall_enabled", operator="equals", value=False
                ),
                remediation="Enable the host firewall.",
                platforms={"LINUX"},
            )
        ],
    )


def policy_version(version: str, *, policy_id: str = "enterprise-default") -> PolicyBundle:
    document = policy().model_dump(mode="json")
    document["policy_id"] = policy_id
    document["policy_version"] = version
    document["rules"][0]["rule_id"] = f"FIREWALL-{version.replace('.', '-')}"
    return PolicyBundle.model_validate(document)


def validated_policy(bundle: PolicyBundle) -> ValidatedPolicyDocument:
    checksum = hashlib.sha256(canonical_policy_bytes(bundle)).hexdigest()
    return ValidatedPolicyDocument(bundle=bundle, checksum=checksum)


def authorization(*, endpoint: bool = True) -> AuthorizationScope:
    now = datetime.now(UTC)
    return AuthorizationScope(
        scope_id="scope-1",
        authorized=True,
        authorization_reference="ticket-1",
        valid_from=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=1),
        allowed_endpoint_ids={"endpoint-1"} if endpoint else set(),
        allowed_domains={"example.test"} if not endpoint else set(),
    )


class FakePipeline:
    def __init__(self, *, firewall_enabled: bool = False) -> None:
        self.calls = 0
        self.firewall_enabled = firewall_enabled
        self.deadlines: list[float | None] = []

    def collect(
        self, job: ScanJob, *, deadline_at: float | None = None
    ) -> CollectionBundle:
        self.calls += 1
        self.deadlines.append(deadline_at)
        if job.scan_type is ScanType.ATTACK_SURFACE:
            return CollectionBundle(
                inventory={
                    "attack_surface": [
                        AttackSurfaceAsset(
                            scan_id=job.scan_id,
                            hostname="api.example.test",
                            root_domain="example.test",
                            in_scope=True,
                        )
                    ]
                },
                collectors={
                    "amass": CollectorStatus(name="amass", status=CollectorState.SUCCESS)
                },
            )
        return CollectionBundle(
            inventory={
                "hostname": "linux-1",
                "os": OperatingSystem(
                    family=OperatingSystemFamily.LINUX,
                    name="Test Linux",
                    version="1",
                ),
                "security": SecurityPosture(firewall_enabled=self.firewall_enabled),
            },
            collectors={
                "native.firewall": CollectorStatus(
                    name="native.firewall", status=CollectorState.SUCCESS, records_collected=1
                )
            },
        )


class CommandLinePipeline(FakePipeline):
    def collect(
        self, job: ScanJob, *, deadline_at: float | None = None
    ) -> CollectionBundle:
        bundle = super().collect(job, deadline_at=deadline_at)
        bundle.inventory["processes"] = [
            Process(pid=42, name="worker", command_line="worker --tenant-secret value")
        ]
        bundle.observed_inventory_sections.add("processes")
        return bundle


def orchestrator(tmp_path: Path, pipeline: FakePipeline) -> ScannerOrchestrator:
    settings = ScannerSettings(
        environment="test",
        data_directory=tmp_path,
        retention=RetentionSettings(minimum_free_disk_bytes=16 * 1024 * 1024),
    )
    storage = SQLiteStorage(settings.database_path)
    return ScannerOrchestrator(
        settings,
        storage,
        policy(),
        collectors=pipeline,  # type: ignore[arg-type]
        report_writer=AtomicReportWriter(tmp_path / "reports"),
    )


def endpoint_job(scan_id: str) -> ScanJob:
    return ScanJob(
        scan_id=scan_id,
        scan_type=ScanType.QUICK,
        endpoint_id="endpoint-1",
        authorization=authorization(),
    )


def drain_uploads(scanner: ScannerOrchestrator) -> list[QueuedUpload]:
    drained: list[QueuedUpload] = []
    while claimed := scanner.storage.claim_uploads(
        limit=10, now=time.time() + 1
    ):
        for upload in claimed:
            drained.append(upload)
            assert scanner.storage.mark_upload_succeeded(
                upload.upload_id, upload.lease_token
            )
    return drained


def test_orchestrator_analyzes_persists_and_deduplicates(tmp_path: Path) -> None:
    pipeline = FakePipeline()
    scanner = orchestrator(tmp_path, pipeline)
    try:
        job = endpoint_job("scan-1")
        result = scanner.execute(job)
        assert result.findings[0].rule_id == "FIREWALL-TEST"
        assert result.risk is not None and result.risk.score < 100
        assert scanner.storage.get_normalized_result("scan-1") is not None
        report_name = AtomicReportWriter.filename_for(job.scan_id)
        assert (tmp_path / "reports" / report_name).is_file()

        duplicate = scanner.execute(job)
        assert duplicate.scan_id == result.scan_id
        assert pipeline.calls == 1
    finally:
        scanner.storage.close()


def test_default_privacy_never_transmits_process_command_lines(tmp_path: Path) -> None:
    scanner = orchestrator(tmp_path, CommandLinePipeline())
    try:
        result = scanner.execute(endpoint_job("scan-command-line-privacy"))

        assert len(result.processes) == 1
        assert result.processes[0].command_line is None
        report_path = (
            tmp_path / "reports" / AtomicReportWriter.filename_for(result.scan_id)
        )
        assert "tenant-secret" not in report_path.read_text(encoding="utf-8")
    finally:
        scanner.storage.close()


def test_second_unchanged_scan_queues_small_differential(tmp_path: Path) -> None:
    pipeline = FakePipeline()
    scanner = orchestrator(tmp_path, pipeline)
    try:
        scanner.execute(endpoint_job("scan-1"))
        scanner.execute(endpoint_job("scan-2"))
        uploads = drain_uploads(scanner)
        documents = [
            json.loads(upload.payload) for upload in uploads if upload.kind == "scan_result"
        ]
        second = next(item for item in documents if item["result"]["scan_id"] == "scan-2")
        assert second["inventory_sync"]["mode"] == "unchanged"
        assert "snapshot" not in second["inventory_sync"]
        status_documents = [
            json.loads(upload.payload) for upload in uploads if upload.kind == "scan_status"
        ]
        second_status = next(item for item in status_documents if item["scan_id"] == "scan-2")
        assert second_status["status"] == "SUCCESS"
    finally:
        scanner.storage.close()


def test_endpoint_upload_contains_verified_cyclonedx_evidence(tmp_path: Path) -> None:
    scanner = orchestrator(tmp_path, CommandLinePipeline())
    try:
        result = scanner.execute(endpoint_job("scan-sbom-upload"))
        uploads = drain_uploads(scanner)
        envelope = json.loads(
            next(upload.payload for upload in uploads if upload.kind == "scan_result")
        )

        expected = build_cyclonedx_sbom(result)
        assert envelope["evidence_envelope_version"] == "1.0"
        assert envelope["sbom"] == expected
        assert envelope["sbom_sha256"] == hashlib.sha256(
            canonical_json(expected).encode("utf-8")
        ).hexdigest()
        assert "tenant-secret" not in canonical_json(envelope)
    finally:
        scanner.storage.close()


def test_previous_snapshot_change_does_not_imply_approved_baseline_drift(
    tmp_path: Path,
) -> None:
    pipeline = FakePipeline(firewall_enabled=True)
    scanner = orchestrator(tmp_path, pipeline)
    try:
        scanner.execute(endpoint_job("scan-before-posture-change"))
        pipeline.firewall_enabled = False

        changed = scanner.execute(endpoint_job("scan-after-posture-change"))

        assert changed.security is not None
        assert changed.security.firewall_enabled is False
        assert changed.security.configuration_drift is None
    finally:
        scanner.storage.close()


def test_unobserved_security_section_suppresses_approved_baseline_drift(
    tmp_path: Path,
) -> None:
    settings = ScannerSettings(
        environment="test",
        data_directory=tmp_path,
        retention=RetentionSettings(minimum_free_disk_bytes=16 * 1024 * 1024),
        analysis=AnalysisSettings(
            approved_security_posture={"firewall_enabled": True}
        ),
    )
    storage = SQLiteStorage(settings.database_path)
    scanner = ScannerOrchestrator(
        settings,
        storage,
        policy(),
        collectors=FakePipeline(firewall_enabled=False),  # type: ignore[arg-type]
        report_writer=AtomicReportWriter(tmp_path / "reports"),
    )
    try:
        result = scanner.execute(endpoint_job("scan-unobserved-security-baseline"))

        assert result.security is not None
        assert result.security.firewall_enabled is False
        assert result.security.configuration_drift is None
        assert result.security.controls["configuration_baseline_observed"] is False
    finally:
        scanner.storage.close()


def test_policy_checksum_provenance_is_consistent_across_lifecycle_outputs(
    tmp_path: Path,
) -> None:
    scanner = orchestrator(tmp_path, FakePipeline())
    try:
        job = endpoint_job("scan-policy-provenance")
        result = scanner.execute(job)
        expected_checksum = hashlib.sha256(canonical_policy_bytes(policy())).hexdigest()

        assert result.policy_checksum == expected_checksum
        stored = scanner.storage.get_normalized_result(job.scan_id)
        assert stored is not None
        assert stored["payload"]["policy_checksum"] == expected_checksum

        uploads = drain_uploads(scanner)
        result_upload = json.loads(
            next(upload.payload for upload in uploads if upload.kind == "scan_result")
        )
        status_upload = json.loads(
            next(upload.payload for upload in uploads if upload.kind == "scan_status")
        )
        assert result_upload["result"]["policy_checksum"] == expected_checksum
        assert status_upload["policy_checksum"] == expected_checksum

        with scanner.storage.transaction() as connection:
            completion = connection.execute(
                "SELECT details_json FROM audit_log "
                "WHERE scan_id=? AND event_type='SCAN_COMPLETED'",
                (job.scan_id,),
            ).fetchone()
        assert completion is not None
        assert json.loads(completion["details_json"])["policy_checksum"] == expected_checksum
    finally:
        scanner.storage.close()


def test_attack_surface_target_is_preserved_locally(tmp_path: Path) -> None:
    pipeline = FakePipeline()
    scanner = orchestrator(tmp_path, pipeline)
    try:
        job = ScanJob(
            scan_id="scan-domain-1",
            scan_type=ScanType.ATTACK_SURFACE,
            target="example.test",
            authorization=authorization(endpoint=False),
        )
        result = scanner.execute(job)
        stored = scanner.storage.get_normalized_result(job.scan_id)
        assert result.attack_surface[0].hostname == "api.example.test"
        assert stored is not None and stored["target"] == "example.test"
    finally:
        scanner.storage.close()


@pytest.mark.parametrize(
    ("policy_id", "policy_version"),
    [("untrusted-policy", None), ("enterprise-default", "9.9.9")],
)
def test_orchestrator_rejects_uninstalled_policy_and_audits_decision(
    tmp_path: Path, policy_id: str, policy_version: str | None
) -> None:
    pipeline = FakePipeline()
    scanner = orchestrator(tmp_path, pipeline)
    try:
        job = endpoint_job("scan-untrusted-policy").model_copy(
            update={"policy_id": policy_id, "policy_version": policy_version}
        )

        for _ in range(2):
            with pytest.raises(ValueError, match="not validated and cached locally"):
                scanner.execute(job)

        assert pipeline.calls == 0
        with scanner.storage.transaction() as connection:
            audits = connection.execute(
                "SELECT event_type,outcome,details_json FROM audit_log WHERE scan_id=?",
                (job.scan_id,),
            ).fetchall()
        assert len(audits) == 1
        audit = audits[0]
        assert audit["event_type"] == "SCAN_REJECTED"
        assert audit["outcome"] == "REJECTED"
        assert "not validated and cached locally" in audit["details_json"]
    finally:
        scanner.storage.close()


def test_running_job_redelivery_reuses_original_start_and_completes(
    tmp_path: Path,
) -> None:
    pipeline = FakePipeline()
    scanner = orchestrator(tmp_path, pipeline)
    try:
        job = endpoint_job("scan-running-redelivery")
        original_started_at = datetime.now(UTC)
        resumed_at = original_started_at + timedelta(seconds=5)
        job_payload = job.model_dump(mode="json", exclude_none=True)
        job_payload.update({"status": "QUEUED", "initiator": job.initiated_by})
        assert scanner.storage.create_scan_job(job_payload) is True
        scanner.storage.update_scan_job(
            job.scan_id,
            "RUNNING",
            started_at=original_started_at.isoformat(),
        )
        digest = hashlib.sha256(job.scan_id.encode("utf-8")).hexdigest()[:32]
        scanner.storage.record_audit_event(
            "SCAN_STARTED",
            "SUCCESS",
            event_id=f"scan-started:{digest}",
            actor=job.initiated_by,
            resource_type="endpoint",
            resource_id=job.endpoint_id,
            scan_id=job.scan_id,
            endpoint_id=job.endpoint_id,
            authorization_scope_id=job.authorization.scope_id,
            details={"scan_type": job.scan_type.value, "policy_id": job.policy_id},
            created_at=original_started_at.isoformat(),
        )
        scanner.clock = lambda: resumed_at

        result = scanner.execute(job)

        assert result.started_at == original_started_at
        assert result.finished_at == resumed_at
        assert pipeline.calls == 1
        record = scanner.storage.get_scan_job(job.scan_id)
        assert record is not None
        assert record["status"] == "COMPLETED"
        assert scanner.storage.get_normalized_result(job.scan_id) is not None
        with scanner.storage.transaction() as connection:
            starts = connection.execute(
                "SELECT created_at FROM audit_log "
                "WHERE scan_id=? AND event_type='SCAN_STARTED'",
                (job.scan_id,),
            ).fetchall()
        assert [row["created_at"] for row in starts] == [
            original_started_at.isoformat()
        ]
        assert scanner.storage.verify_audit_chain() is True
    finally:
        scanner.storage.close()


def test_cloud_policy_assignment_activates_atomically_and_resolves_exact_versions(
    tmp_path: Path,
) -> None:
    pipeline = FakePipeline()
    scanner = orchestrator(tmp_path, pipeline)
    try:
        version_two = policy_version("2.0.0")
        version_three = policy_version("3.0.0", policy_id="special-policy")

        assert scanner.install_policy_assignment(
            [validated_policy(version_two), validated_policy(version_three)],
            "enterprise-default",
            "2.0.0",
            "assignment-123",
        ) is True
        assert scanner.install_policy_assignment(
            [validated_policy(version_two), validated_policy(version_three)],
            "enterprise-default",
            "2.0.0",
            "assignment-123",
        ) is False

        active = scanner.storage.get_active_policy_document()
        assert active is not None
        assert (active["policy_id"], active["version"], active["source"]) == (
            "enterprise-default",
            "2.0.0",
            "cloud",
        )
        assert scanner.policy is version_two
        assert scanner.resolve_policy(endpoint_job("scan-active")) is version_two
        exact_old = endpoint_job("scan-old").model_copy(
            update={"policy_version": "1.0.0"}
        )
        with pytest.raises(ValueError, match="not validated and cached locally"):
            scanner.resolve_policy(exact_old)
        exact_other = endpoint_job("scan-other").model_copy(
            update={"policy_id": "special-policy", "policy_version": "3.0.0"}
        )
        assert scanner.resolve_policy(exact_other) is version_three

        exact_result = scanner.execute(exact_other)
        assert exact_result.policy_id == "special-policy"
        assert exact_result.policy_version == "3.0.0"
        assert exact_result.findings[0].rule_id == "FIREWALL-3-0-0"

        with scanner.storage.transaction() as connection:
            activations = connection.execute(
                "SELECT details_json FROM audit_log WHERE event_type='POLICY_ACTIVATED'"
            ).fetchall()
        assert len(activations) == 1
        details = json.loads(activations[0]["details_json"])
        assert details["assignment_id"] == "assignment-123"
        assert details["previous_policy_version"] == "1.0.0"
        assert details["policy_version"] == "2.0.0"
    finally:
        scanner.storage.close()


def test_policy_assignment_rolls_back_cache_and_activation_on_any_invalid_document(
    tmp_path: Path,
) -> None:
    scanner = orchestrator(tmp_path, FakePipeline())
    try:
        version_two = policy_version("2.0.0")
        version_three = policy_version("3.0.0")
        tampered = ValidatedPolicyDocument(bundle=version_three, checksum="0" * 64)

        with pytest.raises(ValueError, match="checksum changed"):
            scanner.install_policy_assignment(
                [validated_policy(version_two), tampered],
                "enterprise-default",
                "2.0.0",
                "assignment-tampered",
            )

        assert scanner.policy.policy_version == "1.0.0"
        assert [item["version"] for item in scanner.storage.list_policy_documents()] == [
            "1.0.0"
        ]
        with scanner.storage.transaction() as connection:
            activation_count = connection.execute(
                "SELECT COUNT(*) FROM audit_log WHERE event_type='POLICY_ACTIVATED'"
            ).fetchone()[0]
        assert activation_count == 0
    finally:
        scanner.storage.close()


def test_invalid_cloud_policy_schema_is_rejected_and_audited_idempotently(
    tmp_path: Path,
) -> None:
    scanner = orchestrator(tmp_path, FakePipeline())
    invalid_assignment = {
        "schema_version": "2.0",
        "assignment_id": "assignment-invalid",
        "active_policy_id": "enterprise-default",
        "active_policy_version": "1.0.0",
        "policies": [],
        "authorization_token": "must-never-be-audited",
    }
    client = SimpleNamespace(fetch_policies=lambda: invalid_assignment)
    synchronizer = CloudPolicySynchronizer(
        client,  # type: ignore[arg-type]
        PolicyLoader(),
        scanner.install_policy_assignment,
        scanner.record_policy_sync_rejection,
    )
    try:
        with pytest.raises(PolicySyncError, match="invalid schema"):
            synchronizer.sync()
        with pytest.raises(PolicySyncError, match="invalid schema"):
            synchronizer.sync()

        assert scanner.policy.policy_version == "1.0.0"
        with scanner.storage.transaction() as connection:
            rows = connection.execute(
                "SELECT details_json FROM audit_log WHERE event_type='POLICY_SYNC_REJECTED'"
            ).fetchall()
        assert len(rows) == 1
        assert "must-never-be-audited" not in rows[0]["details_json"]
        details = json.loads(rows[0]["details_json"])
        assert details["reason"] == "cloud policy assignment has an invalid schema"
        assert len(details["document_sha256"]) == 64
    finally:
        scanner.storage.close()


def test_active_cloud_policy_is_restored_from_validated_cache_after_restart(
    tmp_path: Path,
) -> None:
    local_policy = policy()
    local_path = tmp_path / "local-policy.json"
    local_path.write_text(
        json.dumps(local_policy.model_dump(mode="json")),
        encoding="utf-8",
    )
    settings = ScannerSettings(
        environment="test",
        data_directory=tmp_path,
        policies=PolicySettings(directory=local_path, cloud_sync_enabled=False),
    )
    first = ScannerOrchestrator(
        settings,
        SQLiteStorage(settings.database_path),
        local_policy,
        collectors=FakePipeline(),  # type: ignore[arg-type]
        report_writer=AtomicReportWriter(tmp_path / "reports"),
    )
    try:
        version_two = policy_version("2.0.0")
        assert first.install_policy_assignment(
            [validated_policy(version_two)],
            "enterprise-default",
            "2.0.0",
            "assignment-restart",
        ) is True
    finally:
        first.storage.close()

    restarted = ScannerOrchestrator.from_settings(settings)
    try:
        assert restarted.policy.policy_id == "enterprise-default"
        assert restarted.policy.policy_version == "2.0.0"
        active = restarted.storage.get_active_policy_document()
        assert active is not None
        assert active["version"] == "2.0.0"
        assert active["source"] == "cloud"
    finally:
        restarted.storage.close()


def test_restart_migrates_legacy_unordered_policy_checksum(tmp_path: Path) -> None:
    document = policy().model_dump(mode="json")
    document["rules"][0]["platforms"] = ["WINDOWS", "LINUX"]
    document["rules"][0]["scan_types"] = ["QUICK", "FULL"]
    document["rules"][0]["tags"] = ["zeta", "alpha"]
    local_policy = PolicyBundle.model_validate(document)
    canonical_document = canonical_policy_document(local_policy)
    legacy_document = json.loads(json.dumps(canonical_document))
    legacy_document["rules"][0]["platforms"].reverse()
    legacy_document["rules"][0]["scan_types"].reverse()
    legacy_document["rules"][0]["tags"].reverse()
    legacy_checksum = hashlib.sha256(
        canonical_json(legacy_document).encode("utf-8")
    ).hexdigest()
    canonical_checksum = hashlib.sha256(canonical_policy_bytes(local_policy)).hexdigest()
    assert legacy_checksum != canonical_checksum

    local_path = tmp_path / "local-policy.json"
    local_path.write_text(json.dumps(legacy_document), encoding="utf-8")
    settings = ScannerSettings(
        environment="test",
        data_directory=tmp_path,
        policies=PolicySettings(directory=local_path, cloud_sync_enabled=False),
    )
    with SQLiteStorage(settings.database_path) as storage:
        storage.cache_policy_document(
            local_policy.policy_id,
            local_policy.policy_version,
            legacy_checksum,
            legacy_document,
            source="local",
            active=True,
        )

    restarted = ScannerOrchestrator.from_settings(settings)
    try:
        active = restarted.storage.get_active_policy_document()
        assert active is not None
        assert active["checksum"] == canonical_checksum
        assert active["document"] == canonical_document
    finally:
        restarted.storage.close()


def test_duplicate_scan_rebuilds_missing_report_and_idempotent_outbox(tmp_path: Path) -> None:
    pipeline = FakePipeline()
    scanner = orchestrator(tmp_path, pipeline)
    try:
        job = endpoint_job("scan-reconcile")
        expected = scanner.execute(job)
        report = tmp_path / "reports" / AtomicReportWriter.filename_for(job.scan_id)
        report.unlink()
        with scanner.storage.transaction() as connection:
            connection.execute("DELETE FROM upload_queue")

        reused = scanner.execute(job)

        assert reused == expected
        assert pipeline.calls == 1
        assert report.is_file()
        queued = drain_uploads(scanner)
        assert {item.kind for item in queued} == {"scan_result", "scan_status"}
        assert len(queued) == 2
        payload = json.loads(next(item.payload for item in queued if item.kind == "scan_result"))
        assert payload["result"]["scan_id"] == "scan-reconcile"
        assert payload["inventory_sync"]["mode"] == "full"
        status = json.loads(next(item.payload for item in queued if item.kind == "scan_status"))
        assert status["scan_id"] == "scan-reconcile"
        assert status["status"] == "SUCCESS"
    finally:
        scanner.storage.close()


def test_duplicate_reconciliation_failure_preserves_authoritative_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = FakePipeline()
    scanner = orchestrator(tmp_path, pipeline)
    try:
        job = endpoint_job("scan-duplicate-repair-failure")
        original_result = scanner.execute(job)
        original_job = scanner.storage.get_scan_job(job.scan_id)
        original_stored_result = scanner.storage.get_normalized_result(job.scan_id)
        assert original_job is not None
        assert original_stored_result is not None
        assert original_job["status"] == "COMPLETED"
        assert original_job["result_status"] == original_result.status.value

        def fail_outbox_repair(*_args: object, **_kwargs: object) -> None:
            raise OSError("duplicate outbox repair unavailable")

        monkeypatch.setattr(scanner.storage, "enqueue_upload", fail_outbox_repair)

        with pytest.raises(
            ScanExecutionError,
            match=(
                r"completed scan .* reconciliation failed: "
                r"duplicate outbox repair unavailable"
            ),
        ):
            scanner.execute(job)

        persisted_job = scanner.storage.get_scan_job(job.scan_id)
        assert persisted_job is not None
        assert persisted_job["status"] == "COMPLETED"
        assert persisted_job["result_status"] == original_job["result_status"]
        assert persisted_job["completed_at"] == original_job["completed_at"]
        assert persisted_job["error"] == original_job["error"]
        assert scanner.storage.get_normalized_result(job.scan_id) == original_stored_result
        assert pipeline.calls == 1
        with scanner.storage.transaction() as connection:
            failed_events = connection.execute(
                "SELECT COUNT(*) AS count FROM audit_log "
                "WHERE scan_id=? AND event_type='SCAN_FAILED'",
                (job.scan_id,),
            ).fetchone()
        assert failed_events is not None
        assert failed_events["count"] == 0
    finally:
        scanner.storage.close()


def test_result_and_terminal_outbox_use_custom_cloud_routes(tmp_path: Path) -> None:
    settings = ScannerSettings(
        environment="test",
        data_directory=tmp_path,
        retention=RetentionSettings(minimum_free_disk_bytes=16 * 1024 * 1024),
        cloud=CloudAPISettings(
            routes=CloudRouteSettings(
                scan_submit_path="/tenant/results",
                scan_status_path="/tenant/results/status",
            )
        ),
    )
    storage = SQLiteStorage(settings.database_path)
    scanner = ScannerOrchestrator(
        settings,
        storage,
        policy(),
        collectors=FakePipeline(),  # type: ignore[arg-type]
        report_writer=AtomicReportWriter(tmp_path / "reports"),
    )
    try:
        scanner.execute(endpoint_job("scan-custom-routes"))

        endpoints = {item.kind: item.endpoint for item in drain_uploads(scanner)}
        assert endpoints == {
            "scan_result": "/tenant/results",
            "scan_status": "/tenant/results/status",
        }
    finally:
        storage.close()


def test_failed_scan_persists_failure_and_queues_terminal_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = FakePipeline()
    scanner = orchestrator(tmp_path, pipeline)
    try:
        job = endpoint_job("scan-failed-status")

        def fail_collection(
            _job: ScanJob, *, deadline_at: float | None = None
        ) -> CollectionBundle:
            del deadline_at
            raise TimeoutError("simulated collection deadline")

        monkeypatch.setattr(pipeline, "collect", fail_collection)
        with pytest.raises(ScanExecutionError, match="collection deadline"):
            scanner.execute(job)

        persisted_job = scanner.storage.get_scan_job(job.scan_id)
        assert persisted_job is not None
        assert persisted_job["status"] == "FAILED"
        queued = scanner.storage.claim_uploads(limit=10, now=time.time() + 1)
        assert len(queued) == 1
        assert queued[0].kind == "scan_status"
        assert queued[0].endpoint == "/api/v1/scans/status"
        assert json.loads(queued[0].payload)["status"] == "FAILED"
    finally:
        scanner.storage.close()


def test_collection_uses_the_original_total_scan_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = FakePipeline()
    scanner = orchestrator(tmp_path, pipeline)
    monotonic_calls = 0

    def monotonic() -> float:
        nonlocal monotonic_calls
        monotonic_calls += 1
        return 100.0 if monotonic_calls == 1 else 104.0

    monkeypatch.setattr("app.orchestrator.scanner.time.monotonic", monotonic)
    try:
        job = endpoint_job("scan-total-deadline").model_copy(
            update={"timeout_seconds": 10}
        )

        scanner.execute(job)

        assert pipeline.deadlines == [110.0]
    finally:
        scanner.storage.close()


def test_disk_reserve_blocks_scan_before_any_endpoint_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = FakePipeline()
    scanner = orchestrator(tmp_path, pipeline)
    monkeypatch.setattr(
        "app.storage.maintenance.shutil.disk_usage",
        lambda _path: SimpleNamespace(free=0),
    )
    try:
        with pytest.raises(ScanExecutionError, match="free disk"):
            scanner.execute(endpoint_job("scan-capacity-denied"))

        assert pipeline.calls == 0
        persisted = scanner.storage.get_scan_job("scan-capacity-denied")
        assert persisted is not None
        assert persisted["status"] == "FAILED"
    finally:
        scanner.storage.close()


def test_terminal_status_reconciliation_repairs_interrupted_outbox(tmp_path: Path) -> None:
    scanner = orchestrator(tmp_path, FakePipeline())
    try:
        job = endpoint_job("scan-terminal-reconcile")
        stored_job = job.model_dump(mode="json", exclude_none=True)
        stored_job.update({"status": "QUEUED", "initiator": job.initiated_by})
        scanner.storage.create_scan_job(stored_job)
        scanner.storage.update_scan_job(
            job.scan_id,
            "FAILED",
            completed_at=datetime.now(UTC).isoformat(),
            result_status="FAILED",
            error="interrupted before terminal outbox enqueue",
        )

        assert scanner.storage.queue_stats().active == 0
        assert scanner.reconcile_terminal_statuses(limit=10) == 1
        assert scanner.reconcile_terminal_statuses(limit=10) == 0

        queued = scanner.storage.claim_uploads(limit=10, now=time.time() + 1)
        assert len(queued) == 1
        assert queued[0].kind == "scan_status"
        assert queued[0].endpoint == "/api/v1/scans/status"
        payload = json.loads(queued[0].payload)
        assert payload["scan_id"] == job.scan_id
        assert payload["status"] == "FAILED"
        assert payload["authorization_scope_id"] == job.authorization.scope_id
    finally:
        scanner.storage.close()


def test_terminal_reconciliation_uses_persisted_result_policy_provenance(
    tmp_path: Path,
) -> None:
    scanner = orchestrator(tmp_path, FakePipeline())
    try:
        job = endpoint_job("scan-terminal-policy-provenance").model_copy(
            update={"policy_version": "1.0.0"}
        )
        produced = scanner.execute(job)
        assert produced.policy_version == "1.0.0"
        assert produced.policy_checksum is not None

        with scanner.storage.transaction() as connection:
            connection.execute("DELETE FROM upload_queue")
            connection.execute(
                "DELETE FROM scan_history WHERE scan_id=? "
                "AND event='TERMINAL_STATUS_QUEUED'",
                (job.scan_id,),
            )

        replacement = ScannerOrchestrator(
            scanner.settings,
            scanner.storage,
            policy_version("2.0.0"),
            collectors=FakePipeline(),  # type: ignore[arg-type]
            report_writer=scanner.report_writer,
        )
        with pytest.raises(ValueError, match="not validated and cached"):
            replacement.resolve_policy(job)

        assert replacement.reconcile_terminal_statuses(limit=10) == 1
        queued = replacement.storage.claim_uploads(limit=10, now=time.time() + 1)
        assert len(queued) == 1
        assert queued[0].kind == "scan_status"
        payload = json.loads(queued[0].payload)
        assert payload["policy_id"] == produced.policy_id
        assert payload["policy_version"] == produced.policy_version
        assert payload["policy_checksum"] == produced.policy_checksum
        assert payload["status"] == produced.status.value
    finally:
        scanner.storage.close()


def test_result_outbox_and_completion_roll_back_together_on_queue_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = FakePipeline()
    scanner = orchestrator(tmp_path, pipeline)
    try:
        job = endpoint_job("scan-atomic")

        def fail_queue(*_args: object, **_kwargs: object) -> None:
            raise OSError("simulated queue disk failure")

        monkeypatch.setattr(scanner.storage, "enqueue_upload", fail_queue)
        with pytest.raises(ScanExecutionError, match="queue disk failure"):
            scanner.execute(job)

        assert scanner.storage.get_normalized_result(job.scan_id) is None
        assert scanner.storage.queue_stats().active == 0
        persisted_job = scanner.storage.get_scan_job(job.scan_id)
        assert persisted_job is not None
        assert persisted_job["status"] == "FAILED"
    finally:
        scanner.storage.close()
