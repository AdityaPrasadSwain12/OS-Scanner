from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from random import Random

import pytest

from app.storage import (
    DatabaseIntegrityError,
    IdempotencyConflictError,
    RetryPolicy,
    SQLiteStorage,
    StorageError,
    UploadStatus,
)
from app.storage.serialization import canonical_json, parse_json


def _job(scan_id: str, endpoint_id: str = "endpoint-1") -> dict[str, str]:
    return {
        "scan_id": scan_id,
        "endpoint_id": endpoint_id,
        "scan_type": "FULL",
        "status": "QUEUED",
        "authorization": {"scope_id": "scope-1", "authorized": True},
    }


def test_database_migrates_and_persists_endpoint_job(tmp_path: Path) -> None:
    path = tmp_path / "scanner.db"
    with SQLiteStorage(path) as storage:
        assert storage.schema_version >= 5
        storage.upsert_endpoint("endpoint-1", {"hostname": "host-a"})
        assert storage.create_scan_job(_job("scan-1")) is True
        assert storage.create_scan_job(_job("scan-1")) is False

    with SQLiteStorage(path) as reopened:
        assert reopened.get_endpoint("endpoint-1")["state"] == {"hostname": "host-a"}
        assert reopened.get_scan_job("scan-1")["authorization"]["authorized"] is True
        assert reopened.check_integrity()


def test_validated_policy_documents_are_cached_and_activated_durably(tmp_path: Path) -> None:
    database = tmp_path / "scanner.db"
    first = {
        "schema_version": "1.0",
        "policy_id": "enterprise-policy",
        "policy_version": "1.0.0",
        "rules": [{"rule_id": "CONTROL-1"}],
    }
    second = {
        "schema_version": "1.0",
        "policy_id": "enterprise-policy",
        "policy_version": "2.0.0",
        "rules": [{"rule_id": "CONTROL-2"}],
    }

    def checksum(document: dict[str, object]) -> str:
        return sha256(canonical_json(document).encode("utf-8")).hexdigest()

    with SQLiteStorage(database) as storage:
        storage.cache_policy_document(
            "enterprise-policy",
            "1.0.0",
            checksum(first),
            first,
            source="bundled",
            active=True,
        )
        storage.cache_policy_document(
            "enterprise-policy",
            "2.0.0",
            checksum(second),
            second,
            source="cloud",
        )
        assert storage.get_active_policy_document()["version"] == "1.0.0"

        storage.activate_policy_document("enterprise-policy", "2.0.0")
        documents = storage.list_policy_documents()
        assert [item["version"] for item in documents] == ["2.0.0", "1.0.0"]
        assert documents[0]["active"] is True
        assert documents[0]["assigned"] is True
        assert documents[0]["source"] == "cloud"
        assert documents[0]["document"] == second
        assert documents[1]["active"] is False

        storage.cache_policy_document(
            "enterprise-policy",
            "2.0.0",
            checksum(second),
            second,
            source="cloud",
        )
        assert storage.get_active_policy_document()["version"] == "2.0.0"

        conflicting = {
            **second,
            "rules": [{"rule_id": "CONTROL-TAMPERED"}],
        }
        with pytest.raises(IdempotencyConflictError, match="different content"):
            storage.cache_policy_document(
                "enterprise-policy",
                "2.0.0",
                checksum(conflicting),
                conflicting,
                source="cloud",
            )
        assert storage.get_active_policy_document()["document"] == second

        with pytest.raises(ValueError, match="checksum"):
            storage.cache_policy_document(
                "enterprise-policy",
                "3.0.0",
                "0" * 64,
                second,
                source="cloud",
            )
        with pytest.raises(ValueError, match="not cached"):
            storage.activate_policy_document("enterprise-policy", "9.9.9")

    with SQLiteStorage(database) as reopened:
        active = reopened.get_active_policy_document()
        assert active is not None
        assert active["version"] == "2.0.0"
        assert active["document"] == second


def test_endpoint_identity_listing_can_require_enrollment() -> None:
    with SQLiteStorage(":memory:") as storage:
        storage.upsert_endpoint(
            "placeholder",
            {"hostname": "unknown"},
            now="2025-12-31T00:00:00+00:00",
        )
        storage.upsert_endpoint(
            "enrolled-1",
            {"hostname": "host-1"},
            enrolled_at="2026-01-01T00:00:00+00:00",
            now="2026-01-01T00:00:00+00:00",
        )
        storage.upsert_endpoint(
            "enrolled-2",
            {"hostname": "host-2"},
            enrolled_at="2026-01-02T00:00:00+00:00",
            now="2026-01-02T00:00:00+00:00",
        )

        assert storage.list_endpoint_ids(enrolled_only=True, limit=10) == [
            "enrolled-1",
            "enrolled-2",
        ]
        assert storage.list_endpoint_ids(limit=2) == ["placeholder", "enrolled-1"]
        with pytest.raises(ValueError, match="endpoint list limit"):
            storage.list_endpoint_ids(limit=0)


def test_scan_job_idempotency_rejects_changed_content() -> None:
    with SQLiteStorage(":memory:") as storage:
        storage.create_scan_job(_job("scan-1"))
        changed = {**_job("scan-1"), "scan_type": "QUICK"}
        with pytest.raises(IdempotencyConflictError):
            storage.create_scan_job(changed)


def test_snapshot_deduplication_and_differential_payloads() -> None:
    with SQLiteStorage(":memory:") as storage:
        first = storage.store_snapshot(
            "endpoint-1",
            "scan-1",
            {"os": {"version": "1"}, "software": [{"name": "Browser", "version": "1"}]},
            "1.0",
        )
        unchanged = storage.store_snapshot(
            "endpoint-1",
            "scan-2",
            {"software": [{"version": "1", "name": "Browser"}], "os": {"version": "1"}},
            "1.0",
        )
        changed = storage.store_snapshot(
            "endpoint-1",
            "scan-3",
            {"os": {"version": "1"}, "software": [{"name": "Browser", "version": "2"}]},
            "1.0",
        )

        assert storage.snapshot_upload_payload(first.snapshot_id)["mode"] == "full"
        assert unchanged.changed is False
        assert storage.snapshot_upload_payload(unchanged.snapshot_id)["mode"] == "unchanged"
        assert changed.events == ("SOFTWARE_CHANGED",)
        delta = storage.snapshot_upload_payload(changed.snapshot_id)
        assert delta["mode"] == "delta"
        assert delta["sections"]["software"][0]["version"] == "2"


def test_snapshot_projection_ignores_per_scan_context_but_keeps_state_timestamps() -> None:
    first = {
        "endpoint": {
            "endpoint_id": "endpoint-1",
            "hostname": "host-1",
            "last_seen_at": "2026-01-01T00:00:00Z",
        },
        "software": [{"name": "Browser", "version": "1", "installed_at": "2025-01-01T00:00:00Z"}],
        "vulnerabilities": [
            {
                "scan_id": "scan-1",
                "endpoint_id": "endpoint-1",
                "schema_version": "1.0",
                "scanner_version": "1.0.0",
                "vulnerability_id": "CVE-2026-0001",
                "package_name": "Browser",
                "installed_version": "1",
                "severity": "HIGH",
                "detected_at": "2026-01-01T00:00:00Z",
            }
        ],
        "compliance": [
            {
                "scan_id": "scan-1",
                "endpoint_id": "endpoint-1",
                "schema_version": "1.0",
                "scanner_version": "1.0.0",
                "rule_id": "RULE-1",
                "status": "FAIL",
                "evaluated_at": "2026-01-01T00:00:00Z",
            }
        ],
    }
    second = {
        **first,
        "endpoint": {**first["endpoint"], "last_seen_at": "2026-01-02T00:00:00Z"},
        "vulnerabilities": [
            {
                **first["vulnerabilities"][0],
                "scan_id": "scan-2",
                "detected_at": "2026-01-02T00:00:00Z",
            }
        ],
        "compliance": [
            {
                **first["compliance"][0],
                "scan_id": "scan-2",
                "evaluated_at": "2026-01-02T00:00:00Z",
            }
        ],
    }
    with SQLiteStorage(":memory:") as storage:
        storage.store_snapshot("endpoint-1", "scan-1", first, "1.0")
        unchanged = storage.store_snapshot("endpoint-1", "scan-2", second, "1.0")
        assert unchanged.changed is False

        third = {
            **second,
            "software": [
                {
                    **second["software"][0],
                    "installed_at": "2026-01-02T00:00:00Z",
                }
            ],
        }
        changed = storage.store_snapshot("endpoint-1", "scan-3", third, "1.0")
        assert changed.events == ("SOFTWARE_CHANGED",)


def test_partial_snapshot_preserves_last_known_unobserved_sections() -> None:
    first_result = {
        "schema_version": "1.0",
        "scanner_version": "1.0.0",
        "scan_id": "scan-complete",
        "scan_type": "FULL",
        "status": "SUCCESS",
        "software": [{"name": "Enterprise Browser", "version": "1.0"}],
        "services": [{"name": "security-agent", "state": "RUNNING"}],
        "metadata": {
            "observed_inventory_sections": ["services", "software"],
        },
    }
    partial_result = {
        "schema_version": "1.0",
        "scanner_version": "1.0.0",
        "scan_id": "scan-partial",
        "scan_type": "FULL",
        "status": "PARTIAL",
        "services": [{"name": "security-agent", "state": "RUNNING"}],
        "metadata": {
            "observed_inventory_sections": ["services"],
        },
    }

    with SQLiteStorage(":memory:") as storage:
        storage.save_scan_result("scan-complete", "endpoint-1", first_result)
        change = storage.save_scan_result("scan-partial", "endpoint-1", partial_result)

        assert change is not None
        assert "SOFTWARE_CHANGED" not in change.events
        latest = storage.get_latest_snapshot("endpoint-1")
        assert latest is not None
        snapshot = latest["snapshot"]
        assert snapshot["software"] == [
            {"name": "Enterprise Browser", "version": "1.0"}
        ]
        assert snapshot["collection_completeness"]["observed_sections"] == [
            "services"
        ]
        assert "software" in snapshot["collection_completeness"][
            "unobserved_sections"
        ]
        differential = storage.snapshot_upload_payload(change.snapshot_id)
        assert "software" not in differential.get("removed_sections", [])


def test_partial_security_evidence_does_not_replace_authoritative_posture() -> None:
    complete_result = {
        "schema_version": "1.0",
        "scanner_version": "1.0.0",
        "scan_id": "scan-security-complete",
        "scan_type": "QUICK",
        "status": "SUCCESS",
        "security": {
            "firewall_enabled": True,
            "disk_encryption_enabled": True,
        },
        "metadata": {"observed_inventory_sections": ["security"]},
    }
    partial_result = {
        "schema_version": "1.0",
        "scanner_version": "1.0.0",
        "scan_id": "scan-security-partial",
        "scan_type": "QUICK",
        "status": "PARTIAL",
        # Successful firewall evidence remains available in this scan result,
        # while failed encryption collection prevents snapshot authority.
        "security": {"firewall_enabled": False},
        "metadata": {"observed_inventory_sections": []},
        "collectors": {
            "native.firewall": {"status": "SUCCESS"},
            "native.disk_encryption": {"status": "FAILED"},
        },
    }

    with SQLiteStorage(":memory:") as storage:
        storage.save_scan_result(
            "scan-security-complete", "endpoint-1", complete_result
        )
        change = storage.save_scan_result(
            "scan-security-partial", "endpoint-1", partial_result
        )

        assert change is not None
        assert "SECURITY_POSTURE_CHANGED" not in change.events
        current = storage.get_normalized_result("scan-security-partial")
        assert current is not None
        assert current["payload"]["security"] == {"firewall_enabled": False}
        latest = storage.get_latest_snapshot("endpoint-1")
        assert latest is not None
        assert latest["snapshot"]["security"] == {
            "disk_encryption_enabled": True,
            "firewall_enabled": True,
        }


def test_full_results_and_attack_surface_results_are_persisted() -> None:
    with SQLiteStorage(":memory:") as storage:
        endpoint_result = {
            "schema_version": "1.0",
            "scanner_version": "1.0.0",
            "scan_id": "scan-1",
            "scan_type": "FULL",
            "status": "SUCCESS",
            "timestamp": "2026-01-01T00:00:00Z",
            "software": [{"name": "Browser", "version": "1"}],
            "findings": [],
            "collectors": {"optional": {"status": "SKIPPED"}},
        }
        snapshot = storage.save_scan_result("scan-1", "endpoint-1", endpoint_result)
        assert snapshot is not None
        assert storage.get_normalized_result("scan-1")["payload"] == endpoint_result

        attack_result = {
            "schema_version": "1.0",
            "scan_id": "scan-attack",
            "scan_type": "ATTACK_SURFACE",
            "status": "SUCCESS",
            "metadata": {"authorized_target": "example.test"},
            "attack_surface": [{"hostname": "api.example.test", "type": "SUBDOMAIN"}],
        }
        assert storage.save_scan_result("scan-attack", None, attack_result) is None
        stored = storage.get_normalized_result("scan-attack")
        assert stored is not None
        assert stored["result_type"] == "ATTACK_SURFACE"
        assert stored["target"] == "example.test"
        assert stored["payload"]["attack_surface"][0]["hostname"] == "api.example.test"


def test_transaction_rolls_back_all_nested_result_writes() -> None:
    with SQLiteStorage(":memory:") as storage:
        invalid = {
            "schema_version": "1.0",
            "scan_type": "FULL",
            "status": "SUCCESS",
            "software": [],
            "findings": [{"finding_id": "f1", "rule_id": "r1", "severity": "UNKNOWN"}],
        }
        with pytest.raises(ValueError, match="severity"):
            storage.save_scan_result("scan-1", "endpoint-1", invalid)
        assert storage.get_normalized_result("scan-1") is None


def test_upload_queue_deduplicates_claims_and_recovers_expired_leases() -> None:
    with SQLiteStorage(":memory:") as storage:
        first = storage.enqueue_upload(
            "scan-result",
            {"scan_id": "scan-1"},
            "scan:1",
            "/api/v1/scans",
            max_attempts=2,
            not_before=100,
        )
        duplicate = storage.enqueue_upload(
            "scan-result", {"scan_id": "scan-1"}, "scan:1", "/api/v1/scans", max_attempts=2
        )
        assert first.upload_id == duplicate.upload_id
        assert duplicate.created is False
        with pytest.raises(IdempotencyConflictError):
            storage.enqueue_upload("scan-result", {"scan_id": "changed"}, "scan:1", "/api/v1/scans")

        claim = storage.claim_uploads(now=100, lease_seconds=10)[0]
        assert storage.claim_uploads(now=105) == []
        recovered = storage.claim_uploads(now=111, lease_seconds=10)[0]
        assert recovered.upload_id == claim.upload_id
        assert recovered.attempt_count == 2
        status = storage.mark_upload_failed(
            recovered.upload_id, recovered.lease_token, "offline", now=111
        )
        assert status == UploadStatus.DEAD


def test_causal_uploads_are_claimed_in_per_endpoint_lifecycle_order() -> None:
    with SQLiteStorage(":memory:") as storage:
        enqueued = [
            storage.enqueue_upload(
                kind,
                {"scan_id": scan_id, "endpoint_id": "endpoint-1"},
                f"causal-{index}",
                endpoint,
                metadata={"scan_id": scan_id, "endpoint_id": "endpoint-1"},
                not_before=0,
            )
            for index, (kind, scan_id, endpoint) in enumerate(
                (
                    ("scan_result", "scan-1", "/api/v1/scans"),
                    ("scan_status", "scan-1", "/api/v1/scans/status"),
                    ("scan_result", "scan-2", "/api/v1/scans"),
                ),
                start=1,
            )
        ]

        for expected in enqueued:
            claimed = storage.claim_uploads(limit=10, now=1)
            assert [item.upload_id for item in claimed] == [expected.upload_id]
            assert storage.mark_upload_succeeded(
                claimed[0].upload_id, claimed[0].lease_token
            )
        assert storage.claim_uploads(limit=10, now=1) == []


def test_retrying_or_dead_predecessor_blocks_later_causal_uploads() -> None:
    with SQLiteStorage(":memory:") as storage:
        first = storage.enqueue_upload(
            "scan_result",
            {"scan_id": "scan-1", "endpoint_id": "endpoint-1"},
            "causal-blocking-result",
            "/api/v1/scans",
            metadata={"scan_id": "scan-1", "endpoint_id": "endpoint-1"},
            max_attempts=2,
            not_before=0,
        )
        later = storage.enqueue_upload(
            "scan_status",
            {"scan_id": "scan-1", "endpoint_id": "endpoint-1"},
            "causal-blocked-status",
            "/api/v1/scans/status",
            metadata={"scan_id": "scan-1", "endpoint_id": "endpoint-1"},
            not_before=0,
        )

        first_claim = storage.claim_uploads(limit=10, now=1)
        assert [item.upload_id for item in first_claim] == [first.upload_id]
        assert storage.mark_upload_failed(
            first_claim[0].upload_id,
            first_claim[0].lease_token,
            "temporary",
            retry_policy=RetryPolicy(base_delay_seconds=1, jitter_ratio=0),
            now=1,
        ) is UploadStatus.PENDING
        assert storage.claim_uploads(limit=10, now=1) == []

        retry = storage.claim_uploads(limit=10, now=2)
        assert [item.upload_id for item in retry] == [first.upload_id]
        assert storage.mark_upload_failed(
            retry[0].upload_id,
            retry[0].lease_token,
            "terminal",
            permanent=True,
            now=2,
        ) is UploadStatus.DEAD
        assert storage.claim_uploads(limit=10, now=10) == []
        assert storage.get_upload(later.upload_id)["status"] == UploadStatus.PENDING.value


def test_operator_requeue_repairs_dead_predecessor_without_skipping_causality() -> None:
    with SQLiteStorage(":memory:") as storage:
        uploads = [
            storage.enqueue_upload(
                kind,
                {"scan_id": scan_id, "endpoint_id": "endpoint-1"},
                f"operator-recovery-{index}",
                endpoint,
                metadata={"scan_id": scan_id, "endpoint_id": "endpoint-1"},
                max_attempts=1,
                not_before=0,
            )
            for index, (kind, scan_id, endpoint) in enumerate(
                (
                    ("scan_result", "scan-1", "/api/v1/scans"),
                    ("scan_status", "scan-1", "/api/v1/scans/status"),
                    ("scan_result", "scan-2", "/api/v1/scans"),
                ),
                start=1,
            )
        ]
        failed = storage.claim_uploads(limit=10, now=1)[0]
        assert failed.upload_id == uploads[0].upload_id
        assert storage.mark_upload_failed(
            failed.upload_id,
            failed.lease_token,
            "terminal token=do-not-audit",
            permanent=True,
            now=1,
        ) is UploadStatus.DEAD
        assert storage.claim_uploads(limit=10, now=10) == []

        recovery = storage.requeue_dead_upload(
            failed.upload_id,
            actor="security-operator@example.test",
            reason="approved incident INC-42; token=do-not-store",
            max_attempts=3,
            now=20,
        )

        assert recovery["status"] == UploadStatus.PENDING.value
        repaired = storage.get_upload(failed.upload_id)
        assert repaired is not None
        assert repaired["attempt_count"] == 0
        assert repaired["max_attempts"] == 3
        assert repaired["predecessor_upload_id"] is None
        assert "do-not-store" not in canonical_json(repaired["metadata"])
        assert repaired["metadata"]["operator_recovery"]["reason"].endswith(
            "token=[REDACTED]"
        )

        with storage.transaction() as connection:
            audit = connection.execute(
                "SELECT * FROM audit_log WHERE event_id=?",
                (recovery["audit_event_id"],),
            ).fetchone()
        assert audit is not None
        details = parse_json(audit["details_json"])
        assert audit["event_type"] == "upload.dead_letter_requeued"
        assert audit["actor"] == "security-operator@example.test"
        assert audit["resource_id"] == str(failed.upload_id)
        assert details["previous_error_sha256"] == sha256(
            b"terminal token=[REDACTED]"
        ).hexdigest()
        assert "payload" not in details
        assert "idempotency_key" not in details
        assert "do-not-store" not in audit["details_json"]
        assert storage.verify_audit_chain()

        for expected in uploads:
            claimed = storage.claim_uploads(limit=10, now=20)
            assert [item.upload_id for item in claimed] == [expected.upload_id]
            assert storage.mark_upload_succeeded(
                claimed[0].upload_id, claimed[0].lease_token
            )


def test_operator_requeue_rejects_non_dead_and_superseded_rows() -> None:
    with SQLiteStorage(":memory:") as storage:
        pending = storage.enqueue_upload(
            "scan_result",
            {"scan_id": "scan-pending", "endpoint_id": "endpoint-1"},
            "operator-pending",
            "/api/v1/scans",
            metadata={"scan_id": "scan-pending", "endpoint_id": "endpoint-1"},
            not_before=0,
        )
        with pytest.raises(StorageError, match="only a DEAD"):
            storage.requeue_dead_upload(
                pending.upload_id, actor="operator-1", reason="not dead", now=1
            )

        storage.store_snapshot(
            "endpoint-1", "scan-base", {"software": [{"version": "1"}]}, "1.0"
        )
        changed = storage.store_snapshot(
            "endpoint-1", "scan-change", {"software": [{"version": "2"}]}, "1.0"
        )
        original = storage.enqueue_upload(
            "scan_result",
            {
                "result": {"scan_id": "scan-change", "endpoint_id": "endpoint-1"},
                "inventory_sync": storage.snapshot_upload_payload(changed.snapshot_id),
            },
            "operator-superseded",
            "/api/v1/scans",
            metadata={"scan_id": "scan-change", "endpoint_id": "endpoint-1"},
            not_before=0,
        )
        first_claim = storage.claim_uploads(limit=1, now=1)[0]
        assert first_claim.upload_id == pending.upload_id
        assert storage.mark_upload_succeeded(first_claim.upload_id, first_claim.lease_token)
        original_claim = storage.claim_uploads(limit=1, now=1)[0]
        assert original_claim.upload_id == original.upload_id
        replacement = storage.schedule_full_resync(
            original_claim.upload_id,
            original_claim.lease_token,
            "remote inventory conflict",
            now=1,
        )
        with pytest.raises(StorageError, match="superseding upload"):
            storage.requeue_dead_upload(
                original.upload_id,
                actor="operator-1",
                reason="wrong recovery target",
                now=2,
            )
        with pytest.raises(StorageError, match="only a DEAD"):
            storage.requeue_dead_upload(
                replacement.upload_id,
                actor="operator-1",
                reason="replacement remains pending",
                now=2,
            )


def test_operator_requeue_rolls_back_when_audit_append_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStorage(":memory:") as storage:
        upload = storage.enqueue_upload(
            "scan_result",
            {"scan_id": "scan-rollback", "endpoint_id": "endpoint-1"},
            "operator-rollback",
            "/api/v1/scans",
            metadata={"scan_id": "scan-rollback", "endpoint_id": "endpoint-1"},
            max_attempts=1,
            not_before=0,
        )
        claimed = storage.claim_uploads(limit=1, now=1)[0]
        assert storage.mark_upload_failed(
            claimed.upload_id, claimed.lease_token, "terminal", permanent=True, now=1
        ) is UploadStatus.DEAD
        storage.record_audit_event(
            "unrelated.event", "SUCCESS", event_id="fixed-recovery-event"
        )
        monkeypatch.setattr(
            "app.storage.upload_queue.uuid4", lambda: "fixed-recovery-event"
        )

        with pytest.raises(IdempotencyConflictError):
            storage.requeue_dead_upload(
                upload.upload_id,
                actor="operator-1",
                reason="exercise atomic rollback",
                now=2,
            )

        unchanged = storage.get_upload(upload.upload_id)
        assert unchanged is not None
        assert unchanged["status"] == UploadStatus.DEAD.value
        assert unchanged["attempt_count"] == 1
        assert unchanged["last_error"] == "terminal"
        assert "operator_recovery" not in unchanged["metadata"]
        assert storage.verify_audit_chain()


@pytest.mark.parametrize(
    ("actor", "reason"),
    (("", "valid"), ("operator", ""), ("operator\nname", "valid")),
)
def test_operator_requeue_requires_bounded_nonempty_identity_and_reason(
    actor: str, reason: str
) -> None:
    with SQLiteStorage(":memory:") as storage, pytest.raises(ValueError):
        storage.requeue_dead_upload(1, actor=actor, reason=reason)

    with SQLiteStorage(":memory:") as storage, pytest.raises(ValueError):
        storage.requeue_dead_upload(1, actor="operator", reason="x" * 513)


def test_upload_backoff_is_exponential_and_bounded() -> None:
    policy = RetryPolicy(
        max_attempts=5,
        base_delay_seconds=2,
        multiplier=2,
        max_delay_seconds=5,
        jitter_ratio=0,
    )
    random_source = Random(0)  # noqa: S311 - deterministic retry timing test
    assert policy.delay_for_attempt(1, random_source=random_source) == 2
    assert policy.delay_for_attempt(2, random_source=random_source) == 4
    assert policy.delay_for_attempt(3, random_source=random_source) == 5


def test_audit_log_is_idempotent_and_hash_chained() -> None:
    with SQLiteStorage(":memory:") as storage:
        first = storage.record_audit_event(
            "scan.authorized",
            "SUCCESS",
            event_id="event-1",
            scan_id="scan-1",
            authorization_scope_id="scope-1",
            details={"authorized": True},
            created_at="2026-01-01T00:00:00Z",
        )
        assert first == storage.record_audit_event(
            "scan.authorized",
            "SUCCESS",
            event_id="event-1",
            scan_id="scan-1",
            authorization_scope_id="scope-1",
            details={"authorized": True},
            created_at="2026-01-01T00:00:00Z",
        )
        storage.record_audit_event("scan.completed", "SUCCESS", event_id="event-2")
        assert storage.verify_audit_chain()


def test_corrupt_database_is_reported_without_replacement(tmp_path: Path) -> None:
    path = tmp_path / "scanner.db"
    original = b"this is not a sqlite database"
    path.write_bytes(original)
    with pytest.raises(DatabaseIntegrityError):
        SQLiteStorage(path)
    assert path.read_bytes() == original


def test_closed_storage_rejects_operations() -> None:
    storage = SQLiteStorage(":memory:")
    storage.close()
    with pytest.raises(StorageError):
        storage.queue_stats()
