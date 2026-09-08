from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.storage.maintenance as maintenance_module
from app.core import RetentionSettings
from app.reporting import AtomicReportWriter
from app.storage import SQLiteStorage, StorageCapacityError, StorageMaintenance, UploadStatus


def _job(scan_id: str, endpoint_id: str) -> dict[str, object]:
    return {
        "scan_id": scan_id,
        "endpoint_id": endpoint_id,
        "scan_type": "FULL",
        "status": "QUEUED",
        "authorization": {"scope_id": "scope-1", "authorized": True},
    }


def _complete(
    storage: SQLiteStorage,
    scan_id: str,
    endpoint_id: str,
    *,
    completed_at: datetime,
) -> None:
    storage.create_scan_job(_job(scan_id, endpoint_id))
    storage.update_scan_job(
        scan_id,
        "COMPLETED",
        completed_at=completed_at.isoformat(),
        result_status="SUCCESS",
    )


def test_pruning_protects_legal_hold_latest_snapshot_and_active_or_dead_outbox(
    tmp_path: Path,
) -> None:
    old = datetime(2020, 1, 1, tzinfo=UTC)
    scan_ids = {
        "scan-legal-hold": "endpoint-held",
        "scan-latest": "endpoint-latest",
        "scan-pending-upload": "endpoint-pending",
        "scan-inflight-upload": "endpoint-inflight",
        "scan-dead-upload": "endpoint-dead",
    }
    with SQLiteStorage(tmp_path / "scanner.db") as storage:
        for scan_id, endpoint_id in scan_ids.items():
            _complete(storage, scan_id, endpoint_id, completed_at=old)
        storage.store_snapshot(
            "endpoint-latest",
            "scan-latest",
            {"os": {"version": "1"}},
            "1.0",
            created_at=old.isoformat(),
        )

        dead = storage.enqueue_upload(
            "artifact",
            {"scan_id": "scan-dead-upload"},
            "retention-dead",
            "/api/v1/artifacts",
            metadata={"scan_id": "scan-dead-upload"},
            max_attempts=1,
            not_before=0,
        )
        dead_claim = storage.claim_uploads(limit=1, now=1)[0]
        assert dead_claim.upload_id == dead.upload_id
        assert (
            storage.mark_upload_failed(
                dead_claim.upload_id,
                dead_claim.lease_token,
                "permanent delivery failure",
                permanent=True,
                now=1,
            )
            is UploadStatus.DEAD
        )
        inflight = storage.enqueue_upload(
            "artifact",
            {"scan_id": "scan-inflight-upload"},
            "retention-inflight",
            "/api/v1/artifacts",
            metadata={"scan_id": "scan-inflight-upload"},
            not_before=0,
        )
        inflight_claim = storage.claim_uploads(limit=1, now=1)[0]
        assert inflight_claim.upload_id == inflight.upload_id
        storage.enqueue_upload(
            "artifact",
            {"scan_id": "scan-pending-upload"},
            "retention-pending",
            "/api/v1/artifacts",
            metadata={"scan_id": "scan-pending-upload"},
            not_before=0,
        )

        removed = storage.prune_completed_scan_records(
            older_than=datetime(2025, 1, 1, tzinfo=UTC).isoformat(),
            max_completed_scans=100,
            protected_scan_ids={"scan-legal-hold"},
            limit=100,
        )

        assert removed == 0
        assert all(storage.get_scan_job(scan_id) is not None for scan_id in scan_ids)


def test_pruning_delivered_old_scan_rebases_child_and_removes_orphan_payloads(
    tmp_path: Path,
) -> None:
    old = datetime(2020, 1, 1, tzinfo=UTC)
    recent = datetime(2026, 1, 1, tzinfo=UTC)
    with SQLiteStorage(tmp_path / "scanner.db") as storage:
        _complete(storage, "scan-old", "endpoint-1", completed_at=old)
        old_result = {
            "schema_version": "1.0",
            "scanner_version": "1.0.0",
            "scan_id": "scan-old",
            "endpoint_id": "endpoint-1",
            "scan_type": "FULL",
            "status": "SUCCESS",
            "software": [{"name": "browser", "version": "1"}],
        }
        storage.save_scan_result("scan-old", "endpoint-1", old_result)
        delivered = storage.enqueue_upload(
            "artifact",
            {"scan_id": "scan-old"},
            "retention-delivered",
            "/api/v1/artifacts",
            metadata={"scan_id": "scan-old"},
            not_before=0,
        )
        claim = storage.claim_uploads(limit=1, now=1)[0]
        assert claim.upload_id == delivered.upload_id
        assert storage.mark_upload_succeeded(
            claim.upload_id,
            claim.lease_token,
            delivered_at=old.isoformat(),
        )

        _complete(storage, "scan-new", "endpoint-1", completed_at=recent)
        new_result = {
            **old_result,
            "scan_id": "scan-new",
            "software": [{"name": "browser", "version": "2"}],
        }
        new_change = storage.save_scan_result("scan-new", "endpoint-1", new_result)
        assert new_change is not None and new_change.previous_hash is not None
        with storage.transaction() as connection:
            assert connection.execute("SELECT COUNT(*) FROM result_payloads").fetchone()[0] == 2
            assert connection.execute("SELECT COUNT(*) FROM inventory_payloads").fetchone()[0] == 2

        removed = storage.prune_completed_scan_records(
            older_than=datetime(2025, 1, 1, tzinfo=UTC).isoformat(),
            max_completed_scans=100,
            limit=100,
        )

        assert removed == 1
        assert storage.get_scan_job("scan-old") is None
        assert storage.get_normalized_result("scan-old") is None
        assert storage.get_scan_job("scan-new") is not None
        rebased = storage.snapshot_upload_payload(new_change.snapshot_id)
        assert rebased["mode"] == "full"
        assert rebased["previous_hash"] is None
        assert rebased["snapshot"]["software"][0]["version"] == "2"
        with storage.transaction() as connection:
            assert connection.execute("SELECT COUNT(*) FROM result_payloads").fetchone()[0] == 1
            assert connection.execute("SELECT COUNT(*) FROM inventory_payloads").fetchone()[0] == 1


def test_report_retention_honors_age_count_and_legal_holds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    reports = tmp_path / "reports"
    writer = AtomicReportWriter(reports)
    held = writer.write("scan-held", {"scan_id": "scan-held"})
    stale = writer.write("scan-stale", {"scan_id": "scan-stale"})
    fresh = [
        writer.write(f"scan-fresh-{index:03d}", {"scan_id": f"scan-fresh-{index:03d}"})
        for index in range(101)
    ]
    old_timestamp = (now - timedelta(days=2)).timestamp()
    os.utime(held, (old_timestamp, old_timestamp))
    os.utime(stale, (old_timestamp, old_timestamp))
    monkeypatch.setattr(
        maintenance_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=1024 * 1024 * 1024),
    )
    settings = RetentionSettings(
        report_retention_days=1,
        max_report_files=100,
        legal_hold_scan_ids={"scan-held"},
    )
    with SQLiteStorage(tmp_path / "scanner.db") as storage:
        result = StorageMaintenance(storage, reports, settings).run(now=now)

    assert result.pruned_reports == 2
    assert held.is_file()
    assert not stale.exists()
    assert sum(path.is_file() for path in fresh) == 100


@pytest.mark.parametrize("constraint", ["high_water", "free_space"])
def test_capacity_admission_fails_closed_without_relying_on_host_disk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constraint: str,
) -> None:
    settings = RetentionSettings()
    with SQLiteStorage(tmp_path / "scanner.db") as storage:
        maintenance = StorageMaintenance(storage, tmp_path / "reports", settings)
        local_bytes = (
            settings.max_local_storage_bytes + 1 if constraint == "high_water" else 0
        )
        free_bytes = (
            settings.minimum_free_disk_bytes - 1
            if constraint == "free_space"
            else settings.minimum_free_disk_bytes + 1
        )
        monkeypatch.setattr(maintenance, "_local_usage_bytes", lambda: local_bytes)
        monkeypatch.setattr(
            maintenance_module.shutil,
            "disk_usage",
            lambda _path: SimpleNamespace(free=free_bytes),
        )

        expected = "high-water mark" if constraint == "high_water" else "free disk"
        with pytest.raises(StorageCapacityError, match=expected):
            maintenance.run(now=datetime(2026, 1, 1, tzinfo=UTC))
