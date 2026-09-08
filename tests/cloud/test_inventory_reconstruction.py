from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

import pytest

from app.storage.snapshots import normalize_snapshot, snapshot_hash
from cloud_service.models import canonical_sha256, utc_now
from cloud_service.repository import (
    DevicePrincipal,
    IdempotencyConflict,
    InMemoryRepository,
    InventoryResyncRequired,
    InventorySyncError,
    ScanRecord,
)


def _principal(tenant_id: str = "tenant-a", endpoint_id: str = "endpoint-a") -> DevicePrincipal:
    return DevicePrincipal(tenant_id, endpoint_id, "credential-a", 1)


def _queue_scan(
    repository: InMemoryRepository,
    scan_id: str,
    *,
    tenant_id: str = "tenant-a",
    endpoint_id: str = "endpoint-a",
) -> None:
    now = utc_now()
    repository.scans[scan_id] = ScanRecord(
        tenant_id=tenant_id,
        endpoint_id=endpoint_id,
        scan_id=scan_id,
        job_id=f"job-{scan_id}",
        state="DISPATCHED",
        job_document={
            "scan_id": scan_id,
            "endpoint_id": endpoint_id,
            "scan_type": "FULL",
            "policy_id": "enterprise-default",
            "policy_version": "1.0.0",
            "deadline": (now + timedelta(hours=1)).isoformat(),
            "authorization": {
                "scope_id": f"scope-{scan_id}",
                "authorized": True,
                "allowed_endpoint_ids": [endpoint_id],
            },
        },
        created_at=now,
        updated_at=now,
    )


def _upload(scan_id: str, inventory_sync: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_envelope_version": "1.0",
        "result": {
            "schema_version": "1.0",
            "scanner_version": "1.1.0",
            "scan_id": scan_id,
            "endpoint_id": "endpoint-a",
            "scan_type": "FULL",
            "status": "SUCCESS",
            "policy_id": "enterprise-default",
            "policy_version": "1.0.0",
            "authorization_scope_id": f"scope-{scan_id}",
        },
        "inventory_sync": {
            "scan_id": scan_id,
            "endpoint_id": "endpoint-a",
            **inventory_sync,
        },
    }


async def _ingest(
    repository: InMemoryRepository,
    scan_id: str,
    inventory_sync: dict[str, Any],
    *,
    key: str | None = None,
) -> ScanRecord:
    upload = _upload(scan_id, inventory_sync)
    return await repository.ingest_scan(
        principal=_principal(),
        scan_id=scan_id,
        upload=upload,
        idempotency_key=key or f"upload-{scan_id}",
        request_hash=canonical_sha256(upload),
        tasks=(),
    )


def test_full_delta_and_unchanged_are_reconstructed_for_workers() -> None:
    async def exercise() -> None:
        repository = InMemoryRepository()
        initial = {
            "software": [
                {"name": "zeta", "version": "1"},
                {"name": "alpha", "version": "1"},
            ],
            "services": [{"name": "old-service", "state": "running"}],
            "security": {"firewall": True},
        }
        _queue_scan(repository, "scan-full")
        full = await _ingest(
            repository,
            "scan-full",
            {
                "mode": "full",
                "snapshot_hash": snapshot_hash(initial),
                "previous_hash": None,
                "snapshot": initial,
            },
        )
        expected_initial = normalize_snapshot(initial)
        assert full.upload is not None
        assert full.upload["inventory_sync"]["reconstructed_snapshot"] == expected_initial

        expected_delta = {
            "software": [{"name": "alpha", "version": "2"}],
            "security": {"firewall": True},
            "users": [{"username": "alice", "uid": "1000"}],
        }
        _queue_scan(repository, "scan-delta")
        delta = await _ingest(
            repository,
            "scan-delta",
            {
                "mode": "delta",
                "previous_hash": snapshot_hash(initial),
                "snapshot_hash": snapshot_hash(expected_delta),
                "sections": {
                    "software": expected_delta["software"],
                    "users": expected_delta["users"],
                },
                "removed_sections": ["services"],
                "changes": [{"section": "software"}],
            },
        )
        assert delta.upload is not None
        reconstructed = delta.upload["inventory_sync"]["reconstructed_snapshot"]
        assert reconstructed == normalize_snapshot(expected_delta)
        assert delta.upload["inventory_sync"]["mode"] == "delta"
        assert "changes" in delta.upload["inventory_sync"]

        _queue_scan(repository, "scan-unchanged")
        unchanged = await _ingest(
            repository,
            "scan-unchanged",
            {
                "mode": "unchanged",
                "previous_hash": snapshot_hash(expected_delta),
                "snapshot_hash": snapshot_hash(expected_delta),
            },
        )
        assert unchanged.upload is not None
        assert unchanged.upload["inventory_sync"]["reconstructed_snapshot"] == normalize_snapshot(
            expected_delta
        )

        state = await repository.get_inventory_state("tenant-a", "endpoint-a")
        assert state is not None
        assert state.snapshot == normalize_snapshot(expected_delta)
        assert state.snapshot_hash == snapshot_hash(expected_delta)
        assert state.source_scan_id == "scan-unchanged"
        worker_input = await repository.get_scan_analysis_input("scan-delta")
        assert worker_input is not None
        assert (
            worker_input.upload["inventory_sync"]["reconstructed_snapshot"]
            == normalize_snapshot(expected_delta)
        )

    asyncio.run(exercise())


def test_missing_or_stale_delta_requests_full_resynchronization_transactionally() -> None:
    async def exercise() -> None:
        repository = InMemoryRepository()
        _queue_scan(repository, "scan-missing")
        with pytest.raises(InventoryResyncRequired, match="upload a full snapshot"):
            await _ingest(
                repository,
                "scan-missing",
                {
                    "mode": "delta",
                    "previous_hash": "1" * 64,
                    "snapshot_hash": "2" * 64,
                    "sections": {"software": []},
                    "removed_sections": [],
                },
                key="recoverable-upload",
            )
        assert repository.scans["scan-missing"].upload is None
        assert repository.inventory_states == {}

        snapshot = {"software": []}
        # A failed differential reservation is not remembered, so the endpoint's
        # causal-recovery full upload may safely reuse its transport operation.
        recovered = await _ingest(
            repository,
            "scan-missing",
            {
                "mode": "full",
                "previous_hash": None,
                "snapshot_hash": snapshot_hash(snapshot),
                "snapshot": snapshot,
            },
            key="recoverable-upload",
        )
        assert recovered.upload is not None

        state_before = await repository.get_inventory_state("tenant-a", "endpoint-a")
        _queue_scan(repository, "scan-stale")
        with pytest.raises(InventoryResyncRequired, match="base hash mismatch"):
            await _ingest(
                repository,
                "scan-stale",
                {
                    "mode": "delta",
                    "previous_hash": "3" * 64,
                    "snapshot_hash": "4" * 64,
                    "sections": {"software": [{"name": "stale"}]},
                    "removed_sections": [],
                },
            )
        assert repository.scans["scan-stale"].upload is None
        assert await repository.get_inventory_state("tenant-a", "endpoint-a") == state_before

    asyncio.run(exercise())


def test_inventory_replay_is_idempotent_and_tenant_scoped() -> None:
    async def exercise() -> None:
        repository = InMemoryRepository()
        snapshot = {"software": [{"name": "agent", "version": "1"}]}
        sync = {
            "mode": "full",
            "previous_hash": None,
            "snapshot_hash": snapshot_hash(snapshot),
            "snapshot": snapshot,
        }
        _queue_scan(repository, "scan-replay")
        first = await _ingest(repository, "scan-replay", sync, key="same-key")
        state_before = await repository.get_inventory_state("tenant-a", "endpoint-a")
        replay = await _ingest(repository, "scan-replay", sync, key="same-key")
        assert replay == first
        assert await repository.get_inventory_state("tenant-a", "endpoint-a") == state_before
        assert await repository.get_inventory_state("tenant-b", "endpoint-a") is None

        changed = _upload("scan-replay", {**sync, "snapshot_hash": "f" * 64})
        with pytest.raises(IdempotencyConflict):
            await repository.ingest_scan(
                principal=_principal(),
                scan_id="scan-replay",
                upload=changed,
                idempotency_key="same-key",
                request_hash=canonical_sha256(changed),
                tasks=(),
            )

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "sync,error",
    [
        (
            {"mode": "mystery", "snapshot_hash": "a" * 64},
            "mode must be full, delta, or unchanged",
        ),
        (
            {
                "mode": "full",
                "snapshot_hash": "a" * 64,
                "snapshot": {"software": []},
            },
            "snapshot_hash does not match",
        ),
        (
            {
                "mode": "full",
                "snapshot_hash": snapshot_hash({"software": []}),
                "snapshot": {"software": []},
                "reconstructed_snapshot": {"software": [{"name": "spoofed"}]},
            },
            "server-managed",
        ),
    ],
)
def test_invalid_inventory_envelopes_are_rejected(sync: dict[str, Any], error: str) -> None:
    async def exercise() -> None:
        repository = InMemoryRepository()
        _queue_scan(repository, "scan-invalid")
        with pytest.raises(InventorySyncError, match=error):
            await _ingest(repository, "scan-invalid", sync)
        assert repository.scans["scan-invalid"].upload is None

    asyncio.run(exercise())


def test_inventory_section_count_is_bounded() -> None:
    async def exercise() -> None:
        repository = InMemoryRepository()
        oversized = {f"section-{index}": index for index in range(513)}
        _queue_scan(repository, "scan-oversized")
        with pytest.raises(InventorySyncError, match="too many sections"):
            await _ingest(
                repository,
                "scan-oversized",
                {
                    "mode": "full",
                    "snapshot_hash": snapshot_hash(oversized),
                    "snapshot": oversized,
                },
            )

    asyncio.run(exercise())
