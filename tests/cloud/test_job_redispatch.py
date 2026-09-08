from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from cloud_service.repository import (
    JOB_DISPATCH_GRACE_SECONDS,
    DevicePrincipal,
    EndpointRecord,
    InMemoryRepository,
    ScanRecord,
)

BASE = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _repository() -> tuple[InMemoryRepository, DevicePrincipal]:
    repository = InMemoryRepository()
    endpoint = EndpointRecord(
        tenant_id="tenant-a",
        endpoint_id="endpoint-a",
        hostname="host-a",
        os_family="WINDOWS",
        os_version="11",
        architecture="x86_64",
        scanner_version="1.1.0",
        credential_generation=1,
        enrolled_at=BASE,
        last_seen_at=BASE,
    )
    repository.endpoints[endpoint.endpoint_id] = endpoint
    return repository, DevicePrincipal("tenant-a", "endpoint-a", "credential-a", 1)


def _job(
    *,
    state: str = "QUEUED",
    deadline: datetime | None = None,
    authorization_expires_at: datetime | None = None,
    timeout_seconds: int = 10,
) -> ScanRecord:
    effective_deadline = deadline or BASE + timedelta(minutes=30)
    auth_expiry = authorization_expires_at or BASE + timedelta(minutes=30)
    return ScanRecord(
        tenant_id="tenant-a",
        endpoint_id="endpoint-a",
        scan_id="scan-a",
        job_id="job-a",
        state=state,
        job_document={
            "scan_id": "scan-a",
            "endpoint_id": "endpoint-a",
            "timeout_seconds": timeout_seconds,
            "requested_at": (BASE - timedelta(minutes=1)).isoformat(),
            "deadline": effective_deadline.isoformat(),
            "authorization": {
                "authorized": True,
                "valid_from": (BASE - timedelta(minutes=1)).isoformat(),
                "expires_at": auth_expiry.isoformat(),
                "allowed_endpoint_ids": ["endpoint-a"],
            },
        },
        created_at=BASE - timedelta(minutes=1),
        updated_at=BASE - timedelta(minutes=1),
    )


def test_dispatched_job_is_not_duplicated_before_its_lease_expires() -> None:
    async def exercise() -> None:
        repository, principal = _repository()
        repository.scans["scan-a"] = _job()

        first = await repository.claim_next_job(principal, BASE)
        assert first is not None and first.state == "DISPATCHED"

        last_active_instant = BASE + timedelta(
            seconds=10 + JOB_DISPATCH_GRACE_SECONDS - 1
        )
        assert await repository.claim_next_job(principal, last_active_instant) is None
        assert repository.scans["scan-a"].updated_at == BASE
        assert [event.event_type for event in repository.audit_events] == ["SCAN_DISPATCHED"]

    asyncio.run(exercise())


def test_abandoned_dispatch_is_reclaimed_after_timeout_and_grace() -> None:
    async def exercise() -> None:
        repository, principal = _repository()
        repository.scans["scan-a"] = _job()
        assert await repository.claim_next_job(principal, BASE) is not None

        reclaim_at = BASE + timedelta(seconds=10 + JOB_DISPATCH_GRACE_SECONDS)
        reclaimed = await repository.claim_next_job(principal, reclaim_at)

        assert reclaimed is not None
        assert reclaimed.scan_id == "scan-a"
        assert reclaimed.state == "DISPATCHED"
        assert reclaimed.updated_at == reclaim_at
        assert [event.event_type for event in repository.audit_events] == [
            "SCAN_DISPATCHED",
            "SCAN_REDISPATCHED",
        ]
        assert repository.audit_events[-1].details == {
            "lease_timeout_seconds": 10,
            "lease_grace_seconds": JOB_DISPATCH_GRACE_SECONDS,
        }

        # Reclaiming renews the lease; another immediate poll cannot duplicate it.
        assert await repository.claim_next_job(principal, reclaim_at) is None

    asyncio.run(exercise())


@pytest.mark.parametrize("initial_state", ["QUEUED", "DISPATCHED"])
def test_expired_job_is_never_dispatched(initial_state: str) -> None:
    async def exercise() -> None:
        repository, principal = _repository()
        expired = _job(state=initial_state, deadline=BASE - timedelta(seconds=1))
        if initial_state == "DISPATCHED":
            expired = replace(expired, updated_at=BASE - timedelta(seconds=1))
        repository.scans["scan-a"] = expired

        assert await repository.claim_next_job(principal, BASE) is None
        assert repository.scans["scan-a"].state == "EXPIRED"

    asyncio.run(exercise())


def test_expired_authorization_prevents_redispatch_even_before_job_deadline() -> None:
    async def exercise() -> None:
        repository, principal = _repository()
        repository.scans["scan-a"] = replace(
            _job(
                state="DISPATCHED",
                deadline=BASE + timedelta(hours=1),
                authorization_expires_at=BASE - timedelta(seconds=1),
            ),
            updated_at=BASE - timedelta(minutes=10),
        )

        assert await repository.claim_next_job(principal, BASE) is None
        assert repository.scans["scan-a"].state == "EXPIRED"

    asyncio.run(exercise())
