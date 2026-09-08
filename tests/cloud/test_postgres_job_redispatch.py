from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from cloud_service.postgres import PostgresRepository
from cloud_service.repository import (
    JOB_DISPATCH_GRACE_SECONDS,
    CredentialRecord,
    DevicePrincipal,
    EndpointRecord,
    ScanRecord,
)

DATABASE_URL = os.getenv("SCANNER_TEST_DATABASE_URL")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="SCANNER_TEST_DATABASE_URL is required for PostgreSQL integration tests",
    ),
]


def test_postgres_dispatch_lease_recovery_and_expiry_are_durable() -> None:
    async def exercise() -> None:
        assert DATABASE_URL is not None
        repository = PostgresRepository(DATABASE_URL)
        await repository.startup()
        try:
            suffix = uuid4().hex
            tenant_id = f"tenant-{suffix}"
            endpoint_id = f"endpoint-{suffix}"
            base = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
            endpoint = EndpointRecord(
                tenant_id=tenant_id,
                endpoint_id=endpoint_id,
                hostname="postgres-host",
                os_family="LINUX",
                os_version="24.04",
                architecture="x86_64",
                scanner_version="1.1.0",
                credential_generation=1,
                enrolled_at=base,
                last_seen_at=base,
            )
            credential = CredentialRecord(
                tenant_id=tenant_id,
                endpoint_id=endpoint_id,
                credential_id=f"credential-{suffix}",
                token_hash=hashlib.sha256(suffix.encode()).hexdigest(),
                generation=1,
                issued_at=base,
                expires_at=base + timedelta(days=1),
            )
            await repository.enroll_endpoint(
                tenant_id=tenant_id,
                endpoint=endpoint,
                credential=credential,
                idempotency_key=f"enroll-{suffix}",
                request_hash="a" * 64,
            )
            principal = DevicePrincipal(
                tenant_id,
                endpoint_id,
                credential.credential_id,
                1,
            )

            def record(scan_name: str, deadline: datetime) -> ScanRecord:
                scan_id = f"scan-{scan_name}-{suffix}"
                return ScanRecord(
                    tenant_id=tenant_id,
                    endpoint_id=endpoint_id,
                    scan_id=scan_id,
                    job_id=f"job-{scan_name}-{suffix}",
                    state="QUEUED",
                    job_document={
                        "scan_id": scan_id,
                        "endpoint_id": endpoint_id,
                        "timeout_seconds": 10,
                        "deadline": deadline.isoformat(),
                        "authorization": {
                            "authorized": True,
                            "valid_from": (base - timedelta(minutes=1)).isoformat(),
                            "expires_at": (base + timedelta(hours=1)).isoformat(),
                            "allowed_endpoint_ids": [endpoint_id],
                        },
                    },
                    created_at=base,
                    updated_at=base,
                )

            recoverable = record("recoverable", base + timedelta(hours=1))
            await repository.create_scan_job(
                tenant_id=tenant_id,
                record=recoverable,
                idempotency_key=f"create-recoverable-{suffix}",
                request_hash="b" * 64,
            )
            assert await repository.claim_next_job(principal, base) is not None
            assert (
                await repository.claim_next_job(
                    principal,
                    base + timedelta(seconds=10 + JOB_DISPATCH_GRACE_SECONDS - 1),
                )
                is None
            )
            reclaim_at = base + timedelta(seconds=10 + JOB_DISPATCH_GRACE_SECONDS)
            reclaimed = await repository.claim_next_job(principal, reclaim_at)
            assert reclaimed is not None
            assert reclaimed.scan_id == recoverable.scan_id
            assert reclaimed.updated_at == reclaim_at

            expired = record("expired", base + timedelta(seconds=1))
            await repository.create_scan_job(
                tenant_id=tenant_id,
                record=expired,
                idempotency_key=f"create-expired-{suffix}",
                request_hash="c" * 64,
            )
            assert await repository.claim_next_job(principal, base + timedelta(seconds=2)) is None
            expired_state = await repository.get_scan_for_endpoint(principal, expired.scan_id)
            assert expired_state is not None and expired_state.state == "EXPIRED"
        finally:
            await repository.shutdown()

    asyncio.run(exercise())
