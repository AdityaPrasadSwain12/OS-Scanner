"""Production PostgreSQL repository using psycopg's asynchronous connection pool."""

from __future__ import annotations

from datetime import datetime, timedelta
from importlib.resources import files
from typing import Any, cast

from .models import JsonObject, utc_now
from .repository import (
    JOB_DISPATCH_GRACE_SECONDS,
    AnalysisTask,
    CredentialRecord,
    DevicePrincipal,
    EndpointRecord,
    EnrollmentGrantRecord,
    IdempotencyConflict,
    InventoryState,
    NotFoundError,
    OwnershipError,
    ScanAnalysisInput,
    ScanRecord,
    ScanReportLookup,
    StateConflict,
    TaskKind,
    _failed_normalization_report,
    _job_dispatch_eligibility,
    _sanitize_error,
    reconstruct_inventory,
    validate_scan_status,
    validate_scan_upload,
)


class PostgresRepository:
    """Transactional repository; imports psycopg only when PostgreSQL is configured."""

    def __init__(self, database_url: str, *, run_migrations: bool = True) -> None:
        self.database_url = database_url.replace("postgresql+psycopg://", "postgresql://", 1)
        self.run_migrations = run_migrations
        self._pool: Any = None

    async def startup(self) -> None:
        try:
            from psycopg.rows import dict_row
            from psycopg_pool import AsyncConnectionPool
        except ImportError as exc:
            raise RuntimeError("PostgreSQL mode requires psycopg[binary,pool]") from exc
        self._pool = AsyncConnectionPool(
            conninfo=self.database_url,
            min_size=1,
            max_size=20,
            kwargs={"autocommit": False, "row_factory": dict_row},
            open=False,
        )
        await self._pool.open(wait=True)
        if self.run_migrations:
            migration_directory = files("cloud_service").joinpath("sql")
            migrations = sorted(
                (
                    migration
                    for migration in migration_directory.iterdir()
                    if migration.is_file() and migration.name.endswith(".sql")
                ),
                key=lambda migration: migration.name,
            )
            async with self._pool.connection() as connection:
                for migration in migrations:
                    await connection.execute(migration.read_text(encoding="utf-8"))
                await connection.commit()

    async def shutdown(self) -> None:
        if self._pool is not None:
            await self._pool.close()

    async def ready(self) -> bool:
        if self._pool is None:
            return False
        try:
            async with self._pool.connection(timeout=2) as connection:
                row = await (await connection.execute("SELECT 1 AS ready")).fetchone()
                return bool(row and row["ready"] == 1)
        except Exception:
            return False

    def _connection(self) -> Any:
        if self._pool is None:
            raise RuntimeError("repository has not been started")
        return self._pool.connection()

    @staticmethod
    def _json(value: Any) -> Any:
        # Imported lazily so the in-memory service remains runnable without psycopg.
        from psycopg.types.json import Jsonb

        return Jsonb(value)

    @staticmethod
    async def _reserve(
        connection: Any,
        tenant: str,
        operation: str,
        key: str,
        digest: str,
    ) -> JsonObject | None:
        cursor = await connection.execute(
            """INSERT INTO scanner_idempotency
               (tenant_id, operation, idempotency_key, request_hash)
               VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING response""",
            (tenant, operation, key, digest),
        )
        inserted = await cursor.fetchone()
        if inserted is not None:
            return None
        cursor = await connection.execute(
            """SELECT request_hash,response FROM scanner_idempotency
               WHERE tenant_id=%s AND operation=%s AND idempotency_key=%s FOR UPDATE""",
            (tenant, operation, key),
        )
        existing = await cursor.fetchone()
        if existing is None or existing["request_hash"] != digest:
            raise IdempotencyConflict("idempotency key was reused with different content")
        if existing["response"] is None:
            raise StateConflict("idempotent operation is not complete")
        return cast(JsonObject, existing["response"])

    @staticmethod
    async def _finish(
        connection: Any, tenant: str, operation: str, key: str, response: JsonObject
    ) -> None:
        await connection.execute(
            """UPDATE scanner_idempotency SET response=%s
               WHERE tenant_id=%s AND operation=%s AND idempotency_key=%s""",
            (PostgresRepository._json(response), tenant, operation, key),
        )

    @staticmethod
    async def _audit(
        connection: Any,
        tenant: str,
        event: str,
        actor_type: str,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        details: JsonObject | None = None,
    ) -> None:
        await connection.execute(
            """INSERT INTO scanner_audit_events
               (tenant_id,event_type,actor_type,actor_id,resource_type,resource_id,details)
               VALUES (%s,%s,%s,%s,%s,%s,%s)""",
            (
                tenant,
                event,
                actor_type,
                actor_id,
                resource_type,
                resource_id,
                PostgresRepository._json(details or {}),
            ),
        )

    @staticmethod
    def _credential(row: Any) -> CredentialRecord:
        return CredentialRecord(**dict(row))

    @staticmethod
    def _endpoint(row: Any) -> EndpointRecord:
        return EndpointRecord(**dict(row))

    @staticmethod
    def _scan(row: Any) -> ScanRecord:
        return ScanRecord(**dict(row))

    @staticmethod
    def _task(row: Any) -> AnalysisTask:
        return AnalysisTask(**dict(row))

    async def authenticate_device(self, token_hash: str, now: datetime) -> DevicePrincipal | None:
        async with self._connection() as connection:
            row = await (
                await connection.execute(
                    """SELECT tenant_id,endpoint_id,credential_id,generation
                       FROM scanner_credentials WHERE token_hash=%s AND expires_at>%s
                       AND (valid_until IS NULL OR valid_until>%s)""",
                    (token_hash, now, now),
                )
            ).fetchone()
            return DevicePrincipal(**dict(row)) if row else None

    async def authenticate_enrollment_grant(
        self, token_hash: str, now: datetime
    ) -> EnrollmentGrantRecord | None:
        async with self._connection() as connection:
            row = await (
                await connection.execute(
                    """SELECT tenant_id,grant_id,token_hash,issued_by,issued_at,expires_at,
                              os_family,label,consumed_at,endpoint_id
                       FROM scanner_enrollment_grants
                       WHERE token_hash=%s AND expires_at>%s""",
                    (token_hash, now),
                )
            ).fetchone()
            return EnrollmentGrantRecord(**dict(row)) if row else None

    async def create_enrollment_grant(
        self,
        *,
        grant: EnrollmentGrantRecord,
        idempotency_key: str,
        request_hash: str,
    ) -> EnrollmentGrantRecord:
        operation = "create-enrollment-grant"
        async with self._connection() as connection, connection.transaction():
            replay = await self._reserve(
                connection,
                grant.tenant_id,
                operation,
                idempotency_key,
                request_hash,
            )
            if replay:
                row = await (
                    await connection.execute(
                        "SELECT * FROM scanner_enrollment_grants WHERE grant_id=%s",
                        (replay["grant_id"],),
                    )
                ).fetchone()
                if row is None:
                    raise StateConflict("idempotent enrollment grant is missing")
                return EnrollmentGrantRecord(**dict(row))
            await connection.execute(
                """INSERT INTO scanner_enrollment_grants
                   (grant_id,tenant_id,token_hash,issued_by,issued_at,expires_at,os_family,label)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    grant.grant_id,
                    grant.tenant_id,
                    grant.token_hash,
                    grant.issued_by,
                    grant.issued_at,
                    grant.expires_at,
                    grant.os_family,
                    grant.label,
                ),
            )
            await self._finish(
                connection,
                grant.tenant_id,
                operation,
                idempotency_key,
                {"grant_id": grant.grant_id},
            )
            await self._audit(
                connection,
                grant.tenant_id,
                "ENDPOINT_ENROLLMENT_GRANT_CREATED",
                "platform",
                grant.issued_by,
                "enrollment-grant",
                grant.grant_id,
                {"expires_at": grant.expires_at.isoformat(), "os_family": grant.os_family},
            )
            return grant

    async def enroll_endpoint(
        self,
        *,
        tenant_id: str,
        endpoint: EndpointRecord,
        credential: CredentialRecord,
        idempotency_key: str,
        request_hash: str,
        enrollment_grant_hash: str | None = None,
    ) -> CredentialRecord:
        async with self._connection() as connection, connection.transaction():
            grant: Any = None
            replay = await self._reserve(
                connection, tenant_id, "enroll", idempotency_key, request_hash
            )
            if replay:
                row = await (
                    await connection.execute(
                        "SELECT * FROM scanner_credentials WHERE credential_id=%s",
                        (replay["credential_id"],),
                    )
                ).fetchone()
                if not row:
                    raise StateConflict("idempotent credential record is missing")
                return self._credential(row)
            if enrollment_grant_hash is not None:
                grant = await (
                    await connection.execute(
                        """SELECT * FROM scanner_enrollment_grants
                           WHERE token_hash=%s FOR UPDATE""",
                        (enrollment_grant_hash,),
                    )
                ).fetchone()
                if grant is None or grant["tenant_id"] != tenant_id:
                    raise OwnershipError("enrollment grant is invalid")
                if credential.issued_at >= grant["expires_at"]:
                    raise StateConflict("enrollment grant has expired")
                if grant["consumed_at"] is not None:
                    raise StateConflict("enrollment grant has already been used")
                if grant["os_family"] is not None and grant["os_family"] != endpoint.os_family:
                    raise StateConflict("enrollment grant is for a different operating system")
            await connection.execute(
                """INSERT INTO scanner_endpoints VALUES
                   (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    endpoint.endpoint_id,
                    endpoint.tenant_id,
                    endpoint.hostname,
                    endpoint.os_family,
                    endpoint.os_version,
                    endpoint.architecture,
                    endpoint.scanner_version,
                    endpoint.credential_generation,
                    endpoint.enrolled_at,
                    endpoint.last_seen_at,
                ),
            )
            await connection.execute(
                """INSERT INTO scanner_credentials
                   (token_hash,credential_id,tenant_id,endpoint_id,generation,issued_at,expires_at,
                    superseded_at,valid_until) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    credential.token_hash,
                    credential.credential_id,
                    credential.tenant_id,
                    credential.endpoint_id,
                    credential.generation,
                    credential.issued_at,
                    credential.expires_at,
                    None,
                    None,
                ),
            )
            if enrollment_grant_hash is not None:
                await connection.execute(
                    """UPDATE scanner_enrollment_grants
                       SET consumed_at=%s,endpoint_id=%s WHERE token_hash=%s""",
                    (credential.issued_at, endpoint.endpoint_id, enrollment_grant_hash),
                )
            await self._finish(
                connection,
                tenant_id,
                "enroll",
                idempotency_key,
                {"credential_id": credential.credential_id},
            )
            await self._audit(
                connection,
                tenant_id,
                "ENDPOINT_ENROLLED",
                "enrollment-grant" if grant is not None else "bootstrap",
                str(grant["grant_id"]) if grant is not None else tenant_id,
                "endpoint",
                endpoint.endpoint_id,
            )
            return credential

    async def rotate_credential(
        self,
        *,
        principal: DevicePrincipal,
        expected_generation: int,
        expected_credential_id: str,
        credential: CredentialRecord,
        overlap_seconds: int,
        idempotency_key: str,
        request_hash: str,
    ) -> CredentialRecord:
        operation = f"rotate:{principal.endpoint_id}"
        async with self._connection() as connection, connection.transaction():
            replay = await self._reserve(
                connection, principal.tenant_id, operation, idempotency_key, request_hash
            )
            if replay:
                row = await (
                    await connection.execute(
                        "SELECT * FROM scanner_credentials WHERE credential_id=%s",
                        (replay["credential_id"],),
                    )
                ).fetchone()
                if not row:
                    raise StateConflict("idempotent credential record is missing")
                return self._credential(row)
            endpoint = await (
                await connection.execute(
                    "SELECT * FROM scanner_endpoints WHERE endpoint_id=%s FOR UPDATE",
                    (principal.endpoint_id,),
                )
            ).fetchone()
            if not endpoint or endpoint["tenant_id"] != principal.tenant_id:
                raise OwnershipError("endpoint ownership mismatch")
            if (
                expected_generation != principal.generation
                or endpoint["credential_generation"] != principal.generation
            ):
                raise StateConflict("credential generation is stale")
            if expected_credential_id != principal.credential_id:
                raise StateConflict("credential identifier is stale")
            if credential.generation != principal.generation + 1:
                raise StateConflict("new credential generation is invalid")
            current = await (
                await connection.execute(
                    """SELECT tenant_id,endpoint_id,generation FROM scanner_credentials
                       WHERE credential_id=%s FOR UPDATE""",
                    (principal.credential_id,),
                )
            ).fetchone()
            if (
                not current
                or current["tenant_id"] != principal.tenant_id
                or current["endpoint_id"] != principal.endpoint_id
                or current["generation"] != principal.generation
            ):
                raise StateConflict("authenticated credential is stale")
            overlap = credential.issued_at + timedelta(seconds=overlap_seconds)
            await connection.execute(
                """UPDATE scanner_credentials SET superseded_at=%s,
                   valid_until=LEAST(expires_at,%s) WHERE credential_id=%s""",
                (credential.issued_at, overlap, principal.credential_id),
            )
            await connection.execute(
                """INSERT INTO scanner_credentials
                   (token_hash,credential_id,tenant_id,endpoint_id,generation,issued_at,expires_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                (
                    credential.token_hash,
                    credential.credential_id,
                    credential.tenant_id,
                    credential.endpoint_id,
                    credential.generation,
                    credential.issued_at,
                    credential.expires_at,
                ),
            )
            await connection.execute(
                """UPDATE scanner_endpoints SET credential_generation=%s,last_seen_at=%s
                   WHERE endpoint_id=%s""",
                (credential.generation, credential.issued_at, principal.endpoint_id),
            )
            await self._finish(
                connection,
                principal.tenant_id,
                operation,
                idempotency_key,
                {"credential_id": credential.credential_id},
            )
            await self._audit(
                connection,
                principal.tenant_id,
                "ENDPOINT_CREDENTIAL_ROTATED",
                "endpoint",
                principal.endpoint_id,
                "endpoint",
                principal.endpoint_id,
                {"generation": credential.generation},
            )
            return credential

    async def list_endpoints(
        self, tenant_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[EndpointRecord]:
        if not 1 <= limit <= 500 or offset < 0:
            raise ValueError("invalid endpoint page")
        async with self._connection() as connection:
            rows = await (
                await connection.execute(
                    """SELECT * FROM scanner_endpoints WHERE tenant_id=%s
                       ORDER BY enrolled_at DESC LIMIT %s OFFSET %s""",
                    (tenant_id, limit, offset),
                )
            ).fetchall()
            return [self._endpoint(row) for row in rows]

    async def create_scan_job(
        self, *, tenant_id: str, record: ScanRecord, idempotency_key: str, request_hash: str
    ) -> ScanRecord:
        async with self._connection() as connection, connection.transaction():
            replay = await self._reserve(
                connection, tenant_id, "create-scan", idempotency_key, request_hash
            )
            if replay:
                row = await (
                    await connection.execute(
                        "SELECT * FROM scanner_scans WHERE scan_id=%s", (replay["scan_id"],)
                    )
                ).fetchone()
                if not row:
                    raise StateConflict("idempotent scan record is missing")
                return self._scan(row)
            endpoint = await (
                await connection.execute(
                    "SELECT tenant_id FROM scanner_endpoints WHERE endpoint_id=%s",
                    (record.endpoint_id,),
                )
            ).fetchone()
            if not endpoint or endpoint["tenant_id"] != tenant_id:
                raise NotFoundError("endpoint was not found")
            await connection.execute(
                """INSERT INTO scanner_scans
                   (scan_id,job_id,tenant_id,endpoint_id,state,job_document,created_at,updated_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    record.scan_id,
                    record.job_id,
                    tenant_id,
                    record.endpoint_id,
                    record.state,
                    self._json(record.job_document),
                    record.created_at,
                    record.updated_at,
                ),
            )
            await self._finish(
                connection, tenant_id, "create-scan", idempotency_key, {"scan_id": record.scan_id}
            )
            await self._audit(
                connection,
                tenant_id,
                "SCAN_AUTHORIZED",
                "platform",
                str(record.job_document.get("initiated_by", "platform")),
                "scan",
                record.scan_id,
            )
            return record

    async def claim_next_job(self, principal: DevicePrincipal, now: datetime) -> ScanRecord | None:
        async with self._connection() as connection, connection.transaction():
            await connection.execute(
                """UPDATE scanner_endpoints SET last_seen_at=%s
                   WHERE tenant_id=%s AND endpoint_id=%s""",
                (now, principal.tenant_id, principal.endpoint_id),
            )
            rows = await (
                await connection.execute(
                    """SELECT * FROM scanner_scans WHERE tenant_id=%s AND endpoint_id=%s
                       AND state IN ('QUEUED','DISPATCHED')
                       ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 256""",
                    (principal.tenant_id, principal.endpoint_id),
                )
            ).fetchall()
            selected: Any = None
            redispatched = False
            for candidate in rows:
                record = self._scan(candidate)
                eligibility = _job_dispatch_eligibility(record, principal.endpoint_id, now)
                if eligibility == "EXPIRED":
                    await connection.execute(
                        "UPDATE scanner_scans SET state='EXPIRED',updated_at=%s WHERE scan_id=%s",
                        (now, record.scan_id),
                    )
                    await self._audit(
                        connection,
                        principal.tenant_id,
                        "SCAN_EXPIRED",
                        "control-plane",
                        "dispatcher",
                        "scan",
                        record.scan_id,
                    )
                    continue
                if eligibility == "ELIGIBLE":
                    selected = candidate
                    redispatched = record.state == "DISPATCHED"
                    break
            if selected is None:
                return None
            await connection.execute(
                "UPDATE scanner_scans SET state='DISPATCHED',updated_at=%s WHERE scan_id=%s",
                (now, selected["scan_id"]),
            )
            selected["state"], selected["updated_at"] = "DISPATCHED", now
            await self._audit(
                connection,
                principal.tenant_id,
                "SCAN_REDISPATCHED" if redispatched else "SCAN_DISPATCHED",
                "endpoint",
                principal.endpoint_id,
                "scan",
                selected["scan_id"],
                {
                    "lease_timeout_seconds": selected["job_document"]["timeout_seconds"],
                    "lease_grace_seconds": JOB_DISPATCH_GRACE_SECONDS,
                },
            )
            return self._scan(selected)

    async def ingest_scan(
        self,
        *,
        principal: DevicePrincipal,
        scan_id: str,
        upload: JsonObject,
        idempotency_key: str,
        request_hash: str,
        tasks: tuple[AnalysisTask, ...],
    ) -> ScanRecord:
        operation = f"ingest:{scan_id}"
        async with self._connection() as connection, connection.transaction():
            replay = await self._reserve(
                connection, principal.tenant_id, operation, idempotency_key, request_hash
            )
            row = await (
                await connection.execute(
                    "SELECT * FROM scanner_scans WHERE scan_id=%s FOR UPDATE", (scan_id,)
                )
            ).fetchone()
            if (
                not row
                or row["tenant_id"] != principal.tenant_id
                or row["endpoint_id"] != principal.endpoint_id
            ):
                raise OwnershipError("scan ownership mismatch")
            if replay:
                return self._scan(row)
            if row["upload"] is not None:
                raise StateConflict("scan already has a different accepted upload")
            now = utc_now()
            validate_scan_upload(self._scan(row), upload, now)
            # Lock the stable endpoint row even when there is no inventory-state
            # row yet.  This serializes first/full and concurrent delta uploads
            # for one endpoint without blocking other tenants or endpoints.
            endpoint_row = await (
                await connection.execute(
                    """SELECT endpoint_id FROM scanner_endpoints
                       WHERE tenant_id=%s AND endpoint_id=%s FOR UPDATE""",
                    (principal.tenant_id, principal.endpoint_id),
                )
            ).fetchone()
            if endpoint_row is None:
                raise OwnershipError("scan ownership mismatch")
            inventory_row = await (
                await connection.execute(
                    """SELECT tenant_id,endpoint_id,snapshot_hash,snapshot,
                              source_scan_id,updated_at
                       FROM scanner_inventory_states
                       WHERE tenant_id=%s AND endpoint_id=%s FOR UPDATE""",
                    (principal.tenant_id, principal.endpoint_id),
                )
            ).fetchone()
            current = InventoryState(**dict(inventory_row)) if inventory_row else None
            reconstruction = reconstruct_inventory(
                tenant_id=principal.tenant_id,
                endpoint_id=principal.endpoint_id,
                scan_id=scan_id,
                inventory_sync=cast(JsonObject, upload.get("inventory_sync")),
                current=current,
                now=now,
            )
            accepted_upload = dict(upload)
            accepted_upload["inventory_sync"] = reconstruction.inventory_sync
            state = reconstruction.state
            await connection.execute(
                """INSERT INTO scanner_inventory_states
                   (tenant_id,endpoint_id,snapshot_hash,snapshot,source_scan_id,updated_at)
                   VALUES (%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (tenant_id,endpoint_id) DO UPDATE SET
                     snapshot_hash=EXCLUDED.snapshot_hash,
                     snapshot=EXCLUDED.snapshot,
                     source_scan_id=EXCLUDED.source_scan_id,
                     updated_at=EXCLUDED.updated_at""",
                (
                    state.tenant_id,
                    state.endpoint_id,
                    state.snapshot_hash,
                    self._json(state.snapshot),
                    state.source_scan_id,
                    state.updated_at,
                ),
            )
            await connection.execute(
                """UPDATE scanner_scans SET upload=%s,state='ANALYZING',updated_at=%s
                   WHERE scan_id=%s""",
                (self._json(accepted_upload), now, scan_id),
            )
            for task in tasks:
                await connection.execute(
                    """INSERT INTO scanner_analysis_tasks
                       (task_id,tenant_id,endpoint_id,scan_id,kind,state,attempts,payload,created_at,
                        updated_at,available_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        task.task_id,
                        task.tenant_id,
                        task.endpoint_id,
                        task.scan_id,
                        task.kind,
                        task.state,
                        task.attempts,
                        self._json(task.payload),
                        task.created_at,
                        task.updated_at,
                        task.available_at,
                    ),
                )
            await self._finish(
                connection, principal.tenant_id, operation, idempotency_key, {"scan_id": scan_id}
            )
            await self._audit(
                connection,
                principal.tenant_id,
                "SCAN_EVIDENCE_ACCEPTED",
                "endpoint",
                principal.endpoint_id,
                "scan",
                scan_id,
                {
                    "analysis_tasks": [task.kind for task in tasks],
                    "inventory_mode": reconstruction.inventory_sync["mode"],
                    "snapshot_hash": reconstruction.state.snapshot_hash,
                },
            )
            row["upload"], row["state"], row["updated_at"] = (
                accepted_upload,
                "ANALYZING",
                now,
            )
            return self._scan(row)

    async def record_scan_status(
        self,
        *,
        principal: DevicePrincipal,
        scan_id: str,
        status: JsonObject,
        idempotency_key: str,
        request_hash: str,
    ) -> ScanRecord:
        operation = f"scan-status:{scan_id}"
        async with self._connection() as connection, connection.transaction():
            replay = await self._reserve(
                connection, principal.tenant_id, operation, idempotency_key, request_hash
            )
            row = await (
                await connection.execute(
                    "SELECT * FROM scanner_scans WHERE scan_id=%s FOR UPDATE", (scan_id,)
                )
            ).fetchone()
            if (
                not row
                or row["tenant_id"] != principal.tenant_id
                or row["endpoint_id"] != principal.endpoint_id
            ):
                raise OwnershipError("scan ownership mismatch")
            if replay:
                return self._scan(row)
            validate_scan_status(self._scan(row), status)
            now = utc_now()
            await connection.execute(
                "UPDATE scanner_scans SET terminal_status=%s,updated_at=%s WHERE scan_id=%s",
                (self._json(status), now, scan_id),
            )
            await self._finish(
                connection, principal.tenant_id, operation, idempotency_key, {"scan_id": scan_id}
            )
            await self._audit(
                connection,
                principal.tenant_id,
                "SCAN_ENDPOINT_STATUS_ACCEPTED",
                "endpoint",
                principal.endpoint_id,
                "scan",
                scan_id,
                {"status": status["status"]},
            )
            row["terminal_status"], row["updated_at"] = status, now
            return self._scan(row)

    async def record_rejection(
        self,
        *,
        principal: DevicePrincipal,
        payload: JsonObject,
        idempotency_key: str,
        request_hash: str,
    ) -> None:
        operation = f"rejection:{payload['document_sha256']}"
        async with self._connection() as connection, connection.transaction():
            replay = await self._reserve(
                connection, principal.tenant_id, operation, idempotency_key, request_hash
            )
            if replay:
                return
            scan_id = payload.get("scan_id")
            if scan_id:
                row = await (
                    await connection.execute(
                        "SELECT tenant_id,endpoint_id FROM scanner_scans WHERE scan_id=%s",
                        (scan_id,),
                    )
                ).fetchone()
                if row and (
                    row["tenant_id"] != principal.tenant_id
                    or row["endpoint_id"] != principal.endpoint_id
                ):
                    raise OwnershipError("scan ownership mismatch")
                if row:
                    await connection.execute(
                        "UPDATE scanner_scans SET state='REJECTED',updated_at=%s WHERE scan_id=%s",
                        (utc_now(), scan_id),
                    )
            await connection.execute(
                """INSERT INTO scanner_rejections
                   (tenant_id,endpoint_id,scan_id,reason,document_sha256) VALUES (%s,%s,%s,%s,%s)
                   ON CONFLICT DO NOTHING""",
                (
                    principal.tenant_id,
                    principal.endpoint_id,
                    scan_id,
                    payload["reason"],
                    payload["document_sha256"],
                ),
            )
            await self._finish(
                connection, principal.tenant_id, operation, idempotency_key, {"accepted": True}
            )
            await self._audit(
                connection,
                principal.tenant_id,
                "SCAN_JOB_REJECTED",
                "endpoint",
                principal.endpoint_id,
                "scan",
                str(scan_id or payload["document_sha256"]),
                {"reason": payload["reason"]},
            )

    async def get_scan_for_endpoint(
        self, principal: DevicePrincipal, scan_id: str
    ) -> ScanRecord | None:
        async with self._connection() as connection:
            row = await (
                await connection.execute("SELECT * FROM scanner_scans WHERE scan_id=%s", (scan_id,))
            ).fetchone()
            if not row:
                return None
            if (
                row["tenant_id"] != principal.tenant_id
                or row["endpoint_id"] != principal.endpoint_id
            ):
                raise OwnershipError("scan ownership mismatch")
            return self._scan(row)

    async def list_scans(
        self, tenant_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[ScanRecord]:
        if not 1 <= limit <= 500 or offset < 0:
            raise ValueError("invalid scan page")
        async with self._connection() as connection:
            rows = await (
                await connection.execute(
                    """SELECT tenant_id,endpoint_id,scan_id,job_id,state,
                              '{}'::jsonb AS job_document,created_at,updated_at,
                              NULL::jsonb AS upload,terminal_status,
                              CASE WHEN final_report IS NULL THEN NULL
                                   ELSE '{}'::jsonb END AS final_report
                       FROM scanner_scans WHERE tenant_id=%s
                       ORDER BY created_at DESC LIMIT %s OFFSET %s""",
                    (tenant_id, limit, offset),
                )
            ).fetchall()
            return [self._scan(row) for row in rows]

    async def get_scan_for_tenant(
        self, tenant_id: str, scan_id: str
    ) -> ScanRecord | None:
        async with self._connection() as connection:
            row = await (
                await connection.execute(
                    "SELECT * FROM scanner_scans WHERE tenant_id=%s AND scan_id=%s",
                    (tenant_id, scan_id),
                )
            ).fetchone()
            return self._scan(row) if row else None

    async def get_final_report(self, tenant_id: str, scan_id: str) -> JsonObject | None:
        async with self._connection() as connection:
            row = await (
                await connection.execute(
                    "SELECT final_report FROM scanner_scans WHERE tenant_id=%s AND scan_id=%s",
                    (tenant_id, scan_id),
                )
            ).fetchone()
            return cast(JsonObject | None, row["final_report"]) if row else None

    async def get_scan_report(self, tenant_id: str, scan_id: str) -> ScanReportLookup:
        async with self._connection() as connection:
            row = await (
                await connection.execute(
                    """SELECT final_report FROM scanner_scans
                       WHERE tenant_id=%s AND scan_id=%s""",
                    (tenant_id, scan_id),
                )
            ).fetchone()
            if row is None:
                return ScanReportLookup("NOT_FOUND")
            report = cast(JsonObject | None, row["final_report"])
            if report is None:
                return ScanReportLookup("PENDING")
            return ScanReportLookup("READY", report)

    async def get_inventory_state(
        self, tenant_id: str, endpoint_id: str
    ) -> InventoryState | None:
        async with self._connection() as connection:
            row = await (
                await connection.execute(
                    """SELECT tenant_id,endpoint_id,snapshot_hash,snapshot,
                              source_scan_id,updated_at
                       FROM scanner_inventory_states
                       WHERE tenant_id=%s AND endpoint_id=%s""",
                    (tenant_id, endpoint_id),
                )
            ).fetchone()
            return InventoryState(**dict(row)) if row else None

    async def claim_analysis_task(
        self, kind: TaskKind, worker_id: str, lease_seconds: int
    ) -> AnalysisTask | None:
        if not worker_id or len(worker_id) > 128 or not 10 <= lease_seconds <= 3600:
            raise ValueError("invalid worker lease request")
        now = utc_now()
        async with self._connection() as connection, connection.transaction():
            row = await (
                await connection.execute(
                    """SELECT * FROM scanner_analysis_tasks WHERE kind=%s AND available_at<=%s
                   AND (state IN ('PENDING','RETRY') OR
                        (state='RUNNING' AND lease_expires_at<=%s))
                   ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1""",
                    (kind, now, now),
                )
            ).fetchone()
            if not row:
                return None
            lease = now + timedelta(seconds=lease_seconds)
            await connection.execute(
                """UPDATE scanner_analysis_tasks SET state='RUNNING',attempts=attempts+1,
                   leased_by=%s,lease_expires_at=%s,updated_at=%s WHERE task_id=%s""",
                (worker_id, lease, now, row["task_id"]),
            )
            row.update(
                state="RUNNING",
                attempts=row["attempts"] + 1,
                leased_by=worker_id,
                lease_expires_at=lease,
                updated_at=now,
            )
            return self._task(row)

    async def complete_analysis_task(
        self, task_id: str, worker_id: str, result: JsonObject
    ) -> None:
        async with self._connection() as connection, connection.transaction():
            cursor = await connection.execute(
                """UPDATE scanner_analysis_tasks SET state='SUCCEEDED',result=%s,leased_by=NULL,
                   lease_expires_at=NULL,updated_at=%s WHERE task_id=%s AND state='RUNNING'
                   AND leased_by=%s""",
                (self._json(result), utc_now(), task_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise StateConflict("analysis task is not leased by this worker")

    async def fail_analysis_task(
        self, task_id: str, worker_id: str, error: str, retry_at: datetime, dead_letter: bool
    ) -> None:
        async with self._connection() as connection, connection.transaction():
            cursor = await connection.execute(
                """UPDATE scanner_analysis_tasks SET state=%s,last_error=%s,available_at=%s,
                   leased_by=NULL,lease_expires_at=NULL,updated_at=%s WHERE task_id=%s
                   AND state='RUNNING' AND leased_by=%s""",
                (
                    "FAILED" if dead_letter else "RETRY",
                    _sanitize_error(error),
                    max(utc_now(), retry_at),
                    utc_now(),
                    task_id,
                    worker_id,
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflict("analysis task is not leased by this worker")

    async def get_scan_analysis_input(self, scan_id: str) -> ScanAnalysisInput | None:
        async with self._connection() as connection:
            row = await (
                await connection.execute(
                    """SELECT tenant_id,endpoint_id,scan_id,upload
                       FROM scanner_scans WHERE scan_id=%s""",
                    (scan_id,),
                )
            ).fetchone()
            if not row or row["upload"] is None:
                return None
            return ScanAnalysisInput(
                row["tenant_id"],
                row["endpoint_id"],
                row["scan_id"],
                cast(JsonObject, row["upload"]),
            )

    async def list_scan_analysis_results(self, scan_id: str) -> dict[str, JsonObject]:
        async with self._connection() as connection:
            rows = await (
                await connection.execute(
                    """SELECT kind,state,result,last_error,attempts FROM scanner_analysis_tasks
                   WHERE scan_id=%s""",
                    (scan_id,),
                )
            ).fetchall()
            results: dict[str, JsonObject] = {}
            for row in rows:
                if row["state"] == "SUCCEEDED" and row["result"] is not None:
                    results[row["kind"]] = cast(JsonObject, row["result"])
                elif row["state"] == "FAILED":
                    results[row["kind"]] = {
                        "tool": str(row["kind"]).lower(),
                        "status": "FAILED",
                        "error": row["last_error"] or "analysis task reached dead letter state",
                        "attempts": row["attempts"],
                    }
            return results

    async def next_scan_ready_for_finalization(self) -> str | None:
        async with self._connection() as connection:
            row = await (
                await connection.execute(
                    """SELECT s.scan_id
                       FROM scanner_scans s
                       WHERE s.state='ANALYZING' AND s.final_report IS NULL
                         AND (SELECT count(*) FROM scanner_analysis_tasks t
                              WHERE t.scan_id=s.scan_id) = 2
                         AND NOT EXISTS (
                           SELECT 1 FROM scanner_analysis_tasks t
                           WHERE t.scan_id=s.scan_id
                             AND t.state NOT IN ('SUCCEEDED','FAILED')
                         )
                       ORDER BY s.updated_at, s.scan_id
                       LIMIT 1"""
                )
            ).fetchone()
            return str(row["scan_id"]) if row else None

    async def finalize_scan_report(self, scan_id: str, report: JsonObject) -> None:
        async with self._connection() as connection, connection.transaction():
            scan = await (
                await connection.execute(
                    """SELECT tenant_id,final_report FROM scanner_scans
                       WHERE scan_id=%s FOR UPDATE""",
                    (scan_id,),
                )
            ).fetchone()
            if not scan:
                raise NotFoundError("scan was not found")
            if scan["final_report"] is not None:
                if scan["final_report"] == report:
                    return
                raise StateConflict("scan already has a different final report")
            rows = await (
                await connection.execute(
                    "SELECT kind,state FROM scanner_analysis_tasks WHERE scan_id=%s", (scan_id,)
                )
            ).fetchall()
            states = {row["kind"]: row["state"] for row in rows}
            if set(states) != {"OSV", "DEPSCAN"} or any(
                value not in {"SUCCEEDED", "FAILED"} for value in states.values()
            ):
                raise StateConflict("all expected analysis tasks must be terminal")
            await connection.execute(
                """UPDATE scanner_scans SET state='COMPLETE',final_report=%s,updated_at=%s
                   WHERE scan_id=%s""",
                (self._json(report), utc_now(), scan_id),
            )
            await self._audit(
                connection,
                scan["tenant_id"],
                "SCAN_REPORT_FINALIZED",
                "worker",
                "normalizer",
                "scan",
                scan_id,
                {"analysis_states": states},
            )

    async def finalize_scan_report_failure(self, scan_id: str, error: str) -> None:
        async with self._connection() as connection, connection.transaction():
            row = await (
                await connection.execute(
                    "SELECT * FROM scanner_scans WHERE scan_id=%s FOR UPDATE",
                    (scan_id,),
                )
            ).fetchone()
            if not row:
                raise NotFoundError("scan was not found")
            if row["final_report"] is not None:
                return
            record = self._scan(row)
            report = _failed_normalization_report(record, error)
            now = utc_now()
            await connection.execute(
                """UPDATE scanner_scans SET state='COMPLETE',final_report=%s,updated_at=%s
                   WHERE scan_id=%s""",
                (self._json(report), now, scan_id),
            )
            await self._audit(
                connection,
                record.tenant_id,
                "SCAN_REPORT_NORMALIZATION_FAILED",
                "worker",
                "normalizer",
                "scan",
                scan_id,
                {"error": _sanitize_error(error)},
            )
