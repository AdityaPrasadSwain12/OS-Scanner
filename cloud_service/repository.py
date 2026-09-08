"""Repository boundary and deterministic in-memory implementation.

The API uses high-level atomic operations instead of spreading authorization and
idempotency decisions over several database calls.  The in-memory repository is
feature-equivalent enough for local Docker smoke tests and unit tests; production
uses :class:`cloud_service.postgres.PostgresRepository`.
"""

from __future__ import annotations

import asyncio
import copy
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Literal, Protocol, cast

from app.storage.serialization import canonical_json
from app.storage.snapshots import normalize_snapshot, snapshot_hash

from .models import JsonObject, bounded_json, utc_now

TaskKind = Literal["OSV", "DEPSCAN"]
TaskState = Literal["PENDING", "RUNNING", "SUCCEEDED", "RETRY", "FAILED"]
JOB_DISPATCH_GRACE_SECONDS = 60
SCAN_UPLOAD_GRACE_SECONDS = 7 * 24 * 60 * 60


class RepositoryError(RuntimeError):
    pass


class NotFoundError(RepositoryError):
    pass


class OwnershipError(RepositoryError):
    pass


class IdempotencyConflict(RepositoryError):
    pass


class StateConflict(RepositoryError):
    pass


class InventorySyncError(StateConflict):
    """The endpoint inventory envelope is malformed or internally inconsistent."""


class InventoryResyncRequired(InventorySyncError):
    """The cloud cannot safely apply a differential upload without a full snapshot."""


@dataclass(frozen=True, slots=True)
class DevicePrincipal:
    tenant_id: str
    endpoint_id: str
    credential_id: str
    generation: int


@dataclass(frozen=True, slots=True)
class EndpointRecord:
    tenant_id: str
    endpoint_id: str
    hostname: str
    os_family: str
    os_version: str
    architecture: str
    scanner_version: str
    credential_generation: int
    enrolled_at: datetime
    last_seen_at: datetime


@dataclass(frozen=True, slots=True)
class CredentialRecord:
    tenant_id: str
    endpoint_id: str
    credential_id: str
    token_hash: str
    generation: int
    issued_at: datetime
    expires_at: datetime
    superseded_at: datetime | None = None
    valid_until: datetime | None = None


@dataclass(frozen=True, slots=True)
class EnrollmentGrantRecord:
    tenant_id: str
    grant_id: str
    token_hash: str
    issued_by: str
    issued_at: datetime
    expires_at: datetime
    os_family: str | None = None
    label: str | None = None
    consumed_at: datetime | None = None
    endpoint_id: str | None = None


@dataclass(frozen=True, slots=True)
class ScanRecord:
    tenant_id: str
    endpoint_id: str
    scan_id: str
    job_id: str
    state: str
    job_document: JsonObject
    created_at: datetime
    updated_at: datetime
    upload: JsonObject | None = None
    terminal_status: JsonObject | None = None
    final_report: JsonObject | None = None


@dataclass(frozen=True, slots=True)
class InventoryState:
    tenant_id: str
    endpoint_id: str
    snapshot_hash: str
    snapshot: JsonObject
    source_scan_id: str
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class InventoryReconstruction:
    inventory_sync: JsonObject
    state: InventoryState


@dataclass(frozen=True, slots=True)
class AnalysisTask:
    task_id: str
    tenant_id: str
    endpoint_id: str
    scan_id: str
    kind: TaskKind
    state: TaskState
    attempts: int
    payload: JsonObject
    created_at: datetime
    updated_at: datetime
    available_at: datetime
    lease_expires_at: datetime | None = None
    leased_by: str | None = None
    last_error: str | None = None
    result: JsonObject | None = None


@dataclass(frozen=True, slots=True)
class ScanAnalysisInput:
    tenant_id: str
    endpoint_id: str
    scan_id: str
    upload: JsonObject
    expected_kinds: tuple[TaskKind, ...] = ("OSV", "DEPSCAN")


@dataclass(frozen=True, slots=True)
class ScanReportLookup:
    state: Literal["NOT_FOUND", "PENDING", "READY"]
    report: JsonObject | None = None


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    tenant_id: str
    event_type: str
    actor_type: str
    actor_id: str
    resource_type: str
    resource_id: str
    occurred_at: datetime
    details: JsonObject = field(default_factory=dict)


_SNAPSHOT_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_INVENTORY_SECTIONS = 512
_MAX_INVENTORY_NODES = 300_000
_MAX_RECONSTRUCTED_BYTES = 16 * 1024 * 1024


def _inventory_digest(value: Any, field_name: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SNAPSHOT_DIGEST.fullmatch(value) is None:
        raise InventorySyncError(f"inventory_sync.{field_name} must be a lowercase SHA-256")
    return value


def _bounded_snapshot(value: Any) -> JsonObject:
    if not isinstance(value, dict):
        raise InventorySyncError("inventory snapshot must be a JSON object")
    try:
        bounded_json(value, max_depth=32, max_nodes=_MAX_INVENTORY_NODES)
        normalized = normalize_snapshot(copy.deepcopy(value))
        encoded = canonical_json(normalized).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InventorySyncError("inventory snapshot is not valid bounded JSON") from exc
    if len(normalized) > _MAX_INVENTORY_SECTIONS:
        raise InventorySyncError("inventory snapshot contains too many sections")
    if len(encoded) > _MAX_RECONSTRUCTED_BYTES:
        raise InventorySyncError("reconstructed inventory exceeds the size limit")
    return normalized


def reconstruct_inventory(
    *,
    tenant_id: str,
    endpoint_id: str,
    scan_id: str,
    inventory_sync: JsonObject,
    current: InventoryState | None,
    now: datetime,
) -> InventoryReconstruction:
    """Validate and transactionally reconstruct one endpoint inventory envelope.

    The caller owns the transaction/lock.  This pure function never trusts a
    client-supplied reconstructed snapshot and always verifies the endpoint's
    content-addressed hash after applying a delta.
    """

    if not isinstance(inventory_sync, dict):
        raise InventorySyncError("inventory_sync must be a JSON object")
    if "reconstructed_snapshot" in inventory_sync:
        raise InventorySyncError("inventory_sync.reconstructed_snapshot is server-managed")
    mode = inventory_sync.get("mode")
    if mode not in {"full", "delta", "unchanged"}:
        raise InventorySyncError("inventory_sync.mode must be full, delta, or unchanged")
    claimed_hash = cast(
        str,
        _inventory_digest(inventory_sync.get("snapshot_hash"), "snapshot_hash"),
    )
    previous_hash = _inventory_digest(
        inventory_sync.get("previous_hash"), "previous_hash", nullable=True
    )

    if mode == "full":
        if any(name in inventory_sync for name in ("sections", "removed_sections")):
            raise InventorySyncError("full inventory cannot contain delta fields")
        snapshot = _bounded_snapshot(inventory_sync.get("snapshot"))
        calculated = snapshot_hash(snapshot)
        if calculated != claimed_hash:
            raise InventorySyncError("full inventory snapshot_hash does not match its content")
        # A null previous_hash is an intentional reset/full-resync.  If a base is
        # supplied, it still must be the current base so stale full uploads cannot
        # silently replace newer state.
        if previous_hash is not None and (
            current is None or previous_hash != current.snapshot_hash
        ):
            raise InventoryResyncRequired(
                "inventory base hash mismatch; upload a full snapshot with previous_hash null"
            )
    elif mode == "delta":
        if current is None:
            raise InventoryResyncRequired(
                "inventory base is unavailable; upload a full snapshot"
            )
        if previous_hash is None or previous_hash != current.snapshot_hash:
            raise InventoryResyncRequired(
                "inventory base hash mismatch; upload a full snapshot"
            )
        if "snapshot" in inventory_sync:
            raise InventorySyncError("delta inventory cannot contain a full snapshot")
        sections_value = inventory_sync.get("sections", {})
        removed_value = inventory_sync.get("removed_sections", [])
        if not isinstance(sections_value, dict) or not isinstance(removed_value, list):
            raise InventorySyncError("delta sections and removed_sections have invalid types")
        if len(sections_value) + len(removed_value) > _MAX_INVENTORY_SECTIONS:
            raise InventorySyncError("delta inventory contains too many sections")
        if any(
            not isinstance(section, str) or not section or len(section) > 256
            for section in sections_value
        ) or any(
            not isinstance(section, str) or not section or len(section) > 256
            for section in removed_value
        ):
            raise InventorySyncError("delta inventory contains an invalid section name")
        if len(set(cast(list[str], removed_value))) != len(removed_value):
            raise InventorySyncError("delta removed_sections contains duplicates")
        overlap = set(sections_value).intersection(cast(list[str], removed_value))
        if overlap:
            raise InventorySyncError("delta cannot replace and remove the same section")
        if not sections_value and not removed_value:
            raise InventorySyncError("empty delta must use unchanged mode")
        reconstructed: JsonObject = copy.deepcopy(current.snapshot)
        reconstructed.update(copy.deepcopy(sections_value))
        for section in cast(list[str], removed_value):
            reconstructed.pop(section, None)
        snapshot = _bounded_snapshot(reconstructed)
        calculated = snapshot_hash(snapshot)
        if calculated != claimed_hash:
            raise InventorySyncError("delta snapshot_hash does not match reconstructed content")
    else:
        if current is None:
            raise InventoryResyncRequired(
                "inventory base is unavailable; upload a full snapshot"
            )
        if claimed_hash != current.snapshot_hash:
            raise InventoryResyncRequired(
                "inventory base hash mismatch; upload a full snapshot"
            )
        if previous_hash is not None and previous_hash != current.snapshot_hash:
            raise InventoryResyncRequired(
                "inventory previous_hash mismatch; upload a full snapshot"
            )
        if any(
            name in inventory_sync
            for name in ("snapshot", "sections", "removed_sections")
        ):
            raise InventorySyncError("unchanged inventory cannot contain snapshot data")
        snapshot = copy.deepcopy(current.snapshot)

    state = InventoryState(
        tenant_id=tenant_id,
        endpoint_id=endpoint_id,
        snapshot_hash=claimed_hash,
        snapshot=snapshot,
        source_scan_id=scan_id,
        updated_at=now,
    )
    accepted_sync = copy.deepcopy(inventory_sync)
    accepted_sync["reconstructed_snapshot"] = copy.deepcopy(snapshot)
    return InventoryReconstruction(accepted_sync, state)


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _job_dispatch_eligibility(
    record: ScanRecord, endpoint_id: str, now: datetime
) -> Literal["ELIGIBLE", "ACTIVE", "WAITING", "EXPIRED"]:
    """Fail closed unless the endpoint's complete authorization is still valid."""

    document = record.job_document
    authorization = document.get("authorization")
    deadline = _timestamp(document.get("deadline"))
    if not isinstance(authorization, dict) or deadline is None:
        return "EXPIRED"
    valid_from = _timestamp(authorization.get("valid_from"))
    expires_at = _timestamp(authorization.get("expires_at"))
    allowed = authorization.get("allowed_endpoint_ids")
    if (
        authorization.get("authorized") is not True
        or valid_from is None
        or expires_at is None
        or not isinstance(allowed, list)
        or endpoint_id not in allowed
    ):
        return "EXPIRED"
    if now >= deadline or now >= expires_at:
        return "EXPIRED"
    if now < valid_from:
        return "WAITING"
    not_before_value = document.get("not_before")
    if not_before_value is not None:
        not_before = _timestamp(not_before_value)
        if not_before is None:
            return "EXPIRED"
        if now < not_before:
            return "WAITING"
    if record.state == "QUEUED":
        return "ELIGIBLE"
    if record.state != "DISPATCHED":
        return "ACTIVE"
    timeout = document.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 10 <= timeout <= 86_400:
        return "EXPIRED"
    lease_expires_at = record.updated_at + timedelta(
        seconds=timeout + JOB_DISPATCH_GRACE_SECONDS
    )
    return "ELIGIBLE" if now >= lease_expires_at else "ACTIVE"


def validate_scan_upload(record: ScanRecord, upload: JsonObject, now: datetime) -> None:
    """Bind untrusted endpoint evidence to the exact dispatched authorization."""

    if record.state != "DISPATCHED":
        raise StateConflict("scan evidence is accepted only for a dispatched job")
    result = upload.get("result")
    inventory_sync = upload.get("inventory_sync")
    job = record.job_document
    authorization = job.get("authorization")
    if not isinstance(result, dict) or not isinstance(inventory_sync, dict):
        raise StateConflict("scan upload documents are invalid")
    if not isinstance(authorization, dict):
        raise StateConflict("scan authorization is invalid")
    deadline = _timestamp(job.get("deadline"))
    if deadline is None or now > deadline + timedelta(seconds=SCAN_UPLOAD_GRACE_SECONDS):
        raise StateConflict("scan upload authorization window has expired")
    identity_fields = {
        "scan_id": record.scan_id,
        "endpoint_id": record.endpoint_id,
    }
    if any(
        result.get(name) != expected or inventory_sync.get(name) != expected
        for name, expected in identity_fields.items()
    ):
        raise StateConflict("scan upload identity does not match the dispatched job")
    expected_fields = {
        "scan_type": job.get("scan_type"),
        "authorization_scope_id": authorization.get("scope_id"),
        "policy_id": job.get("policy_id"),
    }
    if any(
        expected is None or result.get(name) != expected
        for name, expected in expected_fields.items()
    ):
        raise StateConflict("scan evidence provenance does not match the dispatched job")
    expected_policy_version = job.get("policy_version")
    if (
        expected_policy_version is not None
        and result.get("policy_version") != expected_policy_version
    ):
        raise StateConflict("scan evidence policy version does not match the dispatched job")
    if result.get("status") not in {"SUCCESS", "PARTIAL", "FAILED"}:
        raise StateConflict("scan evidence has an invalid terminal status")


def validate_scan_status(record: ScanRecord, status: JsonObject) -> None:
    """Require one immutable terminal status matching the accepted result."""

    if record.upload is None:
        raise StateConflict("terminal status cannot precede scan evidence")
    if record.terminal_status is not None:
        raise StateConflict("terminal scan status is immutable")
    result = record.upload.get("result")
    if not isinstance(result, dict):
        raise StateConflict("accepted scan evidence is invalid")
    fields = (
        "scan_id",
        "endpoint_id",
        "schema_version",
        "scanner_version",
        "authorization_scope_id",
        "policy_id",
        "policy_version",
        "status",
    )
    if any(status.get(name) != result.get(name) for name in fields):
        raise StateConflict("terminal status does not match accepted scan evidence")


class CloudRepository(Protocol):
    async def startup(self) -> None: ...
    async def shutdown(self) -> None: ...
    async def ready(self) -> bool: ...

    async def authenticate_device(
        self, token_hash: str, now: datetime
    ) -> DevicePrincipal | None: ...

    async def authenticate_enrollment_grant(
        self, token_hash: str, now: datetime
    ) -> EnrollmentGrantRecord | None: ...

    async def create_enrollment_grant(
        self,
        *,
        grant: EnrollmentGrantRecord,
        idempotency_key: str,
        request_hash: str,
    ) -> EnrollmentGrantRecord: ...

    async def enroll_endpoint(
        self,
        *,
        tenant_id: str,
        endpoint: EndpointRecord,
        credential: CredentialRecord,
        idempotency_key: str,
        request_hash: str,
        enrollment_grant_hash: str | None = None,
    ) -> CredentialRecord: ...

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
    ) -> CredentialRecord: ...

    async def list_endpoints(
        self, tenant_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[EndpointRecord]: ...

    async def create_scan_job(
        self,
        *,
        tenant_id: str,
        record: ScanRecord,
        idempotency_key: str,
        request_hash: str,
    ) -> ScanRecord: ...

    async def claim_next_job(
        self, principal: DevicePrincipal, now: datetime
    ) -> ScanRecord | None: ...

    async def ingest_scan(
        self,
        *,
        principal: DevicePrincipal,
        scan_id: str,
        upload: JsonObject,
        idempotency_key: str,
        request_hash: str,
        tasks: tuple[AnalysisTask, ...],
    ) -> ScanRecord: ...

    async def record_scan_status(
        self,
        *,
        principal: DevicePrincipal,
        scan_id: str,
        status: JsonObject,
        idempotency_key: str,
        request_hash: str,
    ) -> ScanRecord: ...

    async def record_rejection(
        self,
        *,
        principal: DevicePrincipal,
        payload: JsonObject,
        idempotency_key: str,
        request_hash: str,
    ) -> None: ...

    async def get_scan_for_endpoint(
        self, principal: DevicePrincipal, scan_id: str
    ) -> ScanRecord | None: ...
    async def list_scans(
        self, tenant_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[ScanRecord]: ...
    async def get_scan_for_tenant(
        self, tenant_id: str, scan_id: str
    ) -> ScanRecord | None: ...
    async def get_final_report(self, tenant_id: str, scan_id: str) -> JsonObject | None: ...
    async def get_scan_report(
        self, tenant_id: str, scan_id: str
    ) -> ScanReportLookup: ...
    async def get_inventory_state(
        self, tenant_id: str, endpoint_id: str
    ) -> InventoryState | None: ...

    async def claim_analysis_task(
        self, kind: TaskKind, worker_id: str, lease_seconds: int
    ) -> AnalysisTask | None: ...
    async def complete_analysis_task(
        self, task_id: str, worker_id: str, result: JsonObject
    ) -> None: ...
    async def fail_analysis_task(
        self,
        task_id: str,
        worker_id: str,
        error: str,
        retry_at: datetime,
        dead_letter: bool,
    ) -> None: ...
    async def get_scan_analysis_input(self, scan_id: str) -> ScanAnalysisInput | None: ...
    async def list_scan_analysis_results(self, scan_id: str) -> dict[str, JsonObject]: ...
    async def next_scan_ready_for_finalization(self) -> str | None: ...
    async def finalize_scan_report(self, scan_id: str, report: JsonObject) -> None: ...
    async def finalize_scan_report_failure(self, scan_id: str, error: str) -> None: ...


def _sanitize_error(value: str) -> str:
    cleaned = "".join(character if ord(character) >= 32 else " " for character in value)
    return cleaned[:512] or "worker failure"


def _failed_normalization_report(record: ScanRecord, error: str) -> JsonObject:
    message = _sanitize_error(error)
    completed_at = utc_now().isoformat()
    return {
        "schema_version": "1.0",
        "report_type": "CLOUD_ENDPOINT_SECURITY_REPORT",
        "report_id": f"cloud-report:{record.scan_id}",
        "tenant_id": record.tenant_id,
        "endpoint_id": record.endpoint_id,
        "scan_id": record.scan_id,
        "status": "FAILED",
        "analysis_completed_at": completed_at,
        "endpoint_evidence": {},
        "cloud_analysis": {"vulnerabilities": [], "tools": {}},
        "summary": {
            "status": "FAILED",
            "vulnerability_count": 0,
            "vulnerabilities_by_severity": {},
            "successful_tools": [],
            "degraded_tools": ["REPORT_NORMALIZATION"],
        },
        "completeness": {
            "complete": False,
            "fixture_mode": False,
            "gaps": ["cloud report normalization failed"],
        },
        "errors": [{"code": "REPORT_NORMALIZATION_FAILED", "message": message}],
        "provenance": {"normalization_failure_recorded_at": completed_at},
    }


class InMemoryRepository:
    """Concurrency-safe repository for tests and single-process local demonstrations."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.endpoints: dict[str, EndpointRecord] = {}
        self.credentials: dict[str, CredentialRecord] = {}
        self.enrollment_grants: dict[str, EnrollmentGrantRecord] = {}
        self.scans: dict[str, ScanRecord] = {}
        self.inventory_states: dict[tuple[str, str], InventoryState] = {}
        self.tasks: dict[str, AnalysisTask] = {}
        self.audit_events: list[AuditEvent] = []
        self.rejections: list[JsonObject] = []
        self._idempotency: dict[tuple[str, str, str], tuple[str, Any]] = {}

    async def startup(self) -> None:
        return None

    async def shutdown(self) -> None:
        return None

    async def ready(self) -> bool:
        return True

    def _replay(self, tenant: str, operation: str, key: str, digest: str) -> Any | None:
        existing = self._idempotency.get((tenant, operation, key))
        if existing is None:
            return None
        existing_digest, response = existing
        if existing_digest != digest:
            raise IdempotencyConflict("idempotency key was reused with different content")
        return response

    def _remember(self, tenant: str, operation: str, key: str, digest: str, response: Any) -> None:
        self._idempotency[(tenant, operation, key)] = (digest, response)

    def _audit(
        self,
        tenant_id: str,
        event_type: str,
        actor_type: str,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        details: JsonObject | None = None,
    ) -> None:
        sequence = len(self.audit_events) + 1
        self.audit_events.append(
            AuditEvent(
                event_id=f"audit-{sequence}",
                tenant_id=tenant_id,
                event_type=event_type,
                actor_type=actor_type,
                actor_id=actor_id,
                resource_type=resource_type,
                resource_id=resource_id,
                occurred_at=utc_now(),
                details=details or {},
            )
        )

    async def authenticate_device(self, token_hash: str, now: datetime) -> DevicePrincipal | None:
        async with self._lock:
            credential = self.credentials.get(token_hash)
            if credential is None or now >= credential.expires_at:
                return None
            if credential.valid_until is not None and now >= credential.valid_until:
                return None
            return DevicePrincipal(
                credential.tenant_id,
                credential.endpoint_id,
                credential.credential_id,
                credential.generation,
            )

    async def authenticate_enrollment_grant(
        self, token_hash: str, now: datetime
    ) -> EnrollmentGrantRecord | None:
        async with self._lock:
            grant = self.enrollment_grants.get(token_hash)
            if grant is None or now >= grant.expires_at:
                return None
            return grant

    async def create_enrollment_grant(
        self,
        *,
        grant: EnrollmentGrantRecord,
        idempotency_key: str,
        request_hash: str,
    ) -> EnrollmentGrantRecord:
        async with self._lock:
            operation = "create-enrollment-grant"
            replay = self._replay(
                grant.tenant_id, operation, idempotency_key, request_hash
            )
            if replay is not None:
                return cast(EnrollmentGrantRecord, replay)
            if grant.token_hash in self.enrollment_grants:
                raise StateConflict("generated enrollment grant already exists")
            self.enrollment_grants[grant.token_hash] = grant
            self._remember(
                grant.tenant_id, operation, idempotency_key, request_hash, grant
            )
            self._audit(
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
        async with self._lock:
            replay = self._replay(tenant_id, "enroll", idempotency_key, request_hash)
            if replay is not None:
                return cast(CredentialRecord, replay)
            grant: EnrollmentGrantRecord | None = None
            if enrollment_grant_hash is not None:
                grant = self.enrollment_grants.get(enrollment_grant_hash)
                if grant is None or grant.tenant_id != tenant_id:
                    raise OwnershipError("enrollment grant is invalid")
                if credential.issued_at >= grant.expires_at:
                    raise StateConflict("enrollment grant has expired")
                if grant.consumed_at is not None:
                    raise StateConflict("enrollment grant has already been used")
                if grant.os_family is not None and grant.os_family != endpoint.os_family:
                    raise StateConflict("enrollment grant is for a different operating system")
            if endpoint.endpoint_id in self.endpoints or credential.token_hash in self.credentials:
                raise StateConflict("generated endpoint or credential already exists")
            self.endpoints[endpoint.endpoint_id] = endpoint
            self.credentials[credential.token_hash] = credential
            if enrollment_grant_hash is not None:
                self.enrollment_grants[enrollment_grant_hash] = replace(
                    self.enrollment_grants[enrollment_grant_hash],
                    consumed_at=credential.issued_at,
                    endpoint_id=endpoint.endpoint_id,
                )
            self._remember(tenant_id, "enroll", idempotency_key, request_hash, credential)
            self._audit(
                tenant_id,
                "ENDPOINT_ENROLLED",
                "enrollment-grant" if grant is not None else "bootstrap",
                grant.grant_id if grant is not None else tenant_id,
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
        async with self._lock:
            operation = f"rotate:{principal.endpoint_id}"
            replay = self._replay(principal.tenant_id, operation, idempotency_key, request_hash)
            if replay is not None:
                return cast(CredentialRecord, replay)
            endpoint = self.endpoints.get(principal.endpoint_id)
            if endpoint is None or endpoint.tenant_id != principal.tenant_id:
                raise OwnershipError("endpoint is not owned by authenticated tenant")
            if (
                expected_generation != principal.generation
                or endpoint.credential_generation != principal.generation
            ):
                raise StateConflict("credential generation is stale")
            if expected_credential_id != principal.credential_id:
                raise StateConflict("credential identifier is stale")
            if credential.generation != principal.generation + 1:
                raise StateConflict("new credential generation is invalid")
            current_hash = next(
                (
                    digest
                    for digest, value in self.credentials.items()
                    if value.credential_id == principal.credential_id
                ),
                None,
            )
            if current_hash is None:
                raise StateConflict("current credential no longer exists")
            current = self.credentials[current_hash]
            if (
                current.tenant_id != principal.tenant_id
                or current.endpoint_id != principal.endpoint_id
                or current.generation != principal.generation
            ):
                raise StateConflict("authenticated credential is stale")
            overlap_until = credential.issued_at + timedelta(seconds=overlap_seconds)
            self.credentials[current_hash] = replace(
                current,
                superseded_at=credential.issued_at,
                valid_until=min(current.expires_at, overlap_until),
            )
            self.credentials[credential.token_hash] = credential
            self.endpoints[endpoint.endpoint_id] = replace(
                endpoint,
                credential_generation=credential.generation,
                last_seen_at=credential.issued_at,
            )
            self._remember(
                principal.tenant_id, operation, idempotency_key, request_hash, credential
            )
            self._audit(
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
        async with self._lock:
            records = sorted(
                (value for value in self.endpoints.values() if value.tenant_id == tenant_id),
                key=lambda value: value.enrolled_at,
                reverse=True,
            )
            return records[offset : offset + limit]

    async def create_scan_job(
        self,
        *,
        tenant_id: str,
        record: ScanRecord,
        idempotency_key: str,
        request_hash: str,
    ) -> ScanRecord:
        async with self._lock:
            replay = self._replay(tenant_id, "create-scan", idempotency_key, request_hash)
            if replay is not None:
                return cast(ScanRecord, replay)
            endpoint = self.endpoints.get(record.endpoint_id)
            if endpoint is None or endpoint.tenant_id != tenant_id:
                raise NotFoundError("endpoint was not found")
            if record.scan_id in self.scans:
                raise StateConflict("scan identifier already exists")
            self.scans[record.scan_id] = record
            self._remember(tenant_id, "create-scan", idempotency_key, request_hash, record)
            self._audit(
                tenant_id,
                "SCAN_AUTHORIZED",
                "platform",
                record.job_document.get("initiated_by", "platform"),
                "scan",
                record.scan_id,
                {
                    "endpoint_id": record.endpoint_id,
                    "authorization_reference": record.job_document["authorization"][
                        "authorization_reference"
                    ],
                },
            )
            return record

    async def claim_next_job(self, principal: DevicePrincipal, now: datetime) -> ScanRecord | None:
        async with self._lock:
            endpoint = self.endpoints.get(principal.endpoint_id)
            if endpoint is not None and endpoint.tenant_id == principal.tenant_id:
                self.endpoints[principal.endpoint_id] = replace(endpoint, last_seen_at=now)
            candidates = sorted(self.scans.values(), key=lambda value: value.created_at)
            for record in candidates:
                if (
                    record.tenant_id != principal.tenant_id
                    or record.endpoint_id != principal.endpoint_id
                    or record.state not in {"QUEUED", "DISPATCHED"}
                ):
                    continue
                eligibility = _job_dispatch_eligibility(record, principal.endpoint_id, now)
                if eligibility == "EXPIRED":
                    self.scans[record.scan_id] = replace(
                        record,
                        state="EXPIRED",
                        updated_at=now,
                    )
                    self._audit(
                        principal.tenant_id,
                        "SCAN_EXPIRED",
                        "control-plane",
                        "dispatcher",
                        "scan",
                        record.scan_id,
                    )
                    continue
                if eligibility != "ELIGIBLE":
                    continue
                redispatched = record.state == "DISPATCHED"
                claimed = replace(record, state="DISPATCHED", updated_at=now)
                self.scans[record.scan_id] = claimed
                self._audit(
                    principal.tenant_id,
                    "SCAN_REDISPATCHED" if redispatched else "SCAN_DISPATCHED",
                    "endpoint",
                    principal.endpoint_id,
                    "scan",
                    record.scan_id,
                    {
                        "lease_timeout_seconds": record.job_document["timeout_seconds"],
                        "lease_grace_seconds": JOB_DISPATCH_GRACE_SECONDS,
                    },
                )
                return claimed
            return None

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
        async with self._lock:
            operation = f"ingest:{scan_id}"
            replay = self._replay(principal.tenant_id, operation, idempotency_key, request_hash)
            if replay is not None:
                return cast(ScanRecord, replay)
            record = self.scans.get(scan_id)
            if (
                record is None
                or record.tenant_id != principal.tenant_id
                or record.endpoint_id != principal.endpoint_id
            ):
                raise OwnershipError("scan is not owned by authenticated endpoint")
            if record.upload is not None:
                raise StateConflict("scan already has a different accepted upload")
            now = utc_now()
            validate_scan_upload(record, upload, now)
            state_key = (principal.tenant_id, principal.endpoint_id)
            reconstruction = reconstruct_inventory(
                tenant_id=principal.tenant_id,
                endpoint_id=principal.endpoint_id,
                scan_id=scan_id,
                inventory_sync=cast(JsonObject, upload.get("inventory_sync")),
                current=self.inventory_states.get(state_key),
                now=now,
            )
            accepted_upload = copy.deepcopy(upload)
            accepted_upload["inventory_sync"] = reconstruction.inventory_sync
            accepted = replace(
                record,
                state="ANALYZING",
                upload=accepted_upload,
                updated_at=now,
            )
            for task in tasks:
                if (
                    task.scan_id != scan_id
                    or task.tenant_id != principal.tenant_id
                    or task.endpoint_id != principal.endpoint_id
                ):
                    raise StateConflict("analysis task does not match accepted scan")
                if task.task_id in self.tasks:
                    raise StateConflict("analysis task identifier already exists")
            self.scans[scan_id] = accepted
            self.inventory_states[state_key] = reconstruction.state
            for task in tasks:
                self.tasks[task.task_id] = task
            self._remember(principal.tenant_id, operation, idempotency_key, request_hash, accepted)
            self._audit(
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
            return accepted

    async def record_scan_status(
        self,
        *,
        principal: DevicePrincipal,
        scan_id: str,
        status: JsonObject,
        idempotency_key: str,
        request_hash: str,
    ) -> ScanRecord:
        async with self._lock:
            operation = f"scan-status:{scan_id}"
            replay = self._replay(principal.tenant_id, operation, idempotency_key, request_hash)
            if replay is not None:
                return cast(ScanRecord, replay)
            record = self.scans.get(scan_id)
            if (
                record is None
                or record.tenant_id != principal.tenant_id
                or record.endpoint_id != principal.endpoint_id
            ):
                raise OwnershipError("scan is not owned by authenticated endpoint")
            validate_scan_status(record, status)
            updated = replace(record, terminal_status=status, updated_at=utc_now())
            self.scans[scan_id] = updated
            self._remember(principal.tenant_id, operation, idempotency_key, request_hash, updated)
            self._audit(
                principal.tenant_id,
                "SCAN_ENDPOINT_STATUS_ACCEPTED",
                "endpoint",
                principal.endpoint_id,
                "scan",
                scan_id,
                {"status": status["status"]},
            )
            return updated

    async def record_rejection(
        self,
        *,
        principal: DevicePrincipal,
        payload: JsonObject,
        idempotency_key: str,
        request_hash: str,
    ) -> None:
        async with self._lock:
            operation = f"rejection:{payload['document_sha256']}"
            replay = self._replay(principal.tenant_id, operation, idempotency_key, request_hash)
            if replay is not None:
                return None
            scan_id = payload.get("scan_id")
            if scan_id:
                record = self.scans.get(scan_id)
                if record and (
                    record.tenant_id != principal.tenant_id
                    or record.endpoint_id != principal.endpoint_id
                ):
                    raise OwnershipError("rejected scan is not owned by endpoint")
                if record:
                    self.scans[scan_id] = replace(record, state="REJECTED", updated_at=utc_now())
            self.rejections.append(payload)
            self._remember(principal.tenant_id, operation, idempotency_key, request_hash, True)
            self._audit(
                principal.tenant_id,
                "SCAN_JOB_REJECTED",
                "endpoint",
                principal.endpoint_id,
                "scan",
                scan_id or payload["document_sha256"],
                {"reason": payload["reason"]},
            )

    async def get_scan_for_endpoint(
        self, principal: DevicePrincipal, scan_id: str
    ) -> ScanRecord | None:
        async with self._lock:
            record = self.scans.get(scan_id)
            if record is None:
                return None
            if (
                record.tenant_id != principal.tenant_id
                or record.endpoint_id != principal.endpoint_id
            ):
                raise OwnershipError("scan is not owned by authenticated endpoint")
            return record

    async def list_scans(
        self, tenant_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[ScanRecord]:
        if not 1 <= limit <= 500 or offset < 0:
            raise ValueError("invalid scan page")
        async with self._lock:
            records = sorted(
                (record for record in self.scans.values() if record.tenant_id == tenant_id),
                key=lambda value: value.created_at,
                reverse=True,
            )
            return records[offset : offset + limit]

    async def get_scan_for_tenant(
        self, tenant_id: str, scan_id: str
    ) -> ScanRecord | None:
        async with self._lock:
            record = self.scans.get(scan_id)
            if record is None or record.tenant_id != tenant_id:
                return None
            return copy.deepcopy(record)

    async def get_final_report(self, tenant_id: str, scan_id: str) -> JsonObject | None:
        async with self._lock:
            record = self.scans.get(scan_id)
            if record is None or record.tenant_id != tenant_id:
                return None
            return record.final_report

    async def get_scan_report(self, tenant_id: str, scan_id: str) -> ScanReportLookup:
        async with self._lock:
            record = self.scans.get(scan_id)
            if record is None or record.tenant_id != tenant_id:
                return ScanReportLookup("NOT_FOUND")
            if record.final_report is None:
                return ScanReportLookup("PENDING")
            return ScanReportLookup("READY", copy.deepcopy(record.final_report))

    async def get_inventory_state(
        self, tenant_id: str, endpoint_id: str
    ) -> InventoryState | None:
        async with self._lock:
            return self.inventory_states.get((tenant_id, endpoint_id))

    async def claim_analysis_task(
        self, kind: TaskKind, worker_id: str, lease_seconds: int
    ) -> AnalysisTask | None:
        if not worker_id or len(worker_id) > 128 or not 10 <= lease_seconds <= 3600:
            raise ValueError("invalid worker lease request")
        now = utc_now()
        async with self._lock:
            candidates = sorted(self.tasks.values(), key=lambda value: value.created_at)
            for task in candidates:
                lease_expired = task.lease_expires_at is not None and task.lease_expires_at <= now
                eligible = task.state in {"PENDING", "RETRY"} or (
                    task.state == "RUNNING" and lease_expired
                )
                if task.kind != kind or not eligible or task.available_at > now:
                    continue
                claimed = replace(
                    task,
                    state="RUNNING",
                    attempts=task.attempts + 1,
                    leased_by=worker_id,
                    lease_expires_at=now + timedelta(seconds=lease_seconds),
                    updated_at=now,
                )
                self.tasks[task.task_id] = claimed
                return claimed
            return None

    async def complete_analysis_task(
        self, task_id: str, worker_id: str, result: JsonObject
    ) -> None:
        async with self._lock:
            task = self.tasks.get(task_id)
            if task is None:
                raise NotFoundError("analysis task was not found")
            if task.state != "RUNNING" or task.leased_by != worker_id:
                raise StateConflict("analysis task is not leased by this worker")
            self.tasks[task_id] = replace(
                task,
                state="SUCCEEDED",
                result=result,
                lease_expires_at=None,
                leased_by=None,
                updated_at=utc_now(),
            )

    async def fail_analysis_task(
        self,
        task_id: str,
        worker_id: str,
        error: str,
        retry_at: datetime,
        dead_letter: bool,
    ) -> None:
        async with self._lock:
            task = self.tasks.get(task_id)
            if task is None:
                raise NotFoundError("analysis task was not found")
            if task.state != "RUNNING" or task.leased_by != worker_id:
                raise StateConflict("analysis task is not leased by this worker")
            now = utc_now()
            self.tasks[task_id] = replace(
                task,
                state="FAILED" if dead_letter else "RETRY",
                available_at=max(now, retry_at),
                lease_expires_at=None,
                leased_by=None,
                last_error=_sanitize_error(error),
                updated_at=now,
            )

    async def get_scan_analysis_input(self, scan_id: str) -> ScanAnalysisInput | None:
        async with self._lock:
            record = self.scans.get(scan_id)
            if record is None or record.upload is None:
                return None
            return ScanAnalysisInput(record.tenant_id, record.endpoint_id, scan_id, record.upload)

    async def list_scan_analysis_results(self, scan_id: str) -> dict[str, JsonObject]:
        async with self._lock:
            results: dict[str, JsonObject] = {}
            for task in self.tasks.values():
                if task.scan_id != scan_id:
                    continue
                if task.state == "SUCCEEDED" and task.result is not None:
                    results[task.kind] = task.result
                elif task.state == "FAILED":
                    results[task.kind] = {
                        "tool": task.kind.lower(),
                        "status": "FAILED",
                        "error": task.last_error or "analysis task reached dead letter state",
                        "attempts": task.attempts,
                    }
            return results

    async def next_scan_ready_for_finalization(self) -> str | None:
        async with self._lock:
            records = sorted(self.scans.values(), key=lambda item: item.updated_at)
            for record in records:
                if record.state != "ANALYZING" or record.final_report is not None:
                    continue
                states = {
                    task.kind: task.state
                    for task in self.tasks.values()
                    if task.scan_id == record.scan_id
                }
                if set(states) == {"OSV", "DEPSCAN"} and all(
                    state in {"SUCCEEDED", "FAILED"} for state in states.values()
                ):
                    return record.scan_id
            return None

    async def finalize_scan_report(self, scan_id: str, report: JsonObject) -> None:
        async with self._lock:
            record = self.scans.get(scan_id)
            if record is None:
                raise NotFoundError("scan was not found")
            if record.final_report is not None:
                if record.final_report == report:
                    return
                raise StateConflict("scan already has a different final report")
            task_states = {
                task.kind: task.state for task in self.tasks.values() if task.scan_id == scan_id
            }
            if set(task_states) != {"OSV", "DEPSCAN"} or any(
                state not in {"SUCCEEDED", "FAILED"} for state in task_states.values()
            ):
                raise StateConflict("all expected analysis tasks must be terminal")
            self.scans[scan_id] = replace(
                record, state="COMPLETE", final_report=report, updated_at=utc_now()
            )
            self._audit(
                record.tenant_id,
                "SCAN_REPORT_FINALIZED",
                "worker",
                "normalizer",
                "scan",
                scan_id,
                {"analysis_states": task_states},
            )

    async def finalize_scan_report_failure(self, scan_id: str, error: str) -> None:
        async with self._lock:
            record = self.scans.get(scan_id)
            if record is None:
                raise NotFoundError("scan was not found")
            if record.final_report is not None:
                return
            report = _failed_normalization_report(record, error)
            self.scans[scan_id] = replace(
                record,
                state="COMPLETE",
                final_report=report,
                updated_at=utc_now(),
            )
            self._audit(
                record.tenant_id,
                "SCAN_REPORT_NORMALIZATION_FAILED",
                "worker",
                "normalizer",
                "scan",
                scan_id,
                {"error": _sanitize_error(error)},
            )
