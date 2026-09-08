"""Persistent leased upload queue repository."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping
from random import Random
from typing import Any, cast
from uuid import uuid4

from .audit import AuditStorage
from .base import StorageBase
from .errors import IdempotencyConflictError, StorageError
from .queue import EnqueueResult, QueuedUpload, QueueStats, UploadStatus
from .retry import RetryPolicy
from .serialization import canonical_json, clean_error, clean_identifier, parse_json, utc_now_iso

_CAUSAL_UPLOAD_KINDS = frozenset(
    {
        "inventory-snapshot",
        "scan-result",
        "scan-status",
    }
)
_UNSCOPED_CAUSAL_GROUP = "endpoint:unscoped"


class UploadQueueStorage(StorageBase):
    """Crash-recoverable at-least-once upload state."""

    @staticmethod
    def _normalized_kind(kind: str) -> str:
        return kind.strip().casefold().replace("_", "-")

    @classmethod
    def _causal_group(
        cls,
        kind: str,
        metadata: Mapping[str, Any],
        body: bytes | None = None,
    ) -> str | None:
        """Return an opaque per-endpoint stream for state-dependent uploads."""

        if cls._normalized_kind(kind) not in _CAUSAL_UPLOAD_KINDS:
            return None
        candidates: list[object] = [metadata.get("endpoint_id")]
        if body is not None:
            try:
                decoded = parse_json(body)
            except (TypeError, ValueError):
                decoded = None
            if isinstance(decoded, Mapping):
                candidates.append(decoded.get("endpoint_id"))
                result = decoded.get("result")
                if isinstance(result, Mapping):
                    candidates.append(result.get("endpoint_id"))
                inventory_sync = decoded.get("inventory_sync")
                if isinstance(inventory_sync, Mapping):
                    candidates.append(inventory_sync.get("endpoint_id"))
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            try:
                endpoint_id = clean_identifier(candidate, "endpoint_id")
            except (TypeError, ValueError):
                continue
            digest = hashlib.sha256(endpoint_id.encode("utf-8")).hexdigest()
            return f"endpoint:{digest}"
        # Malformed legacy scan uploads are serialized together instead of
        # silently bypassing ordering protection.
        return _UNSCOPED_CAUSAL_GROUP

    @classmethod
    def _backfill_causal_links(cls, connection: Any) -> None:
        """Link pre-migration outbox rows without relying on SQLite JSON1."""

        rows = connection.execute(
            """
            SELECT upload_id,kind,payload,metadata_json,resync_for_upload_id
            FROM upload_queue
            WHERE causal_group IS NULL
              AND lower(replace(kind,'_','-')) IN (
                  'inventory-snapshot','scan-result','scan-status'
              )
            ORDER BY upload_id
            """
        ).fetchall()
        for row in rows:
            raw_metadata = parse_json(row["metadata_json"])
            metadata = raw_metadata if isinstance(raw_metadata, Mapping) else {}
            group = cls._causal_group(str(row["kind"]), metadata, bytes(row["payload"]))
            if group is None:
                continue
            predecessor = None
            if row["resync_for_upload_id"] is None:
                predecessor = connection.execute(
                    """
                    SELECT upload_id FROM upload_queue
                    WHERE causal_group=? AND upload_id<?
                    ORDER BY upload_id DESC LIMIT 1
                    """,
                    (group, int(row["upload_id"])),
                ).fetchone()
            connection.execute(
                """
                UPDATE upload_queue
                SET causal_group=?, predecessor_upload_id=COALESCE(
                    predecessor_upload_id,?
                )
                WHERE upload_id=? AND causal_group IS NULL
                """,
                (
                    group,
                    int(predecessor["upload_id"]) if predecessor is not None else None,
                    int(row["upload_id"]),
                ),
            )

    def enqueue_upload(
        self,
        kind: str,
        payload: Mapping[str, Any] | bytes,
        idempotency_key: str,
        endpoint: str,
        *,
        method: str = "POST",
        content_type: str = "application/json",
        request_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        max_attempts: int = 8,
        not_before: float | None = None,
    ) -> EnqueueResult:
        kind = clean_identifier(kind, "kind", max_length=128)
        idempotency_key = clean_identifier(idempotency_key, "idempotency_key")
        endpoint = clean_identifier(endpoint, "endpoint", max_length=2048)
        if not endpoint.startswith("/") or endpoint.startswith("//"):
            raise ValueError("upload endpoint must be an absolute API path")
        method = clean_identifier(method.upper(), "method", max_length=16)
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("upload queue method is not supported")
        if not 1 <= max_attempts <= 100:
            raise ValueError("max_attempts must be between 1 and 100")
        body = (
            bytes(payload)
            if isinstance(payload, bytes)
            else canonical_json(payload).encode("utf-8")
        )
        digest = hashlib.sha256(body).hexdigest()
        request_id = clean_identifier(request_id or str(uuid4()), "request_id")
        now_epoch = time.time()
        next_attempt = now_epoch if not_before is None else float(not_before)
        now_text = utc_now_iso()
        metadata_value = dict(metadata or {})
        metadata_json = canonical_json(metadata_value)
        causal_group = self._causal_group(kind, metadata_value, body)
        with self.transaction() as connection:
            self._backfill_causal_links(connection)
            existing = connection.execute(
                "SELECT * FROM upload_queue WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if existing:
                if (
                    existing["kind"],
                    existing["method"],
                    existing["endpoint"],
                    existing["payload_hash"],
                    existing["content_type"],
                ) != (kind, method, endpoint, digest, content_type):
                    raise IdempotencyConflictError(
                        "upload idempotency key was reused with different content"
                    )
                return EnqueueResult(int(existing["upload_id"]), False)
            predecessor = None
            if causal_group is not None:
                predecessor = connection.execute(
                    """
                    SELECT upload_id FROM upload_queue
                    WHERE causal_group=? ORDER BY upload_id DESC LIMIT 1
                    """,
                    (causal_group,),
                ).fetchone()
            cursor = connection.execute(
                """
                INSERT INTO upload_queue(
                    kind,method,endpoint,payload,payload_hash,content_type,idempotency_key,
                    request_id,status,attempt_count,max_attempts,next_attempt_at,
                    metadata_json,created_at,updated_at,causal_group,predecessor_upload_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    kind,
                    method,
                    endpoint,
                    body,
                    digest,
                    content_type,
                    idempotency_key,
                    request_id,
                    UploadStatus.PENDING.value,
                    0,
                    max_attempts,
                    next_attempt,
                    metadata_json,
                    now_text,
                    now_text,
                    causal_group,
                    int(predecessor["upload_id"]) if predecessor is not None else None,
                ),
            )
            return EnqueueResult(self._inserted_id(cursor), True)

    def claim_uploads(
        self,
        *,
        limit: int = 10,
        lease_seconds: float = 60.0,
        now: float | None = None,
    ) -> list[QueuedUpload]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        if not 1 <= lease_seconds <= 86_400:
            raise ValueError("lease_seconds must be between 1 and 86400")
        current = time.time() if now is None else float(now)
        leases: list[QueuedUpload] = []
        with self.transaction() as connection:
            self._backfill_causal_links(connection)
            connection.execute(
                """
                UPDATE upload_queue SET status='DEAD', lease_token=NULL, leased_until=NULL,
                    last_error=COALESCE(last_error,'upload lease expired at retry limit'),
                    updated_at=?
                WHERE status='IN_FLIGHT' AND leased_until<=? AND attempt_count>=max_attempts
                """,
                (utc_now_iso(), current),
            )
            connection.execute(
                """
                UPDATE upload_queue SET status='PENDING', lease_token=NULL, leased_until=NULL,
                    next_attempt_at=?, updated_at=?
                WHERE status='IN_FLIGHT' AND leased_until<=? AND attempt_count<max_attempts
                """,
                (current, utc_now_iso(), current),
            )
            rows = connection.execute(
                """
                SELECT queued.* FROM upload_queue AS queued
                LEFT JOIN upload_queue AS predecessor
                    ON predecessor.upload_id=queued.predecessor_upload_id
                LEFT JOIN upload_queue AS replacement
                    ON replacement.upload_id=predecessor.superseded_by_upload_id
                WHERE queued.status='PENDING'
                  AND queued.next_attempt_at<=?
                  AND queued.attempt_count<queued.max_attempts
                  AND (
                      queued.predecessor_upload_id IS NULL
                      OR predecessor.status='SUCCEEDED'
                      OR replacement.status='SUCCEEDED'
                  )
                ORDER BY queued.next_attempt_at,queued.upload_id LIMIT ?
                """,
                (current, limit),
            ).fetchall()
            for row in rows:
                lease_token = uuid4().hex
                attempt_count = int(row["attempt_count"]) + 1
                updated = connection.execute(
                    """
                    UPDATE upload_queue SET status='IN_FLIGHT',attempt_count=?,lease_token=?,
                        leased_until=?,updated_at=? WHERE upload_id=? AND status='PENDING'
                    """,
                    (
                        attempt_count,
                        lease_token,
                        current + lease_seconds,
                        utc_now_iso(),
                        row["upload_id"],
                    ),
                )
                if updated.rowcount != 1:
                    continue
                leases.append(
                    QueuedUpload(
                        upload_id=int(row["upload_id"]),
                        kind=str(row["kind"]),
                        method=str(row["method"]),
                        endpoint=str(row["endpoint"]),
                        payload=bytes(row["payload"]),
                        content_type=str(row["content_type"]),
                        idempotency_key=str(row["idempotency_key"]),
                        request_id=str(row["request_id"]),
                        attempt_count=attempt_count,
                        max_attempts=int(row["max_attempts"]),
                        lease_token=lease_token,
                        metadata=parse_json(row["metadata_json"]),
                    )
                )
        return leases

    def schedule_full_resync(
        self,
        upload_id: int,
        lease_token: str,
        error: object,
        *,
        now: float | None = None,
    ) -> EnqueueResult:
        """Atomically replace a rejected differential with its exact full snapshot.

        Only one recovery generation is permitted.  A conflict on the recovery
        itself therefore follows ordinary bounded dead-letter handling instead
        of creating an infinite chain of full snapshots.
        """

        lease_token = clean_identifier(lease_token, "lease_token")
        current = time.time() if now is None else float(now)
        now_text = utc_now_iso()
        with self.transaction() as connection:
            row = connection.execute(
                """
                SELECT * FROM upload_queue
                WHERE upload_id=? AND status='IN_FLIGHT' AND lease_token=?
                """,
                (int(upload_id), lease_token),
            ).fetchone()
            if row is None:
                raise StorageError("upload lease is no longer valid")
            metadata_value = parse_json(row["metadata_json"])
            if not isinstance(metadata_value, Mapping):
                raise StorageError("upload metadata is not a JSON object")
            if bool(metadata_value.get("causal_recovery")):
                raise StorageError("a full-resync upload cannot be superseded again")

            original_payload = parse_json(bytes(row["payload"]))
            if not isinstance(original_payload, Mapping):
                raise StorageError("differential upload payload is not a JSON object")
            inventory_sync = original_payload.get("inventory_sync")
            if inventory_sync is None and "mode" in original_payload:
                inventory_sync = original_payload
            if not isinstance(inventory_sync, Mapping):
                raise StorageError("upload does not contain differential inventory state")
            scan_id_value = metadata_value.get("scan_id") or inventory_sync.get("scan_id")
            try:
                scan_id = clean_identifier(scan_id_value, "scan_id")
            except (TypeError, ValueError) as exc:
                raise StorageError("differential upload has no valid scan_id") from exc

            snapshot_row = connection.execute(
                """
                SELECT snapshots.*,payloads.payload_json,
                    previous.payload_hash AS previous_hash
                FROM inventory_snapshots AS snapshots
                JOIN inventory_payloads AS payloads
                    ON payloads.payload_hash=snapshots.payload_hash
                LEFT JOIN inventory_snapshots AS previous
                    ON previous.snapshot_id=snapshots.previous_snapshot_id
                WHERE snapshots.scan_id=?
                """,
                (scan_id,),
            ).fetchone()
            if snapshot_row is None:
                raise StorageError("full-resync snapshot is no longer available")
            full_sync = {
                "endpoint_id": str(snapshot_row["endpoint_id"]),
                "scan_id": str(snapshot_row["scan_id"]),
                "schema_version": str(snapshot_row["schema_version"]),
                "policy_version": snapshot_row["policy_version"],
                "scanner_version": snapshot_row["scanner_version"],
                "snapshot_hash": str(snapshot_row["payload_hash"]),
                # A null prerequisite explicitly resets the remote differential
                # base to this content-addressed snapshot.
                "previous_hash": None,
                "mode": "full",
                "snapshot": parse_json(snapshot_row["payload_json"]),
            }
            if "inventory_sync" in original_payload:
                recovery_payload = dict(original_payload)
                recovery_payload["inventory_sync"] = full_sync
            else:
                recovery_payload = full_sync
            body = canonical_json(recovery_payload).encode("utf-8")
            payload_hash = hashlib.sha256(body).hexdigest()
            recovery_identity = hashlib.sha256(
                (f"{snapshot_row['endpoint_id']}:{scan_id}:{snapshot_row['payload_hash']}").encode()
            ).hexdigest()
            idempotency_key = f"full-resync:{recovery_identity}"
            recovery_metadata = dict(metadata_value)
            recovery_metadata.update(
                {
                    "causal_recovery": True,
                    "resync_for_upload_id": int(upload_id),
                    "snapshot_hash": str(snapshot_row["payload_hash"]),
                }
            )
            metadata_json = canonical_json(recovery_metadata)
            existing = connection.execute(
                "SELECT * FROM upload_queue WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["endpoint"],
                    existing["payload_hash"],
                    existing["content_type"],
                ) != (row["endpoint"], payload_hash, row["content_type"]):
                    raise IdempotencyConflictError(
                        "full-resync idempotency key has conflicting content"
                    )
                recovery_id = int(existing["upload_id"])
                created = False
            else:
                cursor = connection.execute(
                    """
                    INSERT INTO upload_queue(
                        kind,method,endpoint,payload,payload_hash,content_type,
                        idempotency_key,request_id,status,attempt_count,max_attempts,
                        next_attempt_at,metadata_json,created_at,updated_at,
                        causal_group,predecessor_upload_id,resync_for_upload_id
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        "inventory_full_resync",
                        row["method"],
                        row["endpoint"],
                        body,
                        payload_hash,
                        row["content_type"],
                        idempotency_key,
                        str(uuid4()),
                        UploadStatus.PENDING.value,
                        0,
                        int(row["max_attempts"]),
                        current,
                        metadata_json,
                        now_text,
                        now_text,
                        row["causal_group"],
                        row["predecessor_upload_id"],
                        int(upload_id),
                    ),
                )
                recovery_id = self._inserted_id(cursor)
                created = True
            updated = connection.execute(
                """
                UPDATE upload_queue
                SET status='DEAD',next_attempt_at=?,lease_token=NULL,leased_until=NULL,
                    last_error=?,updated_at=?,superseded_by_upload_id=?
                WHERE upload_id=? AND status='IN_FLIGHT' AND lease_token=?
                """,
                (
                    current,
                    clean_error(error),
                    now_text,
                    recovery_id,
                    int(upload_id),
                    lease_token,
                ),
            )
            if updated.rowcount != 1:
                raise StorageError("upload lease is no longer valid")
            return EnqueueResult(recovery_id, created)

    def mark_upload_succeeded(
        self,
        upload_id: int,
        lease_token: str,
        *,
        delivered_at: str | None = None,
    ) -> bool:
        lease_token = clean_identifier(lease_token, "lease_token")
        now = delivered_at or utc_now_iso()
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE upload_queue SET status='SUCCEEDED',lease_token=NULL,leased_until=NULL,
                    last_error=NULL,delivered_at=?,updated_at=?
                WHERE upload_id=? AND status='IN_FLIGHT' AND lease_token=?
                """,
                (now, now, int(upload_id), lease_token),
            )
            return cursor.rowcount == 1

    def mark_upload_failed(
        self,
        upload_id: int,
        lease_token: str,
        error: object,
        *,
        permanent: bool = False,
        retry_after_seconds: float | None = None,
        retry_policy: RetryPolicy | None = None,
        random_source: Random | None = None,
        now: float | None = None,
    ) -> UploadStatus:
        lease_token = clean_identifier(lease_token, "lease_token")
        current = time.time() if now is None else float(now)
        with self.transaction() as connection:
            row = connection.execute(
                """
                SELECT attempt_count,max_attempts FROM upload_queue
                WHERE upload_id=? AND status='IN_FLIGHT' AND lease_token=?
                """,
                (int(upload_id), lease_token),
            ).fetchone()
            if row is None:
                raise StorageError("upload lease is no longer valid")
            terminal = permanent or int(row["attempt_count"]) >= int(row["max_attempts"])
            status = UploadStatus.DEAD if terminal else UploadStatus.PENDING
            if terminal:
                next_attempt = current
            elif retry_after_seconds is not None:
                next_attempt = current + max(0.0, float(retry_after_seconds))
            else:
                policy = retry_policy or RetryPolicy(max_attempts=int(row["max_attempts"]))
                next_attempt = current + policy.delay_for_attempt(
                    int(row["attempt_count"]), random_source=random_source
                )
            connection.execute(
                """
                UPDATE upload_queue SET status=?,next_attempt_at=?,lease_token=NULL,
                    leased_until=NULL,last_error=?,updated_at=? WHERE upload_id=?
                """,
                (
                    status.value,
                    next_attempt,
                    clean_error(error),
                    utc_now_iso(),
                    int(upload_id),
                ),
            )
            return status

    def requeue_dead_upload(
        self,
        upload_id: int,
        *,
        actor: str,
        reason: str,
        max_attempts: int | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Explicitly requeue one unresolved dead letter with an audit record.

        This is deliberately an operator action rather than an automatic skip.
        The existing payload, idempotency key, and causal links are retained, so
        later scan results and statuses remain blocked until this predecessor is
        actually accepted by the server.  Rows already superseded by a recovery
        upload must be repaired through that replacement instead.
        """

        operator = clean_identifier(actor, "actor", max_length=256)
        requested_reason = clean_identifier(reason, "reason", max_length=512)
        safe_reason = clean_error(requested_reason, max_length=512).strip()
        if not safe_reason:
            raise ValueError("reason must not be empty after sanitization")
        if max_attempts is not None and not 1 <= int(max_attempts) <= 100:
            raise ValueError("max_attempts must be between 1 and 100")

        current = time.time() if now is None else float(now)
        recorded_at = utc_now_iso()
        audit_event_id = str(uuid4())
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM upload_queue WHERE upload_id=?",
                (int(upload_id),),
            ).fetchone()
            if row is None:
                raise StorageError("upload does not exist")
            if row["status"] != UploadStatus.DEAD.value:
                raise StorageError("only a DEAD upload can be requeued by an operator")
            if row["superseded_by_upload_id"] is not None:
                raise StorageError(
                    "upload has a replacement; requeue the superseding upload instead"
                )

            metadata_value = parse_json(row["metadata_json"])
            if not isinstance(metadata_value, Mapping):
                raise StorageError("upload metadata is not a JSON object")
            metadata = dict(metadata_value)
            retry_limit = (
                int(row["max_attempts"])
                if max_attempts is None
                else int(max_attempts)
            )
            prior_error = str(row["last_error"]) if row["last_error"] is not None else None
            prior_error_hash = (
                hashlib.sha256(prior_error.encode("utf-8")).hexdigest()
                if prior_error is not None
                else None
            )
            metadata["operator_recovery"] = {
                "action": "requeue",
                "actor": operator,
                "audit_event_id": audit_event_id,
                "reason": safe_reason,
                "recorded_at": recorded_at,
            }
            updated = connection.execute(
                """
                UPDATE upload_queue
                SET status='PENDING',attempt_count=0,max_attempts=?,next_attempt_at=?,
                    lease_token=NULL,leased_until=NULL,last_error=NULL,delivered_at=NULL,
                    metadata_json=?,updated_at=?
                WHERE upload_id=? AND status='DEAD'
                  AND superseded_by_upload_id IS NULL
                """,
                (
                    retry_limit,
                    current,
                    canonical_json(metadata),
                    recorded_at,
                    int(upload_id),
                ),
            )
            if updated.rowcount != 1:
                raise StorageError("dead-letter recovery state changed concurrently")

            scan_id = self._optional_metadata_identifier(metadata, "scan_id")
            endpoint_id = self._optional_metadata_identifier(metadata, "endpoint_id")
            audit_hash = AuditStorage.record_audit_event(
                cast(AuditStorage, self),
                "upload.dead_letter_requeued",
                "SUCCESS",
                event_id=audit_event_id,
                actor=operator,
                resource_type="upload_queue",
                resource_id=str(int(upload_id)),
                scan_id=scan_id,
                endpoint_id=endpoint_id,
                details={
                    "action": "requeue",
                    "kind": str(row["kind"]),
                    "previous_attempt_count": int(row["attempt_count"]),
                    "previous_error_sha256": prior_error_hash,
                    "reason": safe_reason,
                    "retry_limit": retry_limit,
                },
                created_at=recorded_at,
            )
        return {
            "upload_id": int(upload_id),
            "status": UploadStatus.PENDING.value,
            "attempt_count": 0,
            "max_attempts": retry_limit,
            "audit_event_id": audit_event_id,
            "audit_event_hash": audit_hash,
        }

    @staticmethod
    def _optional_metadata_identifier(
        metadata: Mapping[str, Any], field: str
    ) -> str | None:
        value = metadata.get(field)
        if value is None:
            return None
        try:
            return clean_identifier(value, field)
        except (TypeError, ValueError):
            # Legacy diagnostics may lack valid identifiers.  Recovery remains
            # possible, but malformed values are never copied into the audit
            # event's indexed identity fields.
            return None

    def queue_stats(self) -> QueueStats:
        with self._lock:
            self._ensure_open()
            counts = {
                row["status"]: int(row["count"])
                for row in self._connection.execute(
                    """
                    SELECT queued.status,COUNT(*) AS count
                    FROM upload_queue AS queued
                    LEFT JOIN upload_queue AS replacement
                        ON replacement.upload_id=queued.superseded_by_upload_id
                    WHERE queued.status!='DEAD'
                       OR replacement.status IS NULL
                       OR replacement.status!='SUCCEEDED'
                    GROUP BY queued.status
                    """
                ).fetchall()
            }
        return QueueStats(
            pending=counts.get(UploadStatus.PENDING.value, 0),
            in_flight=counts.get(UploadStatus.IN_FLIGHT.value, 0),
            succeeded=counts.get(UploadStatus.SUCCEEDED.value, 0),
            dead=counts.get(UploadStatus.DEAD.value, 0),
        )

    def get_upload(self, upload_id: int, *, include_payload: bool = False) -> dict[str, Any] | None:
        """Return queue diagnostics; payload bytes are opt-in to limit accidental exposure."""

        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT * FROM upload_queue WHERE upload_id=?", (int(upload_id),)
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["metadata"] = parse_json(result.pop("metadata_json"))
        if not include_payload:
            result.pop("payload", None)
        return result

    def purge_succeeded_uploads(self, *, older_than: str, limit: int = 1000) -> int:
        if not 1 <= limit <= 100_000:
            raise ValueError("limit must be between 1 and 100000")
        with self.transaction() as connection:
            # A rejected delta whose replacement has been delivered is a
            # resolved recovery record, not an operator-action dead letter.
            resolved = connection.execute(
                """
                DELETE FROM upload_queue WHERE upload_id IN (
                    SELECT original.upload_id
                    FROM upload_queue AS original
                    JOIN upload_queue AS replacement
                        ON replacement.upload_id=original.superseded_by_upload_id
                    WHERE original.status='DEAD'
                      AND replacement.status='SUCCEEDED'
                      AND replacement.delivered_at<?
                    ORDER BY original.upload_id LIMIT ?
                )
                """,
                (older_than, limit),
            ).rowcount
            remaining = max(0, limit - resolved)
            if remaining == 0:
                return resolved
            cursor = connection.execute(
                """
                DELETE FROM upload_queue WHERE upload_id IN (
                    SELECT candidate.upload_id FROM upload_queue AS candidate
                    WHERE candidate.status='SUCCEEDED' AND candidate.delivered_at<?
                      AND NOT EXISTS (
                          SELECT 1 FROM upload_queue AS superseded
                          WHERE superseded.superseded_by_upload_id=candidate.upload_id
                      )
                    ORDER BY candidate.upload_id LIMIT ?
                )
                """,
                (older_than, remaining),
            )
            return resolved + cursor.rowcount
