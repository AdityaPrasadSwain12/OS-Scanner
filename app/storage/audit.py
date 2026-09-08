"""Append-only hash-chained audit event repository."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import uuid4

from .base import StorageBase
from .errors import IdempotencyConflictError
from .serialization import canonical_json, clean_identifier, utc_now_iso


class AuditStorage(StorageBase):
    """Traceability records with idempotency and tamper-evident chaining."""

    def record_audit_event(
        self,
        event_type: str,
        outcome: str,
        *,
        event_id: str | None = None,
        actor: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        scan_id: str | None = None,
        endpoint_id: str | None = None,
        authorization_scope_id: str | None = None,
        details: Mapping[str, Any] | None = None,
        created_at: str | None = None,
        return_existing: bool = False,
    ) -> str:
        event_type = clean_identifier(event_type, "event_type", max_length=128)
        outcome = clean_identifier(outcome, "outcome", max_length=64)
        event_id = clean_identifier(event_id or str(uuid4()), "event_id")
        timestamp = created_at or utc_now_iso()
        details_json = canonical_json(details or {})
        content = {
            "event_id": event_id,
            "event_type": event_type,
            "actor": actor,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "scan_id": scan_id,
            "endpoint_id": endpoint_id,
            "authorization_scope_id": authorization_scope_id,
            "outcome": outcome,
            "details_json": details_json,
            "created_at": timestamp,
        }
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM audit_log WHERE event_id=?", (event_id,)
            ).fetchone()
            if existing:
                comparable = {key: existing[key] for key in content}
                if comparable != content and not return_existing:
                    raise IdempotencyConflictError(
                        "audit event_id was reused with different content"
                    )
                return str(existing["event_hash"])
            previous = connection.execute(
                "SELECT event_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1"
            ).fetchone()
            previous_hash = str(previous["event_hash"]) if previous else None
            event_hash = self._hash_text(
                canonical_json({"previous_hash": previous_hash, **content})
            )
            connection.execute(
                """
                INSERT INTO audit_log(
                    event_id,event_type,actor,resource_type,resource_id,scan_id,endpoint_id,
                    authorization_scope_id,outcome,details_json,previous_hash,event_hash,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event_id,
                    event_type,
                    actor,
                    resource_type,
                    resource_id,
                    scan_id,
                    endpoint_id,
                    authorization_scope_id,
                    outcome,
                    details_json,
                    previous_hash,
                    event_hash,
                    timestamp,
                ),
            )
        return event_hash

    def has_audit_event(self, event_id: str) -> bool:
        event_id = clean_identifier(event_id, "event_id")
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT 1 FROM audit_log WHERE event_id=?", (event_id,)
            ).fetchone()
        return row is not None

    def verify_audit_chain(self) -> bool:
        with self._lock:
            self._ensure_open()
            rows = self._connection.execute("SELECT * FROM audit_log ORDER BY audit_id").fetchall()
        previous_hash: str | None = None
        for row in rows:
            content = {
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "actor": row["actor"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "scan_id": row["scan_id"],
                "endpoint_id": row["endpoint_id"],
                "authorization_scope_id": row["authorization_scope_id"],
                "outcome": row["outcome"],
                "details_json": row["details_json"],
                "created_at": row["created_at"],
            }
            expected = self._hash_text(canonical_json({"previous_hash": previous_hash, **content}))
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
                return False
            previous_hash = str(row["event_hash"])
        return True
