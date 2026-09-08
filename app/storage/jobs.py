"""Endpoint, scan-job, finding, and collector-status repositories."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .base import StorageBase
from .errors import IdempotencyConflictError, StorageError
from .serialization import canonical_json, clean_error, clean_identifier, parse_json, utc_now_iso


class JobStorage(StorageBase):
    """Persistence operations for endpoint scan execution state."""

    def upsert_endpoint(
        self,
        endpoint_id: str,
        state: Mapping[str, Any],
        *,
        enrolled_at: str | None = None,
        last_seen_at: str | None = None,
        now: str | None = None,
    ) -> None:
        endpoint_id = clean_identifier(endpoint_id, "endpoint_id")
        serialized = canonical_json(state)
        timestamp = now or utc_now_iso()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO endpoints(
                    endpoint_id,state_json,state_hash,enrolled_at,last_seen_at,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(endpoint_id) DO UPDATE SET
                    state_json=excluded.state_json,
                    state_hash=excluded.state_hash,
                    enrolled_at=COALESCE(excluded.enrolled_at,endpoints.enrolled_at),
                    last_seen_at=COALESCE(excluded.last_seen_at,endpoints.last_seen_at),
                    updated_at=excluded.updated_at
                """,
                (
                    endpoint_id,
                    serialized,
                    self._hash_text(serialized),
                    enrolled_at,
                    last_seen_at,
                    timestamp,
                    timestamp,
                ),
            )

    def get_endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        endpoint_id = clean_identifier(endpoint_id, "endpoint_id")
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT * FROM endpoints WHERE endpoint_id=?", (endpoint_id,)
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["state"] = parse_json(result.pop("state_json"))
        return result

    def list_endpoint_ids(
        self, *, enrolled_only: bool = False, limit: int = 100
    ) -> list[str]:
        if not 1 <= limit <= 10_000:
            raise ValueError("endpoint list limit must be between 1 and 10,000")
        where = "WHERE enrolled_at IS NOT NULL" if enrolled_only else ""
        with self._lock:
            self._ensure_open()
            rows = self._connection.execute(
                f"SELECT endpoint_id FROM endpoints {where} "  # noqa: S608 - fixed local fragment
                "ORDER BY created_at, endpoint_id LIMIT ?",
                (limit,),
            ).fetchall()
        return [str(row["endpoint_id"]) for row in rows]

    def create_scan_job(self, job: Mapping[str, Any]) -> bool:
        if not isinstance(job, Mapping):
            raise TypeError("job must be a mapping")
        scan_id = clean_identifier(job.get("scan_id"), "scan_id")
        endpoint_value = job.get("endpoint_id")
        endpoint_id = clean_identifier(endpoint_value, "endpoint_id") if endpoint_value else None
        scan_type = clean_identifier(job.get("scan_type", "UNKNOWN"), "scan_type", max_length=64)
        status = clean_identifier(job.get("status", "PENDING"), "status", max_length=64)
        timestamp = str(job.get("requested_at") or utc_now_iso())
        serialized = canonical_json(job)
        digest = self._hash_text(serialized)
        authorization = canonical_json(
            job.get("authorization", job.get("authorization_metadata", {}))
        )
        with self.transaction() as connection:
            if endpoint_id:
                self._ensure_endpoint(connection, endpoint_id, timestamp)
            existing = connection.execute(
                "SELECT job_hash FROM scan_jobs WHERE scan_id=?", (scan_id,)
            ).fetchone()
            if existing:
                # UNKNOWN placeholders are replaced by the authoritative cloud job.
                placeholder = connection.execute(
                    "SELECT scan_type FROM scan_jobs WHERE scan_id=?", (scan_id,)
                ).fetchone()[0]
                if placeholder != "UNKNOWN" and existing["job_hash"] != digest:
                    raise IdempotencyConflictError("scan_id was reused with different job content")
                if placeholder != "UNKNOWN":
                    return False
                connection.execute(
                    """
                    UPDATE scan_jobs SET endpoint_id=?,scan_type=?,policy_id=?,status=?,
                        authorization_json=?,initiator=?,target=?,requested_at=?,job_json=?,
                        job_hash=?,updated_at=? WHERE scan_id=?
                    """,
                    (
                        endpoint_id,
                        scan_type,
                        job.get("policy_id"),
                        status,
                        authorization,
                        job.get("initiator"),
                        job.get("target"),
                        timestamp,
                        serialized,
                        digest,
                        timestamp,
                        scan_id,
                    ),
                )
                return True
            connection.execute(
                """
                INSERT INTO scan_jobs(
                    scan_id,endpoint_id,scan_type,policy_id,status,authorization_json,
                    initiator,target,requested_at,job_json,job_hash,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    scan_id,
                    endpoint_id,
                    scan_type,
                    job.get("policy_id"),
                    status,
                    authorization,
                    job.get("initiator"),
                    job.get("target"),
                    timestamp,
                    serialized,
                    digest,
                    timestamp,
                ),
            )
        return True

    def update_scan_job(
        self,
        scan_id: str,
        status: str,
        *,
        started_at: str | None = None,
        completed_at: str | None = None,
        result_status: str | None = None,
        error: str | None = None,
    ) -> None:
        scan_id = clean_identifier(scan_id, "scan_id")
        status = clean_identifier(status, "status", max_length=64)
        timestamp = utc_now_iso()
        with self.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE scan_jobs SET status=?, started_at=COALESCE(?,started_at),
                    completed_at=COALESCE(?,completed_at), result_status=COALESCE(?,result_status),
                    error=?, updated_at=? WHERE scan_id=?
                """,
                (
                    status,
                    started_at,
                    completed_at,
                    result_status,
                    clean_error(error) if error else None,
                    timestamp,
                    scan_id,
                ),
            )
            if updated.rowcount != 1:
                raise StorageError(f"unknown scan_id: {scan_id}")

    def get_scan_job(self, scan_id: str) -> dict[str, Any] | None:
        scan_id = clean_identifier(scan_id, "scan_id")
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT * FROM scan_jobs WHERE scan_id=?", (scan_id,)
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["authorization"] = parse_json(result.pop("authorization_json"))
        result["job"] = parse_json(result.pop("job_json"))
        return result

    def terminal_scan_jobs(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Return bounded terminal jobs for idempotent status-outbox reconciliation."""

        if not 1 <= limit <= 10_000:
            raise ValueError("terminal job limit must be between 1 and 10,000")
        with self._lock:
            self._ensure_open()
            rows = self._connection.execute(
                """
                SELECT scan_id,status,result_status,job_json
                FROM scan_jobs AS jobs
                WHERE status IN ('COMPLETED','FAILED') AND result_status IS NOT NULL
                  AND NOT EXISTS (
                    SELECT 1 FROM scan_history AS history
                    WHERE history.scan_id=jobs.scan_id
                      AND history.event='TERMINAL_STATUS_QUEUED'
                  )
                ORDER BY updated_at,scan_id LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "scan_id": str(row["scan_id"]),
                "status": str(row["status"]),
                "result_status": str(row["result_status"]),
                "job": parse_json(row["job_json"]),
            }
            for row in rows
        ]

    def append_scan_history(
        self,
        scan_id: str,
        event: str,
        *,
        status: str | None = None,
        details: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        created_at: str | None = None,
    ) -> int:
        scan_id = clean_identifier(scan_id, "scan_id")
        event = clean_identifier(event, "event", max_length=128)
        if idempotency_key:
            idempotency_key = clean_identifier(idempotency_key, "idempotency_key")
        timestamp = created_at or utc_now_iso()
        serialized = canonical_json(details or {})
        with self.transaction() as connection:
            self._ensure_scan(connection, scan_id, None, timestamp)
            if idempotency_key:
                row = connection.execute(
                    "SELECT history_id,event,status,details_json FROM scan_history "
                    "WHERE idempotency_key=?",
                    (idempotency_key,),
                ).fetchone()
                if row:
                    if (row["event"], row["status"], row["details_json"]) != (
                        event,
                        status,
                        serialized,
                    ):
                        raise IdempotencyConflictError(
                            "history idempotency key was reused with different content"
                        )
                    return int(row["history_id"])
            cursor = connection.execute(
                """
                INSERT INTO scan_history(
                    scan_id,event,status,details_json,idempotency_key,created_at
                )
                VALUES(?,?,?,?,?,?)
                """,
                (scan_id, event, status, serialized, idempotency_key, timestamp),
            )
            return self._inserted_id(cursor)

    def save_findings(
        self,
        scan_id: str,
        endpoint_id: str | None,
        findings: Sequence[Mapping[str, Any]],
    ) -> int:
        scan_id = clean_identifier(scan_id, "scan_id")
        endpoint_id = clean_identifier(endpoint_id, "endpoint_id") if endpoint_id else None
        now = utc_now_iso()
        saved = 0
        with self.transaction() as connection:
            self._ensure_scan(connection, scan_id, endpoint_id, now)
            for finding in findings:
                finding_id = clean_identifier(finding.get("finding_id"), "finding_id")
                rule_id = clean_identifier(finding.get("rule_id"), "rule_id")
                severity = clean_identifier(
                    str(finding.get("severity", "INFO")).upper(), "severity", max_length=16
                )
                if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                    raise ValueError(f"unsupported finding severity: {severity}")
                status = clean_identifier(finding.get("status", "OPEN"), "status", max_length=64)
                serialized = canonical_json(finding)
                connection.execute(
                    """
                    INSERT INTO findings(
                        finding_id,scan_id,endpoint_id,rule_id,severity,status,detected_at,
                        payload_json,payload_hash,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(finding_id) DO UPDATE SET
                        scan_id=excluded.scan_id, endpoint_id=excluded.endpoint_id,
                        rule_id=excluded.rule_id, severity=excluded.severity,
                        status=excluded.status, detected_at=excluded.detected_at,
                        payload_json=excluded.payload_json, payload_hash=excluded.payload_hash,
                        updated_at=excluded.updated_at
                    """,
                    (
                        finding_id,
                        scan_id,
                        endpoint_id,
                        rule_id,
                        severity,
                        status,
                        str(finding.get("detected_at") or now),
                        serialized,
                        self._hash_text(serialized),
                        now,
                    ),
                )
                saved += 1
        return saved

    def get_finding_first_seen(self, finding_id: str) -> str | None:
        finding_id = clean_identifier(finding_id, "finding_id")
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT payload_json, detected_at FROM findings WHERE finding_id=?",
                (finding_id,),
            ).fetchone()
        if row is None:
            return None
        payload = parse_json(row["payload_json"])
        if isinstance(payload, Mapping):
            value = payload.get("first_seen_at") or payload.get("detected_at")
            if isinstance(value, str) and value:
                return value
        detected_at = row["detected_at"]
        return str(detected_at) if detected_at else None

    def save_collector_status(
        self,
        scan_id: str,
        collector: str,
        status: str,
        *,
        details: Mapping[str, Any] | None = None,
        tool_version: str | None = None,
        started_at: str | None = None,
        completed_at: str | None = None,
        duration_seconds: float | None = None,
    ) -> None:
        scan_id = clean_identifier(scan_id, "scan_id")
        collector = clean_identifier(collector, "collector", max_length=128)
        status = clean_identifier(status.upper(), "status", max_length=16)
        allowed = {"SUCCESS", "PARTIAL", "FAILED", "UNAVAILABLE", "TIMEOUT", "SKIPPED"}
        if status not in allowed:
            raise ValueError(f"unsupported collector status: {status}")
        if duration_seconds is not None and duration_seconds < 0:
            raise ValueError("duration_seconds cannot be negative")
        now = utc_now_iso()
        with self.transaction() as connection:
            self._ensure_scan(connection, scan_id, None, now)
            connection.execute(
                """
                INSERT INTO collector_status(
                    scan_id,collector,status,tool_version,started_at,completed_at,
                    duration_seconds,details_json
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(scan_id,collector) DO UPDATE SET
                    status=excluded.status, tool_version=excluded.tool_version,
                    started_at=excluded.started_at, completed_at=excluded.completed_at,
                    duration_seconds=excluded.duration_seconds, details_json=excluded.details_json
                """,
                (
                    scan_id,
                    collector,
                    status,
                    tool_version,
                    started_at,
                    completed_at,
                    duration_seconds,
                    canonical_json(details or {}),
                ),
            )
