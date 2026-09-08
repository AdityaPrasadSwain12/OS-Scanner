"""Content-addressed normalized results and differential inventory snapshots."""

from __future__ import annotations

import sqlite3
from collections.abc import Collection, Mapping
from typing import Any

from .errors import IdempotencyConflictError, StorageError
from .jobs import JobStorage
from .serialization import canonical_json, clean_identifier, parse_json, utc_now_iso
from .snapshots import SectionChange, SnapshotChange, compare_snapshots, normalize_snapshot


class ResultStorage(JobStorage):
    """Complete scan results, indexed projections, and version state."""

    @staticmethod
    def _deserialize_change(row: sqlite3.Row, endpoint_id: str, scan_id: str) -> SnapshotChange:
        diff = parse_json(row["diff_json"])
        changes = tuple(SectionChange(**item) for item in diff.get("changes", []))
        return SnapshotChange(
            snapshot_id=int(row["snapshot_id"]),
            endpoint_id=endpoint_id,
            scan_id=scan_id,
            snapshot_hash=str(row["payload_hash"]),
            previous_hash=row["previous_hash"],
            initial=bool(diff.get("initial")),
            changed=bool(row["changed"]),
            changes=changes,
        )

    def store_snapshot(
        self,
        endpoint_id: str,
        scan_id: str,
        snapshot: Mapping[str, Any],
        schema_version: str,
        policy_version: str | None = None,
        scanner_version: str | None = None,
        *,
        created_at: str | None = None,
    ) -> SnapshotChange:
        endpoint_id = clean_identifier(endpoint_id, "endpoint_id")
        scan_id = clean_identifier(scan_id, "scan_id")
        schema_version = clean_identifier(schema_version, "schema_version", max_length=64)
        normalized = normalize_snapshot(snapshot)
        serialized = canonical_json(normalized)
        digest = self._hash_text(serialized)
        now = created_at or utc_now_iso()
        with self.transaction() as connection:
            self._ensure_endpoint(connection, endpoint_id, now)
            self._ensure_scan(connection, scan_id, endpoint_id, now)
            existing = connection.execute(
                """
                SELECT s.*, p.payload_hash AS previous_hash
                FROM inventory_snapshots s
                LEFT JOIN inventory_snapshots p ON p.snapshot_id=s.previous_snapshot_id
                WHERE s.scan_id=?
                """,
                (scan_id,),
            ).fetchone()
            if existing:
                if existing["endpoint_id"] != endpoint_id or existing["payload_hash"] != digest:
                    raise IdempotencyConflictError(
                        "scan_id was reused for a different inventory snapshot"
                    )
                return self._deserialize_change(existing, endpoint_id, scan_id)
            previous = connection.execute(
                """
                SELECT s.snapshot_id,s.payload_hash,p.payload_json
                FROM inventory_snapshots s
                JOIN inventory_payloads p ON p.payload_hash=s.payload_hash
                WHERE s.endpoint_id=? ORDER BY s.snapshot_id DESC LIMIT 1
                """,
                (endpoint_id,),
            ).fetchone()
            previous_payload = parse_json(previous["payload_json"]) if previous else None
            changes = compare_snapshots(previous_payload, normalized)
            initial = previous is None
            changed = initial or bool(changes)
            diff_json = canonical_json(
                {
                    "initial": initial,
                    "changed": changed,
                    "changes": [change.as_dict() for change in changes],
                }
            )
            connection.execute(
                """
                INSERT INTO inventory_payloads(payload_hash,payload_json,size_bytes,created_at)
                VALUES(?,?,?,?) ON CONFLICT(payload_hash) DO NOTHING
                """,
                (digest, serialized, len(serialized.encode("utf-8")), now),
            )
            cursor = connection.execute(
                """
                INSERT INTO inventory_snapshots(
                    endpoint_id,scan_id,payload_hash,previous_snapshot_id,schema_version,
                    policy_version,scanner_version,changed,diff_json,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    endpoint_id,
                    scan_id,
                    digest,
                    int(previous["snapshot_id"]) if previous else None,
                    schema_version,
                    policy_version,
                    scanner_version,
                    int(changed),
                    diff_json,
                    now,
                ),
            )
            return SnapshotChange(
                snapshot_id=self._inserted_id(cursor),
                endpoint_id=endpoint_id,
                scan_id=scan_id,
                snapshot_hash=digest,
                previous_hash=str(previous["payload_hash"]) if previous else None,
                initial=initial,
                changed=changed,
                changes=changes,
            )

    def snapshot_upload_payload(self, snapshot_id: int) -> dict[str, Any]:
        """Return full, delta, or unchanged sync data for a stored snapshot."""

        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                """
                SELECT s.*, p.payload_json, prev.payload_hash AS previous_hash
                FROM inventory_snapshots s
                JOIN inventory_payloads p ON p.payload_hash=s.payload_hash
                LEFT JOIN inventory_snapshots prev ON prev.snapshot_id=s.previous_snapshot_id
                WHERE s.snapshot_id=?
                """,
                (snapshot_id,),
            ).fetchone()
        if row is None:
            raise StorageError(f"unknown snapshot_id: {snapshot_id}")
        snapshot = parse_json(row["payload_json"])
        diff = parse_json(row["diff_json"])
        envelope: dict[str, Any] = {
            "endpoint_id": row["endpoint_id"],
            "scan_id": row["scan_id"],
            "schema_version": row["schema_version"],
            "policy_version": row["policy_version"],
            "scanner_version": row["scanner_version"],
            "snapshot_hash": row["payload_hash"],
            "previous_hash": row["previous_hash"],
        }
        if diff["initial"]:
            return {**envelope, "mode": "full", "snapshot": snapshot}
        if not diff["changed"]:
            return {**envelope, "mode": "unchanged"}
        changed_sections = [item["section"] for item in diff["changes"]]
        return {
            **envelope,
            "mode": "delta",
            "changes": diff["changes"],
            "sections": {
                section: snapshot[section] for section in changed_sections if section in snapshot
            },
            "removed_sections": [
                section for section in changed_sections if section not in snapshot
            ],
        }

    def get_latest_snapshot(self, endpoint_id: str) -> dict[str, Any] | None:
        """Return the most recent normalized snapshot and its capture metadata."""

        endpoint_id = clean_identifier(endpoint_id, "endpoint_id")
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                """
                SELECT s.snapshot_id,s.scan_id,s.created_at,s.payload_hash,p.payload_json
                FROM inventory_snapshots s
                JOIN inventory_payloads p ON p.payload_hash=s.payload_hash
                WHERE s.endpoint_id=? ORDER BY s.snapshot_id DESC LIMIT 1
                """,
                (endpoint_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "snapshot_id": int(row["snapshot_id"]),
            "scan_id": str(row["scan_id"]),
            "created_at": str(row["created_at"]),
            "payload_hash": str(row["payload_hash"]),
            "snapshot": parse_json(row["payload_json"]),
        }

    def get_snapshot_change_for_scan(self, scan_id: str) -> SnapshotChange | None:
        """Return the persisted differential state used to rebuild an outbox item."""

        scan_id = clean_identifier(scan_id, "scan_id")
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                """
                SELECT s.*, p.payload_hash AS previous_hash
                FROM inventory_snapshots s
                LEFT JOIN inventory_snapshots p ON p.snapshot_id=s.previous_snapshot_id
                WHERE s.scan_id=?
                """,
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        return self._deserialize_change(row, str(row["endpoint_id"]), scan_id)

    def store_normalized_result(
        self,
        scan_id: str,
        result: Mapping[str, Any],
        *,
        endpoint_id: str | None = None,
        result_type: str | None = None,
        target: str | None = None,
        created_at: str | None = None,
    ) -> int:
        """Persist a complete normalized result, including attack-surface scans."""

        scan_id = clean_identifier(scan_id, "scan_id")
        endpoint_id = clean_identifier(endpoint_id, "endpoint_id") if endpoint_id else None
        normalized_type = clean_identifier(
            result_type or str(result.get("scan_type", "ENDPOINT")),
            "result_type",
            max_length=64,
        )
        schema_version = clean_identifier(
            str(result.get("schema_version", "1.0")), "schema_version", max_length=64
        )
        status = clean_identifier(str(result.get("status", "SUCCESS")), "status", max_length=64)
        serialized = canonical_json(result)
        digest = self._hash_text(serialized)
        timestamp = created_at or utc_now_iso()
        with self.transaction() as connection:
            self._ensure_scan(connection, scan_id, endpoint_id, timestamp)
            existing = connection.execute(
                "SELECT result_id,payload_hash,endpoint_id,result_type "
                "FROM scan_results WHERE scan_id=?",
                (scan_id,),
            ).fetchone()
            if existing:
                if (
                    existing["payload_hash"],
                    existing["endpoint_id"],
                    existing["result_type"],
                ) != (digest, endpoint_id, normalized_type):
                    raise IdempotencyConflictError(
                        "scan_id was reused for a different normalized result"
                    )
                return int(existing["result_id"])
            connection.execute(
                """
                INSERT INTO result_payloads(payload_hash,payload_json,size_bytes,created_at)
                VALUES(?,?,?,?) ON CONFLICT(payload_hash) DO NOTHING
                """,
                (digest, serialized, len(serialized.encode("utf-8")), timestamp),
            )
            cursor = connection.execute(
                """
                INSERT INTO scan_results(
                    scan_id,endpoint_id,result_type,target,schema_version,scanner_version,
                    policy_version,status,payload_hash,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    scan_id,
                    endpoint_id,
                    normalized_type,
                    target or result.get("target"),
                    schema_version,
                    result.get("scanner_version"),
                    result.get("policy_version"),
                    status,
                    digest,
                    timestamp,
                    timestamp,
                ),
            )
            return self._inserted_id(cursor)

    def get_normalized_result(self, scan_id: str) -> dict[str, Any] | None:
        scan_id = clean_identifier(scan_id, "scan_id")
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                """
                SELECT r.*,p.payload_json FROM scan_results r
                JOIN result_payloads p ON p.payload_hash=r.payload_hash WHERE r.scan_id=?
                """,
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["payload"] = parse_json(result.pop("payload_json"))
        return result

    def prune_completed_scan_records(
        self,
        *,
        older_than: str,
        max_completed_scans: int,
        protected_scan_ids: Collection[str] = (),
        limit: int = 1_000,
    ) -> int:
        """Remove safely delivered terminal scan payloads under a bounded policy.

        Append-only audit events and endpoint identities are intentionally kept.
        The latest endpoint snapshot, legal holds, and any scan with a pending,
        in-flight, or dead outbox item are never selected.
        """

        if not 1 <= max_completed_scans <= 1_000_000:
            raise ValueError("max_completed_scans must be between 1 and 1,000,000")
        if not 1 <= limit <= 100_000:
            raise ValueError("limit must be between 1 and 100,000")
        protected = {
            clean_identifier(scan_id, "protected_scan_id") for scan_id in protected_scan_ids
        }
        candidate_limit = min(100_000, max(limit * 4, limit))
        with self.transaction() as connection:
            aged = connection.execute(
                """
                SELECT scan_id FROM scan_jobs
                WHERE status IN ('COMPLETED','FAILED')
                  AND COALESCE(completed_at,updated_at)<?
                ORDER BY COALESCE(completed_at,updated_at),scan_id LIMIT ?
                """,
                (older_than, candidate_limit),
            ).fetchall()
            overflow = connection.execute(
                """
                SELECT scan_id FROM scan_jobs
                WHERE status IN ('COMPLETED','FAILED')
                ORDER BY COALESCE(completed_at,updated_at) DESC,scan_id DESC
                LIMIT ? OFFSET ?
                """,
                (candidate_limit, max_completed_scans),
            ).fetchall()
            candidates = list(
                dict.fromkeys(
                    str(row["scan_id"]) for row in (*aged, *overflow)
                )
            )
            if not candidates:
                return 0
            latest = {
                str(row["scan_id"])
                for row in connection.execute(
                    """
                    SELECT snapshots.scan_id
                    FROM inventory_snapshots AS snapshots
                    JOIN (
                        SELECT endpoint_id,MAX(snapshot_id) AS snapshot_id
                        FROM inventory_snapshots GROUP BY endpoint_id
                    ) AS latest
                    ON latest.snapshot_id=snapshots.snapshot_id
                    """
                ).fetchall()
            }
            blocked: set[str] = set()
            for offset in range(0, len(candidates), 500):
                chunk = candidates[offset : offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                rows = connection.execute(
                    f"""
                    SELECT DISTINCT json_extract(queued.metadata_json,'$.scan_id') AS scan_id
                    FROM upload_queue AS queued
                    LEFT JOIN upload_queue AS replacement
                        ON replacement.upload_id=queued.superseded_by_upload_id
                    WHERE (
                        queued.status IN ('PENDING','IN_FLIGHT')
                        OR (queued.status='DEAD' AND replacement.status!='SUCCEEDED')
                        OR (queued.status='DEAD' AND replacement.status IS NULL)
                    )
                      AND json_extract(queued.metadata_json,'$.scan_id') IN ({placeholders})
                    """,  # noqa: S608 - placeholders are generated, never user supplied
                    chunk,
                ).fetchall()
                blocked.update(str(row["scan_id"]) for row in rows if row["scan_id"])
            selected = [
                scan_id
                for scan_id in candidates
                if scan_id not in protected
                and scan_id not in latest
                and scan_id not in blocked
            ][:limit]
            if not selected:
                return 0
            for offset in range(0, len(selected), 500):
                chunk = selected[offset : offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                # If the retained child of a removed snapshot is ever replayed,
                # it must advertise a full baseline rather than a broken delta.
                connection.execute(
                    f"""
                    UPDATE inventory_snapshots
                    SET previous_snapshot_id=NULL,
                        changed=1,
                        diff_json='{{"changed":true,"changes":[],"initial":true}}'
                    WHERE previous_snapshot_id IN (
                        SELECT snapshot_id FROM inventory_snapshots
                        WHERE scan_id IN ({placeholders})
                    )
                    """,  # noqa: S608 - placeholders are generated, never user supplied
                    chunk,
                )
                connection.executemany(
                    "DELETE FROM scan_jobs WHERE scan_id=?",
                    ((scan_id,) for scan_id in chunk),
                )
            connection.execute(
                """
                DELETE FROM inventory_payloads
                WHERE NOT EXISTS (
                    SELECT 1 FROM inventory_snapshots
                    WHERE inventory_snapshots.payload_hash=inventory_payloads.payload_hash
                )
                """
            )
            connection.execute(
                """
                DELETE FROM result_payloads
                WHERE NOT EXISTS (
                    SELECT 1 FROM scan_results
                    WHERE scan_results.payload_hash=result_payloads.payload_hash
                )
                """
            )
            return len(selected)

    def save_scan_result(
        self,
        scan_id: str,
        endpoint_id: str | None,
        result: Mapping[str, Any],
        *,
        target: str | None = None,
    ) -> SnapshotChange | None:
        """Atomically persist the normalized result and its indexed projections."""

        inventory = result.get("inventory")
        inventory_fields = {
            "endpoint",
            "os",
            "hardware",
            "software",
            "processes",
            "services",
            "users",
            "groups",
            "network",
            "network_interfaces",
            "listening_ports",
            "security",
            "updates",
            "browser_extensions",
            "certificates",
            "persistence",
            "compliance",
            "vulnerabilities",
        }
        if inventory is None:
            inventory = {key: value for key, value in result.items() if key in inventory_fields}
        schema_version = str(result.get("schema_version", "1.0"))
        metadata = result.get("metadata", {})
        metadata_target = None
        observed_sections: set[str] | None = None
        if isinstance(metadata, Mapping):
            metadata_target = (
                metadata.get("authorized_target")
                or metadata.get("target")
                or metadata.get("domain")
            )
            raw_observed = metadata.get("observed_inventory_sections")
            if isinstance(raw_observed, list) and all(
                isinstance(item, str) for item in raw_observed
            ):
                observed_sections = set(raw_observed)
        if isinstance(inventory, Mapping) and observed_sections is not None:
            current_inventory = {
                key: value
                for key, value in inventory.items()
                if key in observed_sections or key == "endpoint"
            }
            if endpoint_id:
                latest = self.get_latest_snapshot(endpoint_id)
                previous = latest.get("snapshot") if latest is not None else None
                if isinstance(previous, Mapping):
                    for key, value in previous.items():
                        if key not in observed_sections and key not in {
                            "collection_completeness",
                        }:
                            current_inventory.setdefault(key, value)
            current_inventory["collection_completeness"] = {
                "observed_sections": sorted(observed_sections),
                "unobserved_sections": sorted(
                    key
                    for key in inventory_fields
                    if key != "endpoint" and key not in observed_sections
                ),
            }
            inventory = current_inventory
        stored_target = target or result.get("target") or metadata_target
        with self.transaction():
            self.store_normalized_result(
                scan_id,
                result,
                endpoint_id=endpoint_id,
                result_type=str(result.get("scan_type", "ENDPOINT")),
                target=str(stored_target) if stored_target else None,
            )
            change: SnapshotChange | None = None
            if endpoint_id:
                if not isinstance(inventory, Mapping):
                    raise TypeError("result.inventory must be a mapping")
                change = self.store_snapshot(
                    endpoint_id,
                    scan_id,
                    inventory,
                    schema_version,
                    str(result["policy_version"]) if result.get("policy_version") else None,
                    str(result["scanner_version"]) if result.get("scanner_version") else None,
                )
            findings = result.get("findings", [])
            if findings:
                self.save_findings(scan_id, endpoint_id, findings)
            collectors = result.get("collectors", {})
            if isinstance(collectors, Mapping):
                for name, collector_result in collectors.items():
                    if isinstance(collector_result, Mapping):
                        self.save_collector_status(
                            scan_id,
                            str(name),
                            str(collector_result.get("status", "FAILED")),
                            details=collector_result,
                            tool_version=(
                                str(collector_result["tool_version"])
                                if collector_result.get("tool_version")
                                else None
                            ),
                            duration_seconds=(
                                float(collector_result["duration_seconds"])
                                if collector_result.get("duration_seconds") is not None
                                else None
                            ),
                        )
            self.append_scan_history(
                scan_id,
                "RESULT_STORED",
                status=str(result.get("status", "SUCCESS")),
                details={
                    "snapshot_id": change.snapshot_id if change else None,
                    "snapshot_hash": change.snapshot_hash if change else None,
                    "result_type": result.get("scan_type", "ENDPOINT"),
                },
                idempotency_key=f"result-stored:{scan_id}",
            )
        return change

    def set_policy_version(
        self,
        policy_id: str,
        version: str,
        checksum: str,
        *,
        metadata: Mapping[str, Any] | None = None,
        active: bool = True,
    ) -> None:
        policy_id = clean_identifier(policy_id, "policy_id")
        version = clean_identifier(version, "version", max_length=64)
        checksum = clean_identifier(checksum, "checksum", max_length=128)
        now = utc_now_iso()
        with self.transaction() as connection:
            if active:
                connection.execute("UPDATE policy_versions SET active=0 WHERE active=1")
            connection.execute(
                """
                INSERT INTO policy_versions(
                    policy_id,version,checksum,metadata_json,activated_at,active
                )
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(policy_id,version) DO UPDATE SET
                    checksum=excluded.checksum, metadata_json=excluded.metadata_json,
                    activated_at=excluded.activated_at, active=excluded.active
                """,
                (policy_id, version, checksum, canonical_json(metadata or {}), now, int(active)),
            )

    def cache_policy_document(
        self,
        policy_id: str,
        version: str,
        checksum: str,
        document: Mapping[str, Any],
        *,
        source: str,
        active: bool = False,
        assigned: bool = True,
    ) -> None:
        """Persist an immutable validated policy document for offline execution."""

        policy_id = clean_identifier(policy_id, "policy_id")
        version = clean_identifier(version, "version", max_length=64)
        checksum = clean_identifier(checksum, "checksum", max_length=128)
        if source not in {"bundled", "local", "cloud"}:
            raise ValueError("unsupported policy document source")
        serialized = canonical_json(document)
        if self._hash_text(serialized) != checksum:
            raise ValueError("policy document checksum does not match its canonical payload")
        now = utc_now_iso()
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT checksum,document_json FROM policy_documents "
                "WHERE policy_id=? AND version=?",
                (policy_id, version),
            ).fetchone()
            if existing is not None and (
                existing["checksum"] != checksum or existing["document_json"] != serialized
            ):
                raise IdempotencyConflictError(
                    "policy ID/version is already cached with different content"
                )
            if active:
                connection.execute("UPDATE policy_documents SET active=0 WHERE active=1")
            connection.execute(
                """
                INSERT INTO policy_documents(
                    policy_id,version,checksum,document_json,source,
                    received_at,activated_at,active,assigned
                ) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(policy_id,version) DO UPDATE SET
                    source=excluded.source,
                    activated_at=CASE
                        WHEN excluded.active=1 THEN excluded.activated_at
                        ELSE policy_documents.activated_at
                    END,
                    active=CASE
                        WHEN excluded.active=1 THEN 1
                        ELSE policy_documents.active
                    END,
                    assigned=excluded.assigned
                """,
                (
                    policy_id,
                    version,
                    checksum,
                    serialized,
                    source,
                    now,
                    now if active else None,
                    int(active),
                    int(assigned),
                ),
            )

    def revoke_cloud_policy_assignments(self) -> None:
        with self.transaction() as connection:
            connection.execute(
                "UPDATE policy_documents SET assigned=0 "
                "WHERE source='cloud' AND assigned=1"
            )

    def migrate_policy_document_canonicalization(
        self,
        policy_id: str,
        version: str,
        expected_checksum: str,
        checksum: str,
        document: Mapping[str, Any],
    ) -> None:
        """Replace only a checksum-equivalent legacy serialization.

        The orchestrator calls this after validating the old stored JSON hash,
        loading the policy through the hardened loader, and proving that the
        deterministic document represents that same validated policy.
        """

        policy_id = clean_identifier(policy_id, "policy_id")
        version = clean_identifier(version, "version", max_length=64)
        expected_checksum = clean_identifier(
            expected_checksum, "expected_checksum", max_length=128
        )
        checksum = clean_identifier(checksum, "checksum", max_length=128)
        serialized = canonical_json(document)
        if self._hash_text(serialized) != checksum:
            raise ValueError("policy document checksum does not match its canonical payload")
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT checksum,document_json FROM policy_documents "
                "WHERE policy_id=? AND version=?",
                (policy_id, version),
            ).fetchone()
            if existing is None:
                raise ValueError("cannot migrate a policy document that is not cached")
            if (
                existing["checksum"] != expected_checksum
                or self._hash_text(str(existing["document_json"])) != expected_checksum
            ):
                raise IdempotencyConflictError(
                    "cached policy changed during canonicalization migration"
                )
            connection.execute(
                "UPDATE policy_documents SET checksum=?,document_json=? "
                "WHERE policy_id=? AND version=? AND checksum=?",
                (checksum, serialized, policy_id, version, expected_checksum),
            )

    def activate_policy_document(self, policy_id: str, version: str) -> None:
        policy_id = clean_identifier(policy_id, "policy_id")
        version = clean_identifier(version, "version", max_length=64)
        now = utc_now_iso()
        with self.transaction() as connection:
            exists = connection.execute(
                "SELECT 1 FROM policy_documents WHERE policy_id=? AND version=?",
                (policy_id, version),
            ).fetchone()
            if exists is None:
                raise ValueError("cannot activate a policy document that is not cached")
            connection.execute("UPDATE policy_documents SET active=0 WHERE active=1")
            connection.execute(
                "UPDATE policy_documents SET active=1,activated_at=? "
                "WHERE policy_id=? AND version=?",
                (now, policy_id, version),
            )

    def list_policy_documents(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 10_000:
            raise ValueError("policy document limit must be between 1 and 10000")
        with self._lock:
            self._ensure_open()
            rows = self._connection.execute(
                """
                SELECT policy_id,version,checksum,document_json,source,
                       received_at,activated_at,active,assigned
                FROM policy_documents
                ORDER BY active DESC, received_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        documents: list[dict[str, Any]] = []
        for row in rows:
            document = parse_json(row["document_json"])
            if not isinstance(document, Mapping):
                raise StorageError("cached policy document is not an object")
            documents.append(
                {
                    "policy_id": str(row["policy_id"]),
                    "version": str(row["version"]),
                    "checksum": str(row["checksum"]),
                    "document": dict(document),
                    "source": str(row["source"]),
                    "received_at": str(row["received_at"]),
                    "activated_at": row["activated_at"],
                    "active": bool(row["active"]),
                    "assigned": bool(row["assigned"]),
                }
            )
        return documents

    def get_active_policy_document(self) -> dict[str, Any] | None:
        documents = self.list_policy_documents(limit=100)
        return next((document for document in documents if document["active"]), None)

    def set_schema_version(
        self,
        schema_name: str,
        version: str,
        *,
        metadata: Mapping[str, Any] | None = None,
        active: bool = True,
    ) -> None:
        schema_name = clean_identifier(schema_name, "schema_name")
        version = clean_identifier(version, "version", max_length=64)
        now = utc_now_iso()
        with self.transaction() as connection:
            if active:
                connection.execute(
                    "UPDATE schema_versions SET active=0 WHERE schema_name=?", (schema_name,)
                )
            connection.execute(
                """
                INSERT INTO schema_versions(schema_name,version,metadata_json,recorded_at,active)
                VALUES(?,?,?,?,?)
                ON CONFLICT(schema_name,version) DO UPDATE SET
                    metadata_json=excluded.metadata_json, recorded_at=excluded.recorded_at,
                    active=excluded.active
                """,
                (schema_name, version, canonical_json(metadata or {}), now, int(active)),
            )
