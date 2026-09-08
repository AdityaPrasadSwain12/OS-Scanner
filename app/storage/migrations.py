"""Forward-only, checksum-verified SQLite migrations."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass

from .errors import MigrationError
from .serialization import utc_now_iso


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


MIGRATIONS = (
    Migration(
        1,
        "core_inventory_and_jobs",
        """
        CREATE TABLE endpoints (
            endpoint_id TEXT PRIMARY KEY,
            state_json TEXT NOT NULL,
            state_hash TEXT NOT NULL,
            enrolled_at TEXT,
            last_seen_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE scan_jobs (
            scan_id TEXT PRIMARY KEY,
            endpoint_id TEXT REFERENCES endpoints(endpoint_id),
            scan_type TEXT NOT NULL,
            policy_id TEXT,
            status TEXT NOT NULL,
            authorization_json TEXT NOT NULL,
            initiator TEXT,
            target TEXT,
            requested_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            result_status TEXT,
            error TEXT,
            job_json TEXT NOT NULL,
            job_hash TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE scan_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL REFERENCES scan_jobs(scan_id) ON DELETE CASCADE,
            event TEXT NOT NULL,
            status TEXT,
            details_json TEXT NOT NULL,
            idempotency_key TEXT UNIQUE,
            created_at TEXT NOT NULL
        );
        CREATE TABLE findings (
            finding_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scan_jobs(scan_id) ON DELETE CASCADE,
            endpoint_id TEXT REFERENCES endpoints(endpoint_id),
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
            status TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE collector_status (
            scan_id TEXT NOT NULL REFERENCES scan_jobs(scan_id) ON DELETE CASCADE,
            collector TEXT NOT NULL,
            status TEXT NOT NULL CHECK (
                status IN ('SUCCESS','PARTIAL','FAILED','UNAVAILABLE','TIMEOUT','SKIPPED')
            ),
            tool_version TEXT,
            started_at TEXT,
            completed_at TEXT,
            duration_seconds REAL,
            details_json TEXT NOT NULL,
            PRIMARY KEY (scan_id, collector)
        );
        CREATE TABLE inventory_payloads (
            payload_hash TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE inventory_snapshots (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id),
            scan_id TEXT NOT NULL UNIQUE REFERENCES scan_jobs(scan_id) ON DELETE CASCADE,
            payload_hash TEXT NOT NULL REFERENCES inventory_payloads(payload_hash),
            previous_snapshot_id INTEGER REFERENCES inventory_snapshots(snapshot_id),
            schema_version TEXT NOT NULL,
            policy_version TEXT,
            scanner_version TEXT,
            changed INTEGER NOT NULL CHECK (changed IN (0,1)),
            diff_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE policy_versions (
            policy_id TEXT NOT NULL,
            version TEXT NOT NULL,
            checksum TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            activated_at TEXT NOT NULL,
            active INTEGER NOT NULL CHECK (active IN (0,1)),
            PRIMARY KEY (policy_id, version)
        );
        CREATE TABLE schema_versions (
            schema_name TEXT NOT NULL,
            version TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            active INTEGER NOT NULL CHECK (active IN (0,1)),
            PRIMARY KEY (schema_name, version)
        );
        """,
    ),
    Migration(
        2,
        "durable_upload_queue_and_audit",
        """
        CREATE TABLE upload_queue (
            upload_id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            method TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            payload BLOB NOT NULL,
            payload_hash TEXT NOT NULL,
            content_type TEXT NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE,
            request_id TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('PENDING','IN_FLIGHT','SUCCEEDED','DEAD')),
            attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
            max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
            next_attempt_at REAL NOT NULL,
            leased_until REAL,
            lease_token TEXT,
            last_error TEXT,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            delivered_at TEXT
        );
        CREATE TABLE audit_log (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            event_type TEXT NOT NULL,
            actor TEXT,
            resource_type TEXT,
            resource_id TEXT,
            scan_id TEXT,
            endpoint_id TEXT,
            authorization_scope_id TEXT,
            outcome TEXT NOT NULL,
            details_json TEXT NOT NULL,
            previous_hash TEXT,
            event_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );
        """,
    ),
    Migration(
        3,
        "query_indexes",
        """
        CREATE INDEX idx_scan_jobs_endpoint_requested ON scan_jobs(endpoint_id, requested_at DESC);
        CREATE INDEX idx_scan_history_scan_created ON scan_history(scan_id, created_at);
        CREATE INDEX idx_findings_scan_severity ON findings(scan_id, severity);
        CREATE INDEX idx_snapshots_endpoint_created
            ON inventory_snapshots(endpoint_id, snapshot_id DESC);
        CREATE INDEX idx_upload_ready ON upload_queue(status, next_attempt_at, upload_id);
        CREATE INDEX idx_upload_lease ON upload_queue(status, leased_until);
        CREATE INDEX idx_audit_scan_created ON audit_log(scan_id, created_at);
        CREATE INDEX idx_audit_endpoint_created ON audit_log(endpoint_id, created_at);
        """,
    ),
    Migration(
        4,
        "generic_normalized_scan_results",
        """
        CREATE TABLE result_payloads (
            payload_hash TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE scan_results (
            result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL UNIQUE REFERENCES scan_jobs(scan_id) ON DELETE CASCADE,
            endpoint_id TEXT REFERENCES endpoints(endpoint_id),
            result_type TEXT NOT NULL,
            target TEXT,
            schema_version TEXT NOT NULL,
            scanner_version TEXT,
            policy_version TEXT,
            status TEXT NOT NULL,
            payload_hash TEXT NOT NULL REFERENCES result_payloads(payload_hash),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX idx_scan_results_endpoint_created ON scan_results(endpoint_id, result_id DESC);
        CREATE INDEX idx_scan_results_type_created ON scan_results(result_type, result_id DESC);
        """,
    ),
    Migration(
        5,
        "durable_policy_documents",
        """
        CREATE TABLE policy_documents (
            policy_id TEXT NOT NULL,
            version TEXT NOT NULL,
            checksum TEXT NOT NULL,
            document_json TEXT NOT NULL,
            source TEXT NOT NULL CHECK (source IN ('bundled','local','cloud')),
            received_at TEXT NOT NULL,
            activated_at TEXT,
            active INTEGER NOT NULL CHECK (active IN (0,1)),
            PRIMARY KEY (policy_id, version)
        );
        CREATE UNIQUE INDEX idx_policy_documents_one_active
            ON policy_documents(active) WHERE active=1;
        CREATE INDEX idx_policy_documents_received
            ON policy_documents(received_at DESC);
        """,
    ),
    Migration(
        6,
        "single_active_policy_version",
        """
        UPDATE policy_versions SET active=0
        WHERE active=1 AND rowid NOT IN (
            SELECT rowid FROM policy_versions
            WHERE active=1 ORDER BY activated_at DESC, rowid DESC LIMIT 1
        );
        CREATE UNIQUE INDEX idx_policy_versions_one_active
            ON policy_versions(active) WHERE active=1;
        """,
    ),
    Migration(
        7,
        "policy_assignment_membership",
        """
        ALTER TABLE policy_documents
            ADD COLUMN assigned INTEGER NOT NULL DEFAULT 1 CHECK (assigned IN (0,1));
        CREATE INDEX idx_policy_documents_assignment
            ON policy_documents(source,assigned);
        """,
    ),
    Migration(
        8,
        "causal_upload_delivery",
        """
        ALTER TABLE upload_queue ADD COLUMN causal_group TEXT;
        ALTER TABLE upload_queue ADD COLUMN predecessor_upload_id INTEGER
            REFERENCES upload_queue(upload_id) ON DELETE SET NULL;
        ALTER TABLE upload_queue ADD COLUMN superseded_by_upload_id INTEGER
            REFERENCES upload_queue(upload_id) ON DELETE SET NULL;
        ALTER TABLE upload_queue ADD COLUMN resync_for_upload_id INTEGER
            REFERENCES upload_queue(upload_id) ON DELETE SET NULL;
        CREATE INDEX idx_upload_causal_group
            ON upload_queue(causal_group,upload_id);
        CREATE INDEX idx_upload_predecessor
            ON upload_queue(predecessor_upload_id);
        CREATE UNIQUE INDEX idx_upload_resync_once
            ON upload_queue(resync_for_upload_id)
            WHERE resync_for_upload_id IS NOT NULL;
        """,
    ),
)


def _statements(script: str) -> list[str]:
    # Migration SQL is repository-owned and intentionally contains no triggers.
    # complete_statement handles quoted values more safely than a raw split.
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines():
        buffer += f"{line}\n"
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                statements.append(statement)
            buffer = ""
    if buffer.strip():
        raise MigrationError("incomplete SQL in bundled migration")
    return statements


def apply_migrations(connection: sqlite3.Connection) -> None:
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        applied = {
            int(row["version"]): row
            for row in connection.execute(
                "SELECT version, name, checksum FROM schema_migrations"
            ).fetchall()
        }
        known_versions = {migration.version for migration in MIGRATIONS}
        unknown = applied.keys() - known_versions
        if unknown:
            raise MigrationError(f"database schema is newer than this scanner: {sorted(unknown)}")
        for migration in MIGRATIONS:
            existing = applied.get(migration.version)
            if existing:
                if existing["name"] != migration.name or existing["checksum"] != migration.checksum:
                    raise MigrationError(f"migration {migration.version} checksum/name mismatch")
                continue
            connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in _statements(migration.sql):
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_migrations(version,name,checksum,applied_at) "
                    "VALUES(?,?,?,?)",
                    (migration.version, migration.name, migration.checksum, utc_now_iso()),
                )
                connection.execute(f"PRAGMA user_version = {migration.version}")
            except Exception:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")
    except MigrationError:
        raise
    except sqlite3.DatabaseError as exc:
        raise MigrationError(f"failed to migrate local database: {exc}") from exc
