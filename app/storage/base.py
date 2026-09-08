"""SQLite connection lifecycle, transactions, and common persistence helpers."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Self
from uuid import uuid4

from .errors import DatabaseIntegrityError, StorageClosedError, StorageError
from .migrations import apply_migrations
from .serialization import canonical_json


@dataclass(frozen=True, slots=True)
class StorageConfig:
    path: str | os.PathLike[str]
    timeout_seconds: float = 10.0
    busy_timeout_ms: int = 10_000
    integrity_check_on_open: bool = True
    synchronous: str = "FULL"

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not 1 <= self.busy_timeout_ms <= 300_000:
            raise ValueError("busy_timeout_ms must be between 1 and 300000")
        if self.synchronous not in {"FULL", "NORMAL"}:
            raise ValueError("synchronous must be FULL or NORMAL")


class StorageBase:
    """Durable scanner repository.

    A single serialized connection is intentional: scan writes are modest,
    transactions remain easy to reason about, and callers can safely share the
    object between worker threads. SQLite's WAL still permits other processes to
    read concurrently.
    """

    def __init__(self, config: StorageConfig | str | os.PathLike[str]) -> None:
        self.config = config if isinstance(config, StorageConfig) else StorageConfig(config)
        self._lock = threading.RLock()
        self._local = threading.local()
        self._closed = False
        path_text = os.fspath(self.config.path)
        if path_text != ":memory:":
            Path(path_text).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        try:
            self._connection = sqlite3.connect(
                path_text,
                timeout=self.config.timeout_seconds,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._configure_connection()
            with self._lock:
                apply_migrations(self._connection)
            if self.config.integrity_check_on_open:
                self.check_integrity(quick=True)
        except (StorageError, ValueError):
            self._close_after_init_failure()
            raise
        except sqlite3.DatabaseError as exc:
            self._close_after_init_failure()
            raise DatabaseIntegrityError(f"unable to open local database: {exc}") from exc

    def _close_after_init_failure(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            with suppress(sqlite3.Error):
                connection.close()
        self._closed = True

    def _configure_connection(self) -> None:
        connection = self._connection
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self.config.busy_timeout_ms}")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(f"PRAGMA synchronous = {self.config.synchronous}")
        connection.execute("PRAGMA wal_autocheckpoint = 1000")
        connection.execute("PRAGMA temp_store = MEMORY")
        with suppress(sqlite3.OperationalError):  # pragma was added after SQLite 3.30
            connection.execute("PRAGMA trusted_schema = OFF")

    def _ensure_open(self) -> None:
        if self._closed:
            raise StorageClosedError("local database is closed")

    @contextmanager
    def transaction(self, mode: str = "IMMEDIATE") -> Iterator[sqlite3.Connection]:
        """Open an atomic transaction; nested calls use SQLite savepoints."""

        if mode not in {"DEFERRED", "IMMEDIATE", "EXCLUSIVE"}:
            raise ValueError("unsupported SQLite transaction mode")
        with self._lock:
            self._ensure_open()
            depth = int(getattr(self._local, "transaction_depth", 0))
            savepoint = f"scanner_sp_{depth}_{uuid4().hex}"
            try:
                if depth == 0:
                    self._connection.execute(f"BEGIN {mode}")
                else:
                    self._connection.execute(f"SAVEPOINT {savepoint}")
                self._local.transaction_depth = depth + 1
                yield self._connection
            except Exception:
                try:
                    if depth == 0:
                        self._connection.execute("ROLLBACK")
                    else:
                        self._connection.execute(f"ROLLBACK TO {savepoint}")
                        self._connection.execute(f"RELEASE {savepoint}")
                except sqlite3.Error:
                    pass
                raise
            else:
                if depth == 0:
                    self._connection.execute("COMMIT")
                else:
                    self._connection.execute(f"RELEASE {savepoint}")
            finally:
                self._local.transaction_depth = depth

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            with suppress(sqlite3.Error):
                self._connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
            self._connection.close()
            self._closed = True

    def __enter__(self) -> Self:
        self._ensure_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def schema_version(self) -> int:
        with self._lock:
            self._ensure_open()
            row = self._connection.execute("PRAGMA user_version").fetchone()
            return int(row[0])

    def check_integrity(self, *, quick: bool = False) -> bool:
        pragma = "quick_check" if quick else "integrity_check"
        try:
            with self._lock:
                self._ensure_open()
                rows = self._connection.execute(f"PRAGMA {pragma}").fetchall()
        except sqlite3.DatabaseError as exc:
            raise DatabaseIntegrityError(f"SQLite {pragma} failed: {exc}") from exc
        messages = [str(row[0]) for row in rows]
        if messages != ["ok"]:
            summary = "; ".join(messages[:5])
            raise DatabaseIntegrityError(f"SQLite {pragma} reported: {summary}")
        return True

    def backup(self, destination: str | os.PathLike[str]) -> Path:
        """Create a consistent online backup without copying live WAL files."""

        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            self._ensure_open()
            try:
                backup_connection = sqlite3.connect(target)
                try:
                    self._connection.backup(backup_connection)
                finally:
                    backup_connection.close()
            except sqlite3.DatabaseError as exc:
                raise StorageError(f"database backup failed: {exc}") from exc
        return target

    def database_size_bytes(self) -> int:
        """Return bounded on-disk SQLite usage, including WAL/shared-memory files."""

        path_text = os.fspath(self.config.path)
        if path_text == ":memory:":
            return 0
        database = Path(path_text).expanduser().resolve()
        total = 0
        for candidate in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
            try:
                if candidate.is_file():
                    total += candidate.stat().st_size
            except OSError:
                continue
        return total

    @staticmethod
    def _hash_text(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _inserted_id(cursor: sqlite3.Cursor) -> int:
        if cursor.lastrowid is None:
            raise StorageError("SQLite insert did not return a row identifier")
        return cursor.lastrowid

    def _ensure_endpoint(self, connection: sqlite3.Connection, endpoint_id: str, now: str) -> None:
        empty = canonical_json({})
        connection.execute(
            """
            INSERT INTO endpoints(endpoint_id,state_json,state_hash,created_at,updated_at)
            VALUES(?,?,?,?,?) ON CONFLICT(endpoint_id) DO NOTHING
            """,
            (endpoint_id, empty, self._hash_text(empty), now, now),
        )

    def _ensure_scan(
        self,
        connection: sqlite3.Connection,
        scan_id: str,
        endpoint_id: str | None,
        now: str,
    ) -> None:
        if endpoint_id:
            self._ensure_endpoint(connection, endpoint_id, now)
        placeholder = {"scan_id": scan_id, "endpoint_id": endpoint_id, "scan_type": "UNKNOWN"}
        serialized = canonical_json(placeholder)
        connection.execute(
            """
            INSERT INTO scan_jobs(
                scan_id,endpoint_id,scan_type,status,authorization_json,requested_at,
                job_json,job_hash,updated_at
            ) VALUES(?,?,?,'PENDING','{}',?,?,?,?)
            ON CONFLICT(scan_id) DO UPDATE SET
                endpoint_id=COALESCE(scan_jobs.endpoint_id,excluded.endpoint_id)
            """,
            (
                scan_id,
                endpoint_id,
                "UNKNOWN",
                now,
                serialized,
                self._hash_text(serialized),
                now,
            ),
        )
