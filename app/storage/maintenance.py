"""Bounded, legal-hold-aware local evidence retention and capacity admission."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from app.core.config import RetentionSettings
from app.reporting import AtomicReportWriter

from .database import SQLiteStorage
from .errors import StorageCapacityError

if TYPE_CHECKING:
    from collections.abc import Collection


@dataclass(frozen=True, slots=True)
class MaintenanceResult:
    pruned_scans: int = 0
    pruned_reports: int = 0
    purged_uploads: int = 0
    local_bytes: int = 0
    free_bytes: int = 0


class StorageMaintenance:
    """Apply configured retention, then fail closed at storage high-water marks."""

    def __init__(
        self,
        storage: SQLiteStorage,
        report_directory: Path,
        settings: RetentionSettings,
    ) -> None:
        self.storage = storage
        self.report_directory = report_directory.expanduser().resolve()
        self.settings = settings

    def run(self, *, now: datetime | None = None) -> MaintenanceResult:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        batch = self.settings.maintenance_batch_size
        upload_cutoff = current - timedelta(
            days=self.settings.succeeded_upload_retention_days
        )
        purged_uploads = self.storage.purge_succeeded_uploads(
            older_than=upload_cutoff.isoformat(), limit=batch
        )
        scan_cutoff = current - timedelta(days=self.settings.retention_days)
        pruned_scans = self.storage.prune_completed_scan_records(
            older_than=scan_cutoff.isoformat(),
            max_completed_scans=self.settings.max_completed_scans,
            protected_scan_ids=self.settings.legal_hold_scan_ids,
            limit=batch,
        )
        protected_reports = self._protected_report_names(
            self.settings.legal_hold_scan_ids
        )
        pruned_reports = self._prune_reports(
            current=current,
            protected_names=protected_reports,
            limit=batch,
        )
        local_bytes = self._local_usage_bytes()
        capacity_root = self.report_directory.parent
        capacity_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        free_bytes = shutil.disk_usage(capacity_root).free
        if pruned_scans or pruned_reports or purged_uploads:
            self.storage.record_audit_event(
                "STORAGE_RETENTION_APPLIED",
                "SUCCESS",
                event_id=f"storage-retention:{uuid4()}",
                resource_type="local-storage",
                resource_id="scanner-data",
                details={
                    "pruned_scans": pruned_scans,
                    "pruned_reports": pruned_reports,
                    "purged_uploads": purged_uploads,
                    "local_bytes": local_bytes,
                },
                created_at=current.isoformat(),
            )
            local_bytes = self._local_usage_bytes()
        if local_bytes > self.settings.max_local_storage_bytes:
            raise StorageCapacityError(
                "local scanner storage high-water mark is exceeded; "
                "resolve pending/dead uploads, export legal holds, or increase the protected limit"
            )
        if free_bytes < self.settings.minimum_free_disk_bytes:
            raise StorageCapacityError(
                "free disk is below the protected scanner reserve; "
                "free space or move the configured data directory"
            )
        return MaintenanceResult(
            pruned_scans=pruned_scans,
            pruned_reports=pruned_reports,
            purged_uploads=purged_uploads,
            local_bytes=local_bytes,
            free_bytes=free_bytes,
        )

    def inspect_capacity(self) -> MaintenanceResult:
        """Read current scanner-owned usage without applying retention."""

        capacity_root = self.report_directory.parent
        return MaintenanceResult(
            local_bytes=self._local_usage_bytes(),
            free_bytes=shutil.disk_usage(capacity_root).free,
        )

    def _protected_report_names(self, legal_holds: Collection[str]) -> set[str]:
        names = {AtomicReportWriter.filename_for(scan_id) for scan_id in legal_holds}
        # Active/dead queue records remain operational evidence and must retain
        # their local JSON report until delivery or explicit operator action.
        with self.storage._lock:
            self.storage._ensure_open()
            rows = self.storage._connection.execute(
                """
                SELECT DISTINCT json_extract(queued.metadata_json,'$.scan_id') AS scan_id
                FROM upload_queue AS queued
                LEFT JOIN upload_queue AS replacement
                    ON replacement.upload_id=queued.superseded_by_upload_id
                WHERE (
                    queued.status IN ('PENDING','IN_FLIGHT')
                    OR (queued.status='DEAD' AND replacement.status!='SUCCEEDED')
                    OR (queued.status='DEAD' AND replacement.status IS NULL)
                )
                  AND json_extract(queued.metadata_json,'$.scan_id') IS NOT NULL
                """
            ).fetchall()
        names.update(
            AtomicReportWriter.filename_for(str(row["scan_id"])) for row in rows
        )
        return names

    def _prune_reports(
        self,
        *,
        current: datetime,
        protected_names: set[str],
        limit: int,
    ) -> int:
        if not self.report_directory.exists():
            return 0
        files: list[tuple[Path, float]] = []
        for candidate in self.report_directory.glob("*.json"):
            try:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                files.append((candidate, candidate.stat().st_mtime))
            except OSError:
                continue
        files.sort(key=lambda item: (item[1], item[0].name), reverse=True)
        cutoff = (current - timedelta(days=self.settings.report_retention_days)).timestamp()
        selected: list[Path] = []
        for index, (candidate, modified_at) in enumerate(files):
            if candidate.name in protected_names:
                continue
            if modified_at < cutoff or index >= self.settings.max_report_files:
                selected.append(candidate)
                if len(selected) >= limit:
                    break
        removed = 0
        for candidate in selected:
            try:
                candidate.unlink(missing_ok=True)
                removed += 1
            except OSError:
                continue
        return removed

    def _local_usage_bytes(self) -> int:
        total = self.storage.database_size_bytes()
        if not self.report_directory.exists():
            return total
        for candidate in self.report_directory.glob("*.json"):
            try:
                if not candidate.is_symlink() and candidate.is_file():
                    total += candidate.stat().st_size
            except OSError:
                continue
        return total
