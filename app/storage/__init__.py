"""Durable local persistence for the endpoint scanner.

The package deliberately accepts JSON-compatible mappings instead of importing
application models.  That keeps persistence usable by collectors, the
orchestrator, and future schema versions without circular dependencies.
"""

from .database import SQLiteStorage, StorageConfig
from .errors import (
    DatabaseIntegrityError,
    IdempotencyConflictError,
    MigrationError,
    StorageCapacityError,
    StorageClosedError,
    StorageError,
)
from .maintenance import MaintenanceResult, StorageMaintenance
from .queue import EnqueueResult, QueuedUpload, QueueStats, UploadStatus
from .retry import RetryPolicy
from .snapshots import SectionChange, SnapshotChange

__all__ = [
    "DatabaseIntegrityError",
    "EnqueueResult",
    "IdempotencyConflictError",
    "MaintenanceResult",
    "MigrationError",
    "QueueStats",
    "QueuedUpload",
    "RetryPolicy",
    "SQLiteStorage",
    "SectionChange",
    "SnapshotChange",
    "StorageCapacityError",
    "StorageClosedError",
    "StorageConfig",
    "StorageError",
    "StorageMaintenance",
    "UploadStatus",
]
