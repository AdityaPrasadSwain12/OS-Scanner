"""Stable façade composing cohesive SQLite repositories."""

from .audit import AuditStorage
from .base import StorageConfig
from .results import ResultStorage
from .upload_queue import UploadQueueStorage


class SQLiteStorage(ResultStorage, AuditStorage, UploadQueueStorage):
    """Public scanner storage API; accepts JSON-compatible application data."""


__all__ = ["SQLiteStorage", "StorageConfig"]
