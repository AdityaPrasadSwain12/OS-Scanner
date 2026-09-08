"""Storage-specific exceptions with safe, actionable failure categories."""


class StorageError(RuntimeError):
    """Base class for local persistence failures."""


class StorageClosedError(StorageError):
    """Raised when an operation is attempted after closing the database."""


class DatabaseIntegrityError(StorageError):
    """Raised when SQLite reports corruption or a failed integrity check."""


class MigrationError(StorageError):
    """Raised when a schema migration cannot be applied or was modified."""


class IdempotencyConflictError(StorageError):
    """The same idempotency identifier was reused for different content."""


class StorageCapacityError(StorageError):
    """Protected local storage cannot safely admit more scan data."""
