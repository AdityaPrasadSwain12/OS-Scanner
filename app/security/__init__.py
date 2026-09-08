"""Security primitives safe for use across the scanner."""

from .redaction import (
    REDACTED,
    TRUNCATED,
    is_sensitive_key,
    redact_command,
    redact_command_line,
    redact_mapping,
    redact_sensitive_data,
    redact_text,
    redact_value,
    sanitize_for_log,
)

__all__ = [
    "REDACTED",
    "TRUNCATED",
    "is_sensitive_key",
    "redact_command",
    "redact_command_line",
    "redact_mapping",
    "redact_sensitive_data",
    "redact_text",
    "redact_value",
    "sanitize_for_log",
]
