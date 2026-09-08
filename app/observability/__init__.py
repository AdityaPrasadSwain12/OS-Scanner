"""Structured, privacy-preserving logs and backend-neutral metrics."""

from .logging import StructuredJsonFormatter, StructuredLogger, configure_logging, log_context
from .metrics import (
    CallbackMetrics,
    InMemoryMetrics,
    MetricSink,
    NoopMetrics,
    ScannerMetrics,
)
from .redaction import RedactionConfig, Redactor, redact

__all__ = [
    "CallbackMetrics",
    "InMemoryMetrics",
    "MetricSink",
    "NoopMetrics",
    "RedactionConfig",
    "Redactor",
    "ScannerMetrics",
    "StructuredJsonFormatter",
    "StructuredLogger",
    "configure_logging",
    "log_context",
    "redact",
]
