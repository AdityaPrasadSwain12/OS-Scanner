"""One-event-per-line JSON logging with bound scan context."""

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, TextIO

from .redaction import Redactor

_EVENT_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,127}$")
_CURRENT_CONTEXT: contextvars.ContextVar[Mapping[str, Any] | None] = contextvars.ContextVar(
    "scanner_log_context", default=None
)


@contextmanager
def log_context(**fields: Any) -> Iterator[None]:
    """Bind scan/job context for all structured logs in the current task/thread."""

    token = _CURRENT_CONTEXT.set({**(_CURRENT_CONTEXT.get() or {}), **fields})
    try:
        yield
    finally:
        _CURRENT_CONTEXT.reset(token)


class StructuredJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = getattr(record, "structured_payload", None)
        if payload is None:
            payload = {
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "level": record.levelname,
                "event": "unstructured_log",
                "message": record.getMessage(),
            }
        return json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )


class StructuredLogger:
    def __init__(
        self,
        logger: logging.Logger,
        *,
        context: Mapping[str, Any] | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self._logger = logger
        self._context = dict(context or {})
        self._redactor = redactor or Redactor()

    def bind(self, **fields: Any) -> StructuredLogger:
        return StructuredLogger(
            self._logger,
            context={**self._context, **fields},
            redactor=self._redactor,
        )

    def log(
        self,
        level: int,
        event: str,
        message: str | None = None,
        **fields: Any,
    ) -> None:
        if not _EVENT_NAME.fullmatch(event):
            raise ValueError("structured log event name is invalid")
        combined = {**(_CURRENT_CONTEXT.get() or {}), **self._context, **fields}
        redacted = self._redactor.value(combined)
        payload = {
            **redacted,
            "timestamp": datetime.now(UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": logging.getLevelName(level),
            "event": event,
        }
        if message is not None:
            payload["message"] = self._redactor.text(message)
        self._logger.log(level, "", extra={"structured_payload": payload})

    def debug(self, event: str, message: str | None = None, **fields: Any) -> None:
        self.log(logging.DEBUG, event, message, **fields)

    def info(self, event: str, message: str | None = None, **fields: Any) -> None:
        self.log(logging.INFO, event, message, **fields)

    def warning(self, event: str, message: str | None = None, **fields: Any) -> None:
        self.log(logging.WARNING, event, message, **fields)

    def error(self, event: str, message: str | None = None, **fields: Any) -> None:
        self.log(logging.ERROR, event, message, **fields)

    def exception(self, event: str, exc: BaseException, **fields: Any) -> None:
        self.error(
            event,
            **fields,
            error_type=type(exc).__name__,
            error_message=str(exc),
        )


def configure_logging(
    name: str = "endpoint_scanner",
    *,
    level: int = logging.INFO,
    stream: TextIO | None = None,
    replace_handlers: bool = False,
    redactor: Redactor | None = None,
) -> StructuredLogger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    if replace_handlers:
        logger.handlers.clear()
    if not logger.handlers:
        handler = logging.StreamHandler(stream or sys.stderr)
        handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(handler)
    return StructuredLogger(logger, redactor=redactor)
