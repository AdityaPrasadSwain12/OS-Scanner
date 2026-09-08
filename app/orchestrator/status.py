"""Translate adapter states and derive an honest overall scan status."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from app.models import CollectorState, CollectorStatus, OverallStatus
from app.security import redact_value, sanitize_for_log


def collector_state(value: object) -> CollectorState:
    raw = getattr(value, "value", value)
    try:
        return CollectorState(str(raw))
    except ValueError:
        return CollectorState.FAILED


def tool_status(name: str, execution: object, *, version: str | None = None) -> CollectorStatus:
    payload = getattr(execution, "payload", None)
    count = len(payload) if isinstance(payload, (list, tuple, dict)) else int(payload is not None)
    raw_metadata = getattr(execution, "metadata", {})
    metadata = redact_value(raw_metadata)
    if not isinstance(metadata, dict):
        metadata = {}
    state = collector_state(getattr(execution, "status", "FAILED"))
    error = getattr(execution, "error", None)
    failure_states = {CollectorState.FAILED, CollectorState.TIMEOUT}
    return CollectorStatus(
        name=name,
        status=state,
        duration_seconds=max(0.0, float(getattr(execution, "duration_seconds", 0.0))),
        tool_version=version or getattr(execution, "version", None),
        records_collected=count,
        error_code=(
            f"{name.upper().replace('.', '_')}_{state.value}"
            if state in failure_states
            else None
        ),
        error_message=str(sanitize_for_log(error))[:2048] if error else None,
        metadata=metadata,
    )


def native_status(status: object) -> CollectorStatus:
    name = f"native.{getattr(status, 'name', 'unknown')}"
    state = collector_state(getattr(status, "status", "FAILED"))
    error = getattr(status, "error", None)
    raw_metadata: Any = getattr(status, "metadata", {})
    metadata = dict(raw_metadata) if isinstance(raw_metadata, Mapping) else {}
    category = getattr(status, "category", None)
    if category:
        metadata["category"] = str(category)
    failure_states = {CollectorState.FAILED, CollectorState.TIMEOUT}
    return CollectorStatus(
        name=name,
        status=state,
        duration_seconds=max(0.0, float(getattr(status, "duration_seconds", 0.0))),
        records_collected=max(0, int(getattr(status, "count", 0) or 0)),
        error_code=f"NATIVE_{state.value}" if state in failure_states else None,
        error_message=str(sanitize_for_log(error))[:2048] if error else None,
        metadata=redact_value(metadata),
    )


def unavailable_status(name: str, reason: str, *, skipped: bool = False) -> CollectorStatus:
    return CollectorStatus(
        name=name,
        status=CollectorState.SKIPPED if skipped else CollectorState.UNAVAILABLE,
        error_message=reason[:2048],
    )


def failed_status(name: str, error: object, *, code: str = "COLLECTOR_FAILED") -> CollectorStatus:
    return CollectorStatus(
        name=name,
        status=CollectorState.FAILED,
        error_code=code,
        error_message=str(sanitize_for_log(error))[:2048] or "collector failed",
    )


def overall_status(statuses: Iterable[CollectorStatus]) -> OverallStatus:
    materialized = [
        status.status for status in statuses if status.status is not CollectorState.SKIPPED
    ]
    if not materialized:
        return OverallStatus.FAILED
    if all(state is CollectorState.SUCCESS for state in materialized):
        return OverallStatus.SUCCESS
    if any(state in {CollectorState.SUCCESS, CollectorState.PARTIAL} for state in materialized):
        return OverallStatus.PARTIAL
    return OverallStatus.FAILED
