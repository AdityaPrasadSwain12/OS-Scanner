from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.models import CollectorState, CollectorStatus, OverallStatus
from app.orchestrator.status import (
    collector_state,
    failed_status,
    native_status,
    overall_status,
    tool_status,
    unavailable_status,
)
from app.tools import ToolState


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (CollectorState.SUCCESS, CollectorState.SUCCESS),
        (ToolState.PARTIAL, CollectorState.PARTIAL),
        ("TIMEOUT", CollectorState.TIMEOUT),
        ("unknown", CollectorState.FAILED),
    ],
)
def test_collector_state_maps_external_states_fail_closed(
    raw: object, expected: CollectorState
) -> None:
    assert collector_state(raw) is expected


def test_tool_status_counts_payload_redacts_errors_and_bounds_duration() -> None:
    execution = SimpleNamespace(
        status=ToolState.TIMEOUT,
        payload=[{"name": "one"}, {"name": "two"}],
        duration_seconds=-1,
        error="Authorization: Bearer super-secret\r\nforged=true",
        metadata={"api_token": "super-secret", "safe": "value"},
        version="1.0",
    )

    status = tool_status("osquery.processes", execution)

    assert status.status is CollectorState.TIMEOUT
    assert status.duration_seconds == 0
    assert status.records_collected == 2
    assert status.error_code == "OSQUERY_PROCESSES_TIMEOUT"
    assert "super-secret" not in (status.error_message or "")
    assert status.metadata["api_token"] == "<redacted>"


@pytest.mark.parametrize(
    ("payload", "count"),
    [(None, 0), ({"one": 1}, 1), ("scalar", 1)],
)
def test_tool_status_counts_supported_payload_shapes(payload: object, count: int) -> None:
    status = tool_status(
        "tool", SimpleNamespace(status="SUCCESS", payload=payload, metadata="invalid")
    )
    assert status.records_collected == count
    assert status.metadata == {}
    assert status.error_code is None


def test_native_status_preserves_safe_category_and_failure_details() -> None:
    status = native_status(
        SimpleNamespace(
            name="firewall",
            status=ToolState.FAILED,
            duration_seconds=-2,
            count=-1,
            error="password=hunter2",
            metadata={"token": "abc"},
            category="posture",
        )
    )
    assert status.name == "native.firewall"
    assert status.error_code == "NATIVE_FAILED"
    assert status.duration_seconds == 0
    assert status.records_collected == 0
    assert status.metadata["category"] == "posture"
    assert status.metadata["token"] == "<redacted>"
    assert "hunter2" not in (status.error_message or "")


def test_status_factories_bound_and_redact_diagnostics() -> None:
    unavailable = unavailable_status("openscap", "x" * 3_000)
    skipped = unavailable_status("openscap", "unsupported", skipped=True)
    failed = failed_status("native", "api_key=secret\nforged", code="NATIVE_ERROR")
    assert len(unavailable.error_message or "") == 2_048
    assert skipped.status is CollectorState.SKIPPED
    assert failed.error_code == "NATIVE_ERROR"
    assert "secret" not in (failed.error_message or "")
    assert "\n" not in (failed.error_message or "")


@pytest.mark.parametrize(
    ("states", "expected"),
    [
        ([], OverallStatus.FAILED),
        ([CollectorState.SKIPPED], OverallStatus.FAILED),
        ([CollectorState.SUCCESS], OverallStatus.SUCCESS),
        ([CollectorState.SUCCESS, CollectorState.SKIPPED], OverallStatus.SUCCESS),
        ([CollectorState.SUCCESS, CollectorState.FAILED], OverallStatus.PARTIAL),
        ([CollectorState.PARTIAL, CollectorState.UNAVAILABLE], OverallStatus.PARTIAL),
        ([CollectorState.FAILED, CollectorState.TIMEOUT], OverallStatus.FAILED),
    ],
)
def test_overall_status_derives_honest_result(
    states: list[CollectorState], expected: OverallStatus
) -> None:
    statuses = [
        CollectorStatus(
            name=f"collector-{index}",
            status=state,
            error_message="test failure"
            if state in {CollectorState.FAILED, CollectorState.TIMEOUT}
            else None,
        )
        for index, state in enumerate(states)
    ]
    assert overall_status(statuses) is expected
