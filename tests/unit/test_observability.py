from __future__ import annotations

import io
import json

from app.observability import (
    InMemoryMetrics,
    RedactionConfig,
    Redactor,
    ScannerMetrics,
    configure_logging,
    log_context,
)


def test_redactor_removes_nested_secrets_and_command_arguments() -> None:
    redactor = Redactor()
    value = redactor.value(
        {
            "authorization": "Bearer secret-token",
            "nested": {"apiKey": "abc", "password_policy": "strong"},
            "command": "agent --password=hunter2 --mode scan",
            "url": "https://cloud.test/path?access_token=secret&ok=1",
        }
    )
    serialized = json.dumps(value)
    assert "secret-token" not in serialized
    assert "hunter2" not in serialized
    assert "access_token=secret" not in serialized
    assert value["nested"]["password_policy"] == "strong"
    assert serialized.count("[REDACTED]") >= 3


def test_redaction_is_bounded_and_handles_cycles() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    redactor = Redactor(RedactionConfig(max_string_length=64, max_collection_items=2, max_depth=3))
    assert redactor.value(cyclic) == ["[CYCLE]"]
    assert "TRUNCATED" in redactor.text("x" * 100)


def test_structured_logger_has_context_single_line_output_and_no_secret() -> None:
    stream = io.StringIO()
    logger = configure_logging(
        "test.observability.structured",
        stream=stream,
        replace_handlers=True,
    ).bind(scanner_version="1.0.0")
    with log_context(scan_id="scan-1", endpoint_id="endpoint-1"):
        logger.info(
            "scan_completed",
            "finished\nforged-entry",
            status="SUCCESS",
            duration_seconds=1.5,
            access_token="must-not-appear",
        )

    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["scan_id"] == "scan-1"
    assert event["endpoint_id"] == "endpoint-1"
    assert event["scanner_version"] == "1.0.0"
    assert event["status"] == "SUCCESS"
    assert event["access_token"] == "[REDACTED]"
    assert "must-not-appear" not in lines[0]
    assert "\\n" in event["message"]


def test_metrics_track_required_scan_collector_upload_and_queue_series() -> None:
    sink = InMemoryMetrics()
    metrics = ScannerMetrics(sink)
    metrics.scan_finished("PARTIAL", 2.5)
    metrics.collector_finished("openscap", "UNAVAILABLE", 0.1)
    metrics.upload_failed(terminal=False)
    metrics.queue_size(7)

    snapshot = sink.snapshot()
    counter_names = [item["name"] for item in snapshot["counters"]]
    histogram_names = [item["name"] for item in snapshot["histograms"]]
    assert "scanner_scans_total" in counter_names
    assert "scanner_collector_failures_total" in counter_names
    assert "scanner_upload_failures_total" in counter_names
    assert "scanner_scan_duration_seconds" in histogram_names
    assert snapshot["gauges"][0]["value"] == 7
