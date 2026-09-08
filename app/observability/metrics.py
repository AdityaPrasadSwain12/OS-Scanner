"""Low-cardinality metrics API ready for Prometheus/OpenTelemetry adapters."""

from __future__ import annotations

import math
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

_METRIC_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]{0,254}$")
_ATTRIBUTE_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")


def _validated(
    name: str, value: float, attributes: Mapping[str, object] | None
) -> tuple[float, tuple[tuple[str, str], ...]]:
    if not _METRIC_NAME.fullmatch(name):
        raise ValueError("metric name is invalid")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("metric value must be finite")
    labels: list[tuple[str, str]] = []
    for key, item in (attributes or {}).items():
        if not _ATTRIBUTE_NAME.fullmatch(key):
            raise ValueError("metric attribute name is invalid")
        text = str(item)
        if len(text) > 128 or any(ord(character) < 32 for character in text):
            raise ValueError("metric attribute value is invalid")
        labels.append((key, text))
    return number, tuple(sorted(labels))


@runtime_checkable
class MetricSink(Protocol):
    def increment(
        self,
        name: str,
        value: float = 1,
        *,
        attributes: Mapping[str, object] | None = None,
    ) -> None: ...

    def set_gauge(
        self,
        name: str,
        value: float,
        *,
        attributes: Mapping[str, object] | None = None,
    ) -> None: ...

    def observe(
        self,
        name: str,
        value: float,
        *,
        attributes: Mapping[str, object] | None = None,
    ) -> None: ...


class NoopMetrics:
    def increment(
        self, name: str, value: float = 1, *, attributes: Mapping[str, object] | None = None
    ) -> None:
        del name, value, attributes

    def set_gauge(
        self, name: str, value: float, *, attributes: Mapping[str, object] | None = None
    ) -> None:
        del name, value, attributes

    def observe(
        self, name: str, value: float, *, attributes: Mapping[str, object] | None = None
    ) -> None:
        del name, value, attributes


@dataclass(slots=True)
class _Histogram:
    count: int = 0
    total: float = 0
    minimum: float | None = None
    maximum: float | None = None

    def add(self, value: float) -> None:
        self.count += 1
        self.total += value
        self.minimum = value if self.minimum is None else min(self.minimum, value)
        self.maximum = value if self.maximum is None else max(self.maximum, value)


class InMemoryMetrics:
    """Thread-safe bounded summaries, primarily for tests and local health APIs."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._histograms: dict[tuple[str, tuple[tuple[str, str], ...]], _Histogram] = {}

    def increment(
        self, name: str, value: float = 1, *, attributes: Mapping[str, object] | None = None
    ) -> None:
        number, labels = _validated(name, value, attributes)
        if number < 0:
            raise ValueError("counter increments cannot be negative")
        with self._lock:
            key = (name, labels)
            self._counters[key] = self._counters.get(key, 0) + number

    def set_gauge(
        self, name: str, value: float, *, attributes: Mapping[str, object] | None = None
    ) -> None:
        number, labels = _validated(name, value, attributes)
        with self._lock:
            self._gauges[(name, labels)] = number

    def observe(
        self, name: str, value: float, *, attributes: Mapping[str, object] | None = None
    ) -> None:
        number, labels = _validated(name, value, attributes)
        with self._lock:
            histogram = self._histograms.setdefault((name, labels), _Histogram())
            histogram.add(number)

    @staticmethod
    def _series(key: tuple[str, tuple[tuple[str, str], ...]], value: object) -> dict[str, object]:
        name, labels = key
        return {"name": name, "attributes": dict(labels), "value": value}

    def snapshot(self) -> dict[str, list[dict[str, object]]]:
        with self._lock:
            return {
                "counters": [self._series(key, value) for key, value in self._counters.items()],
                "gauges": [self._series(key, value) for key, value in self._gauges.items()],
                "histograms": [
                    self._series(
                        key,
                        {
                            "count": value.count,
                            "sum": value.total,
                            "min": value.minimum,
                            "max": value.maximum,
                        },
                    )
                    for key, value in self._histograms.items()
                ],
            }


class CallbackMetrics:
    def __init__(
        self,
        callback: Callable[[str, str, float, Mapping[str, object]], None],
    ) -> None:
        self.callback = callback

    def _emit(
        self, kind: str, name: str, value: float, attributes: Mapping[str, object] | None
    ) -> None:
        number, labels = _validated(name, value, attributes)
        self.callback(kind, name, number, dict(labels))

    def increment(
        self, name: str, value: float = 1, *, attributes: Mapping[str, object] | None = None
    ) -> None:
        if value < 0:
            raise ValueError("counter increments cannot be negative")
        self._emit("counter", name, value, attributes)

    def set_gauge(
        self, name: str, value: float, *, attributes: Mapping[str, object] | None = None
    ) -> None:
        self._emit("gauge", name, value, attributes)

    def observe(
        self, name: str, value: float, *, attributes: Mapping[str, object] | None = None
    ) -> None:
        self._emit("histogram", name, value, attributes)


class ScannerMetrics:
    """Scanner vocabulary with intentionally bounded label cardinality."""

    def __init__(self, sink: MetricSink | None = None) -> None:
        self.sink = sink or NoopMetrics()

    def _safe(self, method: str, name: str, value: float, **attributes: object) -> None:
        """Keep an optional telemetry backend outside the scan failure domain."""

        try:
            getattr(self.sink, method)(name, value, attributes=attributes)
        except Exception:
            # A callback/exporter is advisory.  Durable results, queue state,
            # and lifecycle status must never depend on its availability.
            return

    def scan_finished(self, status: str, duration_seconds: float) -> None:
        attributes = {"status": status.upper()}
        self._safe("increment", "scanner_scans_total", 1, **attributes)
        self._safe(
            "observe", "scanner_scan_duration_seconds", duration_seconds, **attributes
        )

    def collector_finished(self, collector: str, status: str, duration_seconds: float) -> None:
        attributes = {"collector": collector, "status": status.upper()}
        self._safe("increment", "scanner_collector_runs_total", 1, **attributes)
        self._safe(
            "observe", "scanner_collector_duration_seconds", duration_seconds, **attributes
        )
        if status.upper() in {"FAILED", "TIMEOUT", "UNAVAILABLE"}:
            self._safe("increment", "scanner_collector_failures_total", 1, **attributes)

    def upload_failed(self, *, terminal: bool) -> None:
        self._safe("increment", "scanner_upload_failures_total", 1, terminal=terminal)

    def queue_size(self, value: int) -> None:
        self._safe("set_gauge", "scanner_upload_queue_size", value)
