"""Small, testable scheduling primitives for long-running endpoint agents."""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any


class TriggerType(StrEnum):
    STARTUP = "STARTUP"
    PERIODIC = "PERIODIC"
    MANUAL = "MANUAL"
    CLOUD = "CLOUD"
    POLICY = "POLICY"


@dataclass(frozen=True, slots=True)
class SchedulePolicy:
    interval: timedelta
    jitter_ratio: float = 0.10

    def __post_init__(self) -> None:
        if self.interval.total_seconds() <= 0:
            raise ValueError("interval must be positive")
        if not 0 <= self.jitter_ratio <= 0.5:
            raise ValueError("jitter_ratio must be between 0 and 0.5")

    def next_run(
        self,
        previous: datetime,
        *,
        random_source: random.Random | None = None,
    ) -> datetime:
        generator = random_source or random.SystemRandom()
        spread = self.interval.total_seconds() * self.jitter_ratio
        jitter = generator.uniform(-spread, spread)
        return previous + self.interval + timedelta(seconds=jitter)


@dataclass(slots=True)
class CooperativeScanScheduler:
    """Yield at most one local job when a startup, periodic, or policy trigger is due.

    The scanner agent owns execution, so scheduled work cannot overlap another
    scan in the same service process. A protected local configuration creates
    the jobs; this class only controls cadence and fleet-safe jitter.
    """

    job_factory: Callable[[TriggerType, datetime], Any]
    policy: SchedulePolicy | None = None
    startup_scan: bool = True
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    random_source: random.Random = field(default_factory=random.SystemRandom)
    _startup_pending: bool = field(init=False)
    _policy_requested: threading.Event = field(default_factory=threading.Event, init=False)
    _next_run: datetime | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self._startup_pending = self.startup_scan
        if self.policy is not None:
            self._next_run = self.policy.next_run(
                self.clock(), random_source=self.random_source
            )

    def request_policy_scan(self) -> None:
        """Coalesce one or more policy-change signals into a single scan."""

        self._policy_requested.set()

    def poll(self) -> Any | None:
        now = self.clock()
        if self._startup_pending:
            self._startup_pending = False
            return self.job_factory(TriggerType.STARTUP, now)
        if self._policy_requested.is_set():
            self._policy_requested.clear()
            return self.job_factory(TriggerType.POLICY, now)
        if self.policy is not None and self._next_run is not None and now >= self._next_run:
            self._next_run = self.policy.next_run(now, random_source=self.random_source)
            return self.job_factory(TriggerType.PERIODIC, now)
        return None


@dataclass(slots=True)
class PeriodicScheduler:
    """Cooperative scheduler; service managers retain process supervision duties."""

    policy: SchedulePolicy
    callback: Callable[[TriggerType, datetime], None]
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    random_source: random.Random = field(default_factory=random.SystemRandom)
    _stop: threading.Event = field(default_factory=threading.Event, init=False)

    def stop(self) -> None:
        self._stop.set()

    def run(self, *, startup_scan: bool = True) -> None:
        now = self.clock()
        if startup_scan:
            self.callback(TriggerType.STARTUP, now)
        next_run = self.policy.next_run(now, random_source=self.random_source)
        while not self._stop.is_set():
            remaining = max(0.0, (next_run - self.clock()).total_seconds())
            if self._stop.wait(timeout=min(remaining, 60.0)):
                return
            current = self.clock()
            if current >= next_run:
                self.callback(TriggerType.PERIODIC, current)
                next_run = self.policy.next_run(current, random_source=self.random_source)
