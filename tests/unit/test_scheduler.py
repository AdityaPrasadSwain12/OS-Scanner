from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

import pytest

from app.scheduling import CooperativeScanScheduler, SchedulePolicy, TriggerType


def test_schedule_applies_bounded_jitter() -> None:
    start = datetime(2025, 1, 1, tzinfo=UTC)
    policy = SchedulePolicy(timedelta(hours=1), jitter_ratio=0.1)
    result = policy.next_run(start, random_source=random.Random(7))  # noqa: S311
    assert start + timedelta(minutes=54) <= result <= start + timedelta(minutes=66)


def test_schedule_rejects_dangerous_jitter() -> None:
    with pytest.raises(ValueError):
        SchedulePolicy(timedelta(minutes=1), jitter_ratio=1.0)


def test_cooperative_scheduler_yields_startup_policy_and_periodic_jobs() -> None:
    current = [datetime(2026, 1, 1, tzinfo=UTC)]
    created: list[tuple[TriggerType, datetime]] = []

    def factory(trigger: TriggerType, requested_at: datetime) -> str:
        created.append((trigger, requested_at))
        return trigger.value

    scheduler = CooperativeScanScheduler(
        factory,
        policy=SchedulePolicy(timedelta(minutes=5), jitter_ratio=0),
        startup_scan=True,
        clock=lambda: current[0],
        random_source=random.Random(1),  # noqa: S311 - deterministic scheduling test
    )

    assert scheduler.poll() == "STARTUP"
    assert scheduler.poll() is None

    scheduler.request_policy_scan()
    scheduler.request_policy_scan()
    assert scheduler.poll() == "POLICY"
    assert scheduler.poll() is None

    current[0] += timedelta(minutes=5)
    assert scheduler.poll() == "PERIODIC"
    assert scheduler.poll() is None
    assert [trigger for trigger, _ in created] == [
        TriggerType.STARTUP,
        TriggerType.POLICY,
        TriggerType.PERIODIC,
    ]
