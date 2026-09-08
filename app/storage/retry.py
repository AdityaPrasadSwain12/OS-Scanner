"""Retry policy shared by the persistent upload queue and workers."""

from __future__ import annotations

from dataclasses import dataclass
from random import Random, SystemRandom


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 8
    base_delay_seconds: float = 1.0
    multiplier: float = 2.0
    max_delay_seconds: float = 3600.0
    jitter_ratio: float = 0.20

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 100:
            raise ValueError("max_attempts must be between 1 and 100")
        if self.base_delay_seconds <= 0:
            raise ValueError("base_delay_seconds must be positive")
        if self.multiplier < 1:
            raise ValueError("multiplier must be at least 1")
        if self.max_delay_seconds < self.base_delay_seconds:
            raise ValueError("max_delay_seconds cannot be below base delay")
        if not 0 <= self.jitter_ratio <= 1:
            raise ValueError("jitter_ratio must be between 0 and 1")

    def delay_for_attempt(self, attempt: int, *, random_source: Random | None = None) -> float:
        """Delay after a failed 1-based attempt, including bounded jitter."""

        if attempt < 1:
            raise ValueError("attempt must be at least 1")
        # The cap on attempts prevents unbounded exponent creation from hostile data.
        exponent = min(attempt - 1, 63)
        delay = min(
            self.max_delay_seconds,
            self.base_delay_seconds * (self.multiplier**exponent),
        )
        source = random_source or SystemRandom()
        jitter = delay * self.jitter_ratio
        return max(0.0, min(self.max_delay_seconds, delay + source.uniform(-jitter, jitter)))
