"""Value objects for the durable upload queue."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class UploadStatus(StrEnum):
    PENDING = "PENDING"
    IN_FLIGHT = "IN_FLIGHT"
    SUCCEEDED = "SUCCEEDED"
    DEAD = "DEAD"


@dataclass(frozen=True, slots=True)
class QueuedUpload:
    upload_id: int
    kind: str
    method: str
    endpoint: str
    payload: bytes
    content_type: str
    idempotency_key: str
    request_id: str
    attempt_count: int
    max_attempts: int
    lease_token: str
    metadata: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class EnqueueResult:
    upload_id: int
    created: bool


@dataclass(frozen=True, slots=True)
class QueueStats:
    pending: int = 0
    in_flight: int = 0
    succeeded: int = 0
    dead: int = 0

    @property
    def active(self) -> int:
        return self.pending + self.in_flight
