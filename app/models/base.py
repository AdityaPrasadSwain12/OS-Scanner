"""Strict, serialization-safe base models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.0"
SCANNER_VERSION = "1.1.0"

Identifier = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
]
# Values crossing trust boundaries are validated and copied by ``bounded_json``.
# Keeping the annotation non-recursive avoids Python/Pydantic recursive-alias
# edge cases while the runtime validator supplies the stronger guarantee.
JsonScalar: TypeAlias = str | int | float | bool | None  # noqa: UP040
JsonValue: TypeAlias = Any  # noqa: UP040


def utc_now() -> datetime:
    return datetime.now(UTC)


def ensure_aware(value: datetime) -> datetime:
    """Normalize timestamps to UTC and reject ambiguous naive values."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(UTC)


class StrictModel(BaseModel):
    """Base for wire models: unknown data is rejected rather than silently trusted."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=False,
        str_strip_whitespace=True,
        validate_assignment=True,
        validate_default=True,
    )


class VersionedModel(StrictModel):
    schema_version: str = Field(default=SCHEMA_VERSION, pattern=r"^\d+\.\d+$", max_length=16)
    scanner_version: str = Field(
        default=SCANNER_VERSION,
        pattern=r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$",
        max_length=64,
    )


class TimestampedModel(StrictModel):
    timestamp: datetime = Field(default_factory=utc_now)

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return ensure_aware(value)


def bounded_json(value: Any, *, max_depth: int = 12, max_nodes: int = 10_000) -> JsonValue:
    """Validate and copy a JSON-like value with denial-of-service bounds."""

    nodes = 0
    active: set[int] = set()

    def walk(item: Any, depth: int) -> JsonValue:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes:
            raise ValueError("structured value exceeds node limit")
        if depth > max_depth:
            raise ValueError("structured value exceeds depth limit")
        if item is None or isinstance(item, (str, bool, int)):
            return item
        if isinstance(item, float):
            if item != item or item in (float("inf"), float("-inf")):
                raise ValueError("non-finite numbers are not valid")
            return item
        if isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in active:
                raise ValueError("recursive structured value is not valid")
            active.add(identity)
            sequence_result = [walk(child, depth + 1) for child in item]
            active.remove(identity)
            return sequence_result
        if isinstance(item, dict):
            identity = id(item)
            if identity in active:
                raise ValueError("recursive structured value is not valid")
            active.add(identity)
            mapping_result: dict[str, JsonValue] = {}
            for key, child in item.items():
                if not isinstance(key, str) or not key or len(key) > 256:
                    raise ValueError("structured object keys must be non-empty strings")
                mapping_result[key] = walk(child, depth + 1)
            active.remove(identity)
            return mapping_result
        raise ValueError(f"unsupported structured value type: {type(item).__name__}")

    return walk(value, 0)
