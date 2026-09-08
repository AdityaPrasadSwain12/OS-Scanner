"""Common contract and result envelopes for external security tools."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Generic, TypeVar


class ToolState(StrEnum):
    """Portable states shared by tools and native collectors."""

    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True, slots=True)
class ToolHealth:
    """A cheap, side-effect-free view of local tool readiness."""

    name: str
    status: ToolState
    version: str | None = None
    executable: str | None = None
    detail: str | None = None


PayloadT = TypeVar("PayloadT")


@dataclass(frozen=True, slots=True)
class ToolExecution(Generic[PayloadT]):  # noqa: UP046 - compatible with supported mypy
    """Normalized outcome from one adapter operation.

    ``payload`` is normalized data, never an unchecked raw document.  Stderr is
    bounded and sanitized by the process runner before it reaches this object.
    """

    tool: str
    status: ToolState
    payload: PayloadT | None = None
    version: str | None = None
    duration_seconds: float = 0.0
    exit_code: int | None = None
    error: str | None = None
    warnings: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in {ToolState.SUCCESS, ToolState.PARTIAL}


InputT = TypeVar("InputT")
ParsedT = TypeVar("ParsedT")
NormalizedT = TypeVar("NormalizedT")


class ToolAdapter(
    ABC, Generic[InputT, ParsedT, NormalizedT]  # noqa: UP046 - compatible with mypy
):
    """Replaceable boundary for an external command-line security tool."""

    name: str

    @abstractmethod
    def is_available(self) -> bool:
        """Return whether a trusted executable can be resolved locally."""

    @abstractmethod
    def version(self, *, timeout_seconds: float = 5.0) -> str | None:
        """Return a bounded, normalized version string when available."""

    @abstractmethod
    def validate_input(self, value: InputT) -> InputT:
        """Validate and canonicalize caller-controlled input."""

    @abstractmethod
    def execute(self, value: InputT) -> ToolExecution[NormalizedT]:
        """Validate, execute, parse, and normalize one operation."""

    @abstractmethod
    def parse(self, output: str) -> ParsedT:
        """Parse a bounded tool response and reject malformed structures."""

    @abstractmethod
    def normalize(self, parsed: ParsedT) -> NormalizedT:
        """Convert parsed output into stable scanner-owned data."""

    def health(self) -> ToolHealth:
        if not self.is_available():
            return ToolHealth(name=self.name, status=ToolState.UNAVAILABLE)
        return ToolHealth(
            name=self.name,
            status=ToolState.SUCCESS,
            version=self.version(),
            executable=self.executable_path(),
        )

    def executable_path(self) -> str | None:
        """Adapters may override this to expose their resolved executable."""

        return None
