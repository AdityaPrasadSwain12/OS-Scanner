"""Common primitives for small, isolated native platform checks."""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from app.tools._validation import clean_text
from app.tools.base import ToolState
from app.tools.runner import CommandResult, SafeSubprocessRunner, ToolUnavailableError

Parser = Callable[[str], Any]


class Runner(Protocol):
    def is_available(self, executable: str | Path) -> bool: ...

    def run(
        self,
        executable: str | Path,
        arguments: Sequence[str] = (),
        *,
        timeout_seconds: float | None = None,
        cwd: str | Path | None = None,
    ) -> CommandResult: ...


@dataclass(frozen=True, slots=True)
class NativeCommand:
    name: str
    executable: str
    arguments: tuple[str, ...]
    parser: Parser
    allowed_returncodes: frozenset[int] = frozenset({0})
    timeout_seconds: float = 30.0


@dataclass(frozen=True, slots=True)
class NativeCollectorStatus:
    name: str
    category: str
    status: ToolState
    duration_seconds: float = 0.0
    error: str | None = None
    count: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NativeCheckResult:
    status: NativeCollectorStatus
    data: Any = None


@dataclass(frozen=True, slots=True)
class EndpointCollectionResult:
    platform: str
    data: dict[str, dict[str, Any]]
    statuses: tuple[NativeCollectorStatus, ...]

    @property
    def overall_status(self) -> ToolState:
        states = [item.status for item in self.statuses]
        if not states:
            return ToolState.UNAVAILABLE
        if all(state == ToolState.SUCCESS for state in states):
            return ToolState.SUCCESS
        if any(state == ToolState.SUCCESS for state in states):
            return ToolState.PARTIAL
        if all(state == ToolState.UNAVAILABLE for state in states):
            return ToolState.UNAVAILABLE
        if any(state == ToolState.TIMEOUT for state in states) and all(
            state in {ToolState.TIMEOUT, ToolState.UNAVAILABLE} for state in states
        ):
            return ToolState.TIMEOUT
        return ToolState.FAILED


class NativeCollector(ABC):
    """Base for complete native inventory and platform security collectors."""

    platform_name: str
    supported_categories = frozenset({"inventory", "posture", "patches", "persistence"})

    def __init__(
        self,
        runner: Runner,
        *,
        deadline_at: float | None = None,
        max_command_timeout_seconds: float = 60.0,
        max_output_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        if not 0 < max_command_timeout_seconds <= 3_600:
            raise ValueError("native command timeout bound is invalid")
        if not 1_024 <= max_output_bytes <= 100 * 1024 * 1024:
            raise ValueError("native output bound is invalid")
        self.runner = runner
        self.deadline_at = deadline_at
        self.max_command_timeout_seconds = max_command_timeout_seconds
        self.max_output_bytes = max_output_bytes

    def set_deadline(self, deadline_at: float | None) -> None:
        self.deadline_at = deadline_at

    @classmethod
    @abstractmethod
    def default_runner(
        cls,
        *,
        timeout_seconds: float = 60.0,
        max_output_bytes: int = 8 * 1024 * 1024,
    ) -> SafeSubprocessRunner:
        """Build a runner whose allowlist contains only this platform's commands."""

    @abstractmethod
    def posture_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        """Return security-posture commands; tuples represent safe fallbacks."""

    @abstractmethod
    def patch_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        """Return local patch-state commands."""

    @abstractmethod
    def persistence_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        """Return persistence metadata commands."""

    def inventory_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        """Return core OS inventory commands supplied by each platform adapter."""

        return ()

    def filesystem_checks(self, category: str) -> tuple[NativeCheckResult, ...]:
        """Platforms can add bounded metadata-only filesystem checks."""

        return ()

    def _unavailable(self, name: str, category: str) -> NativeCheckResult:
        return NativeCheckResult(
            NativeCollectorStatus(name=name, category=category, status=ToolState.UNAVAILABLE)
        )

    def _run_command(self, command: NativeCommand, category: str) -> NativeCheckResult:
        timeout = min(command.timeout_seconds, self.max_command_timeout_seconds)
        if self.deadline_at is not None:
            remaining = self.deadline_at - time.monotonic()
            if remaining <= 0:
                return NativeCheckResult(
                    NativeCollectorStatus(
                        name=command.name,
                        category=category,
                        status=ToolState.TIMEOUT,
                        error="scan deadline exhausted before native check",
                    )
                )
            timeout = min(timeout, remaining)
        if not self.runner.is_available(command.executable):
            return self._unavailable(command.name, category)
        try:
            result = self.runner.run(
                command.executable,
                command.arguments,
                timeout_seconds=timeout,
            )
        except ToolUnavailableError:
            return self._unavailable(command.name, category)
        except (OSError, ValueError) as exc:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name=command.name,
                    category=category,
                    status=ToolState.FAILED,
                    error=clean_text(exc, maximum=512),
                )
            )
        if result.timed_out:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name=command.name,
                    category=category,
                    status=ToolState.TIMEOUT,
                    duration_seconds=result.duration_seconds,
                    error="native check timed out",
                )
            )
        if result.returncode not in command.allowed_returncodes:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name=command.name,
                    category=category,
                    status=ToolState.FAILED,
                    duration_seconds=result.duration_seconds,
                    error=clean_text(result.stderr, maximum=512) or "native check failed",
                )
            )
        if result.stdout_truncated:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name=command.name,
                    category=category,
                    status=ToolState.FAILED,
                    duration_seconds=result.duration_seconds,
                    error="native check output exceeded the size limit",
                )
            )
        if len(result.stdout.encode("utf-8")) > self.max_output_bytes:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name=command.name,
                    category=category,
                    status=ToolState.FAILED,
                    duration_seconds=result.duration_seconds,
                    error="native check output exceeded the size limit",
                )
            )
        try:
            data = command.parser(result.stdout)
        except (TypeError, ValueError) as exc:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name=command.name,
                    category=category,
                    status=ToolState.FAILED,
                    duration_seconds=result.duration_seconds,
                    error=clean_text(exc, maximum=512),
                )
            )
        count = len(data) if isinstance(data, (dict, list, tuple, set)) else None
        return NativeCheckResult(
            NativeCollectorStatus(
                name=command.name,
                category=category,
                status=ToolState.SUCCESS,
                duration_seconds=result.duration_seconds,
                count=count,
            ),
            data,
        )

    def _run_choice(
        self, choice: NativeCommand | tuple[NativeCommand, ...], category: str
    ) -> NativeCheckResult:
        if isinstance(choice, NativeCommand):
            return self._run_command(choice, category)
        if not choice:
            raise ValueError("native command fallback cannot be empty")
        failures: list[NativeCheckResult] = []
        for command in choice:
            if self.runner.is_available(command.executable):
                result = self._run_command(command, category)
                if result.status.status in {ToolState.SUCCESS, ToolState.PARTIAL}:
                    return result
                failures.append(result)
        if failures:
            return next(
                (
                    result
                    for result in failures
                    if result.status.status is ToolState.TIMEOUT
                ),
                failures[-1],
            )
        return self._unavailable(choice[0].name, category)

    def collect(self, categories: Sequence[str]) -> EndpointCollectionResult:
        selected = tuple(dict.fromkeys(categories))
        if any(category not in self.supported_categories for category in selected):
            raise ValueError("unknown native collector category")
        data: dict[str, dict[str, Any]] = {}
        statuses: list[NativeCollectorStatus] = []
        suppliers = {
            "inventory": self.inventory_checks,
            "posture": self.posture_checks,
            "patches": self.patch_checks,
            "persistence": self.persistence_checks,
        }
        for category in selected:
            category_data: dict[str, Any] = {}
            results = [
                self._run_choice(choice, category) for choice in suppliers[category]()
            ]
            results.extend(self.filesystem_checks(category))
            for result in results:
                statuses.append(result.status)
                if result.status.status in {ToolState.SUCCESS, ToolState.PARTIAL}:
                    category_data[result.status.name] = result.data
            data[category] = category_data
        return EndpointCollectionResult(
            platform=self.platform_name,
            data=data,
            statuses=tuple(statuses),
        )

    @staticmethod
    def collect_directory_metadata(
        *,
        name: str,
        category: str,
        directories: Sequence[Path],
        maximum_items: int = 10_000,
        deadline_at: float | None = None,
    ) -> NativeCheckResult:
        started = time.monotonic()
        records: list[dict[str, str]] = []
        errors: list[str] = []
        for directory in directories:
            try:
                if not directory.is_dir():
                    continue
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if (
                            deadline_at is not None
                            and time.monotonic() >= deadline_at
                        ):
                            return NativeCheckResult(
                                NativeCollectorStatus(
                                    name=name,
                                    category=category,
                                    status=ToolState.TIMEOUT,
                                    duration_seconds=time.monotonic() - started,
                                    error=(
                                        "scan deadline exceeded during filesystem "
                                        "metadata collection"
                                    ),
                                )
                            )
                        if len(records) >= maximum_items:
                            raise ValueError("filesystem metadata item limit exceeded")
                        records.append(
                            {
                                "name": clean_text(entry.name, maximum=512),
                                "location": str(directory),
                                "type": (
                                    "symlink"
                                    if entry.is_symlink()
                                    else "directory"
                                    if entry.is_dir(follow_symlinks=False)
                                    else "file"
                                ),
                            }
                        )
            except (OSError, ValueError) as exc:
                errors.append(clean_text(exc, maximum=256))
        duration = time.monotonic() - started
        if errors and not records:
            return NativeCheckResult(
                NativeCollectorStatus(
                    name=name,
                    category=category,
                    status=ToolState.FAILED,
                    duration_seconds=duration,
                    error="; ".join(errors[:5]),
                )
            )
        status = ToolState.PARTIAL if errors else ToolState.SUCCESS
        return NativeCheckResult(
            NativeCollectorStatus(
                name=name,
                category=category,
                status=status,
                duration_seconds=duration,
                count=len(records),
                error="; ".join(errors[:5]) if errors else None,
            ),
            records,
        )
