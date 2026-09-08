from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest

import app.collectors.base as collector_base
from app.collectors.base import NativeCheckResult, NativeCollector, NativeCommand
from app.tools import CommandResult, SafeSubprocessRunner, ToolState, ToolUnavailableError


def _result(
    *,
    returncode: int = 0,
    stdout: str = "value",
    stderr: str = "",
    timed_out: bool = False,
    truncated: bool = False,
) -> CommandResult:
    return CommandResult(
        executable="test-tool",
        arguments=(),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0.1,
        timed_out=timed_out,
        stdout_truncated=truncated,
    )


class ConfigurableRunner:
    def __init__(
        self,
        response: CommandResult | Exception,
        *,
        available: set[str] | None = None,
    ) -> None:
        self.response = response
        self.available = available if available is not None else {"test-tool"}
        self.calls: list[str] = []

    def is_available(self, executable: str | Path) -> bool:
        return str(executable) in self.available

    def run(
        self,
        executable: str | Path,
        arguments: tuple[str, ...] = (),
        *,
        timeout_seconds: float | None = None,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        del arguments, timeout_seconds, cwd
        self.calls.append(str(executable))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class DummyCollector(NativeCollector):
    platform_name = "test"

    def __init__(
        self,
        runner: ConfigurableRunner,
        checks: Iterable[NativeCommand | tuple[NativeCommand, ...]],
    ) -> None:
        super().__init__(runner)
        self.checks = tuple(checks)

    @classmethod
    def default_runner(cls) -> SafeSubprocessRunner:
        return SafeSubprocessRunner(("test-tool",))

    def posture_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        return self.checks

    def patch_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        return ()

    def persistence_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        return ()


def _command(parser: object = lambda value: {"value": value}) -> NativeCommand:
    return NativeCommand(
        name="check",
        executable="test-tool",
        arguments=("status",),
        parser=parser,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    ("response", "available", "expected"),
    [
        (_result(), set(), ToolState.UNAVAILABLE),
        (ToolUnavailableError("missing"), {"test-tool"}, ToolState.UNAVAILABLE),
        (OSError("permission denied"), {"test-tool"}, ToolState.FAILED),
        (_result(timed_out=True), {"test-tool"}, ToolState.TIMEOUT),
        (_result(returncode=2, stderr="denied"), {"test-tool"}, ToolState.FAILED),
        (_result(truncated=True), {"test-tool"}, ToolState.FAILED),
    ],
)
def test_native_command_failure_modes_are_isolated(
    response: CommandResult | Exception,
    available: set[str],
    expected: ToolState,
) -> None:
    result = DummyCollector(
        ConfigurableRunner(response, available=available), [_command()]
    ).collect(["posture"])
    assert result.statuses[0].status is expected
    assert result.data["posture"] == {}


def test_native_parser_failure_isolated_and_success_counts_records() -> None:
    def invalid(_value: str) -> object:
        raise ValueError("malformed output")

    failed = DummyCollector(ConfigurableRunner(_result()), [_command(invalid)]).collect(
        ["posture"]
    )
    assert failed.statuses[0].status is ToolState.FAILED
    assert failed.statuses[0].error == "malformed output"

    succeeded = DummyCollector(ConfigurableRunner(_result(stdout="ok")), [_command()]).collect(
        ["posture", "posture"]
    )
    assert succeeded.statuses[0].status is ToolState.SUCCESS
    assert succeeded.statuses[0].count == 1
    assert succeeded.data["posture"] == {"check": {"value": "ok"}}


def test_native_fallback_uses_first_available_command_and_validates_selection() -> None:
    first = NativeCommand("fallback", "missing", (), lambda value: value)
    second = NativeCommand("fallback", "test-tool", (), lambda value: value)
    runner = ConfigurableRunner(_result(stdout="selected"), available={"test-tool"})
    collector = DummyCollector(runner, [(first, second)])
    result = collector.collect(["posture"])
    assert result.data["posture"]["fallback"] == "selected"
    assert runner.calls == ["test-tool"]

    unavailable = DummyCollector(ConfigurableRunner(_result(), available=set()), [(first, second)])
    assert unavailable.collect(["posture"]).statuses[0].status is ToolState.UNAVAILABLE
    with pytest.raises(ValueError, match="fallback cannot be empty"):
        DummyCollector(ConfigurableRunner(_result()), [()]).collect(["posture"])
    with pytest.raises(ValueError, match="unknown native"):
        collector.collect(["unknown"])


def test_directory_metadata_is_bounded_and_permission_errors_are_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "startup"
    directory.mkdir()
    (directory / "one").write_text("metadata only", encoding="utf-8")
    (directory / "subdirectory").mkdir()

    result = NativeCollector.collect_directory_metadata(
        name="startup", category="persistence", directories=[directory]
    )
    assert result.status.status is ToolState.SUCCESS
    assert result.status.count == 2
    assert {item["type"] for item in result.data} == {"file", "directory"}

    bounded = NativeCollector.collect_directory_metadata(
        name="startup", category="persistence", directories=[directory], maximum_items=1
    )
    assert bounded.status.status is ToolState.PARTIAL
    assert bounded.status.count == 1

    def denied(_path: Path) -> object:
        raise PermissionError("permission denied")

    monkeypatch.setattr(collector_base.os, "scandir", denied)
    denied_result: NativeCheckResult = NativeCollector.collect_directory_metadata(
        name="startup", category="persistence", directories=[directory]
    )
    assert denied_result.status.status is ToolState.FAILED
    assert "permission denied" in (denied_result.status.error or "")
