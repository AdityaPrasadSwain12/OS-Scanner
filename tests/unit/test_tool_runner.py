from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from app.tools import (
    ExecutableNotAllowedError,
    InvalidCommandError,
    SafeSubprocessRunner,
)


def test_runner_executes_argument_array_without_shell(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    hostile_argument = f"value; touch {marker}"
    runner = SafeSubprocessRunner((sys.executable,), timeout_seconds=5)

    result = runner.run(
        sys.executable,
        ("-c", "import sys; print(sys.argv[1])", hostile_argument),
    )

    assert result.succeeded
    assert result.stdout.strip() == hostile_argument
    assert not marker.exists()


def test_runner_enforces_allowlist_and_argument_controls() -> None:
    runner = SafeSubprocessRunner((sys.executable,))

    with pytest.raises(ExecutableNotAllowedError):
        runner.resolve("definitely-not-approved")
    with pytest.raises(InvalidCommandError):
        runner.run(sys.executable, ("line-one\nline-two",))
    with pytest.raises(InvalidCommandError):
        runner.run(sys.executable, ("bad\x00argument",))


def test_runner_times_out_and_bounds_output() -> None:
    runner = SafeSubprocessRunner(
        (sys.executable,), timeout_seconds=0.1, max_output_bytes=1024
    )
    timed_out = runner.run(sys.executable, ("-c", "import time; time.sleep(5)"))
    oversized = runner.run(sys.executable, ("-c", "print('x' * 5000)"), timeout_seconds=5)

    assert timed_out.timed_out
    assert oversized.stdout_truncated
    assert len(oversized.stdout.encode()) <= 1024


def test_runner_removes_loader_and_python_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHONPATH", "untrusted")
    monkeypatch.setenv("LD_PRELOAD", "untrusted")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "untrusted")

    runner = SafeSubprocessRunner((sys.executable,))

    assert "PYTHONPATH" not in runner.environment
    assert "LD_PRELOAD" not in runner.environment
    assert "DYLD_INSERT_LIBRARIES" not in runner.environment


def test_runner_accepts_only_explicit_absolute_tool_cache_paths(tmp_path: Path) -> None:
    cache = tmp_path / "tool-cache"
    runner = SafeSubprocessRunner(
        (sys.executable,),
        environment={
            "HOME": str(tmp_path),
            "VDB_HOME": str(cache / "vdb"),
            "XDG_CACHE_HOME": str(cache),
        },
    )

    assert runner.environment["VDB_HOME"] == str((cache / "vdb").resolve())
    assert runner.environment["XDG_CACHE_HOME"] == str(cache.resolve())
    with pytest.raises(InvalidCommandError, match="must be absolute"):
        SafeSubprocessRunner((sys.executable,), environment={"VDB_HOME": "relative"})


@pytest.mark.skipif(os.name != "nt", reason="Windows environment contract")
def test_runner_preserves_windows_system_drive_for_native_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYSTEMDRIVE", "C:")

    runner = SafeSubprocessRunner((sys.executable,))

    assert runner.environment["SYSTEMDRIVE"] == "C:"
