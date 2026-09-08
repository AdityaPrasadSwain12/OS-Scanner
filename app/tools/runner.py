"""Hardened, bounded subprocess execution used by every integration.

There is deliberately no escape hatch for a shell.  Executables must be named
up front, are resolved to absolute paths, arguments are passed as an argv array,
and reader threads continuously drain output while retaining only fixed-size
buffers.
"""

from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


class InvalidCommandError(ValueError):
    """The command or one of its arguments violates the execution policy."""


class ExecutableNotAllowedError(PermissionError):
    """The requested executable was not explicitly allowlisted."""


class ToolUnavailableError(FileNotFoundError):
    """An allowlisted executable could not be found in the hardened PATH."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    executable: str
    arguments: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    @property
    def succeeded(self) -> bool:
        return not self.timed_out and self.returncode == 0


class _BoundedBytes:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.truncated = False

    def append(self, chunk: bytes) -> None:
        remaining = self.limit - len(self.data)
        if remaining > 0:
            self.data.extend(chunk[:remaining])
        if len(chunk) > remaining:
            self.truncated = True


class _ReadableStream(Protocol):
    def read(self, size: int = -1) -> bytes: ...

    def close(self) -> None: ...


def _read_bounded(stream: _ReadableStream, target: _BoundedBytes) -> None:
    read = stream.read
    try:
        while chunk := read(64 * 1024):
            target.append(chunk)
    finally:
        stream.close()


def _safe_path(source: str) -> str:
    """Remove relative/empty PATH entries that can resolve from the CWD."""

    entries: list[str] = []
    seen: set[str] = set()
    for raw in source.split(os.pathsep):
        if not raw:
            continue
        path = Path(raw).expanduser()
        if not path.is_absolute():
            continue
        try:
            normalized = str(path.resolve(strict=False))
        except OSError:
            continue
        key = os.path.normcase(normalized)
        if key not in seen:
            entries.append(normalized)
            seen.add(key)
    return os.pathsep.join(entries)


def _hardened_environment(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    allowed = {
        "PATH",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
    }
    environment = {
        key.upper(): value for key, value in os.environ.items() if key.upper() in allowed
    }
    environment["PATH"] = _safe_path(environment.get("PATH", os.defpath))
    environment["LANG"] = "C.UTF-8"
    environment["LC_ALL"] = "C.UTF-8"
    if overrides:
        path_overrides = {"HOME", "VDB_HOME", "XDG_CACHE_HOME"}
        for key, value in overrides.items():
            normalized = key.upper()
            if normalized not in allowed | path_overrides:
                raise InvalidCommandError(f"environment variable is not allowed: {key}")
            if "\x00" in key or "\x00" in value:
                raise InvalidCommandError("environment values cannot contain NUL bytes")
            if normalized in path_overrides:
                candidate = Path(value).expanduser()
                if not candidate.is_absolute():
                    raise InvalidCommandError(
                        f"environment path must be absolute: {normalized}"
                    )
                environment[normalized] = str(candidate.resolve(strict=False))
            else:
                environment[normalized] = _safe_path(value) if normalized == "PATH" else value
    return environment


def _standard_executable_directories() -> tuple[Path, ...]:
    candidates: list[Path] = []
    if os.name == "nt":
        for variable in ("SYSTEMROOT", "PROGRAMFILES", "PROGRAMFILES(X86)"):
            value = os.environ.get(variable)
            if value:
                root = Path(value).resolve(strict=False)
                candidates.append(root / "System32" if variable == "SYSTEMROOT" else root)
    else:
        candidates.extend(
            Path(value)
            for value in (
                "/bin",
                "/sbin",
                "/usr/bin",
                "/usr/sbin",
                "/usr/local",
                "/usr/local/bin",
                "/usr/local/sbin",
                "/opt/homebrew",
                "/opt/homebrew/bin",
                "/opt/local",
                "/opt/local/bin",
                "/snap",
                "/snap/bin",
            )
        )
    return tuple(path.resolve(strict=False) for path in candidates)


class SafeSubprocessRunner:
    """Execute only allowlisted local programs with strict resource bounds."""

    def __init__(
        self,
        allowed_executables: Iterable[str],
        *,
        timeout_seconds: float = 30.0,
        max_output_bytes: int = 2 * 1024 * 1024,
        trusted_directories: Iterable[str | Path] | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        names = tuple(allowed_executables)
        if not names:
            raise ValueError("at least one executable must be allowlisted")
        if timeout_seconds <= 0 or timeout_seconds > 86_400:
            raise ValueError("timeout_seconds must be between 0 and 86400")
        if max_output_bytes < 1024 or max_output_bytes > 100 * 1024 * 1024:
            raise ValueError("max_output_bytes must be between 1 KiB and 100 MiB")

        self._allowed_names: set[str] = set()
        self._allowed_paths: set[Path] = set()
        for value in names:
            self._add_allowed(value)
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.environment = _hardened_environment(environment)
        configured_directories = (
            tuple(Path(item).expanduser().resolve(strict=False) for item in trusted_directories)
            if trusted_directories is not None
            else _standard_executable_directories()
        )
        # An exact absolute executable is itself an explicit trust decision; its
        # parent is added so the common directory check does not reject it.
        configured_directories = (
            *configured_directories,
            *(path.parent for path in self._allowed_paths),
        )
        self._trusted_directories = tuple(dict.fromkeys(configured_directories))

    def _add_allowed(self, value: str) -> None:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("invalid executable allowlist entry")
        candidate = Path(value).expanduser()
        if os.name == "nt" and candidate.suffix.casefold() in {".bat", ".cmd", ".ps1", ".vbs"}:
            raise ValueError("script interpreters cannot be executable allowlist entries")
        if candidate.is_absolute():
            self._allowed_paths.add(candidate.resolve(strict=False))
            self._allowed_names.add(candidate.name.casefold())
            return
        if candidate.name != value or any(separator in value for separator in ("/", "\\")):
            raise ValueError("allowlisted executables must be base names or absolute paths")
        self._allowed_names.add(value.casefold())

    def _is_under_trusted_directory(self, resolved: Path) -> bool:
        return any(
            resolved == root or resolved.is_relative_to(root)
            for root in self._trusted_directories
        )

    def resolve(self, executable: str | Path) -> Path | None:
        text = os.fspath(executable)
        if not text or "\x00" in text:
            raise InvalidCommandError("invalid executable")
        requested = Path(text).expanduser()
        if requested.is_absolute():
            resolved = requested.resolve(strict=False)
            if resolved not in self._allowed_paths:
                raise ExecutableNotAllowedError(f"executable path is not allowlisted: {requested}")
        else:
            if requested.name != text or any(separator in text for separator in ("/", "\\")):
                raise InvalidCommandError(
                    "executable must be a base name or an allowlisted absolute path"
                )
            if text.casefold() not in self._allowed_names:
                raise ExecutableNotAllowedError(f"executable is not allowlisted: {text}")
            found = shutil.which(text, path=self.environment.get("PATH"))
            if found is None:
                return None
            resolved = Path(found).resolve(strict=True)
            if os.name == "nt":
                requested_name = text.casefold()
                allowed_names = {requested_name}
                if not Path(text).suffix:
                    allowed_names.update({f"{requested_name}.exe", f"{requested_name}.com"})
                if resolved.name.casefold() not in allowed_names:
                    return None

        if not resolved.is_file() or not self._is_under_trusted_directory(resolved):
            return None
        if os.name != "nt":
            mode = resolved.stat().st_mode
            if not mode & stat.S_IXUSR or mode & (stat.S_IWGRP | stat.S_IWOTH):
                return None
        return resolved

    def is_available(self, executable: str | Path) -> bool:
        try:
            return self.resolve(executable) is not None
        except (ExecutableNotAllowedError, InvalidCommandError, OSError):
            return False

    @staticmethod
    def _validate_arguments(arguments: Sequence[str]) -> tuple[str, ...]:
        if len(arguments) > 256:
            raise InvalidCommandError("too many command arguments")
        checked: list[str] = []
        total = 0
        for value in arguments:
            if not isinstance(value, str):
                raise InvalidCommandError("command arguments must be strings")
            if "\x00" in value or "\r" in value or "\n" in value:
                raise InvalidCommandError("command arguments contain forbidden control characters")
            encoded_length = len(value.encode("utf-8"))
            if encoded_length > 8192:
                raise InvalidCommandError("individual command argument is too large")
            total += encoded_length
            checked.append(value)
        if total > 65_536:
            raise InvalidCommandError("command argument vector is too large")
        return tuple(checked)

    def run(
        self,
        executable: str | Path,
        arguments: Sequence[str] = (),
        *,
        timeout_seconds: float | None = None,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        """Run a fixed executable without a shell and retain bounded output."""

        resolved = self.resolve(executable)
        if resolved is None:
            raise ToolUnavailableError(f"allowlisted executable is unavailable: {executable}")
        checked_arguments = self._validate_arguments(arguments)
        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        if timeout <= 0 or timeout > 86_400:
            raise InvalidCommandError("timeout must be between 0 and 86400 seconds")

        working_directory: str | None = None
        if cwd is not None:
            resolved_cwd = Path(cwd).expanduser().resolve(strict=True)
            if not resolved_cwd.is_dir():
                raise InvalidCommandError("working directory must be an existing directory")
            working_directory = str(resolved_cwd)

        popen_kwargs: dict[str, Any] = {}
        if os.name == "nt":
            popen_kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            )
        else:
            popen_kwargs["start_new_session"] = True

        started = time.monotonic()
        process = subprocess.Popen(  # noqa: S603 - executable is resolved and allowlisted above
            [str(resolved), *checked_arguments],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=working_directory,
            env=self.environment,
            close_fds=True,
            **popen_kwargs,
        )
        stdout_buffer = _BoundedBytes(self.max_output_bytes)
        stderr_buffer = _BoundedBytes(self.max_output_bytes)
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_thread = threading.Thread(
            target=_read_bounded, args=(process.stdout, stdout_buffer), daemon=True
        )
        stderr_thread = threading.Thread(
            target=_read_bounded, args=(process.stderr, stderr_buffer), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()

        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate_process(process)
        finally:
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

        duration = time.monotonic() - started
        return CommandResult(
            executable=str(resolved),
            arguments=checked_arguments,
            returncode=process.returncode,
            stdout=bytes(stdout_buffer.data).decode("utf-8", errors="replace"),
            stderr=bytes(stderr_buffer.data).decode("utf-8", errors="replace"),
            duration_seconds=duration,
            timed_out=timed_out,
            stdout_truncated=stdout_buffer.truncated,
            stderr_truncated=stderr_buffer.truncated,
        )

    @staticmethod
    def _terminate_process(process: subprocess.Popen[bytes]) -> None:
        try:
            if os.name == "nt":
                # ``Popen.kill`` only terminates the direct Windows process.
                # taskkill's tree mode closes descendants created by security
                # tools as well, preventing orphaned scanners after a timeout.
                system_root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
                taskkill = (
                    system_root.resolve(strict=False) / "System32" / "taskkill.exe"
                    if system_root.is_absolute()
                    else None
                )
                if taskkill is not None and taskkill.is_file():
                    subprocess.run(  # noqa: S603 - fixed OS binary and numeric PID only
                        [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                        shell=False,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                        check=False,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                if process.poll() is None:
                    process.kill()
            else:
                kill_process_group = os.killpg  # type: ignore[attr-defined]
                kill_signal = signal.SIGKILL  # type: ignore[attr-defined]
                kill_process_group(process.pid, kill_signal)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
        finally:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
