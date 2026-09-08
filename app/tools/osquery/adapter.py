"""osquery adapter with a closed query registry."""

from __future__ import annotations

import re
import time
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from threading import Lock

from app.tools._validation import clean_text, parse_json_document
from app.tools.base import ToolAdapter, ToolExecution, ToolState
from app.tools.osquery.queries import DEFAULT_QUERY_REGISTRY, QueryDefinition
from app.tools.runner import CommandResult, SafeSubprocessRunner, ToolUnavailableError

_VERSION_PATTERN = re.compile(r"\b\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9_.-]+)?\b")
_BATCH_SQL_LIMIT_BYTES = 7_900
_BATCH_FIELD_LIMIT = 120


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    expires_at: float
    estimated_bytes: int
    execution: ToolExecution[list[dict[str, object]]]


@dataclass(frozen=True, slots=True)
class _BatchPlan:
    query_ids: tuple[str, ...]
    sql: str
    aliases: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]


class OsqueryAdapter(ToolAdapter[str, list[dict[str, object]], list[dict[str, object]]]):
    """Execute scanner-owned SQL only; arbitrary SQL is intentionally unsupported."""

    name = "osquery"

    def __init__(
        self,
        *,
        runner: SafeSubprocessRunner | None = None,
        query_registry: Mapping[str, QueryDefinition] | None = None,
        executable: str | None = None,
        timeout_seconds: float = 30.0,
        max_concurrency: int = 4,
        max_output_bytes: int = 8 * 1024 * 1024,
        max_cache_entries: int = 64,
        max_cache_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if not 1 <= max_concurrency <= 32:
            raise ValueError("osquery concurrency must be between 1 and 32")
        if not 1024 <= max_output_bytes <= 100 * 1024 * 1024:
            raise ValueError("osquery output limit must be between 1 KiB and 100 MiB")
        if not 1 <= max_cache_entries <= 256:
            raise ValueError("osquery cache entry limit must be between 1 and 256")
        if not 1024 <= max_cache_bytes <= 100 * 1024 * 1024:
            raise ValueError("osquery cache size must be between 1 KiB and 100 MiB")
        self._executable_candidates = (
            (executable,) if executable is not None else ("osqueryi", "osqueryi.exe")
        )
        self._runner = runner or SafeSubprocessRunner(
            self._executable_candidates,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        self._queries = dict(query_registry or DEFAULT_QUERY_REGISTRY)
        if any(key != definition.identifier for key, definition in self._queries.items()):
            raise ValueError("osquery registry keys must match query identifiers")
        self._resolved_name: str | None = None
        self._max_concurrency = max_concurrency
        self._max_output_bytes = max_output_bytes
        self._max_cache_entries = max_cache_entries
        self._max_cache_bytes = max_cache_bytes
        self._cache_bytes = 0
        self._cache: OrderedDict[tuple[str, str], _CacheEntry] = OrderedDict()
        self._version_cache: dict[str, tuple[float, str]] = {}
        self._cache_lock = Lock()

    def _find_executable(self) -> str | None:
        for candidate in self._executable_candidates:
            if self._runner.is_available(candidate):
                self._resolved_name = candidate
                return candidate
        return None

    def executable_path(self) -> str | None:
        name = self._resolved_name or self._find_executable()
        if name is None:
            return None
        resolved = self._runner.resolve(name)
        return str(resolved) if resolved is not None else None

    def is_available(self) -> bool:
        return self._find_executable() is not None

    def _executable_fingerprint(self, executable: str) -> str:
        try:
            resolved = self._runner.resolve(executable)
        except (OSError, ValueError):
            return executable
        if resolved is None:
            return executable
        try:
            stat = resolved.stat()
        except OSError:
            return str(resolved)
        return f"{resolved}:{stat.st_size}:{stat.st_mtime_ns}"

    def version(self, *, timeout_seconds: float = 5.0) -> str | None:
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("osquery version timeout must be between 0 and 60 seconds")
        executable = self._find_executable()
        if executable is None:
            return None
        fingerprint = self._executable_fingerprint(executable)
        now = time.monotonic()
        with self._cache_lock:
            cached = self._version_cache.get(fingerprint)
            if cached is not None and cached[0] > now:
                return cached[1]
        try:
            result = self._runner.run(
                executable,
                ("--version",),
                timeout_seconds=timeout_seconds,
            )
        except (OSError, ValueError):
            return None
        if not result.succeeded:
            return None
        match = _VERSION_PATTERN.search(result.stdout)
        version = match.group(0) if match else clean_text(result.stdout, maximum=128) or None
        if version is not None:
            with self._cache_lock:
                self._version_cache = {fingerprint: (time.monotonic() + 300, version)}
        return version

    def validate_input(self, value: str) -> str:
        if not isinstance(value, str) or value not in self._queries:
            raise ValueError("unknown osquery query identifier")
        return value

    def parse(self, output: str) -> list[dict[str, object]]:
        document = parse_json_document(output, max_chars=self._max_output_bytes)
        if not isinstance(document, list):
            raise ValueError("osquery response must be a JSON array")
        rows: list[dict[str, object]] = []
        for item in document:
            if not isinstance(item, dict):
                raise ValueError("osquery rows must be JSON objects")
            if len(item) > 128:
                raise ValueError("osquery row has too many fields")
            row: dict[str, object] = {}
            for raw_key, raw_value in item.items():
                key = clean_text(raw_key, maximum=128)
                if not key:
                    continue
                if raw_value is None or isinstance(raw_value, (bool, int, float)):
                    row[key] = raw_value
                elif isinstance(raw_value, str):
                    row[key] = clean_text(raw_value, maximum=8192)
                else:
                    raise ValueError("osquery row contains a nested value")
            rows.append(row)
        return rows

    def normalize(self, parsed: list[dict[str, object]]) -> list[dict[str, object]]:
        return parsed

    @staticmethod
    def _copy_execution(
        execution: ToolExecution[list[dict[str, object]]],
        **metadata: object,
    ) -> ToolExecution[list[dict[str, object]]]:
        payload = (
            [dict(row) for row in execution.payload] if execution.payload is not None else None
        )
        return replace(
            execution,
            payload=payload,
            metadata={**execution.metadata, **metadata},
        )

    def _cache_key(self, query_id: str, executable: str) -> tuple[str, str]:
        definition = self._queries[query_id]
        return (
            f"{query_id}:{definition.sql}",
            self._executable_fingerprint(executable),
        )

    def _cached(
        self, query_id: str, executable: str
    ) -> ToolExecution[list[dict[str, object]]] | None:
        if self._queries[query_id].cache_ttl_seconds <= 0:
            return None
        key = self._cache_key(query_id, executable)
        now = time.monotonic()
        with self._cache_lock:
            expired = [item for item, entry in self._cache.items() if entry.expires_at <= now]
            for item in expired:
                expired_entry = self._cache.pop(item, None)
                if expired_entry is not None:
                    self._cache_bytes -= expired_entry.estimated_bytes
            entry = self._cache.pop(key, None)
            if entry is None:
                return None
            self._cache[key] = entry
            execution = entry.execution
        return replace(
            self._copy_execution(execution, cache_hit=True),
            duration_seconds=0.0,
        )

    @staticmethod
    def _estimated_execution_bytes(
        execution: ToolExecution[list[dict[str, object]]],
    ) -> int:
        size = 256
        for row in execution.payload or ():
            size += 128
            for key, value in row.items():
                size += 64 + len(key.encode("utf-8"))
                size += len(str(value).encode("utf-8")) if value is not None else 4
        return size

    def _store_cached(
        self,
        query_id: str,
        executable: str,
        execution: ToolExecution[list[dict[str, object]]],
    ) -> None:
        ttl = self._queries[query_id].cache_ttl_seconds
        if ttl <= 0 or execution.status is not ToolState.SUCCESS:
            return
        key = self._cache_key(query_id, executable)
        estimated_bytes = self._estimated_execution_bytes(execution)
        if estimated_bytes > self._max_cache_bytes:
            return
        entry = _CacheEntry(
            expires_at=time.monotonic() + ttl,
            estimated_bytes=estimated_bytes,
            execution=self._copy_execution(execution, cache_hit=False),
        )
        with self._cache_lock:
            replaced = self._cache.pop(key, None)
            if replaced is not None:
                self._cache_bytes -= replaced.estimated_bytes
            self._cache[key] = entry
            self._cache_bytes += entry.estimated_bytes
            while (
                len(self._cache) > self._max_cache_entries
                or self._cache_bytes > self._max_cache_bytes
            ):
                _old_key, old_entry = self._cache.popitem(last=False)
                self._cache_bytes -= old_entry.estimated_bytes

    @staticmethod
    def _failure(
        query_id: str, result: CommandResult, *, error: str
    ) -> ToolExecution[list[dict[str, object]]]:
        status = ToolState.TIMEOUT if result.timed_out else ToolState.FAILED
        return ToolExecution(
            tool="osquery",
            status=status,
            duration_seconds=result.duration_seconds,
            exit_code=result.returncode,
            error=error,
            metadata={"query_id": query_id},
        )

    def execute(
        self, value: str, *, timeout_seconds: float | None = None
    ) -> ToolExecution[list[dict[str, object]]]:
        query_id = self.validate_input(value)
        definition = self._queries[query_id]
        executable = self._find_executable()
        if executable is None:
            return ToolExecution(
                tool=self.name,
                status=ToolState.UNAVAILABLE,
                error="osquery executable is unavailable",
                metadata={"query_id": query_id},
            )
        cached = self._cached(query_id, executable)
        if cached is not None:
            return cached
        try:
            result = self._runner.run(
                executable,
                ("--json", definition.sql),
                timeout_seconds=timeout_seconds,
            )
        except ToolUnavailableError:
            return ToolExecution(
                tool=self.name,
                status=ToolState.UNAVAILABLE,
                error="osquery executable is unavailable",
                metadata={"query_id": query_id},
            )
        except (OSError, ValueError) as exc:
            return ToolExecution(
                tool=self.name,
                status=ToolState.FAILED,
                error=clean_text(exc, maximum=512),
                metadata={"query_id": query_id},
            )
        if result.timed_out:
            return self._failure(query_id, result, error="osquery execution timed out")
        if result.returncode != 0:
            return self._failure(
                query_id,
                result,
                error=clean_text(result.stderr, maximum=1024) or "osquery execution failed",
            )
        if result.stdout_truncated:
            return self._failure(query_id, result, error="osquery output exceeded the size limit")
        try:
            rows = self.normalize(self.parse(result.stdout))
        except ValueError as exc:
            return self._failure(query_id, result, error=str(exc))
        if len(rows) > definition.maximum_rows:
            return self._failure(query_id, result, error="osquery row limit exceeded")
        execution = ToolExecution(
            tool=self.name,
            status=ToolState.SUCCESS,
            payload=rows,
            duration_seconds=result.duration_seconds,
            exit_code=result.returncode,
            metadata={"query_id": query_id, "category": definition.category, "count": len(rows)},
        )
        self._store_cached(query_id, executable, execution)
        return execution

    @staticmethod
    def _query_sql(definition: QueryDefinition) -> str:
        return definition.sql.strip().removesuffix(";").rstrip()

    def _make_batch_plan(self, query_ids: Sequence[str]) -> _BatchPlan | None:
        if len(query_ids) < 2:
            return None
        ctes: list[str] = []
        selections: list[str] = []
        aliases: list[tuple[str, tuple[tuple[str, str], ...]]] = []
        for index, query_id in enumerate(query_ids):
            definition = self._queries[query_id]
            if definition.maximum_rows != 1 or not definition.batch_columns:
                return None
            table_alias = f"scanner_q{index}"
            ctes.append(f"{table_alias} AS ({self._query_sql(definition)})")
            count_alias = f"__scanner_count_{index}"
            selections.append(
                f'(SELECT COUNT(*) FROM {table_alias}) AS "{count_alias}"'  # noqa: S608
            )
            query_aliases: list[tuple[str, str]] = []
            for column_index, column in enumerate(definition.batch_columns):
                output_alias = f"__scanner_value_{index}_{column_index}"
                selections.append(
                    f'(SELECT "{column}" FROM {table_alias} LIMIT 1) '  # noqa: S608
                    f'AS "{output_alias}"'
                )
                query_aliases.append((column, output_alias))
            aliases.append((count_alias, tuple(query_aliases)))
        sql = f"WITH {', '.join(ctes)} SELECT {', '.join(selections)};"
        if len(sql.encode("utf-8")) > _BATCH_SQL_LIMIT_BYTES:
            return None
        if len(selections) > _BATCH_FIELD_LIMIT:
            return None
        return _BatchPlan(tuple(query_ids), sql, tuple(aliases))

    def _batch_units(self, query_ids: Sequence[str]) -> list[tuple[str, ...]]:
        units: list[tuple[str, ...]] = []
        pending_batch: list[str] = []

        def flush() -> None:
            nonlocal pending_batch
            if pending_batch:
                units.append(tuple(pending_batch))
                pending_batch = []

        for query_id in query_ids:
            definition = self._queries[query_id]
            if definition.maximum_rows != 1 or not definition.batch_columns:
                flush()
                units.append((query_id,))
                continue
            candidate = [*pending_batch, query_id]
            if len(candidate) > 1 and self._make_batch_plan(candidate) is None:
                flush()
                pending_batch.append(query_id)
            else:
                pending_batch = candidate
        flush()
        return units

    @staticmethod
    def _batch_count(value: object) -> int | None:
        try:
            count = int(str(value))
        except (TypeError, ValueError, OverflowError):
            return None
        return count if count in {0, 1} else None

    def _execute_batch(
        self,
        plan: _BatchPlan,
        *,
        timeout_seconds: float | None,
    ) -> dict[str, ToolExecution[list[dict[str, object]]]] | None:
        executable = self._find_executable()
        if executable is None:
            return None
        try:
            result = self._runner.run(
                executable,
                ("--json", plan.sql),
                timeout_seconds=timeout_seconds,
            )
        except (OSError, ValueError, ToolUnavailableError):
            return None
        if result.timed_out:
            return {
                query_id: replace(
                    self._failure(
                        query_id,
                        result,
                        error="osquery batched execution timed out",
                    ),
                    duration_seconds=result.duration_seconds / len(plan.query_ids),
                )
                for query_id in plan.query_ids
            }
        if result.returncode != 0:
            return None
        if result.stdout_truncated:
            return {
                query_id: replace(
                    self._failure(
                        query_id,
                        result,
                        error="osquery batched output exceeded the size limit",
                    ),
                    duration_seconds=result.duration_seconds / len(plan.query_ids),
                )
                for query_id in plan.query_ids
            }
        try:
            rows = self.parse(result.stdout)
        except ValueError:
            return None
        if len(rows) != 1:
            return None
        combined = rows[0]
        expected = {
            alias
            for count_alias, query_aliases in plan.aliases
            for alias in (count_alias, *(output for _column, output in query_aliases))
        }
        if set(combined) != expected:
            return None
        duration = result.duration_seconds / len(plan.query_ids)
        executions: dict[str, ToolExecution[list[dict[str, object]]]] = {}
        for query_id, (count_alias, query_aliases) in zip(
            plan.query_ids, plan.aliases, strict=True
        ):
            count = self._batch_count(combined[count_alias])
            if count is None:
                return None
            payload = (
                [{column: combined[output_alias] for column, output_alias in query_aliases}]
                if count == 1
                else []
            )
            definition = self._queries[query_id]
            execution = ToolExecution(
                tool=self.name,
                status=ToolState.SUCCESS,
                payload=payload,
                duration_seconds=duration,
                exit_code=result.returncode,
                metadata={
                    "query_id": query_id,
                    "category": definition.category,
                    "count": count,
                    "batched": True,
                    "batch_size": len(plan.query_ids),
                    "cache_hit": False,
                },
            )
            executions[query_id] = execution
        for query_id, execution in executions.items():
            self._store_cached(query_id, executable, execution)
        return executions

    def run_registered(
        self,
        query_ids: Sequence[str],
        *,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> dict[str, ToolExecution[list[dict[str, object]]]]:
        if not query_ids or len(query_ids) > len(self._queries):
            raise ValueError("query selection must be non-empty and bounded")
        if len(set(query_ids)) != len(query_ids):
            raise ValueError("query selection contains duplicates")

        selected = tuple(self.validate_input(query_id) for query_id in query_ids)
        executable = self._find_executable()
        if executable is None:
            return {
                query_id: ToolExecution(
                    tool=self.name,
                    status=ToolState.UNAVAILABLE,
                    error="osquery executable is unavailable",
                    metadata={"query_id": query_id},
                )
                for query_id in selected
            }
        if deadline_at is not None and deadline_at - time.monotonic() <= 0:
            return {
                query_id: ToolExecution(
                    tool=self.name,
                    status=ToolState.TIMEOUT,
                    error="scan deadline exhausted before osquery query started",
                    metadata={"query_id": query_id},
                )
                for query_id in selected
            }

        outcomes: dict[str, ToolExecution[list[dict[str, object]]]] = {}
        misses: list[str] = []
        for query_id in selected:
            cached = self._cached(query_id, executable)
            if cached is None:
                misses.append(query_id)
            else:
                outcomes[query_id] = cached

        def execute_with_budget(
            query_id: str,
        ) -> ToolExecution[list[dict[str, object]]]:
            effective_timeout = timeout_seconds
            if deadline_at is not None:
                remaining = deadline_at - time.monotonic()
                if remaining <= 0:
                    return ToolExecution(
                        tool=self.name,
                        status=ToolState.TIMEOUT,
                        error="scan deadline exhausted before osquery query started",
                        metadata={"query_id": query_id},
                    )
                effective_timeout = (
                    remaining if effective_timeout is None else min(effective_timeout, remaining)
                )
            return self.execute(query_id, timeout_seconds=effective_timeout)

        def execute_unit(
            unit: tuple[str, ...],
        ) -> dict[str, ToolExecution[list[dict[str, object]]]]:
            if len(unit) == 1:
                return {unit[0]: execute_with_budget(unit[0])}
            effective_timeout = timeout_seconds
            if deadline_at is not None:
                remaining = deadline_at - time.monotonic()
                if remaining <= 0:
                    return {
                        query_id: ToolExecution(
                            tool=self.name,
                            status=ToolState.TIMEOUT,
                            error="scan deadline exhausted before osquery batch started",
                            metadata={"query_id": query_id},
                        )
                        for query_id in unit
                    }
                effective_timeout = (
                    remaining if effective_timeout is None else min(effective_timeout, remaining)
                )
            plan = self._make_batch_plan(unit)
            batched = (
                self._execute_batch(plan, timeout_seconds=effective_timeout)
                if plan is not None
                else None
            )
            if batched is not None:
                return batched
            return {
                query_id: self._copy_execution(
                    execute_with_budget(query_id),
                    batch_fallback=True,
                )
                for query_id in unit
            }

        units = self._batch_units(misses)
        if not units:
            return {query_id: outcomes[query_id] for query_id in selected}
        worker_count = min(self._max_concurrency, len(units))
        if worker_count == 1:
            for unit in units:
                outcomes.update(execute_unit(unit))
            return {query_id: outcomes[query_id] for query_id in selected}
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="scanner-osquery",
        ) as executor:
            futures = {unit: executor.submit(execute_unit, unit) for unit in units}
            for unit in units:
                outcomes.update(futures[unit].result())
        # Preserve registry order so normalized output and reports remain deterministic.
        return {query_id: outcomes[query_id] for query_id in selected}
