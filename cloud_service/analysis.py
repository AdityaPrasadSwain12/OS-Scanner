"""Bounded cloud vulnerability analysis over endpoint-supplied CycloneDX evidence.

The endpoint upload is treated as untrusted input even after API validation.  This
module writes only the validated SBOM to a private temporary directory and delegates
process execution to the scanner's existing no-shell, bounded tool adapters.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

from app.models import Severity, Vulnerability
from app.models.base import bounded_json
from app.normalization import merge_vulnerabilities, normalize_depscan, normalize_osv
from app.security.redaction import redact_mapping, redact_text, redact_value
from app.tools.base import ToolExecution, ToolHealth, ToolState
from app.tools.depscan import DepScanAdapter, DepScanMode, DepScanRequest
from app.tools.osv_scanner import OsvScannerAdapter, OsvScanRequest

ANALYSIS_VERSION = "1.0.0"
_SUPPORTED_TOOLS = ("OSV", "DEPSCAN")
_SUPPORTED_CYCLONEDX = frozenset({"1.4", "1.5", "1.6", "1.7"})
_FIXTURE_TIME = datetime(2000, 1, 1, tzinfo=UTC)
_FIXTURE_VERSION = "deterministic-fixture-v1"


class PermanentAnalysisError(ValueError):
    """A task cannot succeed on retry without changing its persisted input."""


class AnalysisInputError(PermanentAnalysisError):
    """Endpoint evidence is missing, malformed, inconsistent, or oversized."""


class RetryableAnalysisError(RuntimeError):
    """A transient dependency prevented analysis or report finalization."""


class _OsvAdapter(Protocol):
    def execute(
        self,
        value: OsvScanRequest,
        *,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> ToolExecution[list[dict[str, Any]]]: ...

    def health(self) -> ToolHealth: ...


class _DepScanAdapter(Protocol):
    def execute(
        self,
        value: DepScanRequest,
        *,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> ToolExecution[list[dict[str, Any]]]: ...

    def health(self) -> ToolHealth: ...


OsvAdapterFactory = Callable[[Path], _OsvAdapter]
DepScanAdapterFactory = Callable[[Path], _DepScanAdapter]


@dataclass(frozen=True, slots=True)
class AnalysisLimits:
    """Hard resource and result limits enforced independently of tool defaults."""

    max_sbom_bytes: int = 25 * 1024 * 1024
    max_components: int = 100_000
    max_vulnerabilities_per_tool: int = 50_000
    max_endpoint_evidence_bytes: int = 50 * 1024 * 1024
    max_endpoint_evidence_nodes: int = 500_000
    max_report_bytes: int = 100 * 1024 * 1024
    max_report_nodes: int = 1_000_000
    osv_timeout_seconds: float = 300.0
    depscan_timeout_seconds: float = 900.0

    def __post_init__(self) -> None:
        if not 1_024 <= self.max_sbom_bytes <= 100 * 1024 * 1024:
            raise ValueError("SBOM byte limit must be between 1 KiB and 100 MiB")
        if not 1 <= self.max_components <= 250_000:
            raise ValueError("component limit must be between 1 and 250000")
        if not 1 <= self.max_vulnerabilities_per_tool <= 50_000:
            raise ValueError("per-tool vulnerability limit must be between 1 and 50000")
        if not 1_024 <= self.max_endpoint_evidence_bytes <= 250 * 1024 * 1024:
            raise ValueError("endpoint evidence byte limit is invalid")
        if not 1_000 <= self.max_endpoint_evidence_nodes <= 2_000_000:
            raise ValueError("endpoint evidence node limit is invalid")
        if not 1_024 <= self.max_report_bytes <= 250 * 1024 * 1024:
            raise ValueError("report byte limit is invalid")
        if not 10_000 <= self.max_report_nodes <= 4_000_000:
            raise ValueError("report node limit is invalid")
        if not 1 <= self.osv_timeout_seconds <= 3_600:
            raise ValueError("OSV timeout must be between 1 and 3600 seconds")
        if not 1 <= self.depscan_timeout_seconds <= 7_200:
            raise ValueError("dep-scan timeout must be between 1 and 7200 seconds")


@dataclass(frozen=True, slots=True)
class CloudScanInput:
    """Durable endpoint evidence consumed by cloud analysis workers."""

    tenant_id: str
    endpoint_id: str
    scan_id: str
    result: Mapping[str, Any]
    inventory_sync: Mapping[str, Any]
    sbom: Mapping[str, Any]
    sbom_sha256: str | None = None
    expected_tools: tuple[str, ...] = _SUPPORTED_TOOLS

    def __post_init__(self) -> None:
        for name, value in (
            ("tenant_id", self.tenant_id),
            ("endpoint_id", self.endpoint_id),
            ("scan_id", self.scan_id),
        ):
            if not value or len(value) > 128:
                raise AnalysisInputError(f"{name} must contain 1 to 128 characters")
        normalized_tools = tuple(str(item).upper() for item in self.expected_tools)
        if not normalized_tools or len(set(normalized_tools)) != len(normalized_tools):
            raise AnalysisInputError("expected tools must be non-empty and unique")
        if any(item not in _SUPPORTED_TOOLS for item in normalized_tools):
            raise AnalysisInputError("scan input contains an unsupported analysis tool")
        object.__setattr__(self, "expected_tools", normalized_tools)
        if self.sbom_sha256 is not None:
            checksum = self.sbom_sha256.casefold()
            if len(checksum) != 64 or any(char not in "0123456789abcdef" for char in checksum):
                raise AnalysisInputError("SBOM checksum must be a SHA-256 hexadecimal digest")
            object.__setattr__(self, "sbom_sha256", checksum)
            if not self.sbom:
                raise AnalysisInputError("SBOM checksum cannot be supplied without an SBOM")


def _read_field(value: object, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def coerce_scan_input(
    value: object,
    *,
    tenant_id: str | None = None,
    endpoint_id: str | None = None,
    scan_id: str | None = None,
) -> CloudScanInput:
    """Accept the repository model without importing its persistence module."""

    if isinstance(value, CloudScanInput):
        return value
    if value is None:
        raise RetryableAnalysisError("durable scan analysis input is not available")
    upload = _read_field(value, "upload", value)
    result = _read_field(upload, "result", {})
    inventory_sync = _read_field(upload, "inventory_sync", {})
    sbom = _read_field(upload, "sbom", {})
    if sbom is None:
        sbom = {}
    if not isinstance(result, Mapping):
        raise AnalysisInputError("endpoint result evidence must be an object")
    if not isinstance(inventory_sync, Mapping):
        raise AnalysisInputError("inventory synchronization evidence must be an object")
    if not isinstance(sbom, Mapping):
        raise AnalysisInputError("CycloneDX SBOM evidence must be an object")
    expected_raw = _read_field(
        value,
        "expected_tools",
        _read_field(value, "expected_kinds", _SUPPORTED_TOOLS),
    )
    if not isinstance(expected_raw, Sequence) or isinstance(expected_raw, (str, bytes)):
        raise AnalysisInputError("expected tools must be an array")
    return CloudScanInput(
        tenant_id=str(_read_field(value, "tenant_id", tenant_id) or tenant_id or ""),
        endpoint_id=str(_read_field(value, "endpoint_id", endpoint_id) or endpoint_id or ""),
        scan_id=str(_read_field(value, "scan_id", scan_id) or scan_id or ""),
        result=result,
        inventory_sync=inventory_sync,
        sbom=sbom,
        sbom_sha256=(
            str(checksum)
            if (checksum := _read_field(upload, "sbom_sha256", None)) is not None
            else None
        ),
        expected_tools=tuple(str(item) for item in expected_raw),
    )


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AnalysisInputError("evidence is not valid JSON") from exc


def _count_components(document: Mapping[str, Any], maximum: int) -> int:
    raw_components = document.get("components", [])
    if not isinstance(raw_components, list):
        raise AnalysisInputError("CycloneDX components must be an array")
    stack: list[object] = list(raw_components)
    count = 0
    while stack:
        raw = stack.pop()
        if not isinstance(raw, Mapping):
            raise AnalysisInputError("CycloneDX component entries must be objects")
        count += 1
        if count > maximum:
            raise AnalysisInputError("CycloneDX component count exceeds the configured limit")
        nested = raw.get("components", [])
        if not isinstance(nested, list):
            raise AnalysisInputError("nested CycloneDX components must be an array")
        stack.extend(nested)
    return count


@dataclass(frozen=True, slots=True)
class _ValidatedSbom:
    document: dict[str, Any]
    content: bytes
    sha256: str
    spec_version: str
    component_count: int


def _validate_sbom(scan: CloudScanInput, limits: AnalysisLimits) -> _ValidatedSbom:
    try:
        copied = bounded_json(scan.sbom, max_depth=20, max_nodes=limits.max_report_nodes)
    except ValueError as exc:
        raise AnalysisInputError("CycloneDX SBOM exceeds structural limits") from exc
    if not isinstance(copied, dict):
        raise AnalysisInputError("CycloneDX SBOM evidence must be an object")
    if copied.get("bomFormat") != "CycloneDX":
        raise AnalysisInputError("SBOM must use the CycloneDX format")
    spec_version = str(copied.get("specVersion") or "")
    if spec_version not in _SUPPORTED_CYCLONEDX:
        raise AnalysisInputError("unsupported CycloneDX SBOM specification version")
    component_count = _count_components(copied, limits.max_components)
    content = _canonical_bytes(copied)
    if len(content) > limits.max_sbom_bytes:
        raise AnalysisInputError("CycloneDX SBOM exceeds the configured byte limit")
    digest = hashlib.sha256(content).hexdigest()
    if scan.sbom_sha256 is not None and digest != scan.sbom_sha256:
        raise AnalysisInputError("CycloneDX SBOM checksum does not match its content")
    return _ValidatedSbom(copied, content, digest, spec_version, component_count)


def _bounded_evidence(
    value: Mapping[str, Any], *, limits: AnalysisLimits, label: str
) -> dict[str, Any]:
    try:
        copied = bounded_json(
            value,
            max_depth=20,
            max_nodes=limits.max_endpoint_evidence_nodes,
        )
    except ValueError as exc:
        raise AnalysisInputError(f"{label} exceeds structural limits") from exc
    if not isinstance(copied, dict):
        raise AnalysisInputError(f"{label} must be an object")
    encoded = _canonical_bytes(copied)
    if len(encoded) > limits.max_endpoint_evidence_bytes:
        raise AnalysisInputError(f"{label} exceeds the configured byte limit")
    redacted = redact_value(
        copied,
        max_depth=20,
        max_nodes=limits.max_endpoint_evidence_nodes,
    )
    if not isinstance(redacted, dict):
        raise AnalysisInputError(f"{label} redaction produced an invalid object")
    return redacted


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _normalized_status(value: object) -> str:
    status = str(value).upper()
    allowed = {
        "SUCCESS",
        "PARTIAL",
        "FAILED",
        "UNAVAILABLE",
        "TIMEOUT",
        "SKIPPED",
    }
    return status if status in allowed else "FAILED"


def _tool_result_error(error: object) -> str | None:
    if error is None:
        return None
    cleaned = redact_text(str(error), max_length=2_048).strip()
    return cleaned or None


class CloudAnalysisEngine:
    """Execute one tool task and assemble the persisted cross-tool cloud report."""

    def __init__(
        self,
        *,
        osv_executable: str | None = None,
        depscan_executable: str | None = None,
        limits: AnalysisLimits | None = None,
        osv_factory: OsvAdapterFactory | None = None,
        depscan_factory: DepScanAdapterFactory | None = None,
        fixture_mode: bool = False,
        fixture_records: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.limits = limits or AnalysisLimits()
        self._osv_executable = osv_executable
        self._depscan_executable = depscan_executable
        self._osv_configured = osv_executable is not None or osv_factory is not None
        self._depscan_configured = depscan_executable is not None or depscan_factory is not None
        self._clock = clock or (lambda: datetime.now(UTC))
        self.fixture_mode = fixture_mode
        self._fixture_records = {
            str(key).upper(): tuple(dict(record) for record in records)
            for key, records in (fixture_records or {}).items()
        }
        if fixture_mode and any(
            value is not None
            for value in (osv_executable, depscan_executable, osv_factory, depscan_factory)
        ):
            raise ValueError("fixture mode cannot be combined with executable tool configuration")
        if any(key not in _SUPPORTED_TOOLS for key in self._fixture_records):
            raise ValueError("fixture records contain an unsupported tool")

        self._osv_factory = osv_factory or self._default_osv_factory
        self._depscan_factory = depscan_factory or self._default_depscan_factory

    @property
    def expected_tools(self) -> tuple[str, ...]:
        return _SUPPORTED_TOOLS

    def _now(self) -> datetime:
        value = _FIXTURE_TIME if self.fixture_mode else self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("analysis clock must return a timezone-aware timestamp")
        return value.astimezone(UTC)

    def _default_osv_factory(self, approved_root: Path) -> _OsvAdapter:
        return cast(
            _OsvAdapter,
            OsvScannerAdapter(
                approved_roots=(approved_root,),
                executable=self._osv_executable,
                timeout_seconds=self.limits.osv_timeout_seconds,
                max_output_bytes=min(self.limits.max_report_bytes, 100 * 1024 * 1024),
            ),
        )

    def _default_depscan_factory(self, approved_root: Path) -> _DepScanAdapter:
        cache_environment = {
            name: value
            for name in ("HOME", "VDB_HOME", "XDG_CACHE_HOME")
            if (value := os.environ.get(name))
        }
        return cast(
            _DepScanAdapter,
            DepScanAdapter(
                approved_roots=(approved_root,),
                executable=self._depscan_executable,
                timeout_seconds=self.limits.depscan_timeout_seconds,
                max_report_bytes=min(self.limits.max_report_bytes, 100 * 1024 * 1024),
                max_vulnerabilities=self.limits.max_vulnerabilities_per_tool,
                max_components=self.limits.max_components,
                environment=cache_environment,
            ),
        )

    def health(self) -> dict[str, Any]:
        """Return side-effect-free readiness; it never treats fixture mode as production-ready."""

        if self.fixture_mode:
            return {
                "ready": False,
                "fixture_mode": True,
                "analysis_version": ANALYSIS_VERSION,
                "tools": {
                    tool: {"configured": False, "status": "FIXTURE", "version": _FIXTURE_VERSION}
                    for tool in _SUPPORTED_TOOLS
                },
            }
        tools: dict[str, dict[str, Any]] = {}
        configurations = {
            "OSV": self._osv_executable,
            "DEPSCAN": self._depscan_executable,
        }
        factories: dict[str, Callable[[Path], Any]] = {
            "OSV": self._osv_factory,
            "DEPSCAN": self._depscan_factory,
        }
        for tool in _SUPPORTED_TOOLS:
            configured = configurations[tool] is not None
            # A custom factory is also an explicit configuration used by embedded deployments.
            configured = configured or (
                self._osv_configured if tool == "OSV" else self._depscan_configured
            )
            if not configured:
                tools[tool] = {
                    "configured": False,
                    "status": "UNAVAILABLE",
                    "version": None,
                }
                continue
            try:
                health = factories[tool](Path(tempfile.gettempdir())).health()
                tools[tool] = {
                    "configured": True,
                    "status": health.status.value,
                    "version": health.version,
                }
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                tools[tool] = {
                    "configured": True,
                    "status": "FAILED",
                    "version": None,
                    "detail": _tool_result_error(exc),
                }
        return {
            "ready": all(item["status"] == "SUCCESS" for item in tools.values()),
            "fixture_mode": False,
            "analysis_version": ANALYSIS_VERSION,
            "tools": tools,
        }

    @staticmethod
    def _private_sbom(validated: _ValidatedSbom) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory(prefix="endpoint-cloud-analysis-")
        root = Path(temporary.name).resolve(strict=True)
        try:
            os.chmod(root, 0o700)
            target = root / "endpoint.cdx.json"
            with target.open("xb") as handle:
                handle.write(validated.content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(target, 0o600)
            return temporary, target
        except BaseException:
            temporary.cleanup()
            raise

    def _fixture_execution(self, tool: str) -> ToolExecution[list[dict[str, Any]]]:
        records = self._fixture_records.get(tool, ())
        if len(records) > self.limits.max_vulnerabilities_per_tool:
            return ToolExecution(
                tool=tool.casefold(),
                status=ToolState.FAILED,
                version=_FIXTURE_VERSION,
                error="fixture vulnerability count exceeds the configured limit",
                metadata={"fixture_mode": True},
            )
        return ToolExecution(
            tool=tool.casefold(),
            status=ToolState.SUCCESS,
            version=_FIXTURE_VERSION,
            payload=[dict(record) for record in records],
            metadata={"fixture_mode": True},
        )

    def _execute(self, tool: str, sbom_path: Path) -> ToolExecution[list[dict[str, Any]]]:
        if self.fixture_mode:
            return self._fixture_execution(tool)
        if tool == "OSV":
            if not self._osv_configured:
                return ToolExecution(
                    tool="osv-scanner",
                    status=ToolState.UNAVAILABLE,
                    error="OSV-Scanner is not configured in the cloud worker",
                )
            osv_adapter = self._osv_factory(sbom_path.parent)
            return osv_adapter.execute(
                OsvScanRequest(source=sbom_path, recursive=False),
                timeout_seconds=self.limits.osv_timeout_seconds,
            )
        if not self._depscan_configured:
            return ToolExecution(
                tool="depscan",
                status=ToolState.UNAVAILABLE,
                error="OWASP dep-scan is not configured in the cloud worker",
            )
        depscan_adapter = self._depscan_factory(sbom_path.parent)
        return depscan_adapter.execute(
            DepScanRequest(mode=DepScanMode.SBOM, source=sbom_path, deep=False),
            timeout_seconds=self.limits.depscan_timeout_seconds,
        )

    def analyze_tool(self, tool: str, scan_input: CloudScanInput | object) -> dict[str, Any]:
        """Run exactly one persisted tool task and return a terminal, storable outcome."""

        scan = coerce_scan_input(scan_input)
        normalized_tool = str(tool).upper()
        if normalized_tool not in scan.expected_tools or normalized_tool not in _SUPPORTED_TOOLS:
            raise AnalysisInputError("analysis task requests a tool outside the scan contract")
        started_at = self._now()
        if not scan.sbom:
            result = {
                "schema_version": "1.0",
                "analysis_version": ANALYSIS_VERSION,
                "tenant_id": scan.tenant_id,
                "endpoint_id": scan.endpoint_id,
                "scan_id": scan.scan_id,
                "tool": normalized_tool,
                "status": "SKIPPED",
                "fixture_mode": self.fixture_mode,
                "started_at": _iso(started_at),
                "finished_at": _iso(self._now()),
                "duration_seconds": 0.0,
                "tool_version": None,
                "error": "CycloneDX SBOM was not supplied by the endpoint",
                "warnings": [],
                "vulnerabilities": [],
                "summary": {
                    "vulnerability_count": 0,
                    "normalization_warning_count": 0,
                },
                "provenance": {
                    "execution_mode": (
                        "NON_PRODUCTION_DETERMINISTIC_FIXTURE"
                        if self.fixture_mode
                        else "CLOUD_TOOL_EXECUTION"
                    ),
                    "sbom_sha256": None,
                    "sbom_spec_version": None,
                    "sbom_component_count": None,
                    "adapter": None,
                    "tool_version": None,
                },
            }
            return self._bound_report_object(result, label="tool analysis result")
        validated = _validate_sbom(scan, self.limits)
        temporary, sbom_path = self._private_sbom(validated)
        try:
            try:
                execution = self._execute(normalized_tool, sbom_path)
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                execution = ToolExecution(
                    tool=normalized_tool.casefold(),
                    status=ToolState.FAILED,
                    error=_tool_result_error(exc),
                )
        finally:
            temporary.cleanup()
        finished_at = self._now()
        warnings = [redact_text(str(item), max_length=1_024) for item in execution.warnings[:128]]
        vulnerabilities: list[Vulnerability] = []
        if execution.ok:
            payload = execution.payload
            if not isinstance(payload, list):
                execution = ToolExecution(
                    tool=execution.tool,
                    status=ToolState.FAILED,
                    version=execution.version,
                    duration_seconds=execution.duration_seconds,
                    error="tool returned an invalid normalized payload",
                )
            elif len(payload) > self.limits.max_vulnerabilities_per_tool:
                execution = ToolExecution(
                    tool=execution.tool,
                    status=ToolState.FAILED,
                    version=execution.version,
                    duration_seconds=execution.duration_seconds,
                    error="tool vulnerability count exceeds the configured limit",
                )
            else:
                normalizer = normalize_osv if normalized_tool == "OSV" else normalize_depscan
                try:
                    vulnerabilities, normalization_warnings = normalizer(
                        cast(Sequence[Mapping[str, Any]], payload),
                        scan_id=scan.scan_id,
                        endpoint_id=scan.endpoint_id,
                    )
                    warnings.extend(normalization_warnings[:128])
                    vulnerabilities = merge_vulnerabilities(vulnerabilities)
                except (TypeError, ValueError) as exc:
                    vulnerabilities = []
                    execution = ToolExecution(
                        tool=execution.tool,
                        status=ToolState.FAILED,
                        version=execution.version,
                        duration_seconds=execution.duration_seconds,
                        error=f"tool normalization failed: {_tool_result_error(exc)}",
                    )

        if self.fixture_mode:
            vulnerabilities = [
                item.model_copy(update={"detected_at": _FIXTURE_TIME}) for item in vulnerabilities
            ]

        vulnerability_payload = [
            item.model_dump(mode="json", exclude_none=True) for item in vulnerabilities
        ]
        status = execution.status.value
        if status == "SUCCESS" and warnings:
            status = "PARTIAL"
        result = {
            "schema_version": "1.0",
            "analysis_version": ANALYSIS_VERSION,
            "tenant_id": scan.tenant_id,
            "endpoint_id": scan.endpoint_id,
            "scan_id": scan.scan_id,
            "tool": normalized_tool,
            "status": status,
            "fixture_mode": self.fixture_mode,
            "started_at": _iso(started_at),
            "finished_at": _iso(finished_at),
            "duration_seconds": max(0.0, float(execution.duration_seconds)),
            "tool_version": execution.version,
            "error": _tool_result_error(execution.error),
            "warnings": warnings,
            "vulnerabilities": vulnerability_payload,
            "summary": {
                "vulnerability_count": len(vulnerability_payload),
                "normalization_warning_count": len(warnings),
            },
            "provenance": {
                "execution_mode": (
                    "NON_PRODUCTION_DETERMINISTIC_FIXTURE"
                    if self.fixture_mode
                    else "CLOUD_TOOL_EXECUTION"
                ),
                "sbom_sha256": validated.sha256,
                "sbom_spec_version": validated.spec_version,
                "sbom_component_count": validated.component_count,
                "adapter": execution.tool,
                "tool_version": execution.version,
            },
        }
        return self._bound_report_object(result, label="tool analysis result")

    def _bound_report_object(self, value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
        try:
            copied = bounded_json(value, max_depth=20, max_nodes=self.limits.max_report_nodes)
        except ValueError as exc:
            raise PermanentAnalysisError(f"{label} exceeds structural limits") from exc
        if not isinstance(copied, dict):
            raise PermanentAnalysisError(f"{label} must be an object")
        encoded = _canonical_bytes(copied)
        if len(encoded) > self.limits.max_report_bytes:
            raise PermanentAnalysisError(f"{label} exceeds the configured byte limit")
        return copied

    def build_final_report(
        self,
        scan_input: CloudScanInput | object,
        tool_results: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Merge persisted terminal tool evidence into one normalized cloud report."""

        scan = coerce_scan_input(scan_input)
        validated = _validate_sbom(scan, self.limits) if scan.sbom else None
        endpoint_result = _bounded_evidence(
            scan.result, limits=self.limits, label="endpoint result evidence"
        )
        inventory_sync = _bounded_evidence(
            scan.inventory_sync,
            limits=self.limits,
            label="inventory synchronization evidence",
        )
        normalized_results = {str(key).upper(): value for key, value in tool_results.items()}
        missing = [tool for tool in scan.expected_tools if tool not in normalized_results]
        if missing:
            raise RetryableAnalysisError(
                "analysis results are not terminal for: " + ", ".join(sorted(missing))
            )

        merged_input: list[Vulnerability] = []
        tool_summaries: dict[str, dict[str, Any]] = {}
        completion_times: list[str] = []
        for tool in scan.expected_tools:
            raw = normalized_results[tool]
            if not isinstance(raw, Mapping):
                raise PermanentAnalysisError(f"persisted {tool} result must be an object")
            status = _normalized_status(raw.get("status"))
            # Repository-generated dead-letter summaries intentionally contain no
            # endpoint payload. Their scan ownership comes from the scoped aggregate.
            synthetic_failure = status == "FAILED" and "scan_id" not in raw
            if not synthetic_failure and str(raw.get("scan_id") or "") != scan.scan_id:
                raise PermanentAnalysisError(f"persisted {tool} result belongs to another scan")
            if not synthetic_failure and str(raw.get("endpoint_id") or "") != scan.endpoint_id:
                raise PermanentAnalysisError(f"persisted {tool} result belongs to another endpoint")
            raw_vulnerabilities = raw.get("vulnerabilities", [])
            if not isinstance(raw_vulnerabilities, list):
                raise PermanentAnalysisError(f"persisted {tool} vulnerabilities must be an array")
            if len(raw_vulnerabilities) > self.limits.max_vulnerabilities_per_tool:
                raise PermanentAnalysisError(f"persisted {tool} result exceeds record limits")
            accepted = 0
            rejected = 0
            if status not in {"SUCCESS", "PARTIAL"}:
                rejected = len(raw_vulnerabilities)
            else:
                for item in raw_vulnerabilities:
                    try:
                        merged_input.append(Vulnerability.model_validate(item))
                        accepted += 1
                    except (TypeError, ValueError):
                        rejected += 1
            finished_at = str(raw.get("finished_at") or "")
            if finished_at:
                completion_times.append(finished_at)
            tool_summaries[tool] = {
                "status": status,
                "fixture_mode": raw.get("fixture_mode") is True,
                "tool_version": str(raw.get("tool_version") or "") or None,
                "finished_at": finished_at or None,
                "duration_seconds": raw.get("duration_seconds"),
                "error": _tool_result_error(raw.get("error")),
                "warnings": [
                    redact_text(str(item), max_length=1_024)
                    for item in (
                        raw.get("warnings", []) if isinstance(raw.get("warnings", []), list) else []
                    )[:128]
                ],
                "records_accepted": accepted,
                "records_rejected": rejected,
                "provenance": redact_mapping(
                    raw.get("provenance", {})
                    if isinstance(raw.get("provenance", {}), Mapping)
                    else {}
                ),
            }

        if len(merged_input) > self.limits.max_vulnerabilities_per_tool * len(scan.expected_tools):
            raise PermanentAnalysisError("combined cloud vulnerability limit exceeded")
        merged = merge_vulnerabilities(merged_input)
        severity_counts = {severity.value: 0 for severity in Severity}
        for vulnerability in merged:
            severity_counts[vulnerability.severity.value] += 1

        statuses = {tool: summary["status"] for tool, summary in tool_summaries.items()}
        successful = sorted(tool for tool, status in statuses.items() if status == "SUCCESS")
        usable = sorted(
            tool for tool, status in statuses.items() if status in {"SUCCESS", "PARTIAL"}
        )
        # PARTIAL evidence is useful and remains in the merged result, but it is
        # never equivalent to a completed tool observation.
        degraded = sorted(tool for tool in scan.expected_tools if tool not in successful)
        fixture = self.fixture_mode or any(
            bool(summary["fixture_mode"]) for summary in tool_summaries.values()
        )
        complete = (
            not fixture
            and not degraded
            and all(int(summary["records_rejected"]) == 0 for summary in tool_summaries.values())
        )
        report_status = (
            "FIXTURE"
            if fixture
            else "SUCCESS"
            if complete
            else "PARTIAL"
            if usable or endpoint_result
            else "FAILED"
        )
        result_metadata = endpoint_result.get("metadata", {})
        full_inventory = bool(
            inventory_sync.get("reconstructed_snapshot")
            or inventory_sync.get("mode") == "full"
            or inventory_sync.get("snapshot")
            or (isinstance(result_metadata, Mapping) and result_metadata.get("inventory_complete"))
        )
        report = {
            "schema_version": "1.0",
            "report_type": "CLOUD_ENDPOINT_SECURITY_REPORT",
            "report_id": f"cloud-report:{scan.scan_id}",
            "analysis_version": ANALYSIS_VERSION,
            "tenant_id": scan.tenant_id,
            "endpoint_id": scan.endpoint_id,
            "scan_id": scan.scan_id,
            "status": report_status,
            "analysis_completed_at": (
                max(completion_times) if completion_times else _iso(self._now())
            ),
            "endpoint_evidence": {
                "result": endpoint_result,
                "inventory_sync": inventory_sync,
                "sbom": {
                    "bom_format": "CycloneDX",
                    "spec_version": validated.spec_version if validated else None,
                    "sha256": validated.sha256 if validated else None,
                    "component_count": validated.component_count if validated else None,
                },
            },
            "cloud_analysis": {
                "vulnerabilities": [
                    item.model_dump(mode="json", exclude_none=True) for item in merged
                ],
                "tools": tool_summaries,
            },
            "summary": {
                "status": report_status,
                "component_count": validated.component_count if validated else None,
                "vulnerability_count": len(merged),
                "vulnerabilities_by_severity": severity_counts,
                "successful_tools": successful,
                "usable_tools": usable,
                "degraded_tools": degraded,
            },
            "completeness": {
                "complete": complete,
                "fixture_mode": fixture,
                "endpoint_result_received": bool(endpoint_result),
                "inventory_sync_received": bool(inventory_sync),
                "full_inventory_available": full_inventory,
                "sbom_received": validated is not None,
                "expected_tools": list(scan.expected_tools),
                "terminal_tools": sorted(tool_summaries),
                "successful_tools": successful,
                "usable_tools": usable,
                "degraded_tools": degraded,
                "gaps": (["non-production deterministic fixture evidence"] if fixture else [])
                + [f"{tool} analysis status is {statuses[tool]}" for tool in degraded]
                + [
                    f"{tool} rejected normalized records"
                    for tool, summary in tool_summaries.items()
                    if int(summary["records_rejected"]) > 0
                ],
            },
            "provenance": {
                "cloud_analysis_version": ANALYSIS_VERSION,
                "endpoint_schema_version": endpoint_result.get("schema_version"),
                "endpoint_scanner_version": endpoint_result.get("scanner_version"),
                "endpoint_policy_id": endpoint_result.get("policy_id"),
                "endpoint_policy_version": endpoint_result.get("policy_version"),
                "sbom_sha256": validated.sha256 if validated else None,
                "tool_versions": {
                    tool: summary["tool_version"] for tool, summary in tool_summaries.items()
                },
            },
        }
        return self._bound_report_object(report, label="final cloud report")


__all__ = [
    "ANALYSIS_VERSION",
    "AnalysisInputError",
    "AnalysisLimits",
    "CloudAnalysisEngine",
    "CloudScanInput",
    "DepScanAdapterFactory",
    "OsvAdapterFactory",
    "PermanentAnalysisError",
    "RetryableAnalysisError",
    "coerce_scan_input",
]
