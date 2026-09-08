"""Canonicalize persisted reports at authenticated artifact boundaries."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from app.models.assessment import CanonicalAssessmentReport, build_canonical_assessment
from app.models.enums import CollectorState
from app.models.findings import Vulnerability
from app.models.results import CollectorStatus, ScanResult

from .models import bounded_json

_HYDRATABLE_INVENTORY_FIELDS = frozenset(
    {
        "endpoint",
        "os",
        "hardware",
        "software",
        "processes",
        "services",
        "users",
        "network_interfaces",
        "listening_ports",
        "security",
        "updates",
        "browser_extensions",
        "certificates",
        "persistence",
        "compliance",
        "vulnerabilities",
        "attack_surface",
    }
)
_MAX_HYDRATED_INVENTORY_NODES = 300_000
_MAX_HYDRATED_INVENTORY_BYTES = 16 * 1024 * 1024


class CanonicalReportError(ValueError):
    """Persisted data cannot be represented by the canonical report schema."""


class CanonicalReportIdentityError(CanonicalReportError):
    """A valid report is bound to a different scan or endpoint."""


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CanonicalReportError(f"{label} must be an object")
    return value


def _generated_at(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise CanonicalReportError("legacy report completion timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CanonicalReportError("legacy report completion timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CanonicalReportError("legacy report completion timestamp must include a timezone")
    return parsed


def _hydrate_endpoint_result(
    endpoint_result: object,
    endpoint_evidence: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Rejoin the real agent's summary result with server-reconstructed inventory.

    The endpoint upload deliberately separates stable scan metadata/findings from
    the content-addressed inventory envelope.  Only repository-generated
    ``reconstructed_snapshot`` data is accepted here, and only fields owned by
    :class:`ScanResult` are copied across the artifact boundary.
    """

    result = copy.deepcopy(dict(_mapping(endpoint_result, "legacy endpoint result")))
    raw_sync = endpoint_evidence.get("inventory_sync")
    if raw_sync is None:
        return result
    sync = _mapping(raw_sync, "legacy inventory synchronization evidence")
    raw_snapshot = sync.get("reconstructed_snapshot")
    if raw_snapshot is None:
        return result
    snapshot = _mapping(raw_snapshot, "server-reconstructed inventory snapshot")
    selected = {
        name: copy.deepcopy(value)
        for name, value in snapshot.items()
        if name in _HYDRATABLE_INVENTORY_FIELDS
    }
    try:
        bounded_json(
            selected,
            max_depth=32,
            max_nodes=_MAX_HYDRATED_INVENTORY_NODES,
        )
        encoded = json.dumps(
            selected,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CanonicalReportError(
            "server-reconstructed inventory snapshot exceeds artifact limits"
        ) from exc
    if len(encoded) > _MAX_HYDRATED_INVENTORY_BYTES:
        raise CanonicalReportError(
            "server-reconstructed inventory snapshot exceeds artifact limits"
        )
    result.update(selected)
    return result


def _analysis_tools(value: object) -> tuple[CollectorStatus, ...]:
    tools = _mapping(value, "legacy cloud analysis tools")
    if len(tools) > 64:
        raise CanonicalReportError("legacy cloud analysis tool count exceeds limits")
    normalized: list[CollectorStatus] = []
    for raw_name, raw_summary in tools.items():
        if not isinstance(raw_name, str):
            raise CanonicalReportError("legacy cloud analysis tool name is invalid")
        summary = _mapping(raw_summary, f"legacy {raw_name} tool summary")
        name = "osv-scanner" if raw_name.upper() == "OSV" else raw_name.casefold()
        try:
            state = CollectorState(str(summary.get("status") or "FAILED").upper())
            rejected = int(summary.get("records_rejected") or 0)
            accepted = int(summary.get("records_accepted") or 0)
            normalized.append(
                CollectorStatus(
                    name=name,
                    status=state,
                    finished_at=summary.get("finished_at"),
                    duration_seconds=summary.get("duration_seconds"),
                    tool_version=summary.get("tool_version"),
                    records_collected=accepted,
                    error_code=(
                        "CLOUD_ANALYSIS_FAILED"
                        if state in {CollectorState.FAILED, CollectorState.TIMEOUT}
                        else None
                    ),
                    error_message=summary.get("error"),
                    metadata={
                        "fixture_mode": summary.get("fixture_mode") is True,
                        "records_rejected": rejected,
                        "warnings": (
                            summary.get("warnings")
                            if isinstance(summary.get("warnings"), list)
                            else []
                        ),
                        "provenance": (
                            summary.get("provenance")
                            if isinstance(summary.get("provenance"), Mapping)
                            else {}
                        ),
                    },
                )
            )
        except (TypeError, ValidationError, ValueError) as exc:
            raise CanonicalReportError(
                f"legacy {raw_name} tool summary is invalid"
            ) from exc
    return tuple(normalized)


def canonicalize_stored_report(
    value: object,
    *,
    expected_scan_id: str,
    expected_endpoint_id: str,
    endpoint_result: object | None = None,
) -> CanonicalAssessmentReport:
    """Validate a canonical report or upgrade the bounded legacy cloud aggregate."""

    try:
        report = CanonicalAssessmentReport.model_validate(value)
    except ValidationError as canonical_error:
        legacy = _mapping(value, "persisted report")
        if legacy.get("report_type") != "CLOUD_ENDPOINT_SECURITY_REPORT":
            raise CanonicalReportError(
                "persisted report is not a supported report type"
            ) from canonical_error
        endpoint_evidence = _mapping(
            legacy.get("endpoint_evidence"), "legacy endpoint evidence"
        )
        cloud_analysis = _mapping(legacy.get("cloud_analysis"), "legacy cloud analysis")
        raw_vulnerabilities = cloud_analysis.get("vulnerabilities", [])
        if not isinstance(raw_vulnerabilities, list) or len(raw_vulnerabilities) > 100_000:
            raise CanonicalReportError(
                "legacy vulnerability collection is invalid"
            ) from canonical_error
        try:
            endpoint_scan = ScanResult.model_validate(
                _hydrate_endpoint_result(
                    (
                        endpoint_result
                        if endpoint_result is not None
                        else endpoint_evidence.get("result")
                    ),
                    endpoint_evidence,
                )
            )
            vulnerabilities = tuple(
                Vulnerability.model_validate(item) for item in raw_vulnerabilities
            )
            report_id = legacy.get("report_id")
            if not isinstance(report_id, str):
                raise CanonicalReportError("legacy report identifier is invalid")
            report = build_canonical_assessment(
                endpoint_scan,
                vulnerabilities,
                analysis_tools=_analysis_tools(cloud_analysis.get("tools", {})),
                report_id=report_id,
                generated_at=_generated_at(legacy.get("analysis_completed_at")),
            )
        except (TypeError, ValidationError, ValueError) as exc:
            if isinstance(exc, CanonicalReportError):
                raise
            raise CanonicalReportError(
                "legacy report cannot be upgraded to the canonical assessment schema"
            ) from exc

    if (
        report.endpoint_scan.scan_id != expected_scan_id
        or report.endpoint_scan.endpoint_id != expected_endpoint_id
    ):
        raise CanonicalReportIdentityError(
            "canonical report identity does not match its scan record"
        )
    return report


__all__ = [
    "CanonicalReportError",
    "CanonicalReportIdentityError",
    "canonicalize_stored_report",
]
