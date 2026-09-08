"""Normalize external security-tool records into public scanner models."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import ValidationError

from app.models import (
    AssetType,
    AttackSurfaceAsset,
    ComplianceResult,
    ComplianceStatus,
    Severity,
    Vulnerability,
)

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "MODERATE": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "INFORMATIONAL": Severity.INFO,
    "UNKNOWN": Severity.INFO,
}


def _severity(value: object) -> Severity:
    return _SEVERITY.get(str(value).upper(), Severity.INFO)


def _validation_error_type(exc: ValidationError | TypeError) -> str:
    if isinstance(exc, ValidationError):
        return str(exc.errors()[0]["type"])
    return "invalid_type"


def normalize_osv(
    records: Sequence[Mapping[str, Any]], *, scan_id: str, endpoint_id: str
) -> tuple[list[Vulnerability], list[str]]:
    normalized: list[Vulnerability] = []
    warnings: list[str] = []
    for record in records:
        package = record.get("package")
        package_data = package if isinstance(package, Mapping) else {}
        try:
            normalized.append(
                Vulnerability(
                    scan_id=scan_id,
                    endpoint_id=endpoint_id,
                    vulnerability_id=str(record.get("vulnerability_id", "")),
                    package_name=str(package_data.get("name") or "unknown"),
                    package_ecosystem=str(package_data.get("ecosystem") or "") or None,
                    installed_version=str(package_data.get("version") or "") or None,
                    affected_versions=[
                        str(item) for item in record.get("affected_versions", [])
                    ][:512],
                    fixed_versions=[str(item) for item in record.get("fixed_versions", [])][:512],
                    aliases={str(item) for item in record.get("aliases", [])},
                    severity=_severity(record.get("severity")),
                    cvss_score=record.get("cvss_score"),
                    exploitability=record.get("exploitability"),
                    known_exploited=record.get("known_exploited") is True,
                    summary=str(record.get("summary") or record.get("details") or "") or None,
                    references=[str(item) for item in record.get("references", [])],
                    evidence={
                        "source_tool": "osv-scanner",
                        "source_path": str(record.get("source_path") or ""),
                        "severity_scores": record.get("severity_scores", []),
                    },
                )
            )
        except (ValidationError, TypeError) as exc:
            warnings.append(f"OSV record rejected: {_validation_error_type(exc)}")
    return normalized, warnings


def normalize_depscan(
    records: Sequence[Mapping[str, Any]], *, scan_id: str, endpoint_id: str
) -> tuple[list[Vulnerability], list[str]]:
    """Convert bounded CycloneDX VDR evidence emitted by OWASP dep-scan."""

    normalized: list[Vulnerability] = []
    warnings: list[str] = []
    for record in records:
        package = record.get("package")
        package_data = package if isinstance(package, Mapping) else {}
        raw_aliases = record.get("aliases", [])
        aliases = (
            {str(item) for item in raw_aliases[:512]}
            if isinstance(raw_aliases, list)
            else set()
        )
        raw_affected = record.get("affected_versions", [])
        affected_versions = (
            [str(item) for item in raw_affected[:512]]
            if isinstance(raw_affected, list)
            else []
        )
        raw_fixed = record.get("fixed_versions", [])
        fixed_versions = (
            [str(item) for item in raw_fixed[:512]]
            if isinstance(raw_fixed, list)
            else []
        )
        raw_references = record.get("references", [])
        references = (
            [str(item) for item in raw_references[:128]]
            if isinstance(raw_references, list)
            else []
        )
        raw_ratings = record.get("ratings", [])
        ratings = raw_ratings[:32] if isinstance(raw_ratings, list) else []
        raw_analysis = record.get("analysis", {})
        analysis = dict(raw_analysis) if isinstance(raw_analysis, Mapping) else {}
        raw_properties = record.get("properties", {})
        properties = (
            dict(list(raw_properties.items())[:256])
            if isinstance(raw_properties, Mapping)
            else {}
        )
        raw_insights = record.get("insights", [])
        insights = (
            [str(item) for item in raw_insights[:64]]
            if isinstance(raw_insights, list)
            else []
        )
        raw_source = record.get("source", {})
        source = dict(raw_source) if isinstance(raw_source, Mapping) else {}
        raw_provenance = record.get("provenance", {})
        provenance = (
            dict(raw_provenance) if isinstance(raw_provenance, Mapping) else {}
        )
        raw_cwes = record.get("cwes", [])
        cwes = [str(item) for item in raw_cwes[:128]] if isinstance(raw_cwes, list) else []
        raw_timestamps = record.get("timestamps", {})
        timestamps = (
            dict(raw_timestamps) if isinstance(raw_timestamps, Mapping) else {}
        )
        summary = str(
            record.get("summary")
            or record.get("details")
            or record.get("recommendation")
            or ""
        ) or None
        try:
            normalized.append(
                Vulnerability(
                    scan_id=scan_id,
                    endpoint_id=endpoint_id,
                    vulnerability_id=str(record.get("vulnerability_id", "")),
                    package_name=str(package_data.get("name") or "unknown"),
                    package_ecosystem=str(package_data.get("ecosystem") or "") or None,
                    installed_version=str(package_data.get("version") or "") or None,
                    affected_versions=affected_versions,
                    fixed_versions=fixed_versions,
                    aliases=aliases,
                    severity=_severity(record.get("severity")),
                    cvss_score=record.get("cvss_score"),
                    exploitability=record.get("exploitability"),
                    known_exploited=record.get("known_exploited") is True,
                    summary=summary,
                    references=references,
                    evidence={
                        "source_tool": "owasp-dep-scan",
                        "source": source,
                        "vulnerability_bom_ref": str(
                            record.get("vulnerability_bom_ref") or ""
                        ),
                        "bom_ref": str(package_data.get("bom_ref") or ""),
                        "purl": str(package_data.get("purl") or ""),
                        "cwes": cwes,
                        "timestamps": timestamps,
                        "ratings": ratings,
                        "analysis": analysis,
                        "properties": properties,
                        "insights": insights,
                        "prioritized": record.get("prioritized") is True,
                        "recommendation": str(record.get("recommendation") or ""),
                        "provenance": provenance,
                    },
                )
            )
        except (ValidationError, TypeError) as exc:
            warnings.append(f"DepScan record rejected: {_validation_error_type(exc)}")
    return normalized, warnings


def normalize_openscap(
    records: Sequence[Mapping[str, Any]],
    *,
    scan_id: str,
    endpoint_id: str,
    profile_id: str | None,
) -> tuple[list[ComplianceResult], list[str]]:
    normalized: list[ComplianceResult] = []
    warnings: list[str] = []
    statuses = {
        "PASSED": ComplianceStatus.PASS,
        "PASS": ComplianceStatus.PASS,
        "FAILED": ComplianceStatus.FAIL,
        "FAIL": ComplianceStatus.FAIL,
        "ERROR": ComplianceStatus.ERROR,
        "NOT_APPLICABLE": ComplianceStatus.NOT_APPLICABLE,
        "FIXED": ComplianceStatus.PASS,
    }
    for record in records:
        rule_id = str(record.get("rule_id") or "")
        raw_references = record.get("references", [])
        references = (
            [str(item) for item in raw_references[:64]]
            if isinstance(raw_references, list)
            else []
        )
        try:
            normalized.append(
                ComplianceResult(
                    scan_id=scan_id,
                    endpoint_id=endpoint_id,
                    rule_id=rule_id,
                    profile_id=profile_id,
                    title=str(record.get("title") or rule_id),
                    status=statuses.get(
                        str(record.get("status")).upper(), ComplianceStatus.UNKNOWN
                    ),
                    severity=_severity(record.get("severity")),
                    evidence=dict(record.get("evidence") or {}),
                    remediation=str(record.get("remediation") or "") or None,
                    references=references,
                )
            )
        except (ValidationError, TypeError) as exc:
            warnings.append(f"OpenSCAP record rejected: {_validation_error_type(exc)}")
    return normalized, warnings


def normalize_amass(
    records: Sequence[Mapping[str, Any]], *, scan_id: str, root_domain: str
) -> tuple[list[AttackSurfaceAsset], list[str]]:
    normalized: list[AttackSurfaceAsset] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for record in records:
        hostname = str(record.get("hostname") or record.get("name") or "").casefold().rstrip(".")
        if not hostname or hostname in seen:
            continue
        in_scope = hostname == root_domain or hostname.endswith(f".{root_domain}")
        if not in_scope:
            warnings.append("Amass returned an out-of-scope asset; it was discarded")
            continue
        seen.add(hostname)
        addresses = record.get("addresses", record.get("address", []))
        if isinstance(addresses, str):
            addresses = [addresses]
        try:
            normalized.append(
                AttackSurfaceAsset(
                    scan_id=scan_id,
                    hostname=hostname,
                    root_domain=root_domain,
                    asset_type=AssetType.DOMAIN if hostname == root_domain else AssetType.SUBDOMAIN,
                    addresses=(
                        [str(item) for item in addresses]
                        if isinstance(addresses, Sequence)
                        else []
                    ),
                    dns_records=dict(record.get("dns_records") or {}),
                    in_scope=True,
                    source="amass",
                )
            )
        except (ValidationError, TypeError) as exc:
            warnings.append(f"Amass record rejected: {_validation_error_type(exc)}")
    return normalized, warnings
