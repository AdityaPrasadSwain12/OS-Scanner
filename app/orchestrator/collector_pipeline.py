"""Failure-isolated collection pipeline for endpoint and discovery jobs."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.collectors import EndpointCollector
from app.core import ScannerSettings
from app.models import CollectorState, CollectorStatus, OperatingSystemFamily, ScanJob, ScanType
from app.normalization import (
    fallback_endpoint_identity,
    merge_inventory,
    merge_vulnerabilities,
    normalize_amass,
    normalize_depscan,
    normalize_native,
    normalize_openscap,
    normalize_osquery,
    normalize_osv,
)
from app.tools import (
    AmassAdapter,
    DepScanAdapter,
    DepScanMode,
    DepScanRequest,
    OpenScapAdapter,
    OsqueryAdapter,
    OsvScannerAdapter,
)
from app.tools.base import ToolState
from app.tools.osquery.queries import QueryDefinition

from .status import failed_status, native_status, tool_status, unavailable_status

_QUERIES_BY_SCAN: dict[ScanType, tuple[str, ...]] = {
    ScanType.QUICK: (
        "os_info",
        "system_info",
        "cpu_info",
        "kernel_info",
        "time_info",
        "platform_info",
        "video_info",
        "pci_devices",
        "tpm_info",
        "secure_boot",
        "uptime",
        "software",
        "software_macos",
        "packages",
        "packages_rpm",
        "packages_homebrew",
        "interfaces",
        "interfaces_windows",
        "routes",
        "dns_resolvers",
        "listening_ports",
    ),
    ScanType.FULL: (
        "os_info",
        "system_info",
        "cpu_info",
        "kernel_info",
        "time_info",
        "platform_info",
        "video_info",
        "pci_devices",
        "tpm_info",
        "secure_boot",
        "uptime",
        "software",
        "software_macos",
        "packages",
        "packages_rpm",
        "packages_homebrew",
        "processes",
        "services",
        "services_linux",
        "services_macos",
        "users",
        "groups",
        "user_groups",
        "last_logins",
        "account_status_linux",
        "interfaces",
        "interfaces_windows",
        "routes",
        "dns_resolvers",
        "mounts",
        "logical_drives",
        "listening_ports",
        "startup_items",
        "scheduled_tasks_windows",
        "crontab",
        "browser_extensions",
        "browser_extensions_firefox",
        "browser_extensions_safari",
    ),
    ScanType.COMPLIANCE: (
        "os_info",
        "system_info",
        "cpu_info",
        "kernel_info",
        "time_info",
        "platform_info",
        "video_info",
        "pci_devices",
        "tpm_info",
        "secure_boot",
        "uptime",
        "services",
        "services_linux",
        "services_macos",
        "users",
        "groups",
        "user_groups",
        "last_logins",
        "account_status_linux",
        "interfaces",
        "interfaces_windows",
        "routes",
        "dns_resolvers",
        "listening_ports",
        "startup_items",
        "scheduled_tasks_windows",
        "crontab",
    ),
    ScanType.VULNERABILITY: (
        "os_info",
        "system_info",
        "cpu_info",
        "kernel_info",
        "time_info",
        "platform_info",
        "video_info",
        "pci_devices",
        "tpm_info",
        "secure_boot",
        "software",
        "software_macos",
        "packages",
        "packages_rpm",
        "packages_homebrew",
    ),
}

_NATIVE_NAMES = frozenset({"inventory", "posture", "patches", "persistence"})

_NATIVE_CATEGORIES_BY_SCAN: dict[ScanType, frozenset[str]] = {
    ScanType.QUICK: frozenset({"inventory", "posture"}),
    ScanType.FULL: _NATIVE_NAMES,
    ScanType.COMPLIANCE: frozenset({"inventory", "posture"}),
    ScanType.VULNERABILITY: frozenset({"inventory", "patches"}),
    ScanType.ATTACK_SURFACE: frozenset(),
}

_NATIVE_INVENTORY_SECTIONS: dict[str, str] = {
    "os_info": "os",
    "hardware": "hardware",
    "software": "software",
    "processes": "processes",
    "services": "services",
    "users": "users",
    "network_interfaces": "network_interfaces",
    "listening_ports": "listening_ports",
    "browser_extensions": "browser_extensions",
    "certificates": "certificates",
}

# These Linux checks describe optional or mutually exclusive facilities. Their
# absence is a legitimate platform capability result, not a failed scan. A
# present facility that fails, times out, or returns partial data still
# degrades the category normally.
_LINUX_OPTIONAL_NATIVE_CHECKS = frozenset(
    {
        "firewall_ufw",
        "firewall_firewalld",
        "firewall_nftables",
        "selinux",
        "apparmor",
        "ssh_configuration",
        "automatic_updates",
        "security_agents",
        "ssh_configuration_file",
        "sudo_configuration",
        "password_quality",
        "login_defaults",
        "enabled_systemd_units",
    }
)


@dataclass(slots=True)
class CollectionBundle:
    inventory: dict[str, Any] = field(default_factory=fallback_endpoint_identity)
    collectors: dict[str, CollectorStatus] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)
    observed_inventory_sections: set[str] = field(default_factory=set)
    incomplete_inventory_sections: set[str] = field(default_factory=set)

    def add_status(self, status: CollectorStatus) -> None:
        name = status.name
        if name in self.collectors:
            suffix = 2
            while f"{name}.{suffix}" in self.collectors:
                suffix += 1
            status = status.model_copy(update={"name": f"{name}.{suffix}"})
        self.collectors[status.name] = status


class CollectorPipeline:
    """Own integrations but expose only normalized scanner models upstream."""

    def __init__(
        self,
        settings: ScannerSettings,
        *,
        osquery: OsqueryAdapter | None = None,
        openscap: OpenScapAdapter | None = None,
        osv_scanner: OsvScannerAdapter | None = None,
        depscan: DepScanAdapter | None = None,
        amass: AmassAdapter | None = None,
        native_factory: Callable[[], EndpointCollector] | None = None,
    ) -> None:
        self.settings = settings
        tools = settings.tools
        self.osquery = osquery or OsqueryAdapter(
            executable=str(tools.osquery_executable) if tools.osquery_executable else None,
            timeout_seconds=settings.runtime.subprocess_timeout_seconds,
            max_concurrency=settings.runtime.max_concurrency,
            max_output_bytes=settings.runtime.max_tool_output_bytes,
        )
        self.openscap = openscap or OpenScapAdapter(
            approved_roots=tuple(tools.approved_scap_content_roots),
            executable=str(tools.openscap_executable) if tools.openscap_executable else "oscap",
            timeout_seconds=min(settings.runtime.scan_timeout_seconds, 3600),
            max_result_bytes=settings.runtime.max_tool_output_bytes,
        )
        self.osv_scanner = osv_scanner or OsvScannerAdapter(
            approved_roots=tuple(tools.approved_dependency_roots),
            executable=str(tools.osv_scanner_executable) if tools.osv_scanner_executable else None,
            timeout_seconds=min(settings.runtime.scan_timeout_seconds, 3600),
            max_output_bytes=settings.runtime.max_tool_output_bytes,
        )
        self.depscan = depscan or DepScanAdapter(
            approved_roots=tuple(tools.approved_dependency_roots),
            executable=str(tools.depscan_executable) if tools.depscan_executable else None,
            timeout_seconds=min(settings.runtime.scan_timeout_seconds, 3600),
            max_console_bytes=settings.runtime.max_tool_output_bytes,
            max_report_bytes=settings.runtime.max_tool_output_bytes,
            max_vulnerabilities=min(settings.runtime.max_inventory_records, 1_000_000),
            max_components=min(settings.runtime.max_inventory_records, 1_000_000),
        )
        self.amass = amass or AmassAdapter(
            executable=str(tools.amass_executable) if tools.amass_executable else None,
            maximum_timeout_seconds=settings.discovery.timeout_seconds,
            maximum_dns_concurrency=settings.discovery.max_dns_concurrency,
            maximum_dns_queries_per_second=(
                settings.discovery.max_dns_queries_per_second
            ),
            max_output_bytes=settings.runtime.max_tool_output_bytes,
        )
        self.native_factory = native_factory or (
            lambda: EndpointCollector(
                subprocess_timeout_seconds=settings.runtime.subprocess_timeout_seconds,
                max_output_bytes=settings.runtime.max_tool_output_bytes,
            )
        )

    def collect(
        self,
        job: ScanJob,
        *,
        deadline_at: float | None = None,
    ) -> CollectionBundle:
        budget = min(float(job.timeout_seconds), self.settings.runtime.scan_timeout_seconds)
        if job.deadline is not None:
            budget = min(budget, (job.deadline - datetime.now(UTC)).total_seconds())
        if budget <= 0:
            raise TimeoutError("scan deadline expired before collection started")
        local_deadline = time.monotonic() + budget
        deadline_at = (
            local_deadline if deadline_at is None else min(deadline_at, local_deadline)
        )
        self._remaining(deadline_at)
        if job.scan_type is ScanType.ATTACK_SURFACE:
            return self._attack_surface(job, deadline_at)
        return self._endpoint(job, deadline_at)

    @staticmethod
    def _remaining(deadline_at: float) -> float:
        remaining = deadline_at - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("scan collection deadline exceeded")
        return remaining

    def _selected_queries(
        self, job: ScanJob, family: OperatingSystemFamily
    ) -> tuple[str, ...]:
        definitions = getattr(self.osquery, "_queries", {})
        registry = set(definitions)
        platform_name = family.value.casefold()
        compatible = {
            identifier
            for identifier, definition in definitions.items()
            if not isinstance(definition, QueryDefinition)
            or platform_name in definition.platforms
            or (
                family is OperatingSystemFamily.UNKNOWN
                and len(definition.platforms) == 3
            )
        }
        if job.scan_type is ScanType.ON_DEMAND:
            requested = set(job.approved_collectors) - _NATIVE_NAMES - {
                "depscan",
                "openscap",
                "osv_scanner",
            }
            unknown = requested - registry
            if unknown:
                raise ValueError(
                    f"ON_DEMAND contains unknown collector identifiers: {sorted(unknown)}"
                )
            incompatible = requested - compatible
            if incompatible:
                raise PermissionError(
                    "osquery collectors are incompatible with this platform: "
                    f"{sorted(incompatible)}"
                )
            selected = requested
        else:
            selected = set(_QUERIES_BY_SCAN.get(job.scan_type, ()))
        locally_enabled = set(self.settings.tools.enabled_osquery_queries)
        if locally_enabled:
            forbidden = selected - locally_enabled
            if job.scan_type is ScanType.ON_DEMAND and forbidden:
                raise PermissionError(
                    f"osquery collectors are disabled by local policy: {sorted(forbidden)}"
                )
            selected &= locally_enabled
        return tuple(
            identifier
            for identifier in definitions
            if identifier in selected and identifier in compatible
        )

    def _endpoint(self, job: ScanJob, deadline_at: float) -> CollectionBundle:
        assert job.endpoint_id is not None
        bundle = CollectionBundle()
        self._collect_native(job, bundle, deadline_at)
        self._remaining(deadline_at)
        self._collect_osquery(job, bundle, deadline_at)
        self._remaining(deadline_at)
        family = bundle.inventory["os"].family
        if job.scan_type in {ScanType.FULL, ScanType.COMPLIANCE} or (
            job.scan_type is ScanType.ON_DEMAND and "openscap" in job.approved_collectors
        ):
            self._collect_openscap(job, bundle, family, deadline_at)
            self._remaining(deadline_at)
        if job.scan_type in {ScanType.FULL, ScanType.VULNERABILITY} or (
            job.scan_type is ScanType.ON_DEMAND and "osv_scanner" in job.approved_collectors
        ):
            if self.settings.cloud.offload_vulnerability_analysis:
                bundle.add_status(
                    CollectorStatus(
                        name="osv-scanner.cloud",
                        status=CollectorState.SKIPPED,
                        error_message="OSV analysis is queued after endpoint evidence upload",
                        metadata={
                            "execution_location": "cloud",
                            "analysis_state": "pending_upload",
                        },
                    )
                )
            else:
                self._collect_osv(job, bundle, deadline_at)
            self._remaining(deadline_at)
        if job.scan_type in {ScanType.FULL, ScanType.VULNERABILITY} or (
            job.scan_type is ScanType.ON_DEMAND and "depscan" in job.approved_collectors
        ):
            if self.settings.cloud.offload_vulnerability_analysis:
                bundle.add_status(
                    CollectorStatus(
                        name="depscan.cloud",
                        status=CollectorState.SKIPPED,
                        error_message="dep-scan analysis is queued after endpoint evidence upload",
                        metadata={
                            "execution_location": "cloud",
                            "analysis_state": "pending_upload",
                        },
                    )
                )
            else:
                self._collect_depscan(job, bundle, deadline_at)
            self._remaining(deadline_at)
        # An independently successful source must not make a whole normalized
        # section authoritative when another scheduled contributor was partial.
        # The partial evidence remains in ``inventory`` and therefore in the
        # scan result, but snapshot replacement is intentionally suppressed.
        bundle.observed_inventory_sections.difference_update(
            bundle.incomplete_inventory_sections
        )
        self._enforce_inventory_limit(bundle)
        return bundle

    @staticmethod
    def _native_categories(job: ScanJob) -> frozenset[str]:
        if job.scan_type is ScanType.ON_DEMAND:
            return frozenset(job.approved_collectors & _NATIVE_NAMES)
        return _NATIVE_CATEGORIES_BY_SCAN.get(job.scan_type, frozenset())

    @staticmethod
    def _native_section_contributors(
        platform: str, categories: frozenset[str]
    ) -> dict[str, frozenset[str]]:
        contributors: dict[str, set[str]] = {}

        def contribute(category: str, *sections: str) -> None:
            if category not in categories:
                return
            for section in sections:
                contributors.setdefault(section, set()).add(category)

        contribute("posture", "security")
        contribute("patches", "updates")
        contribute("persistence", "persistence")
        # Patch observations are folded into SecurityPosture when posture is
        # part of the same scan (pending reboot/security-update state).
        if "posture" in categories:
            contribute("patches", "security")
        if platform.casefold() == "windows":
            contribute("posture", "users")
        return {
            section: frozenset(section_categories)
            for section, section_categories in contributors.items()
        }

    def _collect_native(
        self, job: ScanJob, bundle: CollectionBundle, deadline_at: float
    ) -> None:
        categories = self._native_categories(job)
        selected: Sequence[str] | None = None
        if job.scan_type is ScanType.ON_DEMAND:
            selected = tuple(name for name in job.approved_collectors if name in _NATIVE_NAMES)
            if not selected:
                return
        try:
            collector: Any = self.native_factory()
            if isinstance(collector, EndpointCollector):
                result = collector.collect(
                    job.scan_type.value,
                    selected,
                    deadline_at=deadline_at,
                )
            else:
                result = collector.collect(job.scan_type.value, selected)
            normalized = normalize_native(result)
            bundle.inventory = merge_inventory(bundle.inventory, normalized.data)
            platform_name = str(getattr(result, "platform", "")).casefold()
            converted_statuses: list[tuple[object, CollectorStatus]] = []
            for item in result.statuses:
                converted = native_status(item)
                check_name = str(getattr(item, "name", ""))
                raw_state = getattr(getattr(item, "status", None), "value", None)
                section = _NATIVE_INVENTORY_SECTIONS.get(check_name)
                if (
                    raw_state == ToolState.SUCCESS.value
                    and section in normalized.rejected_sections
                ):
                    converted = converted.model_copy(
                        update={
                            "status": CollectorState.PARTIAL,
                            "error_code": "NATIVE_NORMALIZATION_PARTIAL",
                            "error_message": (
                                "native data contained invalid records; this inventory "
                                "section is not authoritative"
                            ),
                        }
                    )
                elif (
                    platform_name == "linux"
                    and raw_state == ToolState.UNAVAILABLE.value
                    and check_name in _LINUX_OPTIONAL_NATIVE_CHECKS
                ):
                    converted = converted.model_copy(
                        update={
                            "status": CollectorState.SKIPPED,
                            "error_code": None,
                            "error_message": (
                                "native Linux capability is not present or applicable "
                                "on this endpoint"
                            ),
                        }
                    )
                converted_statuses.append((item, converted))
            inventory_statuses = {
                str(getattr(item, "name", "")): converted
                for item, converted in converted_statuses
                if str(getattr(item, "category", "")).casefold() == "inventory"
            }
            if "inventory" in categories:
                for check_name, section in _NATIVE_INVENTORY_SECTIONS.items():
                    check = inventory_statuses.get(check_name)
                    if (
                        check is not None
                        and check.status is CollectorState.SUCCESS
                        and section in normalized.data
                        and section not in normalized.rejected_sections
                    ):
                        # Each native inventory section is independently
                        # authoritative. A failed native check can still be
                        # replaced by a complete osquery section later.
                        bundle.observed_inventory_sections.add(section)
            statuses_by_category: dict[str, list[CollectorStatus]] = {
                category: [] for category in categories
            }
            for source_status, converted in converted_statuses:
                category = str(getattr(source_status, "category", "")).casefold()
                if category in statuses_by_category:
                    statuses_by_category[category].append(converted)
            completed_categories = {
                category
                for category, statuses in statuses_by_category.items()
                if statuses
                and any(
                    status.status is not CollectorState.SKIPPED for status in statuses
                )
                and all(
                    status.status in {CollectorState.SUCCESS, CollectorState.SKIPPED}
                    for status in statuses
                )
            }
            contributors = self._native_section_contributors(
                str(getattr(result, "platform", "")), categories
            )
            for section, required_categories in contributors.items():
                if required_categories <= completed_categories:
                    if section in normalized.data:
                        bundle.observed_inventory_sections.add(section)
                else:
                    bundle.incomplete_inventory_sections.add(section)
            bundle.warnings.extend(normalized.warnings)
            for _, converted in converted_statuses:
                bundle.add_status(converted)
        except Exception as exc:  # collector boundary: a platform adapter must not abort the job
            # The platform might be unavailable at this boundary, so use the
            # superset of platform-normalized sections for each scheduled
            # category. This prevents another source's subset from replacing a
            # section that native collection could not complete.
            bundle.incomplete_inventory_sections.update(
                section
                for section, section_categories in {
                    "security": {"posture", "patches"},
                    "users": {"posture"},
                    "updates": {"patches"},
                    "persistence": {"persistence"},
                }.items()
                if categories & section_categories
            )
            bundle.add_status(failed_status("native", exc, code="NATIVE_PIPELINE_FAILED"))

    def _collect_osquery(
        self, job: ScanJob, bundle: CollectionBundle, deadline_at: float
    ) -> None:
        try:
            if (
                isinstance(self.osquery, OsqueryAdapter)
                and self.settings.tools.osquery_executable is None
            ):
                bundle.add_status(
                    unavailable_status(
                        "osquery",
                        "optional osquery enrichment is not enabled; native inventory was used",
                        skipped=True,
                    )
                )
                return
            family = bundle.inventory["os"].family
            selected = self._selected_queries(job, family)
            if not selected:
                bundle.add_status(
                    unavailable_status(
                        "osquery", "no osquery queries are enabled", skipped=True
                    )
                )
                return
            version = (
                self.osquery.version(
                    timeout_seconds=min(5.0, self._remaining(deadline_at))
                )
                if isinstance(self.osquery, OsqueryAdapter)
                else self.osquery.version()
            )
            if version:
                bundle.tool_versions["osquery"] = version
            osquery: Any = self.osquery
            if isinstance(osquery, OsqueryAdapter):
                executions = osquery.run_registered(
                    selected,
                    deadline_at=deadline_at,
                )
            else:
                executions = osquery.run_registered(selected)
            normalized = normalize_osquery(executions)
            bundle.inventory = merge_inventory(bundle.inventory, normalized.data)
            bundle.observed_inventory_sections.update(
                section
                for section in normalized.data
                if section not in normalized.rejected_sections
            )
            bundle.warnings.extend(normalized.warnings)
            query_statuses: list[CollectorStatus] = []
            for query_id, execution in executions.items():
                status = tool_status(f"osquery.{query_id}", execution, version=version)
                query_statuses.append(status)
                bundle.add_status(status)
            states = {item.status for item in query_statuses}
            if states == {CollectorState.SUCCESS}:
                aggregate_state = CollectorState.SUCCESS
            elif CollectorState.SUCCESS in states or CollectorState.PARTIAL in states:
                aggregate_state = CollectorState.PARTIAL
            elif states == {CollectorState.UNAVAILABLE}:
                aggregate_state = CollectorState.UNAVAILABLE
            elif CollectorState.TIMEOUT in states and states <= {
                CollectorState.TIMEOUT,
                CollectorState.UNAVAILABLE,
            }:
                aggregate_state = CollectorState.TIMEOUT
            else:
                aggregate_state = CollectorState.FAILED
            aggregate_error = None
            if normalized.rejected_sections and aggregate_state is CollectorState.SUCCESS:
                aggregate_state = CollectorState.PARTIAL
                aggregate_error = (
                    "normalized osquery data contained invalid records; affected "
                    "inventory sections are not authoritative"
                )
            elif aggregate_state in {CollectorState.FAILED, CollectorState.TIMEOUT}:
                aggregate_error = "one or more controlled osquery queries failed"
            bundle.add_status(
                CollectorStatus(
                    name="osquery",
                    status=aggregate_state,
                    duration_seconds=sum(item.duration_seconds or 0 for item in query_statuses),
                    tool_version=version,
                    records_collected=sum(item.records_collected for item in query_statuses),
                    error_code=f"OSQUERY_{aggregate_state.value}" if aggregate_error else None,
                    error_message=aggregate_error,
                    metadata={"query_count": len(query_statuses)},
                )
            )
        except Exception as exc:
            bundle.add_status(failed_status("osquery", exc, code="OSQUERY_PIPELINE_FAILED"))

    def _collect_openscap(
        self,
        job: ScanJob,
        bundle: CollectionBundle,
        family: OperatingSystemFamily,
        deadline_at: float,
    ) -> None:
        if family is not OperatingSystemFamily.LINUX:
            bundle.add_status(
                unavailable_status("openscap", "OpenSCAP is supported only on Linux", skipped=True)
            )
            return
        if (
            isinstance(self.openscap, OpenScapAdapter)
            and self.settings.tools.openscap_executable is None
        ):
            bundle.add_status(
                unavailable_status(
                    "openscap",
                    "OpenSCAP is not enabled in protected local settings",
                    skipped=job.scan_type is ScanType.FULL,
                )
            )
            return
        content = self.settings.tools.default_scap_content
        profile = self.settings.tools.default_scap_profile
        if content is None or profile is None:
            bundle.add_status(
                unavailable_status(
                    "openscap",
                    "no locally approved SCAP content/profile is configured",
                    skipped=job.scan_type is ScanType.FULL,
                )
            )
            return
        version: str | None = None
        try:
            version = (
                self.openscap.version(
                    timeout_seconds=min(5.0, self._remaining(deadline_at))
                )
                if isinstance(self.openscap, OpenScapAdapter)
                else self.openscap.version()
            )
        except Exception as exc:
            bundle.add_status(
                failed_status(
                    "openscap.version",
                    exc,
                    code="OPENSCAP_VERSION_FAILED",
                )
            )
        if version:
            bundle.tool_versions["openscap"] = version
        try:
            openscap: Any = self.openscap
            if isinstance(openscap, OpenScapAdapter):
                execution = openscap.evaluate(
                    content,
                    profile,
                    timeout_seconds=self._remaining(deadline_at),
                )
            else:
                execution = openscap.evaluate(content, profile)
            status = tool_status("openscap", execution, version=version)
            if execution.status in {ToolState.SUCCESS, ToolState.PARTIAL}:
                records, warnings = normalize_openscap(
                    execution.payload or [],
                    scan_id=job.scan_id,
                    endpoint_id=job.endpoint_id or "",
                    profile_id=profile,
                )
                bundle.inventory["compliance"] = records
                bundle.observed_inventory_sections.add("compliance")
                bundle.warnings.extend(warnings)
            bundle.add_status(status)
        except Exception as exc:
            bundle.incomplete_inventory_sections.add("compliance")
            bundle.add_status(
                failed_status(
                    "openscap",
                    exc,
                    code="OPENSCAP_PIPELINE_FAILED",
                )
            )

    def _collect_osv(
        self, job: ScanJob, bundle: CollectionBundle, deadline_at: float
    ) -> None:
        if not job.approved_sources:
            bundle.add_status(
                unavailable_status(
                    "osv-scanner",
                    "no approved dependency source was supplied",
                    skipped=job.scan_type is ScanType.FULL,
                )
            )
            return
        version: str | None = None
        try:
            version = (
                self.osv_scanner.version(
                    timeout_seconds=min(5.0, self._remaining(deadline_at))
                )
                if isinstance(self.osv_scanner, OsvScannerAdapter)
                else self.osv_scanner.version()
            )
        except Exception as exc:
            bundle.add_status(
                failed_status(
                    "osv-scanner.version",
                    exc,
                    code="OSV_SCANNER_VERSION_FAILED",
                )
            )
        if version:
            bundle.tool_versions["osv-scanner"] = version
        vulnerabilities: list[Any] = []
        all_sources_observed = True
        for index, source in enumerate(job.approved_sources):
            name = f"osv-scanner.{index + 1}"
            try:
                osv_scanner: Any = self.osv_scanner
                if isinstance(osv_scanner, OsvScannerAdapter):
                    execution = osv_scanner.scan(
                        Path(source),
                        deadline_at=deadline_at,
                    )
                else:
                    execution = osv_scanner.scan(Path(source))
                status = tool_status(name, execution, version=version)
                execution_warnings = list(execution.warnings)
                records: list[Any] = []
                normalization_warnings: list[str] = []
                if (
                    execution.status in {ToolState.SUCCESS, ToolState.PARTIAL}
                    and execution.payload
                ):
                    records, normalization_warnings = normalize_osv(
                        execution.payload,
                        scan_id=job.scan_id,
                        endpoint_id=job.endpoint_id or "",
                    )
            except Exception as exc:
                all_sources_observed = False
                bundle.add_status(
                    failed_status(
                        name,
                        exc,
                        code="OSV_SCANNER_PIPELINE_FAILED",
                    )
                )
                continue
            bundle.add_status(status)
            bundle.warnings.extend(execution_warnings)
            vulnerabilities.extend(records)
            bundle.warnings.extend(normalization_warnings)
            if execution.status not in {ToolState.SUCCESS, ToolState.PARTIAL}:
                all_sources_observed = False
        existing = bundle.inventory.get("vulnerabilities", [])
        existing_records = existing if isinstance(existing, list) else []
        try:
            bundle.inventory["vulnerabilities"] = merge_vulnerabilities(
                [*existing_records, *vulnerabilities]
            )
        except Exception as exc:
            all_sources_observed = False
            bundle.inventory["vulnerabilities"] = existing_records
            bundle.add_status(
                failed_status(
                    "osv-scanner.merge",
                    exc,
                    code="OSV_SCANNER_NORMALIZATION_FAILED",
                )
            )
        if all_sources_observed:
            bundle.observed_inventory_sections.add("vulnerabilities")
        else:
            bundle.incomplete_inventory_sections.add("vulnerabilities")

    def _collect_depscan(
        self, job: ScanJob, bundle: CollectionBundle, deadline_at: float
    ) -> None:
        if (
            isinstance(self.depscan, DepScanAdapter)
            and self.settings.tools.depscan_executable is None
        ):
            bundle.add_status(
                unavailable_status(
                    "depscan",
                    "OWASP dep-scan live-OS analysis is not enabled in protected settings",
                    skipped=job.scan_type is ScanType.FULL,
                )
            )
            return

        version: str | None = None
        try:
            version = (
                self.depscan.version(
                    timeout_seconds=min(5.0, self._remaining(deadline_at))
                )
                if isinstance(self.depscan, DepScanAdapter)
                else self.depscan.version()
            )
        except Exception as exc:
            bundle.add_status(
                failed_status(
                    "depscan.version",
                    exc,
                    code="DEPSCAN_VERSION_FAILED",
                )
            )
        if version:
            bundle.tool_versions["depscan"] = version

        requests: list[tuple[str, DepScanRequest]] = [
            ("depscan.live-os", DepScanRequest(mode=DepScanMode.LIVE_OS))
        ]
        for index, raw_source in enumerate(job.approved_sources, start=1):
            source = Path(raw_source)
            if source.is_dir():
                requests.append(
                    (
                        f"depscan.source.{index}",
                        DepScanRequest(mode=DepScanMode.SOURCE, source=source),
                    )
                )
            elif source.name.casefold().endswith((".cdx.json", ".cdx")):
                requests.append(
                    (
                        f"depscan.sbom.{index}",
                        DepScanRequest(mode=DepScanMode.SBOM, source=source, deep=False),
                    )
                )
            else:
                bundle.add_status(
                    unavailable_status(
                        f"depscan.source.{index}",
                        (
                            "source is not a directory or CycloneDX SBOM; "
                            "OSV-Scanner may still analyze it"
                        ),
                        skipped=True,
                    )
                )

        vulnerabilities: list[Any] = []
        all_scheduled_observed = True
        for name, request in requests:
            try:
                depscan: Any = self.depscan
                if isinstance(depscan, DepScanAdapter):
                    execution = depscan.execute(request, deadline_at=deadline_at)
                else:
                    execution = depscan.execute(request)
                status = tool_status(name, execution, version=version)
                execution_warnings = list(execution.warnings)
                records: list[Any] = []
                normalization_warnings: list[str] = []
                if (
                    execution.status in {ToolState.SUCCESS, ToolState.PARTIAL}
                    and execution.payload
                ):
                    records, normalization_warnings = normalize_depscan(
                        execution.payload,
                        scan_id=job.scan_id,
                        endpoint_id=job.endpoint_id or "",
                    )
            except Exception as exc:
                all_scheduled_observed = False
                bundle.add_status(
                    failed_status(
                        name,
                        exc,
                        code="DEPSCAN_PIPELINE_FAILED",
                    )
                )
                continue
            bundle.add_status(status)
            bundle.warnings.extend(execution_warnings)
            vulnerabilities.extend(records)
            bundle.warnings.extend(normalization_warnings)
            if execution.status not in {ToolState.SUCCESS, ToolState.PARTIAL}:
                all_scheduled_observed = False

        existing = bundle.inventory.get("vulnerabilities", [])
        existing_records = existing if isinstance(existing, list) else []
        try:
            bundle.inventory["vulnerabilities"] = merge_vulnerabilities(
                [*existing_records, *vulnerabilities]
            )
        except Exception as exc:
            all_scheduled_observed = False
            bundle.inventory["vulnerabilities"] = existing_records
            bundle.add_status(
                failed_status(
                    "depscan.merge",
                    exc,
                    code="DEPSCAN_NORMALIZATION_FAILED",
                )
            )
        if all_scheduled_observed:
            bundle.observed_inventory_sections.add("vulnerabilities")
        else:
            bundle.incomplete_inventory_sections.add("vulnerabilities")

    def _attack_surface(self, job: ScanJob, deadline_at: float) -> CollectionBundle:
        assert job.target is not None
        bundle = CollectionBundle(inventory={})
        if not self.settings.discovery.enabled:
            bundle.add_status(
                failed_status(
                    "amass",
                    "attack-surface discovery is disabled by local policy",
                    code="DISCOVERY_DISABLED",
                )
            )
            return bundle
        local_roots = self.settings.discovery.authorized_domains
        if not any(
            job.target == root or job.target.endswith(f".{root}")
            for root in local_roots
        ):
            raise PermissionError(
                "attack-surface target is outside the locally administered discovery allowlist"
            )
        if (
            isinstance(self.amass, AmassAdapter)
            and self.settings.tools.amass_executable is None
        ):
            bundle.add_status(
                unavailable_status(
                    "amass",
                    "OWASP Amass is not enabled in protected local settings",
                    skipped=True,
                )
            )
            bundle.inventory["attack_surface"] = []
            self._enforce_inventory_limit(bundle)
            return bundle
        requested_scope = job.parameters.get("scope", [])
        requested_exclusions = job.parameters.get("exclusions", [])
        scope = (
            tuple(str(item) for item in requested_scope)
            if isinstance(requested_scope, list)
            else ()
        )
        # The adapter is intentionally scoped to the exact requested target.
        # Authorization may also contain exclusions for sibling domains, which
        # are relevant to the broader authorization record but not to this
        # invocation and would correctly fail the adapter's target-boundary
        # validation if forwarded.
        exclusions = {
            domain
            for domain in job.authorization.excluded_domains
            if domain == job.target or domain.endswith(f".{job.target}")
        }
        if isinstance(requested_exclusions, list):
            exclusions.update(str(item) for item in requested_exclusions)
        version: str | None = None
        try:
            version = (
                self.amass.version(
                    timeout_seconds=min(5.0, self._remaining(deadline_at))
                )
                if isinstance(self.amass, AmassAdapter)
                else self.amass.version()
            )
        except Exception as exc:
            bundle.add_status(
                failed_status(
                    "amass.version",
                    exc,
                    code="AMASS_VERSION_FAILED",
                )
            )
        if version:
            bundle.tool_versions["amass"] = version
        try:
            execution = self.amass.discover(
                job.target,
                # The exact requested target has passed both the authenticated job
                # scope and protected local allowlist. Do not pass broader roots to
                # the tool adapter.
                authorized_domains=(job.target,),
                authorization_id=job.authorization.scope_id,
                authorized=job.authorization.authorized,
                scope=scope,
                exclusions=tuple(sorted(exclusions)),
                max_dns_concurrency=self.settings.discovery.max_dns_concurrency,
                max_dns_queries_per_second=(
                    self.settings.discovery.max_dns_queries_per_second
                ),
                timeout_seconds=min(
                    self._remaining(deadline_at),
                    self.settings.discovery.timeout_seconds,
                ),
                max_assets=self.settings.discovery.max_discovered_assets,
            )
            status = tool_status("amass", execution, version=version)
            assets: list[Any] = []
            warnings: list[str] = []
            if execution.status in {ToolState.SUCCESS, ToolState.PARTIAL}:
                assets, warnings = normalize_amass(
                    execution.payload or [],
                    scan_id=job.scan_id,
                    root_domain=job.target,
                )
        except Exception as exc:
            bundle.add_status(
                failed_status(
                    "amass",
                    exc,
                    code="AMASS_PIPELINE_FAILED",
                )
            )
            bundle.inventory["attack_surface"] = []
        else:
            bundle.add_status(status)
            bundle.inventory["attack_surface"] = assets
            if execution.status in {ToolState.SUCCESS, ToolState.PARTIAL}:
                bundle.observed_inventory_sections.add("attack_surface")
                bundle.warnings.extend(warnings)
        self._enforce_inventory_limit(bundle)
        return bundle

    def _enforce_inventory_limit(self, bundle: CollectionBundle) -> None:
        def count_records(value: object) -> int:
            if isinstance(value, BaseModel):
                return 1 + sum(count_records(item) for item in value.__dict__.values())
            if isinstance(value, dict):
                return sum(count_records(item) for item in value.values())
            if isinstance(value, (list, tuple, set, frozenset)):
                return sum(count_records(item) for item in value)
            return 0

        count = count_records(bundle.inventory)
        if count > self.settings.runtime.max_inventory_records:
            raise ValueError(
                "normalized inventory exceeds the configured record limit "
                f"({count} > {self.settings.runtime.max_inventory_records})"
            )
