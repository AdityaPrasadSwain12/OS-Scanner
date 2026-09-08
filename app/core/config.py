"""Validated scanner configuration with secure production defaults."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from app.models import SecurityPosture, Severity
from app.models.base import SCANNER_VERSION, SCHEMA_VERSION, JsonValue, StrictModel
from app.security.url_paths import (
    ApiPathValidationError,
    validate_api_path,
    validate_base_url_path,
)

_DEFAULT_POLICY_FILENAME = "enterprise-default.yaml"


def default_policy_path() -> Path:
    """Resolve the default policy as a package-owned filesystem resource.

    Wheels are installed unpacked by supported installers, so the resource is
    a stable local path that the hardened policy loader can validate. Keeping
    it inside ``app.policies`` also supports normal, virtualenv, editable, and
    ``--target`` installations without consulting the working directory.
    """

    resource = files("app.policies.defaults").joinpath(_DEFAULT_POLICY_FILENAME)
    candidate = Path(str(resource)).resolve()
    if not resource.is_file() or not candidate.is_file():
        raise FileNotFoundError(
            "bundled enterprise-default policy is unavailable; reinstall the scanner wheel "
            "or configure policies.directory explicitly"
        )
    return candidate


class RuntimeLimits(StrictModel):
    subprocess_timeout_seconds: float = Field(default=120.0, ge=1.0, le=3_600.0)
    scan_timeout_seconds: float = Field(default=1_800.0, ge=10.0, le=86_400.0)
    max_concurrency: int = Field(default=4, ge=1, le=32)
    max_tool_output_bytes: int = Field(
        default=20 * 1024 * 1024, ge=1_024, le=100 * 1024 * 1024
    )
    max_inventory_records: int = Field(default=250_000, ge=100, le=2_000_000)
    max_policy_operations: int = Field(default=5_000_000, ge=10_000, le=100_000_000)


class RetentionSettings(StrictModel):
    """Protected local storage bounds and evidence-retention controls."""

    retention_days: int = Field(default=90, ge=1, le=3_650)
    report_retention_days: int = Field(default=30, ge=1, le=3_650)
    succeeded_upload_retention_days: int = Field(default=7, ge=1, le=365)
    max_completed_scans: int = Field(default=10_000, ge=100, le=1_000_000)
    max_report_files: int = Field(default=10_000, ge=100, le=1_000_000)
    maintenance_batch_size: int = Field(default=1_000, ge=10, le=100_000)
    max_local_storage_bytes: int = Field(
        default=5 * 1024 * 1024 * 1024,
        ge=64 * 1024 * 1024,
        le=1024 * 1024 * 1024 * 1024,
    )
    minimum_free_disk_bytes: int = Field(
        default=512 * 1024 * 1024,
        ge=16 * 1024 * 1024,
        le=1024 * 1024 * 1024 * 1024,
    )
    legal_hold_scan_ids: frozenset[str] = Field(default_factory=frozenset, max_length=10_000)

    @field_validator("legal_hold_scan_ids")
    @classmethod
    def validate_legal_holds(cls, values: frozenset[str]) -> frozenset[str]:
        pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
        if any(not pattern.fullmatch(value) for value in values):
            raise ValueError("legal-hold scan IDs must be valid bounded identifiers")
        return values


class PolicySettings(StrictModel):
    directory: Path = Field(default_factory=default_policy_path)
    cloud_sync_enabled: bool = True
    max_file_bytes: int = Field(default=2 * 1024 * 1024, ge=1_024, le=16 * 1024 * 1024)
    max_rules: int = Field(default=2_000, ge=1, le=10_000)
    max_expression_depth: int = Field(default=16, ge=1, le=64)
    allow_symlinks: bool = False


class CloudRouteSettings(StrictModel):
    """Locally administered cloud API route map; no route comes from a scan job."""

    enrollment_path: str = Field(default="/api/v1/endpoint/enroll", max_length=2_048)
    credential_rotation_path_template: str = Field(
        default="/api/v1/endpoints/{endpoint_id}/credentials/rotate", max_length=2_048
    )
    scan_submit_path: str = Field(default="/api/v1/scans", max_length=2_048)
    scan_status_path: str = Field(default="/api/v1/scans/status", max_length=2_048)
    scan_lookup_path_template: str = Field(
        default="/api/v1/scans/{scan_id}", max_length=2_048
    )
    next_scan_path_template: str = Field(
        default="/api/v1/scans/next/{endpoint_id}", max_length=2_048
    )
    policies_path: str = Field(default="/api/v1/policies", max_length=2_048)
    heartbeat_path: str = Field(default="/api/v1/heartbeat", max_length=2_048)
    attack_surface_jobs_path: str = Field(
        default="/api/v1/attack-surface/jobs", max_length=2_048
    )
    scan_rejections_path: str = Field(
        default="/api/v1/scans/rejections", max_length=2_048
    )

    @model_validator(mode="after")
    def validate_routes(self) -> CloudRouteSettings:
        templates = {
            "credential_rotation_path_template": frozenset({"endpoint_id"}),
            "scan_lookup_path_template": frozenset({"scan_id"}),
            "next_scan_path_template": frozenset({"endpoint_id"}),
        }
        for name in type(self).model_fields:
            expected = templates.get(name, frozenset())
            try:
                validate_api_path(
                    getattr(self, name), expected_placeholders=expected
                )
            except ApiPathValidationError as exc:
                if exc.kind == "placeholder":
                    raise ValueError(
                        f"cloud route {name} has invalid placeholders"
                    ) from exc
                raise ValueError(
                    f"cloud route {name} is not a safe absolute API path"
                ) from exc
        return self


class CloudAPISettings(StrictModel):
    base_url: str | None = None
    # When enabled, the endpoint collects host evidence and an SBOM but never
    # invokes OSV-Scanner or dep-scan locally. Those tools run in managed cloud
    # workers after the evidence upload has been authenticated and accepted.
    offload_vulnerability_analysis: bool = False
    # Development-only escape hatch for a Docker API bound to this host. It is
    # rejected for non-loopback origins and for staging/production settings.
    allow_insecure_loopback_http: bool = False
    tls_verify: Literal[True] = True
    ca_bundle: Path | None = None
    connect_timeout_seconds: float = Field(default=5.0, ge=0.1, le=60.0)
    read_timeout_seconds: float = Field(default=30.0, ge=0.1, le=300.0)
    max_response_bytes: int = Field(
        default=8 * 1024 * 1024, ge=1024, le=100 * 1024 * 1024
    )
    max_request_bytes: int = Field(
        default=32 * 1024 * 1024, ge=1024, le=100 * 1024 * 1024
    )
    max_retries: int = Field(default=5, ge=0, le=20)
    credential_env_var: str = Field(
        default="ENDPOINT_SCANNER_API_TOKEN", pattern=r"^[A-Z][A-Z0-9_]{2,127}$"
    )
    routes: CloudRouteSettings = Field(default_factory=CloudRouteSettings)
    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if (
            not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "cloud base_url must be an HTTPS URL without credentials, query, or fragment"
            )
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("cloud base_url has an invalid port") from exc
        if parsed.scheme not in {"https", "http"}:
            raise ValueError("cloud base_url must use HTTPS")
        if "?" in value or "#" in value:
            raise ValueError("cloud base_url cannot include query or fragment")
        try:
            validate_base_url_path(parsed.path)
        except ApiPathValidationError as exc:
            raise ValueError("cloud base_url contains an invalid path") from exc
        return value.rstrip("/")

    @model_validator(mode="after")
    def require_secure_transport(self) -> CloudAPISettings:
        if not self.tls_verify:
            raise ValueError("TLS certificate verification cannot be disabled")
        if self.base_url:
            parsed = urlsplit(self.base_url)
            if parsed.scheme == "http" and (
                not self.allow_insecure_loopback_http
                or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            ):
                raise ValueError(
                    "cloud base_url must use HTTPS unless development loopback HTTP is "
                    "explicitly enabled"
                )
        return self


class PrivacySettings(StrictModel):
    redact_logs: Literal[True] = True
    redact_command_lines: Literal[True] = True
    transmit_process_command_lines: bool = False
    collect_passwords: Literal[False] = False
    collect_password_hashes: Literal[False] = False
    collect_private_keys: Literal[False] = False
    collect_browser_secrets: Literal[False] = False
    collect_clipboard: Literal[False] = False
    collect_document_contents: Literal[False] = False
    collect_screenshots: Literal[False] = False


class DiscoverySettings(StrictModel):
    enabled: bool = False
    passive_only: bool = True
    authorized_domains: frozenset[str] = Field(default_factory=frozenset, max_length=10_000)
    max_dns_concurrency: int = Field(default=1, ge=1, le=20)
    max_dns_queries_per_second: int = Field(default=1, ge=1, le=100)
    max_discovered_assets: int = Field(default=25_000, ge=1, le=100_000)
    timeout_seconds: float = Field(default=900.0, ge=10.0, le=7_200.0)

    @field_validator("authorized_domains", mode="before")
    @classmethod
    def normalize_authorized_domains(cls, values: Any) -> frozenset[str]:
        from app.models.validators import normalize_domain

        if values is None:
            return frozenset()
        return frozenset(normalize_domain(str(value)) for value in values)

    @model_validator(mode="after")
    def require_local_authorization_roots(self) -> DiscoverySettings:
        if self.enabled and not self.authorized_domains:
            raise ValueError(
                "enabled discovery requires locally configured authorized_domains"
            )
        return self


class SchedulingSettings(StrictModel):
    """Locally authorized scan cadence for the long-running endpoint service."""

    enabled: bool = False
    startup_scan: bool = True
    periodic_interval_seconds: float | None = Field(
        default=86_400.0, ge=300.0, le=31 * 86_400.0
    )
    jitter_ratio: float = Field(default=0.10, ge=0.0, le=0.5)
    scan_type: Literal["QUICK", "FULL", "COMPLIANCE", "VULNERABILITY"] = "QUICK"
    timeout_seconds: int = Field(default=900, ge=10, le=86_400)
    approved_sources: tuple[Path, ...] = Field(default_factory=tuple, max_length=256)
    authorization_scope_id: str = Field(
        default="local-scheduler", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
    )
    authorization_reference: str = Field(
        default="protected-local-service-configuration", min_length=1, max_length=512
    )

    @model_validator(mode="after")
    def require_a_local_trigger(self) -> SchedulingSettings:
        if self.enabled and not self.startup_scan and self.periodic_interval_seconds is None:
            raise ValueError(
                "enabled scheduling requires a startup scan or periodic interval"
            )
        if self.enabled and self.scan_type == "VULNERABILITY" and not self.approved_sources:
            raise ValueError(
                "scheduled VULNERABILITY scans require protected local approved_sources"
            )
        return self


PortNumber = Annotated[int, Field(ge=1, le=65_535)]


class AnalysisSettings(StrictModel):
    """Locally controlled endpoint baseline inputs for posture analysis.

    Enforcement is opt-in so an empty allowlist never classifies every observed
    item as suspicious. Remote scan jobs cannot replace these local baselines.
    """

    enforce_administrator_allowlist: bool = False
    enforce_port_allowlist: bool = False
    enforce_service_allowlist: bool = False
    enforce_persistence_allowlist: bool = False
    enforce_browser_extension_allowlist: bool = False
    enforce_os_support_catalog: bool = False
    approved_administrator_accounts: frozenset[str] = Field(default_factory=frozenset)
    allowed_listening_ports: frozenset[PortNumber] = Field(default_factory=frozenset)
    approved_service_names: frozenset[str] = Field(default_factory=frozenset)
    approved_persistence_names: frozenset[str] = Field(default_factory=frozenset)
    approved_browser_extension_ids: frozenset[str] = Field(default_factory=frozenset)
    required_security_agent_names: frozenset[str] = Field(default_factory=frozenset)
    required_security_service_names: frozenset[str] = Field(default_factory=frozenset)
    supported_os_releases: frozenset[str] = Field(default_factory=frozenset)
    approved_security_posture: dict[str, JsonValue] = Field(default_factory=dict)
    maximum_administrator_accounts: int = Field(default=4, ge=0, le=1_000)
    stale_scan_after_days: float = Field(default=7.0, ge=0.04, le=365.0)

    @field_validator(
        "approved_administrator_accounts",
        "approved_service_names",
        "approved_persistence_names",
        "approved_browser_extension_ids",
        "required_security_agent_names",
        "required_security_service_names",
    )
    @classmethod
    def validate_baseline_names(cls, values: frozenset[str]) -> frozenset[str]:
        if len(values) > 10_000:
            raise ValueError("analysis allowlist exceeds 10,000 entries")
        if any(
            not value
            or len(value) > 512
            or any(ord(character) < 32 for character in value)
            for value in values
        ):
            raise ValueError("analysis allowlist entries must be bounded printable strings")
        return values

    @field_validator("supported_os_releases")
    @classmethod
    def validate_supported_releases(cls, values: frozenset[str]) -> frozenset[str]:
        pattern = re.compile(r"^(WINDOWS|LINUX|MACOS):[^:\x00\r\n]{1,128}$")
        if len(values) > 10_000 or any(not pattern.fullmatch(value) for value in values):
            raise ValueError(
                "supported_os_releases entries must use FAMILY:exact-version"
            )
        return values

    @field_validator("approved_security_posture", mode="before")
    @classmethod
    def validate_security_baseline(cls, value: Any) -> dict[str, JsonValue]:
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise ValueError("approved_security_posture must be an object")
        prohibited = {"configuration_drift", "scan_age_days", "scan_stale"}
        unknown = set(value) - set(SecurityPosture.model_fields)
        if unknown or set(value) & prohibited:
            raise ValueError(
                "approved_security_posture contains unsupported or scanner-computed fields"
            )
        validated = SecurityPosture.model_validate(value, strict=True).model_dump(
            mode="json", exclude_none=False
        )
        return {str(key): validated[str(key)] for key in value}

    @model_validator(mode="after")
    def require_allowlists_for_enforcement(self) -> AnalysisSettings:
        pairs = (
            (self.enforce_administrator_allowlist, self.approved_administrator_accounts),
            (self.enforce_port_allowlist, self.allowed_listening_ports),
            (self.enforce_service_allowlist, self.approved_service_names),
            (self.enforce_persistence_allowlist, self.approved_persistence_names),
            (self.enforce_browser_extension_allowlist, self.approved_browser_extension_ids),
        )
        if any(enforced and not values for enforced, values in pairs):
            raise ValueError("an analysis allowlist cannot be enforced while empty")
        if self.enforce_os_support_catalog and not self.supported_os_releases:
            raise ValueError("OS support enforcement requires a local lifecycle catalog")
        return self


def _default_risk_penalties() -> dict[Severity, float]:
    return {
        Severity.CRITICAL: 40.0,
        Severity.HIGH: 25.0,
        Severity.MEDIUM: 12.0,
        Severity.LOW: 5.0,
        Severity.INFO: 1.0,
    }


class RiskSettings(StrictModel):
    """Locally administered risk weights and health-score bands."""

    severity_penalties: dict[Severity, float] = Field(default_factory=_default_risk_penalties)
    exploitability_weight: float = Field(default=0.25, ge=0.0, le=1.0)
    asset_criticality_weight: float = Field(default=0.20, ge=0.0, le=1.0)
    exposure_weight: float = Field(default=0.20, ge=0.0, le=1.0)
    compliance_impact_weight: float = Field(default=0.20, ge=0.0, le=1.0)
    age_weight: float = Field(default=0.15, ge=0.0, le=1.0)
    age_saturation_days: float = Field(default=90.0, gt=0.0, le=3_650.0)
    acknowledged_multiplier: float = Field(default=0.85, ge=0.0, le=1.0)
    healthy_minimum: float = Field(default=85.0, ge=0.0, le=100.0)
    low_minimum: float = Field(default=70.0, ge=0.0, le=100.0)
    medium_minimum: float = Field(default=50.0, ge=0.0, le=100.0)
    high_minimum: float = Field(default=30.0, ge=0.0, le=100.0)

    @field_validator("severity_penalties")
    @classmethod
    def validate_penalties(cls, values: dict[Severity, float]) -> dict[Severity, float]:
        if set(values) != set(Severity):
            raise ValueError("risk severity_penalties must define every severity exactly once")
        if any(not 0 <= value <= 100 for value in values.values()):
            raise ValueError("risk severity penalties must be between 0 and 100")
        if not (
            values[Severity.CRITICAL]
            >= values[Severity.HIGH]
            >= values[Severity.MEDIUM]
            >= values[Severity.LOW]
            >= values[Severity.INFO]
        ):
            raise ValueError("risk severity penalties must descend from CRITICAL to INFO")
        return values

    @model_validator(mode="after")
    def validate_bands(self) -> RiskSettings:
        if not (
            100
            >= self.healthy_minimum
            > self.low_minimum
            > self.medium_minimum
            > self.high_minimum
            >= 0
        ):
            raise ValueError("risk score bands must be strictly descending")
        return self


class ToolSettings(StrictModel):
    """Locally administered executable and content allowlists.

    A remote job may select from these values but cannot introduce a new query,
    dependency root, or SCAP content location.
    """

    osquery_executable: Path | None = None
    enabled_osquery_queries: frozenset[str] = Field(default_factory=frozenset, max_length=256)
    osv_scanner_executable: Path | None = None
    depscan_executable: Path | None = None
    approved_dependency_roots: tuple[Path, ...] = Field(default_factory=tuple, max_length=256)
    openscap_executable: Path | None = None
    approved_scap_content_roots: tuple[Path, ...] = Field(default_factory=tuple, max_length=64)
    default_scap_content: Path | None = None
    default_scap_profile: str | None = Field(
        default=None, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    )
    amass_executable: Path | None = None

    @field_validator("enabled_osquery_queries")
    @classmethod
    def validate_query_names(cls, values: frozenset[str]) -> frozenset[str]:
        pattern = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
        if any(not pattern.fullmatch(value) for value in values):
            raise ValueError("osquery selections must be controlled registry names")
        return values

    @model_validator(mode="after")
    def validate_scap_default(self) -> ToolSettings:
        if self.default_scap_content:
            content = self.default_scap_content.resolve()
            roots = tuple(root.resolve() for root in self.approved_scap_content_roots)
            if not roots or not any(content.is_relative_to(root) for root in roots):
                raise ValueError(
                    "default SCAP content must be within an approved local content root"
                )
        return self


class ScannerSettings(StrictModel):
    scanner_version: str = Field(
        default=SCANNER_VERSION,
        pattern=r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$",
        max_length=64,
    )
    schema_version: str = Field(default=SCHEMA_VERSION, pattern=r"^\d+\.\d+$", max_length=16)
    environment: Literal["production", "staging", "development", "test"] = "production"
    data_directory: Path = Path("data")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    runtime: RuntimeLimits = Field(default_factory=RuntimeLimits)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)
    policies: PolicySettings = Field(default_factory=PolicySettings)
    cloud: CloudAPISettings = Field(default_factory=CloudAPISettings)
    privacy: PrivacySettings = Field(default_factory=PrivacySettings)
    discovery: DiscoverySettings = Field(default_factory=DiscoverySettings)
    scheduling: SchedulingSettings = Field(default_factory=SchedulingSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    risk: RiskSettings = Field(default_factory=RiskSettings)
    tools: ToolSettings = Field(default_factory=ToolSettings)

    @model_validator(mode="after")
    def validate_scheduled_dependency_sources(self) -> ScannerSettings:
        if (
            self.cloud.allow_insecure_loopback_http
            and self.environment not in {"development", "test"}
        ):
            raise ValueError(
                "insecure loopback HTTP is allowed only in development or test environments"
            )
        roots = tuple(root.expanduser().resolve() for root in self.tools.approved_dependency_roots)
        for source in self.scheduling.approved_sources:
            resolved = source.expanduser().resolve()
            if not roots or not any(
                resolved == root or resolved.is_relative_to(root) for root in roots
            ):
                raise ValueError(
                    "scheduled approved_sources must remain within approved dependency roots"
                )
        return self

    @property
    def database_path(self) -> Path:
        return self.data_directory / "scanner.sqlite3"

    @property
    def report_directory(self) -> Path:
        return self.data_directory / "reports"

    @classmethod
    def from_env(
        cls, prefix: str = "SCANNER_", environ: Mapping[str, str] | None = None
    ) -> ScannerSettings:
        """Load a deliberately small environment-variable allowlist.

        Credentials are referenced only by environment variable *name* and are
        never read into this serializable settings model.
        """

        source = os.environ if environ is None else environ
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", prefix) or not prefix.endswith("_"):
            raise ValueError(
                "environment prefix must be uppercase and end-user controlled keys are not accepted"
            )
        converters: dict[str, tuple[tuple[str, ...], Any]] = {
            "VERSION": (("scanner_version",), str),
            "SCHEMA_VERSION": (("schema_version",), str),
            "ENVIRONMENT": (("environment",), str),
            "DATA_DIRECTORY": (("data_directory",), str),
            "LOG_LEVEL": (("log_level",), str),
            "MAX_CONCURRENCY": (("runtime", "max_concurrency"), int),
            "SUBPROCESS_TIMEOUT_SECONDS": (("runtime", "subprocess_timeout_seconds"), float),
            "MAX_TOOL_OUTPUT_BYTES": (("runtime", "max_tool_output_bytes"), int),
            "MAX_LOCAL_STORAGE_BYTES": (("retention", "max_local_storage_bytes"), int),
            "MINIMUM_FREE_DISK_BYTES": (("retention", "minimum_free_disk_bytes"), int),
            "POLICY_DIRECTORY": (("policies", "directory"), str),
            "POLICY_MAX_FILE_BYTES": (("policies", "max_file_bytes"), int),
            "CLOUD_BASE_URL": (("cloud", "base_url"), str),
            "CLOUD_ALLOW_INSECURE_LOOPBACK_HTTP": (
                ("cloud", "allow_insecure_loopback_http"),
                _parse_bool,
            ),
            "CLOUD_TLS_VERIFY": (("cloud", "tls_verify"), _parse_bool),
            "CLOUD_CA_BUNDLE": (("cloud", "ca_bundle"), str),
            "CLOUD_CREDENTIAL_ENV_VAR": (("cloud", "credential_env_var"), str),
            "DISCOVERY_ENABLED": (("discovery", "enabled"), _parse_bool),
            "DISCOVERY_PASSIVE_ONLY": (("discovery", "passive_only"), _parse_bool),
        }
        payload: dict[str, Any] = {}
        for suffix, (path, converter) in converters.items():
            key = f"{prefix}{suffix}"
            if key not in source:
                continue
            try:
                converted = converter(source[key])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid value for {key}") from exc
            destination = payload
            for part in path[:-1]:
                destination = destination.setdefault(part, {})
            destination[path[-1]] = converted
        return cls.model_validate(payload)


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError("expected a boolean")


# A concise compatibility name for callers that use ``Config``.
Config = ScannerSettings
