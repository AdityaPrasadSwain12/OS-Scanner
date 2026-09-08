"""Authorized scan scope and immutable job intent."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import Field, IPvAnyNetwork, field_validator, model_validator

from .base import Identifier, JsonValue, StrictModel, bounded_json, ensure_aware, utc_now
from .enums import ScanType
from .validators import normalize_domain


class AuthorizationScope(StrictModel):
    """Explicit assets and validity window authorized by the platform."""

    scope_id: Identifier
    authorized: bool
    authorization_reference: str = Field(min_length=1, max_length=512)
    authorized_by: str | None = Field(default=None, max_length=256)
    purpose: str | None = Field(default=None, max_length=1024)
    valid_from: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    allowed_endpoint_ids: frozenset[Identifier] = Field(
        default_factory=frozenset, max_length=10_000
    )
    allowed_domains: frozenset[str] = Field(default_factory=frozenset, max_length=10_000)
    excluded_domains: frozenset[str] = Field(default_factory=frozenset, max_length=10_000)
    allow_subdomains: bool = True
    allowed_networks: tuple[IPvAnyNetwork, ...] = Field(default_factory=tuple, max_length=1024)
    excluded_networks: tuple[IPvAnyNetwork, ...] = Field(default_factory=tuple, max_length=1024)

    @field_validator("authorized", "allow_subdomains", mode="before")
    @classmethod
    def strict_authorization_booleans(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("authorization flags must be JSON booleans")
        return value

    @field_validator("valid_from", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return ensure_aware(value)

    @field_validator("allowed_endpoint_ids")
    @classmethod
    def validate_endpoint_ids(cls, values: frozenset[str]) -> frozenset[str]:
        for value in values:
            if not value or len(value) > 128 or any(character.isspace() for character in value):
                raise ValueError(
                    "authorized endpoint IDs must be non-empty and contain no whitespace"
                )
        return values

    @field_validator("allowed_domains", "excluded_domains", mode="before")
    @classmethod
    def normalize_domains(cls, values: Any) -> frozenset[str]:
        if values is None:
            return frozenset()
        return frozenset(normalize_domain(str(value)) for value in values)

    @model_validator(mode="after")
    def validate_window_and_exclusions(self) -> AuthorizationScope:
        if self.expires_at <= self.valid_from:
            raise ValueError("authorization expiration must follow its start time")
        overlap = self.allowed_domains & self.excluded_domains
        if overlap:
            raise ValueError(f"domains cannot be both allowed and excluded: {sorted(overlap)!r}")
        return self

    def is_active(self, at: datetime | None = None) -> bool:
        instant = ensure_aware(at) if at else datetime.now(UTC)
        return self.authorized and self.valid_from <= instant < self.expires_at

    def allows_endpoint(self, endpoint_id: str) -> bool:
        return endpoint_id in self.allowed_endpoint_ids

    def allows_domain(self, domain: str) -> bool:
        candidate = normalize_domain(domain)
        if any(
            candidate == denied or candidate.endswith(f".{denied}")
            for denied in self.excluded_domains
        ):
            return False
        if candidate in self.allowed_domains:
            return True
        return self.allow_subdomains and any(
            candidate.endswith(f".{allowed}") for allowed in self.allowed_domains
        )

    def allows_ip(self, address: str) -> bool:
        candidate = ipaddress.ip_address(address)
        if any(candidate in network for network in self.excluded_networks):
            return False
        return any(candidate in network for network in self.allowed_networks)


class ScanJob(StrictModel):
    """A validated, explicitly scoped unit of scanner work."""

    job_id: Identifier = Field(default_factory=lambda: f"job-{uuid4()}")
    scan_id: Identifier = Field(default_factory=lambda: str(uuid4()))
    scan_type: ScanType
    authorization: AuthorizationScope
    endpoint_id: Identifier | None = None
    target: str | None = None
    policy_id: Identifier = "enterprise-default"
    policy_version: str | None = Field(default=None, pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    approved_collectors: frozenset[str] = Field(default_factory=frozenset, max_length=128)
    approved_sources: tuple[str, ...] = Field(default_factory=tuple, max_length=512)
    initiated_by: str | None = Field(default=None, max_length=256)
    requested_at: datetime = Field(default_factory=utc_now)
    not_before: datetime | None = None
    deadline: datetime | None = None
    timeout_seconds: int = Field(default=900, ge=10, le=86_400)
    priority: int = Field(default=50, ge=0, le=100)
    parameters: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("requested_at", "not_before", "deadline")
    @classmethod
    def aware_job_times(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value) if value else None

    @field_validator("approved_collectors")
    @classmethod
    def validate_collectors(cls, values: frozenset[str]) -> frozenset[str]:
        for value in values:
            if (
                not value
                or len(value) > 64
                or not value.replace("_", "").replace("-", "").isalnum()
            ):
                raise ValueError(
                    "collector names may contain only letters, numbers, hyphens, and underscores"
                )
        return values

    @field_validator("approved_sources")
    @classmethod
    def validate_sources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value or len(value) > 4096 or "\x00" in value for value in values):
            raise ValueError("approved sources contain an invalid path or identifier")
        return values

    @field_validator("parameters", mode="before")
    @classmethod
    def validate_parameters(cls, value: Any) -> JsonValue:
        validated = bounded_json(value, max_depth=8, max_nodes=2_000)
        if not isinstance(validated, dict):
            raise ValueError("parameters must be an object")
        return validated

    @model_validator(mode="after")
    def validate_job_scope(self) -> ScanJob:
        if not self.authorization.authorized:
            raise ValueError("scan job is not explicitly authorized")
        if self.not_before and self.deadline and self.deadline <= self.not_before:
            raise ValueError("deadline must be later than not_before")
        if self.scan_type is ScanType.ATTACK_SURFACE:
            if not self.target:
                raise ValueError("ATTACK_SURFACE requires an authorized domain target")
            object.__setattr__(self, "target", normalize_domain(self.target))
            if self.endpoint_id is not None:
                raise ValueError("ATTACK_SURFACE jobs cannot specify an endpoint")
            if not self.authorization.allows_domain(self.target):
                raise ValueError("attack-surface target is outside the authorized domain scope")
        else:
            if self.target is not None:
                raise ValueError("endpoint scan jobs cannot specify an external target")
            if not self.endpoint_id:
                raise ValueError(f"{self.scan_type.value} requires endpoint_id")
            if not self.authorization.allows_endpoint(self.endpoint_id):
                raise ValueError("endpoint is outside the authorized scope")
        if self.scan_type is ScanType.ON_DEMAND and not self.approved_collectors:
            raise ValueError("ON_DEMAND requires at least one approved collector")
        self._validate_parameters_for_scope()
        return self

    def _validate_parameters_for_scope(self) -> None:
        allowed_keys = {"asset_criticality", "scope", "exclusions"}
        unknown_keys = set(self.parameters) - allowed_keys
        if unknown_keys:
            raise ValueError(f"unsupported scan parameters: {sorted(unknown_keys)!r}")
        if "asset_criticality" in self.parameters:
            criticality = self.parameters["asset_criticality"]
            if (
                isinstance(criticality, bool)
                or not isinstance(criticality, (int, float))
                or not 0 <= criticality <= 1
            ):
                raise ValueError("asset_criticality must be a number between 0 and 1")
        domain_parameters = {"scope", "exclusions"} & self.parameters.keys()
        if domain_parameters and self.scan_type is not ScanType.ATTACK_SURFACE:
            raise ValueError("domain scope parameters are valid only for ATTACK_SURFACE jobs")
        for key in domain_parameters:
            raw_domains = self.parameters[key]
            if not isinstance(raw_domains, list) or len(raw_domains) > 10_000:
                raise ValueError(f"{key} must be a bounded list of authorized domains")
            normalized_domains: list[str] = []
            for raw_domain in raw_domains:
                if not isinstance(raw_domain, str):
                    raise ValueError(f"{key} entries must be domain strings")
                domain = normalize_domain(raw_domain)
                if not self.authorization.allows_domain(domain):
                    raise ValueError(f"{key} contains a domain outside authorization scope")
                normalized_domains.append(domain)
            self.parameters[key] = normalized_domains

    def validate_for_execution(self, at: datetime | None = None) -> None:
        instant = ensure_aware(at) if at else datetime.now(UTC)
        if not self.authorization.is_active(instant):
            raise ValueError("authorization is not active at execution time")
        if self.not_before and instant < self.not_before:
            raise ValueError("job is not yet eligible for execution")
        if self.deadline and instant >= self.deadline:
            raise ValueError("job deadline has expired")


# Backwards-friendly name for integrations that call this a target scope.
TargetScope = AuthorizationScope
