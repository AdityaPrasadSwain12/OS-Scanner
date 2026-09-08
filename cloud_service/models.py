"""Strict bounded API documents; uploaded evidence remains JSON, never executable input."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
JsonObject = dict[str, Any]


def utc_now() -> datetime:
    return datetime.now(UTC)


def canonical_sha256(value: Any) -> str:
    data = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(data).hexdigest()


def bounded_json(value: Any, *, max_depth: int, max_nodes: int) -> Any:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise ValueError("JSON value exceeds structural limits")
        if item is None or isinstance(item, (str, bool, int)):
            if isinstance(item, str) and len(item) > 1_000_000:
                raise ValueError("JSON string exceeds size limit")
            continue
        if isinstance(item, float):
            if item != item or item in {float("inf"), float("-inf")}:
                raise ValueError("JSON numbers must be finite")
            continue
        if isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
            continue
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 256:
                    raise ValueError("JSON object contains an invalid key")
                stack.append((child, depth + 1))
            continue
        raise ValueError("value is not JSON compatible")
    return value


Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=IDENTIFIER.pattern)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EndpointEnrollment(StrictModel):
    hostname: str = Field(min_length=1, max_length=255)
    os_family: Literal["WINDOWS", "LINUX", "MACOS"]
    os_version: str = Field(min_length=1, max_length=256)
    architecture: str = Field(min_length=1, max_length=64)
    scanner_version: str = Field(min_length=1, max_length=64)

    @field_validator("hostname", "os_version", "architecture", "scanner_version")
    @classmethod
    def safe_text(cls, value: str) -> str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("value contains control characters")
        return value


class EnrollmentTokenRequest(StrictModel):
    """A short-lived, one-time grant used by one endpoint installation."""

    expires_in_seconds: int = Field(default=900, ge=60, le=3600)
    os_family: Literal["WINDOWS", "LINUX", "MACOS"] | None = None
    label: str | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("label")
    @classmethod
    def safe_label(cls, value: str | None) -> str | None:
        if value is not None and any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("label contains control characters")
        return value


class CredentialRotation(StrictModel):
    endpoint_id: Identifier
    generation: int = Field(ge=1, le=1_000_000)
    credential_id: Identifier


class ScanUpload(StrictModel):
    evidence_envelope_version: Literal["1.0"] = "1.0"
    result: JsonObject
    inventory_sync: JsonObject
    sbom: JsonObject | None = None
    sbom_sha256: str | None = Field(default=None, pattern=SHA256.pattern)

    @field_validator("result", "inventory_sync", "sbom", mode="before")
    @classmethod
    def bound_documents(cls, value: Any) -> Any:
        if value is None:
            return None
        checked = bounded_json(value, max_depth=32, max_nodes=500_000)
        if not isinstance(checked, dict):
            raise ValueError("document must be a JSON object")
        return checked

    @model_validator(mode="after")
    def verify_sbom(self) -> ScanUpload:
        if self.sbom is None and self.sbom_sha256 is not None:
            raise ValueError("sbom_sha256 cannot be supplied without sbom")
        if self.sbom is not None:
            digest = canonical_sha256(self.sbom)
            if self.sbom_sha256 is not None and self.sbom_sha256 != digest:
                raise ValueError("sbom_sha256 does not match canonical SBOM JSON")
            self.sbom_sha256 = digest
        return self


class ScanStatusUpload(StrictModel):
    schema_version: str = Field(min_length=1, max_length=32)
    scanner_version: str = Field(min_length=1, max_length=64)
    scan_id: Identifier
    endpoint_id: Identifier
    target: None = None
    authorization_scope_id: Identifier
    policy_id: Identifier
    policy_version: str = Field(min_length=1, max_length=32)
    policy_checksum: str | None = Field(default=None, pattern=SHA256.pattern)
    status: Literal["SUCCESS", "PARTIAL", "FAILED"]
    requested_at: datetime

    @field_validator("requested_at", mode="before")
    @classmethod
    def parse_requested_at(cls, value: Any) -> datetime:
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("requested_at must be an ISO-8601 timestamp") from exc
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("requested_at must include a timezone")
        return value


class ScanRejectionUpload(StrictModel):
    endpoint_id: Identifier
    scan_id: Identifier | None = None
    reason: Literal["INVALID_JSON", "INVALID_OR_UNAUTHORIZED_JOB"]
    document_sha256: str = Field(pattern=SHA256.pattern)


class PlatformScanRequest(StrictModel):
    endpoint_id: Identifier
    scan_type: Literal["QUICK", "FULL", "VULNERABILITY", "COMPLIANCE", "ON_DEMAND"] = (
        "FULL"
    )
    authorization_reference: str = Field(min_length=1, max_length=512)
    authorized_by: str = Field(min_length=1, max_length=256)
    purpose: str | None = Field(default=None, max_length=1024)
    validity_seconds: int = Field(default=1800, ge=60, le=86_400)
    timeout_seconds: int = Field(default=900, ge=10, le=86_400)
    policy_id: Identifier = "enterprise-default"
    policy_version: str | None = Field(default=None, max_length=32)
    approved_collectors: frozenset[str] = Field(default_factory=frozenset, max_length=128)
    priority: int = Field(default=50, ge=0, le=100)

    @field_validator("approved_collectors")
    @classmethod
    def allowlisted_collectors(cls, values: frozenset[str]) -> frozenset[str]:
        # These are endpoint-owned registry identifiers, never SQL or commands.
        # Importing the immutable registry prevents the API and agent allowlists
        # from drifting as supported osquery tables evolve.
        from app.tools.osquery.queries import DEFAULT_QUERY_REGISTRY

        allowed = set(DEFAULT_QUERY_REGISTRY) | {
            "inventory",
            "patches",
            "posture",
            "persistence",
            "openscap",
            "osv_scanner",
            "depscan",
        }
        if not values <= allowed:
            raise ValueError("approved_collectors contains an unsupported collector")
        return values

    @model_validator(mode="after")
    def on_demand_collectors(self) -> PlatformScanRequest:
        if self.scan_type == "ON_DEMAND" and not self.approved_collectors:
            raise ValueError("ON_DEMAND requires at least one approved collector")
        return self


class CredentialResponse(StrictModel):
    endpoint_id: Identifier
    access_token: str
    refresh_token: None = None
    credential_id: Identifier
    issued_at: datetime
    expires_at: datetime
    generation: int


class HealthResponse(StrictModel):
    status: Literal["ok", "not_ready"]
    timestamp: datetime = Field(default_factory=utc_now)
