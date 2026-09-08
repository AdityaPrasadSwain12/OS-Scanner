"""Validated runtime configuration for the cloud control plane."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_INSTALLER_ROOT = _PROJECT_ROOT / "dist" / "endpoint"
_DEFAULT_RELEASE_MANIFEST = _PROJECT_ROOT / "dist" / "manifest.json"


def _token_map(raw: str | None, variable: str) -> dict[str, str]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{variable} must be a JSON object") from exc
    if not isinstance(value, dict) or not value:
        raise ValueError(f"{variable} must be a non-empty JSON object")
    result: dict[str, str] = {}
    for token, tenant_id in value.items():
        if not isinstance(token, str) or not 16 <= len(token) <= 4096:
            raise ValueError(f"{variable} contains an invalid token")
        if not isinstance(tenant_id, str) or not 1 <= len(tenant_id) <= 128:
            raise ValueError(f"{variable} contains an invalid tenant identifier")
        result[token] = tenant_id
    return result


@dataclass(frozen=True, slots=True)
class CloudServiceSettings:
    """Settings are injectable so tests never require PostgreSQL or environment secrets."""

    environment: str = "development"
    database_url: str | None = None
    credential_pepper: str = "development-only-credential-pepper-change-me"
    bootstrap_tokens: Mapping[str, str] = field(default_factory=dict)
    admin_tokens: Mapping[str, str] = field(default_factory=dict)
    credential_ttl_seconds: int = 30 * 24 * 60 * 60
    credential_rotation_overlap_seconds: int = 5 * 60
    max_request_bytes: int = 32 * 1024 * 1024
    job_default_validity_seconds: int = 30 * 60
    run_migrations: bool = True
    installer_artifact_root: str = str(_DEFAULT_INSTALLER_ROOT)
    installer_manifest_path: str = str(_DEFAULT_RELEASE_MANIFEST)
    installer_max_bytes: int = 256 * 1024 * 1024
    endpoint_online_threshold_seconds: int = 120

    def __post_init__(self) -> None:
        if self.environment not in {"development", "test", "production"}:
            raise ValueError("environment must be development, test, or production")
        if self.database_url is not None and not self.database_url.startswith(
            ("postgresql://", "postgresql+psycopg://")
        ):
            raise ValueError("database_url must be a PostgreSQL URL")
        if not 32 <= len(self.credential_pepper) <= 4096:
            raise ValueError("credential_pepper must contain at least 32 characters")
        if self.environment == "production":
            if not self.database_url:
                raise ValueError("production requires SCANNER_DATABASE_URL")
            if not self.bootstrap_tokens or not self.admin_tokens:
                raise ValueError("production requires bootstrap and admin token mappings")
            if self.credential_pepper.startswith("development-only"):
                raise ValueError("production requires a unique credential pepper")
        if not 300 <= self.credential_ttl_seconds <= 366 * 24 * 60 * 60:
            raise ValueError("credential_ttl_seconds is outside the supported range")
        if not 0 <= self.credential_rotation_overlap_seconds <= 24 * 60 * 60:
            raise ValueError("credential rotation overlap is outside the supported range")
        if not 1024 <= self.max_request_bytes <= 512 * 1024 * 1024:
            raise ValueError("max_request_bytes is outside the supported range")
        if not 60 <= self.job_default_validity_seconds <= 24 * 60 * 60:
            raise ValueError("job_default_validity_seconds is outside the supported range")
        for value, name in (
            (self.installer_artifact_root, "installer_artifact_root"),
            (self.installer_manifest_path, "installer_manifest_path"),
        ):
            if not value or "\x00" in value:
                raise ValueError(f"{name} is invalid")
        if not 1024 * 1024 <= self.installer_max_bytes <= 2 * 1024 * 1024 * 1024:
            raise ValueError("installer_max_bytes is outside the supported range")
        if not 30 <= self.endpoint_online_threshold_seconds <= 24 * 60 * 60:
            raise ValueError("endpoint_online_threshold_seconds is outside the supported range")

    @classmethod
    def from_env(cls) -> CloudServiceSettings:
        return cls(
            environment=os.getenv("SCANNER_ENVIRONMENT", "development").lower(),
            database_url=os.getenv("SCANNER_DATABASE_URL") or None,
            credential_pepper=os.getenv(
                "SCANNER_CREDENTIAL_PEPPER",
                "development-only-credential-pepper-change-me",
            ),
            bootstrap_tokens=_token_map(
                os.getenv("SCANNER_BOOTSTRAP_TOKENS"), "SCANNER_BOOTSTRAP_TOKENS"
            ),
            admin_tokens=_token_map(os.getenv("SCANNER_ADMIN_TOKENS"), "SCANNER_ADMIN_TOKENS"),
            credential_ttl_seconds=int(
                os.getenv("SCANNER_CREDENTIAL_TTL_SECONDS", str(30 * 24 * 60 * 60))
            ),
            credential_rotation_overlap_seconds=int(
                os.getenv("SCANNER_CREDENTIAL_OVERLAP_SECONDS", "300")
            ),
            max_request_bytes=int(os.getenv("SCANNER_MAX_REQUEST_BYTES", str(32 * 1024 * 1024))),
            job_default_validity_seconds=int(os.getenv("SCANNER_JOB_VALIDITY_SECONDS", "1800")),
            run_migrations=os.getenv("SCANNER_RUN_MIGRATIONS", "true").lower()
            in {"1", "true", "yes"},
            installer_artifact_root=os.getenv(
                "SCANNER_INSTALLER_ARTIFACT_ROOT", str(_DEFAULT_INSTALLER_ROOT)
            ),
            installer_manifest_path=os.getenv(
                "SCANNER_INSTALLER_MANIFEST_PATH", str(_DEFAULT_RELEASE_MANIFEST)
            ),
            installer_max_bytes=int(
                os.getenv("SCANNER_INSTALLER_MAX_BYTES", str(256 * 1024 * 1024))
            ),
            endpoint_online_threshold_seconds=int(
                os.getenv("SCANNER_ENDPOINT_ONLINE_THRESHOLD_SECONDS", "120")
            ),
        )
