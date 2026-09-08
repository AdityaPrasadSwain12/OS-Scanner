"""Shared service for explicitly authorized local endpoint scans."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import Field, field_validator

from app.core import ScannerSettings
from app.models import (
    AuthorizationScope,
    Identifier,
    ScanJob,
    ScanResult,
    ScanType,
    StrictModel,
    utc_now,
)
from app.normalization import fallback_endpoint_identity
from app.orchestrator import ScannerOrchestrator
from app.reporting import AtomicReportWriter


class LocalScanRequest(StrictModel):
    """Bounded local scan intent created only after affirmative user consent."""

    authorized: Literal[True]
    scan_type: ScanType = ScanType.QUICK
    endpoint_id: Identifier | None = None
    approved_sources: tuple[Path, ...] = Field(default_factory=tuple, max_length=256)
    timeout_seconds: int = Field(default=900, ge=10, le=86_400)
    authorization_reference: str = Field(
        default="local-device-owner-consent", min_length=1, max_length=512
    )
    origin: Literal["cli", "deep-cli"] = "cli"

    @field_validator("scan_type")
    @classmethod
    def local_scan_types_only(cls, value: ScanType) -> ScanType:
        if value not in {ScanType.QUICK, ScanType.FULL}:
            raise ValueError("local scans support only QUICK or FULL")
        return value

    @field_validator("approved_sources")
    @classmethod
    def validate_approved_sources(cls, values: tuple[Path, ...]) -> tuple[Path, ...]:
        for value in values:
            text = str(value)
            if not text or len(text) > 4096 or "\x00" in text:
                raise ValueError("approved dependency sources contain an invalid path")
        return values


@dataclass(frozen=True, slots=True)
class LocalScanOutcome:
    result: ScanResult
    report_path: Path


def default_local_endpoint_id() -> str:
    """Return a stable, bounded local endpoint identifier without exposing raw input."""

    raw_hostname = str(fallback_endpoint_identity().get("hostname") or "device")
    label = re.sub(r"[^A-Za-z0-9._-]+", "-", raw_hostname).strip("._-") or "device"
    digest = hashlib.sha256(raw_hostname.encode("utf-8")).hexdigest()[:12]
    return f"local-{label[:96]}-{digest}"


def _local_principal() -> str:
    value = os.environ.get("USERNAME") or os.environ.get("USER") or "local-user"
    cleaned = "".join(character for character in value if character >= " " and character != "\x7f")
    return cleaned[:256] or "local-user"


def build_local_scan_job(
    scanner: ScannerOrchestrator,
    request: LocalScanRequest,
) -> ScanJob:
    """Build a strict, short-lived authorization envelope for the local CLI."""

    now = utc_now()
    endpoint_id = request.endpoint_id or default_local_endpoint_id()
    deadline = now + timedelta(seconds=request.timeout_seconds)
    authorization = AuthorizationScope(
        scope_id=f"local-{request.origin}-{uuid4()}",
        authorized=True,
        authorization_reference=request.authorization_reference,
        authorized_by=_local_principal(),
        purpose="explicitly authorized scan of the local device",
        valid_from=now - timedelta(minutes=1),
        expires_at=deadline + timedelta(minutes=5),
        allowed_endpoint_ids=frozenset({endpoint_id}),
    )
    return ScanJob(
        job_id=f"job-{uuid4()}",
        scan_id=f"scan-{uuid4()}",
        scan_type=request.scan_type,
        authorization=authorization,
        endpoint_id=endpoint_id,
        policy_id=scanner.policy.policy_id,
        policy_version=scanner.policy.policy_version,
        approved_sources=tuple(str(source) for source in request.approved_sources),
        initiated_by=f"local-{request.origin}-explicit-consent",
        requested_at=now,
        deadline=deadline,
        timeout_seconds=request.timeout_seconds,
    )


def run_local_scan(
    settings: ScannerSettings,
    request: LocalScanRequest,
    *,
    orchestrator_factory: Callable[[ScannerSettings], ScannerOrchestrator] | None = None,
) -> LocalScanOutcome:
    """Execute one local scan and return its result plus absolute report path."""

    factory = orchestrator_factory or ScannerOrchestrator.from_settings
    scanner = factory(settings)
    try:
        result = scanner.execute(build_local_scan_job(scanner, request))
        report_path = (
            scanner.report_writer.directory
            / AtomicReportWriter.filename_for(result.scan_id)
        ).resolve()
        if not report_path.is_file():
            raise RuntimeError("scan completed without a readable local report")
        return LocalScanOutcome(result=result, report_path=report_path)
    finally:
        scanner.storage.close()


__all__ = [
    "LocalScanOutcome",
    "LocalScanRequest",
    "build_local_scan_job",
    "default_local_endpoint_id",
    "run_local_scan",
]
