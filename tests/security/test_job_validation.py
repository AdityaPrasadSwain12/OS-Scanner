from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from app.orchestrator.job_loader import JobValidationError, load_job_json


def valid_job() -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "scan_id": "scan-1",
        "scan_type": "QUICK",
        "endpoint_id": "endpoint-1",
        "authorization": {
            "scope_id": "scope-1",
            "authorized": True,
            "authorization_reference": "change-123",
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "allowed_endpoint_ids": ["endpoint-1"],
        },
    }


def test_job_rejects_duplicate_properties() -> None:
    with pytest.raises(JobValidationError, match="duplicate"):
        load_job_json('{"scan_type":"QUICK","scan_type":"FULL"}')


def test_job_rejects_unauthorized_endpoint() -> None:
    job = valid_job()
    job["endpoint_id"] = "outside-scope"
    with pytest.raises(JobValidationError, match="outside the authorized scope"):
        load_job_json(json.dumps(job))


def test_job_revalidates_authorization_at_execution() -> None:
    job = load_job_json(json.dumps(valid_job()))
    job.validate_for_execution()


def test_job_size_is_bounded() -> None:
    with pytest.raises(JobValidationError, match="maximum"):
        load_job_json("{" + " " * 2000 + "}", max_bytes=1024)

