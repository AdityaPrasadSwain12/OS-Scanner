from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest

from app.models import OperatingSystemFamily, ScanType
from app.normalization import normalize_osquery
from app.policies import (
    EvaluationContext,
    PolicyBundle,
    PolicyCondition,
    PolicyEngine,
    PolicyRule,
)
from app.tools import ToolExecution, ToolState

pytestmark = pytest.mark.performance


def test_large_software_inventory_has_bounded_runtime_and_serialized_size_proxy() -> None:
    row_count = 20_000
    execution = ToolExecution(
        tool="osquery",
        status=ToolState.SUCCESS,
        payload=[
            {
                "name": f"enterprise-package-{index:05d}",
                "version": f"1.0.{index % 100}",
                "publisher": "Example Vendor",
            }
            for index in range(row_count)
        ],
    )

    started = time.monotonic()
    outcome = normalize_osquery({"software": execution})
    elapsed = time.monotonic() - started

    software = outcome.data["software"]
    serialized_size_proxy = sum(
        len(item.model_dump_json().encode("utf-8")) for item in software
    )
    assert len(software) == row_count
    assert serialized_size_proxy < 20 * 1024 * 1024
    assert elapsed < 30


def test_maximum_policy_pack_scale_has_bounded_runtime_and_output_proxy() -> None:
    rule_count = 2_000
    policy = PolicyBundle(
        policy_id="performance-policy",
        policy_version="1.0.0",
        rules=[
            PolicyRule(
                rule_id=f"PERF-{index:04d}",
                title=f"Performance rule {index}",
                severity="LOW",
                category="performance",
                description="Deterministic bounded policy evaluation fixture.",
                condition=PolicyCondition(
                    field="security.firewall_enabled",
                    operator="equals",
                    value=False,
                ),
                remediation="Enable the approved control.",
                platforms={OperatingSystemFamily.LINUX},
            )
            for index in range(rule_count)
        ],
    )
    context = EvaluationContext(
        scan_id="scan-performance",
        endpoint_id="endpoint-performance",
        platform=OperatingSystemFamily.LINUX,
        scan_type=ScanType.FULL,
        detected_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    started = time.monotonic()
    findings = PolicyEngine().evaluate(
        policy,
        {"security": {"firewall_enabled": False}},
        context,
        max_operations=1_000_000,
        deadline_at=time.monotonic() + 30,
    )
    elapsed = time.monotonic() - started

    serialized_size_proxy = sum(
        len(item.model_dump_json().encode("utf-8")) for item in findings
    )
    assert len(findings) == rule_count
    assert serialized_size_proxy < 20 * 1024 * 1024
    assert elapsed < 30
