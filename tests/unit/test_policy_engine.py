from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest

from app.models import OperatingSystemFamily, ScanType
from app.policies import (
    EvaluationContext,
    PolicyBundle,
    PolicyCondition,
    PolicyEngine,
    PolicyLoader,
    PolicyRule,
)


def context(**updates: object) -> EvaluationContext:
    values: dict[str, object] = {
        "scan_id": "scan-1",
        "endpoint_id": "endpoint-1",
        "platform": OperatingSystemFamily.WINDOWS,
        "scan_type": ScanType.FULL,
        "detected_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    values.update(updates)
    return EvaluationContext(**values)


def rule(condition: PolicyCondition, **updates: object) -> PolicyRule:
    values: dict[str, object] = {
        "id": "TEST-001",
        "title": "Test finding",
        "severity": "HIGH",
        "category": "endpoint_security",
        "description": "A test condition matched.",
        "condition": condition,
        "remediation": "Correct the tested control.",
    }
    values.update(updates)
    return PolicyRule(**values)


def bundle(test_rule: PolicyRule) -> PolicyBundle:
    return PolicyBundle(policy_id="test-policy", policy_version="1.2.3", rules=[test_rule])


def test_enterprise_policy_pack_has_at_least_30_valid_rules() -> None:
    loaded = PolicyLoader(trusted_root="policies").load_file("policies/enterprise-default.yaml")
    assert loaded.policy_version == "1.0.0"
    assert len(loaded.rules) >= 30
    assert len({item.rule_id for item in loaded.rules}) == len(loaded.rules)


@pytest.mark.parametrize(
    ("operator", "actual", "expected", "result"),
    [
        ("equals", 3, 3, True),
        ("not_equals", 3, 4, True),
        ("contains", ["admin", "users"], "admin", True),
        ("not_contains", "hardened", "unsafe", True),
        ("greater_than", 10, 3, True),
        ("less_than", 3, 10, True),
    ],
)
def test_leaf_operators(operator: str, actual: object, expected: object, result: bool) -> None:
    condition = PolicyCondition(field="value", operator=operator, value=expected)
    assert PolicyEngine().matches(condition, {"value": actual}) is result


def test_exists_and_not_exists_distinguish_missing_and_null() -> None:
    engine = PolicyEngine()
    assert engine.matches(PolicyCondition(field="present", operator="exists"), {"present": 1})
    assert engine.matches(PolicyCondition(field="missing", operator="not_exists"), {})
    assert engine.matches(PolicyCondition(field="null", operator="not_exists"), {"null": None})


def test_negative_comparison_fails_closed_when_telemetry_is_missing() -> None:
    engine = PolicyEngine()
    assert not engine.matches(
        PolicyCondition(field="missing", operator="not_equals", value=True), {}
    )
    assert not engine.matches(
        PolicyCondition(field="missing", operator="not_contains", value="x"), {}
    )


@pytest.mark.parametrize(
    ("operator", "expected"),
    [
        ("equals", None),
        ("not_equals", True),
        ("contains", "x"),
        ("not_contains", "x"),
        ("greater_than", 0),
        ("less_than", 0),
    ],
)
def test_comparisons_fail_closed_when_telemetry_is_explicitly_null(
    operator: str, expected: object
) -> None:
    condition = PolicyCondition(field="value", operator=operator, value=expected)

    assert not PolicyEngine().matches(condition, {"value": None})


def test_comparisons_ignore_nulls_when_concrete_values_are_available() -> None:
    condition = PolicyCondition(field="items.value", operator="not_equals", value="unsafe")

    assert PolicyEngine().matches(
        condition,
        {"items": [{"value": None}, {"value": "hardened"}]},
    )


def test_recursive_and_or_conditions() -> None:
    condition = PolicyCondition.model_validate(
        {
            "all": [
                {"field": "security.firewall_enabled", "operator": "equals", "value": False},
                {
                    "any": [
                        {"field": "security.rdp_enabled", "operator": "equals", "value": True},
                        {"field": "ports", "operator": "contains", "value": 23},
                    ]
                },
            ]
        }
    )
    data = {"security": {"firewall_enabled": False, "rdp_enabled": True}, "ports": []}
    assert PolicyEngine().matches(condition, data)


def test_nested_list_and_mapping_wildcard_resolution() -> None:
    engine = PolicyEngine()
    assert engine.resolve_values(
        {"services": [{"state": "RUNNING"}, {"state": "STOPPED"}]}, "services.state"
    ) == [
        "RUNNING",
        "STOPPED",
    ]
    assert engine.matches(
        PolicyCondition(field="collectors.*.status", operator="equals", value="FAILED"),
        {"collectors": {"osquery": {"status": "SUCCESS"}, "native": {"status": "FAILED"}}},
    )


def test_platform_filter_and_deterministic_finding_redact_evidence() -> None:
    test_rule = rule(
        PolicyCondition(field="security.firewall_enabled", operator="equals", value=False),
        platforms={OperatingSystemFamily.WINDOWS},
        evidence_fields=["security", "metadata"],
    )
    loaded = bundle(test_rule)
    data = {
        "security": {"firewall_enabled": False},
        "metadata": {"api_token": "super-secret"},
    }
    engine = PolicyEngine()
    first = engine.evaluate(loaded, data, context())
    second = engine.evaluate(loaded, data, context())
    assert len(first) == 1
    assert first[0].finding_id == second[0].finding_id
    assert first[0].evidence["metadata"]["api_token"] == "<redacted>"
    assert not engine.evaluate(loaded, data, context(platform=OperatingSystemFamily.LINUX))


def test_scan_type_filter() -> None:
    test_rule = rule(
        PolicyCondition(field="bad", operator="equals", value=True),
        scan_types={ScanType.COMPLIANCE},
    )
    assert not PolicyEngine().evaluate(
        bundle(test_rule), {"bad": True}, context(scan_type=ScanType.QUICK)
    )


def test_policy_evaluation_operation_budget_fails_deterministically() -> None:
    loaded = bundle(
        rule(PolicyCondition(field="security.firewall_enabled", operator="equals", value=False))
    )
    engine = PolicyEngine()

    for _ in range(2):
        with pytest.raises(RuntimeError, match="operation budget exceeded"):
            engine.evaluate(
                loaded,
                {"security": {"firewall_enabled": False}},
                context(),
                max_operations=1,
            )


def test_policy_evaluation_rejects_an_expired_monotonic_deadline() -> None:
    loaded = bundle(rule(PolicyCondition(field="bad", operator="equals", value=True)))

    with pytest.raises(TimeoutError, match="deadline exceeded during policy evaluation"):
        PolicyEngine().evaluate(
            loaded,
            {"bad": True},
            context(),
            deadline_at=0.0,
        )


def test_budgeted_policy_evaluation_preserves_deterministic_findings() -> None:
    loaded = bundle(
        rule(PolicyCondition(field="security.firewall_enabled", operator="equals", value=False))
    )
    data = {"security": {"firewall_enabled": False}}
    engine = PolicyEngine()

    ordinary = engine.evaluate(loaded, data, context())
    bounded = engine.evaluate(
        loaded,
        data,
        context(),
        deadline_at=time.monotonic() + 10,
        max_operations=1_000,
    )

    assert bounded == ordinary
