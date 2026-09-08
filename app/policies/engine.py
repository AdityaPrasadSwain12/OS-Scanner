"""Pure, deterministic evaluation of validated policy rules."""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, assert_never
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, Field, model_validator

from app.models import Finding, OperatingSystemFamily, ScanType
from app.models.base import Identifier, StrictModel, ensure_aware, utc_now
from app.security import redact_value

from .models import ConditionOperator, PolicyBundle, PolicyCondition, PolicyRule


class EvaluationContext(StrictModel):
    scan_id: Identifier
    endpoint_id: str | None = Field(default=None, max_length=128)
    asset: str | None = Field(default=None, max_length=2048)
    scanner_version: str = Field(default="1.1.0", max_length=64)
    detected_at: datetime = Field(default_factory=utc_now)
    platform: OperatingSystemFamily | None = None
    scan_type: ScanType | None = None

    @model_validator(mode="after")
    def validate_subject(self) -> EvaluationContext:
        object.__setattr__(self, "detected_at", ensure_aware(self.detected_at))
        if not self.endpoint_id and not self.asset:
            raise ValueError("evaluation context requires endpoint_id or asset")
        return self


@dataclass(slots=True)
class _EvaluationBudget:
    remaining: int
    deadline_at: float | None = None

    def consume(self) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise RuntimeError("policy evaluation operation budget exceeded")
        if self.deadline_at is not None and time.monotonic() >= self.deadline_at:
            raise TimeoutError("scan execution deadline exceeded during policy evaluation")


class PolicyEngine:
    """Evaluate policy ASTs without executing expressions or user code."""

    def evaluate(
        self,
        bundle: PolicyBundle,
        data: BaseModel | Mapping[str, Any],
        context: EvaluationContext,
        *,
        deadline_at: float | None = None,
        max_operations: int = 5_000_000,
    ) -> list[Finding]:
        if not 1 <= max_operations <= 100_000_000:
            raise ValueError("max_operations must be between 1 and 100,000,000")
        budget = _EvaluationBudget(max_operations, deadline_at)
        budget.consume()
        normalized = data.model_dump(mode="python") if isinstance(data, BaseModel) else data
        if not isinstance(normalized, Mapping):
            raise TypeError("policy data must be a Pydantic model or mapping")
        findings: list[Finding] = []
        for rule in bundle.rules:
            budget.consume()
            if not rule.enabled or not self._is_applicable(
                rule, normalized, context, budget
            ):
                continue
            if self._matches(rule.condition, normalized, budget):
                findings.append(
                    self._finding(bundle, rule, normalized, context, budget)
                )
        return findings

    # Compatibility name that reads well at call sites.
    evaluate_bundle = evaluate

    def evaluate_rule(
        self,
        rule: PolicyRule,
        data: BaseModel | Mapping[str, Any],
    ) -> bool:
        normalized = data.model_dump(mode="python") if isinstance(data, BaseModel) else data
        if not isinstance(normalized, Mapping):
            raise TypeError("policy data must be a Pydantic model or mapping")
        budget = _EvaluationBudget(1_000_000)
        return rule.enabled and self._matches(rule.condition, normalized, budget)

    def matches(self, condition: PolicyCondition, data: Mapping[str, Any]) -> bool:
        return self._matches(condition, data, _EvaluationBudget(1_000_000))

    def _matches(
        self,
        condition: PolicyCondition,
        data: Mapping[str, Any],
        budget: _EvaluationBudget,
    ) -> bool:
        budget.consume()
        if condition.operator is ConditionOperator.AND:
            return all(self._matches(child, data, budget) for child in condition.conditions)
        if condition.operator is ConditionOperator.OR:
            return any(self._matches(child, data, budget) for child in condition.conditions)
        if condition.operator is ConditionOperator.ANY_ITEM:
            assert condition.field is not None
            collections = self._resolve_values(data, condition.field, budget)
            items = [
                item
                for value in collections
                for item in (
                    value
                    if isinstance(value, Sequence)
                    and not isinstance(value, (str, bytes, bytearray))
                    else (value,)
                )
            ]
            return any(
                isinstance(item, (BaseModel, Mapping))
                and all(
                    self._matches(
                        child,
                        item.model_dump(mode="python")
                        if isinstance(item, BaseModel)
                        else item,
                        budget,
                    )
                    for child in condition.conditions
                )
                for item in items
            )
        assert condition.field is not None
        values = self._resolve_values(data, condition.field, budget)
        if condition.operator is ConditionOperator.EXISTS:
            return bool(values) and any(value is not None for value in values)
        if condition.operator is ConditionOperator.NOT_EXISTS:
            return not values or all(value is None for value in values)
        concrete_values = [value for value in values if value is not None]
        if not concrete_values:
            # Missing and explicitly null telemetry never satisfy positive or
            # negative comparisons.  Rules that intentionally test telemetry
            # presence must use exists/not_exists instead.
            return False
        expected = condition.value
        if condition.operator is ConditionOperator.EQUALS:
            return any(_equivalent(value, expected) for value in concrete_values)
        if condition.operator is ConditionOperator.NOT_EQUALS:
            return all(not _equivalent(value, expected) for value in concrete_values)
        if condition.operator is ConditionOperator.CONTAINS:
            return any(_contains(value, expected) for value in concrete_values)
        if condition.operator is ConditionOperator.NOT_CONTAINS:
            return all(not _contains(value, expected) for value in concrete_values)
        if condition.operator is ConditionOperator.GREATER_THAN:
            return any(
                _ordered_compare(value, expected, greater=True) for value in concrete_values
            )
        if condition.operator is ConditionOperator.LESS_THAN:
            return any(
                _ordered_compare(value, expected, greater=False) for value in concrete_values
            )
        assert_never(condition.operator)

    @staticmethod
    def resolve_values(data: Any, field: str) -> list[Any]:
        return PolicyEngine._resolve_values(data, field, _EvaluationBudget(1_000_000))

    @staticmethod
    def _resolve_values(
        data: Any,
        field: str,
        budget: _EvaluationBudget,
    ) -> list[Any]:
        segments = field.split(".")

        def walk(current: Any, index: int) -> list[Any]:
            budget.consume()
            if index == len(segments):
                return [current]
            segment = segments[index]
            if isinstance(current, BaseModel):
                current = current.model_dump(mode="python")
            if isinstance(current, Mapping):
                if segment == "*":
                    return [
                        result for child in current.values() for result in walk(child, index + 1)
                    ]
                if segment not in current:
                    return []
                return walk(current[segment], index + 1)
            if isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
                return [result for child in current for result in walk(child, index)]
            return []

        return walk(data, 0)

    def _is_applicable(
        self,
        rule: PolicyRule,
        data: Mapping[str, Any],
        context: EvaluationContext,
        budget: _EvaluationBudget,
    ) -> bool:
        platform = context.platform
        if platform is None:
            values = self._resolve_values(data, "os.family", budget)
            if values:
                try:
                    platform = OperatingSystemFamily(_scalar(values[0]))
                except (TypeError, ValueError):
                    platform = None
        if rule.platforms and platform not in rule.platforms:
            return False
        return not rule.scan_types or context.scan_type in rule.scan_types

    def _finding(
        self,
        bundle: PolicyBundle,
        rule: PolicyRule,
        data: Mapping[str, Any],
        context: EvaluationContext,
        budget: _EvaluationBudget,
    ) -> Finding:
        evidence_fields = rule.evidence_fields or sorted(_leaf_fields(rule.condition))
        evidence: dict[str, Any] = {}
        evidence_budget = [4_000]
        for field in evidence_fields:
            values = self._resolve_values(data, field, budget)
            if values:
                raw_value: Any = values[0] if len(values) == 1 else values
                if isinstance(raw_value, Sequence) and not isinstance(
                    raw_value, (str, bytes, bytearray)
                ):
                    relative = _relative_condition(rule.condition, field)
                    matched = (
                        [
                            item
                            for item in raw_value
                            if isinstance(item, (BaseModel, Mapping))
                            and self._matches(
                                relative,
                                item.model_dump(mode="python")
                                if isinstance(item, BaseModel)
                                else item,
                                budget,
                            )
                        ]
                        if relative is not None
                        else list(raw_value)
                    )
                    sample = matched[:20]
                    raw_value = (
                        {
                            "matched_count": len(matched),
                            "sample": sample,
                            "truncated": True,
                        }
                        if len(matched) > len(sample)
                        else sample
                    )
                evidence[field] = _bounded_evidence(
                    redact_value(raw_value),
                    evidence_budget,
                )
        subject = context.endpoint_id or context.asset or "unknown"
        stable_id = uuid5(
            NAMESPACE_URL, f"{subject}:{bundle.policy_id}:{rule.rule_id}"
        )
        return Finding(
            finding_id=f"finding-{stable_id}",
            schema_version=bundle.schema_version,
            scanner_version=context.scanner_version,
            scan_id=context.scan_id,
            rule_id=rule.rule_id,
            title=rule.title,
            severity=rule.severity,
            category=rule.category,
            description=rule.description,
            endpoint_id=context.endpoint_id,
            asset=context.asset,
            evidence=evidence,
            remediation=rule.remediation,
            references=rule.references,
            detected_at=context.detected_at,
            first_seen_at=context.detected_at,
            exploitability=rule.exploitability,
            exposure=rule.exposure,
            compliance_impact=rule.compliance_impact,
            tags=rule.tags,
        )


def _leaf_fields(condition: PolicyCondition) -> set[str]:
    if condition.field:
        return {condition.field}
    return {field for child in condition.conditions for field in _leaf_fields(child)}


def _relative_condition(
    condition: PolicyCondition, collection_field: str
) -> PolicyCondition | None:
    if condition.operator is ConditionOperator.ANY_ITEM:
        if condition.field == collection_field:
            return PolicyCondition(
                operator=ConditionOperator.AND,
                conditions=condition.conditions,
            )
        return None
    if condition.operator in {ConditionOperator.AND, ConditionOperator.OR}:
        children = [
            child
            for item in condition.conditions
            if (child := _relative_condition(item, collection_field)) is not None
        ]
        if not children:
            return None
        if len(children) == 1:
            return children[0]
        return PolicyCondition(operator=condition.operator, conditions=children)
    if condition.field is None:
        return None
    prefix = f"{collection_field}."
    if not condition.field.startswith(prefix):
        return None
    return condition.model_copy(update={"field": condition.field[len(prefix) :]})


def _bounded_evidence(value: Any, budget: list[int], depth: int = 0) -> Any:
    """Produce deterministic JSON evidence within Finding's node/depth bounds."""

    if budget[0] <= 0 or depth >= 6:
        return "[truncated]"
    budget[0] -= 1
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, str):
        return value[:4_096]
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python")
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        items = sorted(value.items(), key=lambda item: str(item[0]))
        for key, item in items[:64]:
            if budget[0] <= 0:
                break
            result[str(key)[:256]] = _bounded_evidence(item, budget, depth + 1)
        if len(items) > 64 or budget[0] <= 0:
            result["_truncated"] = True
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            _bounded_evidence(item, budget, depth + 1)
            for item in value[:64]
            if budget[0] > 0
        ]
    if isinstance(value, set | frozenset):
        items = sorted(value, key=str)
        return [
            _bounded_evidence(item, budget, depth + 1)
            for item in items[:64]
            if budget[0] > 0
        ]
    return str(value)[:4_096]


def _scalar(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _equivalent(actual: Any, expected: Any) -> bool:
    actual = _scalar(actual)
    expected = _scalar(expected)
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        return Decimal(str(actual)) == Decimal(str(expected))
    return bool(actual == expected)


def _contains(actual: Any, expected: Any) -> bool:
    actual = _scalar(actual)
    expected = _scalar(expected)
    if isinstance(actual, str) and isinstance(expected, str):
        return expected in actual
    if isinstance(actual, Mapping):
        return expected in actual
    if isinstance(actual, Sequence) and not isinstance(actual, (str, bytes, bytearray)):
        return any(_equivalent(item, expected) for item in actual)
    if isinstance(actual, set | frozenset):
        return any(_equivalent(item, expected) for item in actual)
    return False


def _ordered_compare(actual: Any, expected: Any, *, greater: bool) -> bool:
    actual = _scalar(actual)
    expected = _scalar(expected)
    if isinstance(actual, bool) or isinstance(expected, bool):
        return False
    try:
        left = Decimal(str(actual))
        right = Decimal(str(expected))
        return left > right if greater else left < right
    except (InvalidOperation, ValueError):
        pass
    if isinstance(actual, datetime) and isinstance(expected, datetime):
        return actual > expected if greater else actual < expected
    if isinstance(actual, datetime) and isinstance(expected, str):
        try:
            parsed = datetime.fromisoformat(expected.replace("Z", "+00:00"))
        except ValueError:
            return False
        return actual > parsed if greater else actual < parsed
    return False


PolicyEvaluator = PolicyEngine
