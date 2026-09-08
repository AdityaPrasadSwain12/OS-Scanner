"""Validated, versioned policy document schema."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import AliasChoices, Field, field_validator, model_validator

from app.models import OperatingSystemFamily, ScanType, Severity
from app.models.base import Identifier, JsonValue, StrictModel, bounded_json
from app.models.validators import validate_reference

_FIELD_PATH_PATTERN = r"^[A-Za-z0-9_-]+(?:\.(?:[A-Za-z0-9_-]+|\*))*$"


class ConditionOperator(StrEnum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    AND = "AND"
    OR = "OR"
    ANY_ITEM = "any_item"


class PolicyCondition(StrictModel):
    field: str | None = Field(default=None, max_length=512, pattern=_FIELD_PATH_PATTERN)
    operator: ConditionOperator
    value: JsonValue = None
    conditions: list[PolicyCondition] = Field(default_factory=list, max_length=64)

    @model_validator(mode="before")
    @classmethod
    def accept_explicit_boolean_forms(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        copied = dict(value)
        aliases = [("all", "AND"), ("any", "OR")]
        present = [(key, operator) for key, operator in aliases if key in copied]
        if present:
            if len(present) > 1 or "operator" in copied or "conditions" in copied:
                raise ValueError("condition cannot mix all/any with operator/conditions")
            key, operator = present[0]
            copied["operator"] = operator
            copied["conditions"] = copied.pop(key)
        if isinstance(copied.get("operator"), str):
            raw_operator = copied["operator"]
            logical = raw_operator.upper()
            copied["operator"] = logical if logical in {"AND", "OR"} else raw_operator.lower()
        return copied

    @field_validator("value", mode="before")
    @classmethod
    def validate_value(cls, value: Any) -> JsonValue:
        return bounded_json(value, max_depth=8, max_nodes=2_000)

    @model_validator(mode="after")
    def validate_shape(self) -> PolicyCondition:
        logical = self.operator in {ConditionOperator.AND, ConditionOperator.OR}
        if self.operator is ConditionOperator.ANY_ITEM:
            if self.field is None or not self.conditions:
                raise ValueError("any_item requires a collection field and child conditions")
            if "value" in self.model_fields_set and self.value is not None:
                raise ValueError("any_item cannot specify a value")
            return self
        if logical:
            if self.field is not None or not self.conditions:
                raise ValueError("AND/OR conditions require children and cannot specify a field")
            if "value" in self.model_fields_set and self.value is not None:
                raise ValueError("AND/OR conditions cannot specify a value")
        else:
            if self.field is None or self.conditions:
                raise ValueError("leaf conditions require field and cannot have child conditions")
            requires_value = self.operator not in {
                ConditionOperator.EXISTS,
                ConditionOperator.NOT_EXISTS,
            }
            if requires_value and "value" not in self.model_fields_set:
                raise ValueError(f"{self.operator.value} requires value")
            if not requires_value and "value" in self.model_fields_set and self.value is not None:
                raise ValueError(f"{self.operator.value} does not accept value")
        return self


class PolicyRule(StrictModel):
    rule_id: Identifier = Field(validation_alias=AliasChoices("rule_id", "id"))
    title: str = Field(min_length=1, max_length=1024)
    severity: Severity
    category: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_-]*$")
    description: str = Field(min_length=1, max_length=16_384)
    condition: PolicyCondition
    remediation: str = Field(min_length=1, max_length=16_384)
    references: list[str] = Field(default_factory=list, max_length=128)
    evidence_fields: list[str] = Field(default_factory=list, max_length=128)
    platforms: frozenset[OperatingSystemFamily] = Field(default_factory=frozenset)
    scan_types: frozenset[ScanType] = Field(default_factory=frozenset)
    enabled: bool = True
    tags: set[str] = Field(default_factory=set, max_length=128)
    exploitability: float | None = Field(default=None, ge=0.0, le=1.0)
    exposure: float | None = Field(default=None, ge=0.0, le=1.0)
    compliance_impact: float | None = Field(default=None, ge=0.0, le=1.0)

    @field_validator("references")
    @classmethod
    def validate_references(cls, values: list[str]) -> list[str]:
        return [validate_reference(value) for value in values]

    @field_validator("evidence_fields")
    @classmethod
    def validate_evidence_fields(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(_FIELD_PATH_PATTERN, value) for value in values):
            raise ValueError("invalid evidence field path")
        return values

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, values: set[str]) -> set[str]:
        if any(not value or len(value) > 64 for value in values):
            raise ValueError("policy tags must contain 1-64 characters")
        return values


class PolicyBundle(StrictModel):
    schema_version: str = Field(default="1.0", pattern=r"^\d+\.\d+$", max_length=16)
    policy_id: Identifier = Field(validation_alias=AliasChoices("policy_id", "id"))
    policy_version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    description: str | None = Field(default=None, max_length=4096)
    rules: list[PolicyRule] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def unique_rule_ids(self) -> PolicyBundle:
        identifiers = [rule.rule_id for rule in self.rules]
        if len(set(identifiers)) != len(identifiers):
            duplicates = sorted(
                {identifier for identifier in identifiers if identifiers.count(identifier) > 1}
            )
            raise ValueError(f"duplicate policy rule IDs: {duplicates!r}")
        return self

    def enabled_rules(self) -> tuple[PolicyRule, ...]:
        return tuple(rule for rule in self.rules if rule.enabled)


# Short names for callers constructing policy ASTs directly.
Condition = PolicyCondition
Rule = PolicyRule
