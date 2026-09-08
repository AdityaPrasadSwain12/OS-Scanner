"""Validated cloud policy assignment retrieval and activation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from app.models.base import Identifier, JsonValue, StrictModel, bounded_json
from app.storage import IdempotencyConflictError
from app.transport import CloudApiClient

from .loader import PolicyLoader, PolicyLoadError
from .models import PolicyBundle


class PolicySyncError(RuntimeError):
    """A cloud policy assignment was malformed, inconsistent, or unsafe."""


class CloudPolicyDocument(StrictModel):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    document: dict[str, JsonValue]

    @field_validator("document", mode="before")
    @classmethod
    def bound_document(cls, value: Any) -> JsonValue:
        bounded = bounded_json(value, max_depth=32, max_nodes=100_000)
        if not isinstance(bounded, dict):
            raise ValueError("cloud policy document must be an object")
        return bounded


class CloudPolicyAssignment(StrictModel):
    schema_version: str = Field(default="1.0", pattern=r"^1\.0$")
    assignment_id: Identifier
    active_policy_id: Identifier
    active_policy_version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    policies: list[CloudPolicyDocument] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def require_unique_documents(self) -> CloudPolicyAssignment:
        checksums = [item.sha256 for item in self.policies]
        if len(checksums) != len(set(checksums)):
            raise ValueError("cloud policy assignment contains duplicate documents")
        return self


@dataclass(frozen=True, slots=True)
class ValidatedPolicyDocument:
    bundle: PolicyBundle
    checksum: str


PolicyInstaller = Callable[
    [Sequence[ValidatedPolicyDocument], str, str, str],
    bool,
]
PolicyRejectionRecorder = Callable[[str, str], None]


def _canonical_value(value: Any) -> Any:
    """Preserve ordered policy lists while sorting unordered model fields."""

    if isinstance(value, BaseModel):
        return _canonical_value(value.model_dump(mode="python"))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, set | frozenset):
        normalized = [_canonical_value(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(
                item,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    if isinstance(value, list | tuple):
        return [_canonical_value(item) for item in value]
    return value


def canonical_policy_document(bundle: PolicyBundle) -> dict[str, Any]:
    """Return a JSON-compatible policy document stable across process restarts."""

    document = _canonical_value(bundle)
    if not isinstance(document, dict):  # pragma: no cover - PolicyBundle is always an object
        raise TypeError("canonical policy document must be an object")
    return document


def policy_document_bytes(document: Mapping[str, Any]) -> bytes:
    """Serialize an already JSON-compatible document without reordering its arrays."""

    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_policy_bytes(bundle: PolicyBundle) -> bytes:
    return policy_document_bytes(canonical_policy_document(bundle))


class CloudPolicySynchronizer:
    """Fetch an authenticated assignment, validate every bundle, then install atomically."""

    def __init__(
        self,
        client: CloudApiClient,
        loader: PolicyLoader,
        installer: PolicyInstaller,
        rejection_recorder: PolicyRejectionRecorder | None = None,
    ) -> None:
        self.client = client
        self.loader = loader
        self.installer = installer
        self.rejection_recorder = rejection_recorder

    def sync(self) -> bool:
        payload = self.client.fetch_policies()
        if payload is None:
            return False
        try:
            return self._validate_and_install(payload)
        except PolicySyncError as exc:
            encoded = json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
            fingerprint = hashlib.sha256(encoded).hexdigest()
            if self.rejection_recorder is not None:
                self.rejection_recorder(fingerprint, str(exc))
            raise

    def _validate_and_install(self, payload: Any) -> bool:
        try:
            assignment = CloudPolicyAssignment.model_validate(payload)
        except ValidationError as exc:
            raise PolicySyncError("cloud policy assignment has an invalid schema") from exc

        validated: list[ValidatedPolicyDocument] = []
        identities: set[tuple[str, str]] = set()
        for remote in assignment.policies:
            try:
                bundle = self.loader.load_document(
                    remote.document, source_name="cloud policy"
                )
            except PolicyLoadError as exc:
                raise PolicySyncError("cloud policy document failed validation") from exc
            checksum = hashlib.sha256(canonical_policy_bytes(bundle)).hexdigest()
            if checksum != remote.sha256:
                raise PolicySyncError("cloud policy document checksum mismatch")
            identity = (bundle.policy_id, bundle.policy_version)
            if identity in identities:
                raise PolicySyncError("cloud policy assignment repeats an ID/version")
            identities.add(identity)
            validated.append(ValidatedPolicyDocument(bundle=bundle, checksum=checksum))

        active = (assignment.active_policy_id, assignment.active_policy_version)
        if active not in identities:
            raise PolicySyncError("active cloud policy is not present in the assignment")
        try:
            return self.installer(
                validated,
                assignment.active_policy_id,
                assignment.active_policy_version,
                assignment.assignment_id,
            )
        except (IdempotencyConflictError, ValueError) as exc:
            raise PolicySyncError("cloud policy assignment could not be installed") from exc


__all__ = [
    "CloudPolicyAssignment",
    "CloudPolicyDocument",
    "CloudPolicySynchronizer",
    "PolicySyncError",
    "ValidatedPolicyDocument",
    "canonical_policy_bytes",
    "canonical_policy_document",
    "policy_document_bytes",
]
