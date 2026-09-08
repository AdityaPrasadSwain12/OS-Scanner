from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

import pytest

from app.policies import (
    CloudPolicySynchronizer,
    PolicyLoader,
    PolicySyncError,
    ValidatedPolicyDocument,
    canonical_policy_bytes,
    canonical_policy_document,
)


def _policy(
    policy_id: str = "enterprise-policy",
    version: str = "1.0.0",
    *,
    rule_id: str = "CONTROL-1",
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "policy_id": policy_id,
        "policy_version": version,
        "rules": [
            {
                "rule_id": rule_id,
                "title": "Host firewall must be enabled",
                "severity": "HIGH",
                "category": "endpoint_security",
                "description": "The endpoint firewall must remain enabled.",
                "condition": {
                    "field": "security.firewall_enabled",
                    "operator": "equals",
                    "value": False,
                },
                "remediation": "Enable the endpoint firewall.",
            }
        ],
    }


def _remote(document: dict[str, Any]) -> dict[str, Any]:
    bundle = PolicyLoader().load_document(document)
    return {
        "sha256": hashlib.sha256(canonical_policy_bytes(bundle)).hexdigest(),
        "document": document,
    }


def test_policy_canonicalization_sorts_only_unordered_model_fields() -> None:
    document = _policy()
    rule = document["rules"][0]
    rule["platforms"] = ["WINDOWS", "LINUX"]
    rule["scan_types"] = ["FULL", "QUICK"]
    rule["tags"] = ["zeta", "alpha"]
    rule["references"] = ["https://example.test/z", "https://example.test/a"]
    bundle = PolicyLoader().load_document(document)

    canonical = canonical_policy_document(bundle)
    canonical_rule = canonical["rules"][0]

    assert canonical_rule["platforms"] == ["LINUX", "WINDOWS"]
    assert canonical_rule["scan_types"] == ["FULL", "QUICK"]
    assert canonical_rule["tags"] == ["alpha", "zeta"]
    assert canonical_rule["references"] == [
        "https://example.test/z",
        "https://example.test/a",
    ]
    assert canonical_policy_bytes(bundle) == canonical_policy_bytes(bundle)


class PolicyClient:
    def __init__(self, payload: object) -> None:
        self.payload = payload
        self.fetches = 0

    def fetch_policies(self) -> object:
        self.fetches += 1
        return self.payload


def test_cloud_policy_sync_validates_all_documents_before_atomic_install() -> None:
    first = _policy()
    second = _policy("special-policy", "2.0.0", rule_id="CONTROL-2")
    client = PolicyClient(
        {
            "schema_version": "1.0",
            "assignment_id": "assignment-123",
            "active_policy_id": "special-policy",
            "active_policy_version": "2.0.0",
            "policies": [_remote(first), _remote(second)],
        }
    )
    installed: list[tuple[Sequence[ValidatedPolicyDocument], str, str, str]] = []

    def install(
        documents: Sequence[ValidatedPolicyDocument],
        policy_id: str,
        version: str,
        assignment_id: str,
    ) -> bool:
        installed.append((documents, policy_id, version, assignment_id))
        return True

    synchronizer = CloudPolicySynchronizer(
        client,  # type: ignore[arg-type]
        PolicyLoader(),
        install,
    )

    assert synchronizer.sync() is True
    assert client.fetches == 1
    documents, policy_id, version, assignment_id = installed[0]
    assert [(item.bundle.policy_id, item.bundle.policy_version) for item in documents] == [
        ("enterprise-policy", "1.0.0"),
        ("special-policy", "2.0.0"),
    ]
    assert policy_id == "special-policy"
    assert version == "2.0.0"
    assert assignment_id == "assignment-123"


def test_cloud_policy_sync_is_noop_when_server_has_no_assignment() -> None:
    called = False

    def install(
        documents: Sequence[ValidatedPolicyDocument],
        policy_id: str,
        version: str,
        assignment_id: str,
    ) -> bool:
        del documents, policy_id, version, assignment_id
        nonlocal called
        called = True
        return True

    synchronizer = CloudPolicySynchronizer(
        PolicyClient(None),  # type: ignore[arg-type]
        PolicyLoader(),
        install,
    )

    assert synchronizer.sync() is False
    assert called is False


@pytest.mark.parametrize(
    ("mutate", "error"),
    [
        (
            lambda payload: payload.__setitem__("schema_version", "2.0"),
            "invalid schema",
        ),
        (
            lambda payload: payload["policies"][0].__setitem__("sha256", "0" * 64),
            "checksum mismatch",
        ),
        (
            lambda payload: payload.__setitem__("active_policy_version", "9.9.9"),
            "active cloud policy is not present",
        ),
        (
            lambda payload: payload["policies"].append(
                _remote(_policy(rule_id="CONTROL-DUPLICATE"))
            ),
            "repeats an ID/version",
        ),
    ],
)
def test_cloud_policy_sync_fails_closed_before_install(
    mutate: Any,
    error: str,
) -> None:
    payload = {
        "schema_version": "1.0",
        "assignment_id": "assignment-123",
        "active_policy_id": "enterprise-policy",
        "active_policy_version": "1.0.0",
        "policies": [_remote(_policy())],
    }
    mutate(payload)
    installs = 0

    def install(
        documents: Sequence[ValidatedPolicyDocument],
        policy_id: str,
        version: str,
        assignment_id: str,
    ) -> bool:
        del documents, policy_id, version, assignment_id
        nonlocal installs
        installs += 1
        return True

    synchronizer = CloudPolicySynchronizer(
        PolicyClient(payload),  # type: ignore[arg-type]
        PolicyLoader(),
        install,
    )

    with pytest.raises(PolicySyncError, match=error):
        synchronizer.sync()
    assert installs == 0


def test_cloud_policy_sync_rejects_invalid_policy_without_partial_install() -> None:
    invalid = _policy("invalid-policy", "2.0.0")
    invalid["rules"][0]["condition"]["field"] = "../../secret"
    payload = {
        "schema_version": "1.0",
        "assignment_id": "assignment-123",
        "active_policy_id": "enterprise-policy",
        "active_policy_version": "1.0.0",
        "policies": [
            _remote(_policy()),
            {"sha256": "0" * 64, "document": invalid},
        ],
    }
    installs = 0

    def install(
        documents: Sequence[ValidatedPolicyDocument],
        policy_id: str,
        version: str,
        assignment_id: str,
    ) -> bool:
        del documents, policy_id, version, assignment_id
        nonlocal installs
        installs += 1
        return True

    synchronizer = CloudPolicySynchronizer(
        PolicyClient(payload),  # type: ignore[arg-type]
        PolicyLoader(),
        install,
    )

    with pytest.raises(PolicySyncError, match="failed validation"):
        synchronizer.sync()
    assert installs == 0
