from __future__ import annotations

import pytest

from app.policies import PolicyLoader, PolicyLoadError

VALID_PREFIX = """schema_version: '1.0'
policy_id: secure-test
policy_version: 1.0.0
rules:
  - id: TEST-001
    title: Test
    severity: LOW
    category: test
    description: Test rule.
    condition: {field: security.flag, operator: equals, value: true}
    remediation: Correct it.
"""


def write_policy(path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def test_rejects_python_object_yaml_tag(tmp_path) -> None:
    path = tmp_path / "malicious.yaml"
    write_policy(path, "!!python/object/apply:os.system ['whoami']")
    with pytest.raises(PolicyLoadError, match="tags"):
        PolicyLoader(trusted_root=tmp_path).load_file(path)


def test_rejects_yaml_aliases_and_anchors(tmp_path) -> None:
    path = tmp_path / "alias.yaml"
    write_policy(path, "root: &value [1, 2]\ncopy: *value\n")
    with pytest.raises(PolicyLoadError, match="anchors"):
        PolicyLoader(trusted_root=tmp_path).load_file(path)


def test_rejects_duplicate_yaml_keys(tmp_path) -> None:
    path = tmp_path / "duplicate.yaml"
    write_policy(path, VALID_PREFIX + "policy_version: 9.9.9\n")
    with pytest.raises(PolicyLoadError, match="duplicate policy key"):
        PolicyLoader(trusted_root=tmp_path).load_file(path)


def test_rejects_duplicate_json_keys(tmp_path) -> None:
    path = tmp_path / "duplicate.json"
    write_policy(path, '{"policy_id":"one","policy_id":"two","policy_version":"1.0.0","rules":[]}')
    with pytest.raises(PolicyLoadError, match="duplicate policy key"):
        PolicyLoader(trusted_root=tmp_path).load_file(path)


def test_rejects_policy_path_outside_trusted_root(tmp_path) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    outside = tmp_path / "outside.yaml"
    write_policy(outside, VALID_PREFIX)
    with pytest.raises(PolicyLoadError, match="escapes"):
        PolicyLoader(trusted_root=trusted).load_file(outside)


def test_rejects_oversized_policy_before_parsing(tmp_path) -> None:
    path = tmp_path / "large.yaml"
    write_policy(path, VALID_PREFIX + ("# padding\n" * 500))
    with pytest.raises(PolicyLoadError, match="size limit"):
        PolicyLoader(trusted_root=tmp_path, max_file_bytes=1024).load_file(path)


def test_rejects_expression_depth_above_limit(tmp_path) -> None:
    path = tmp_path / "deep.yaml"
    condition = "{field: security.flag, operator: equals, value: true}"
    for _ in range(5):
        condition = f"{{operator: AND, conditions: [{condition}]}}"
    text = VALID_PREFIX.replace("{field: security.flag, operator: equals, value: true}", condition)
    write_policy(path, text)
    with pytest.raises(PolicyLoadError, match="expression exceeds"):
        PolicyLoader(trusted_root=tmp_path, max_depth=3).load_file(path)
