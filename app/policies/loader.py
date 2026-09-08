"""Bounded and non-executable YAML/JSON policy loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from yaml.events import AliasEvent
from yaml.tokens import AnchorToken, TagToken

from .models import PolicyBundle


class PolicyLoadError(ValueError):
    """A policy could not be safely decoded or validated."""


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise PolicyLoadError("policy mapping keys must be scalar values") from exc
        if duplicate:
            raise PolicyLoadError(f"duplicate policy key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _json_unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyLoadError(f"duplicate policy key: {key!r}")
        result[key] = value
    return result


class PolicyLoader:
    def __init__(
        self,
        *,
        trusted_root: str | Path | None = None,
        max_file_bytes: int = 2 * 1024 * 1024,
        max_rules: int = 2_000,
        max_depth: int = 16,
        max_nodes: int = 100_000,
        allow_symlinks: bool = False,
    ) -> None:
        if not 1_024 <= max_file_bytes <= 16 * 1024 * 1024:
            raise ValueError("max_file_bytes must be between 1 KiB and 16 MiB")
        if not 1 <= max_rules <= 10_000:
            raise ValueError("max_rules must be between 1 and 10,000")
        if not 1 <= max_depth <= 64 or max_nodes < 100:
            raise ValueError("invalid policy structure limits")
        self.trusted_root = Path(trusted_root).resolve() if trusted_root else None
        self.max_file_bytes = max_file_bytes
        self.max_rules = max_rules
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.allow_symlinks = allow_symlinks

    def load_file(self, path: str | Path) -> PolicyBundle:
        policy_path = self._validated_path(path)
        try:
            with policy_path.open("rb") as handle:
                payload = handle.read(self.max_file_bytes + 1)
        except OSError as exc:
            raise PolicyLoadError(f"unable to read policy file: {policy_path.name}") from exc
        if len(payload) > self.max_file_bytes:
            raise PolicyLoadError("policy file exceeds configured size limit")
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise PolicyLoadError("policy must be UTF-8 text") from exc
        raw = self._decode(text, policy_path.suffix.lower())
        return self.load_document(raw, source_name=policy_path.name)

    def load_bytes(self, payload: bytes, *, format_hint: str = ".json") -> PolicyBundle:
        """Validate an in-memory policy received through a trusted transport."""

        if not isinstance(payload, bytes):
            raise TypeError("policy payload must be bytes")
        if len(payload) > self.max_file_bytes:
            raise PolicyLoadError("policy payload exceeds configured size limit")
        if format_hint not in {".json", ".yaml", ".yml"}:
            raise PolicyLoadError("unsupported policy payload format")
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise PolicyLoadError("policy must be UTF-8 text") from exc
        return self.load_document(
            self._decode(text, format_hint), source_name="remote policy"
        )

    def load_document(self, raw: Any, *, source_name: str = "policy document") -> PolicyBundle:
        """Apply all structural, schema, rule-count, and expression bounds."""

        self._validate_structure(raw)
        bundle_payload = self._normalize_document(raw)
        try:
            bundle = PolicyBundle.model_validate(bundle_payload)
        except ValidationError as exc:
            raise PolicyLoadError(f"invalid policy schema in {source_name}: {exc}") from exc
        if len(bundle.rules) > self.max_rules:
            raise PolicyLoadError("policy contains more rules than configured")
        self._validate_expression_depth(bundle)
        return bundle

    # Conventional alias used in a few integrations.
    load_path = load_file

    def load_directory(self, path: str | Path) -> PolicyBundle:
        directory = Path(path)
        if directory.is_symlink() and not self.allow_symlinks:
            raise PolicyLoadError("symbolic-link policy directories are disabled")
        resolved = directory.resolve(strict=True)
        self._assert_in_root(resolved)
        if not resolved.is_dir():
            raise PolicyLoadError("policy directory is not a directory")
        files = sorted(
            candidate
            for candidate in resolved.iterdir()
            if candidate.is_file() and candidate.suffix.lower() in {".yaml", ".yml", ".json"}
        )
        if not files:
            raise PolicyLoadError("policy directory contains no YAML or JSON policies")
        bundles = [self.load_file(file) for file in files]
        first = bundles[0]
        if any(
            (bundle.policy_id, bundle.policy_version, bundle.schema_version)
            != (first.policy_id, first.policy_version, first.schema_version)
            for bundle in bundles[1:]
        ):
            raise PolicyLoadError(
                "all policy files in a directory must use the same policy ID and versions"
            )
        rules = [rule for bundle in bundles for rule in bundle.rules]
        if len(rules) > self.max_rules:
            raise PolicyLoadError("policy directory contains more rules than configured")
        try:
            return PolicyBundle(
                schema_version=first.schema_version,
                policy_id=first.policy_id,
                policy_version=first.policy_version,
                description=first.description,
                rules=rules,
            )
        except ValidationError as exc:
            raise PolicyLoadError(f"invalid combined policy directory: {exc}") from exc

    def _validated_path(self, path: str | Path) -> Path:
        candidate = Path(path)
        if candidate.suffix.lower() not in {".yaml", ".yml", ".json"}:
            raise PolicyLoadError("policy files must use .yaml, .yml, or .json")
        if candidate.is_symlink() and not self.allow_symlinks:
            raise PolicyLoadError("symbolic-link policies are disabled")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise PolicyLoadError("policy file does not exist") from exc
        self._assert_in_root(resolved)
        if not resolved.is_file():
            raise PolicyLoadError("policy path is not a regular file")
        return resolved

    def _assert_in_root(self, resolved: Path) -> None:
        if self.trusted_root and not resolved.is_relative_to(self.trusted_root):
            raise PolicyLoadError("policy path escapes the trusted policy directory")

    def _decode(self, text: str, suffix: str) -> Any:
        try:
            if suffix == ".json":
                return json.loads(
                    text,
                    object_pairs_hook=_json_unique_object,
                    parse_constant=self._reject_json_constant,
                )
            tokens = tuple(yaml.scan(text, Loader=yaml.SafeLoader))
            if any(isinstance(token, (AnchorToken, TagToken)) for token in tokens):
                raise PolicyLoadError(
                    "YAML anchors and explicit tags are not allowed in policy files"
                )
            if any(
                isinstance(event, AliasEvent) for event in yaml.parse(text, Loader=yaml.SafeLoader)
            ):
                raise PolicyLoadError("YAML aliases are not allowed in policy files")
            loader = _UniqueKeySafeLoader(text)
            try:
                return loader.get_single_data()
            finally:
                loader.dispose()
        except PolicyLoadError:
            raise
        except (json.JSONDecodeError, yaml.YAMLError, UnicodeError) as exc:
            raise PolicyLoadError("policy is not valid YAML/JSON") from exc

    @staticmethod
    def _reject_json_constant(value: str) -> None:
        raise PolicyLoadError(f"non-finite JSON number is not allowed: {value}")

    def _validate_structure(self, root: Any) -> None:
        nodes = 0
        active: set[int] = set()

        def walk(value: Any, depth: int) -> None:
            nonlocal nodes
            nodes += 1
            if nodes > self.max_nodes:
                raise PolicyLoadError("policy exceeds configured node limit")
            # Policy-expression depth has its own tighter semantic check after
            # schema validation. This is a hard parser-structure backstop.
            if depth > max(32, self.max_depth * 4):
                raise PolicyLoadError("policy exceeds configured structure depth")
            if value is None or isinstance(value, (str, bool, int)):
                return
            if isinstance(value, float):
                if value != value or value in (float("inf"), float("-inf")):
                    raise PolicyLoadError("non-finite policy numbers are not allowed")
                return
            if not isinstance(value, (dict, list)):
                raise PolicyLoadError(f"unsupported policy value type: {type(value).__name__}")
            identity = id(value)
            if identity in active:
                raise PolicyLoadError("recursive policy structures are not allowed")
            active.add(identity)
            if isinstance(value, dict):
                for key, child in value.items():
                    if not isinstance(key, str) or not key or len(key) > 256:
                        raise PolicyLoadError(
                            "policy object keys must be bounded non-empty strings"
                        )
                    walk(child, depth + 1)
            else:
                for child in value:
                    walk(child, depth + 1)
            active.remove(identity)

        walk(root, 0)

    @staticmethod
    def _normalize_document(raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise PolicyLoadError(
                "policy document must be an object with explicit version metadata"
            )
        if "rules" in raw:
            return raw
        if "condition" not in raw:
            raise PolicyLoadError("policy document must contain rules")
        copied = dict(raw)
        try:
            policy_id = copied.pop("policy_id")
            policy_version = copied.pop("policy_version")
        except KeyError as exc:
            raise PolicyLoadError(
                "single-rule policies require policy_id and policy_version"
            ) from exc
        schema_version = copied.pop("schema_version", "1.0")
        return {
            "schema_version": schema_version,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "rules": [copied],
        }

    def _validate_expression_depth(self, bundle: PolicyBundle) -> None:
        def depth(condition: Any, current: int) -> None:
            if current > self.max_depth:
                raise PolicyLoadError("policy expression exceeds configured depth")
            for child in condition.conditions:
                depth(child, current + 1)

        for rule in bundle.rules:
            depth(rule.condition, 1)
