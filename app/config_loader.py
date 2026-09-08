"""Bounded local YAML/JSON configuration loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from yaml.events import AliasEvent
from yaml.tokens import AnchorToken, TagToken

from app.core import ScannerSettings


class ConfigurationError(ValueError):
    pass


class _UniqueSafeLoader(yaml.SafeLoader):
    pass


def _unique_mapping(
    loader: _UniqueSafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[str, Any]:
    loader.flatten_mapping(node)
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ConfigurationError("configuration keys must be strings")
        if key in result:
            raise ConfigurationError(f"duplicate configuration key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping
)


def _json_mapping(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError(f"duplicate configuration key: {key}")
        result[key] = value
    return result


def load_settings_file(path: Path, *, max_bytes: int = 1024 * 1024) -> ScannerSettings:
    candidate = path.expanduser().absolute()
    if candidate.is_symlink():
        raise ConfigurationError("configuration path cannot be a symbolic link")
    try:
        if not candidate.is_file() or candidate.stat().st_size > max_bytes:
            raise ConfigurationError("configuration must be a bounded regular file")
        raw = candidate.read_bytes()
    except OSError as exc:
        raise ConfigurationError("configuration cannot be read") from exc
    try:
        text = raw.decode("utf-8-sig", errors="strict")
        if candidate.suffix.casefold() == ".json":
            value = json.loads(
                text,
                object_pairs_hook=_json_mapping,
                parse_constant=lambda item: (_ for _ in ()).throw(
                    ConfigurationError(f"non-finite number is forbidden: {item}")
                ),
            )
        elif candidate.suffix.casefold() in {".yaml", ".yml"}:
            tokens = tuple(yaml.scan(text, Loader=yaml.SafeLoader))
            if any(isinstance(token, (AnchorToken, TagToken)) for token in tokens):
                raise ConfigurationError("YAML anchors and explicit tags are forbidden")
            events = yaml.parse(text, Loader=yaml.SafeLoader)
            if any(isinstance(event, AliasEvent) for event in events):
                raise ConfigurationError("YAML aliases are forbidden")
            loader = _UniqueSafeLoader(text)
            try:
                value = loader.get_single_data()
            finally:
                loader.dispose()
        else:
            raise ConfigurationError("configuration must use .yaml, .yml, or .json")
    except ConfigurationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ConfigurationError("configuration is not valid YAML/JSON") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("configuration root must be an object")
    try:
        return ScannerSettings.model_validate(value)
    except ValidationError as exc:
        message = exc.errors()[0]["msg"]
        raise ConfigurationError(f"configuration validation failed: {message}") from exc
