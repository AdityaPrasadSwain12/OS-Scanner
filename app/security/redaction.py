"""Deterministic secret redaction for telemetry, evidence, and command lines."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

REDACTED: Final[str] = "<redacted>"
TRUNCATED: Final[str] = "<truncated>"

_SENSITIVE_KEY = re.compile(
    r"(?:^|[_\-.])(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|authorization|cookie|session|credential)(?:$|[_\-.])",
    re.IGNORECASE,
)
_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|authorization|cookie|session)\b\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_CLI_ASSIGNMENT = re.compile(
    r"(?i)((?:--?)(?:password|passwd|secret|token|api[-_]?key|access[-_]?key|"
    r"client[-_]?secret|authorization|cookie|session)(?:=|\s+))([^\s]+)"
)
_BEARER = re.compile(r"(?i)(\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+")
_URL_CREDENTIALS = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)([^\s@/]+)(@)")
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)
_PEM_SECRET = re.compile(
    r"-----BEGIN (?:OPENSSH|PGP) PRIVATE KEY BLOCK-----.*?"
    r"-----END (?:OPENSSH|PGP) PRIVATE KEY BLOCK-----",
    re.DOTALL,
)
_AWS_ACCESS_KEY = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_SENSITIVE_FLAGS = frozenset(
    {
        "--password",
        "--passwd",
        "--secret",
        "--token",
        "--api-key",
        "--api_key",
        "--access-key",
        "--client-secret",
        "--authorization",
        "--cookie",
        "--session-token",
    }
)

# These names describe security-control state; they never contain a password.
# Keeping the allow-list narrow prevents the final report redactor from turning
# useful facts such as ``local_admin_password_managed: true`` into a redaction.
_NON_SECRET_SECURITY_FACT_KEYS = frozenset(
    {
        "local_admin_password_managed",
        "password_policy_compliant",
        "password_required",
        "password_never_expires",
        "password_expires",
        "user_may_change_password",
        "passwordauthentication",
        "permitemptypasswords",
        "ssh_password_authentication_enabled",
        "ssh_permit_empty_passwords",
    }
)
_NON_SECRET_SECURITY_FACT_VALUES = frozenset(
    {"0", "1", "true", "false", "yes", "no", "enabled", "disabled", "not set"}
)


def is_sensitive_key(key: object) -> bool:
    return isinstance(key, str) and bool(_SENSITIVE_KEY.search(key))


def _is_non_secret_security_fact(key: object, value: Any) -> bool:
    if not isinstance(key, str) or key.casefold() not in _NON_SECRET_SECURITY_FACT_KEYS:
        return False
    if value is None or isinstance(value, bool):
        return True
    return isinstance(value, str) and value.strip().casefold() in _NON_SECRET_SECURITY_FACT_VALUES


def redact_text(value: str, *, max_length: int = 16_384) -> str:
    """Remove common credential forms without returning matched secret material."""

    text = value[:max_length]
    text = _PRIVATE_KEY.sub(REDACTED, text)
    text = _PEM_SECRET.sub(REDACTED, text)
    text = _URL_CREDENTIALS.sub(rf"\1{REDACTED}\3", text)
    text = _BEARER.sub(rf"\1{REDACTED}", text)
    text = _CLI_ASSIGNMENT.sub(rf"\1{REDACTED}", text)
    text = _ASSIGNMENT.sub(rf"\1{REDACTED}", text)
    text = _JWT.sub(REDACTED, text)
    text = _AWS_ACCESS_KEY.sub(REDACTED, text)
    if len(value) > max_length:
        text += TRUNCATED
    return text


def redact_command_line(command: str | Sequence[str]) -> str | list[str]:
    """Redact a command string or argv while preserving its original shape."""

    if isinstance(command, str):
        return redact_text(command)
    result: list[str] = []
    redact_next = False
    for raw_argument in command:
        argument = str(raw_argument)
        if redact_next:
            result.append(REDACTED)
            redact_next = False
            continue
        flag, separator, _ = argument.partition("=")
        normalized_flag = flag.lower()
        if normalized_flag in _SENSITIVE_FLAGS:
            if separator:
                result.append(f"{flag}={REDACTED}")
            else:
                result.append(argument)
                redact_next = True
            continue
        result.append(redact_text(argument, max_length=4_096))
    return result


def redact_value(value: Any, *, max_depth: int = 12, max_nodes: int = 20_000) -> Any:
    """Return a redacted, cycle-safe copy of JSON-like structured data."""

    nodes = 0
    active: set[int] = set()

    def walk(item: Any, depth: int, sensitive: bool = False) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            return TRUNCATED
        if sensitive:
            return REDACTED
        if item is None or isinstance(item, (bool, int, float)):
            return item
        if isinstance(item, str):
            return redact_text(item)
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in active:
                return TRUNCATED
            active.add(identity)
            mapping_copy = {
                str(key): walk(
                    child,
                    depth + 1,
                    is_sensitive_key(key) and not _is_non_secret_security_fact(key, child),
                )
                for key, child in item.items()
            }
            active.remove(identity)
            return mapping_copy
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            identity = id(item)
            if identity in active:
                return TRUNCATED
            active.add(identity)
            sequence_copy = [walk(child, depth + 1) for child in item]
            active.remove(identity)
            return sequence_copy
        return redact_text(str(item))

    return walk(value, 0)


def redact_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    redacted = redact_value(value)
    return redacted if isinstance(redacted, dict) else {"value": redacted}


def sanitize_for_log(value: Any) -> Any:
    """Redact secrets and neutralize CR/LF log-forging characters in strings."""

    redacted = redact_value(value)

    def clean(item: Any) -> Any:
        if isinstance(item, str):
            return _CONTROL.sub("?", item).replace("\r", "\\r").replace("\n", "\\n")
        if isinstance(item, dict):
            return {clean(key): clean(child) for key, child in item.items()}
        if isinstance(item, list):
            return [clean(child) for child in item]
        return item

    return clean(redacted)


# Compatibility aliases used by logging and transport layers.
redact_sensitive_data = redact_value
redact_command = redact_command_line
