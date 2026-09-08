"""Canonical validation for locally administered cloud API paths.

Routes are configuration, not untrusted job input, but they still cross a trust
boundary when they are joined to the cloud origin.  Keeping the validation in
one place prevents the configuration, enrollment, and transport layers from
disagreeing about ambiguous URL syntax.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


class ApiPathValidationError(ValueError):
    """A route is invalid; ``kind`` distinguishes templates from path syntax."""

    def __init__(self, message: str, *, kind: str = "path") -> None:
        super().__init__(message)
        self.kind = kind


def _fully_unquote(value: str) -> str:
    """Decode nested percent escapes while rejecting malformed/deep encodings."""

    current = value
    # Each valid decoding pass shortens a nested escape.  The input-length bound
    # therefore gives a deterministic upper limit without permitting a bypass
    # through three or more layers of percent encoding.
    for _ in range(len(value) + 1):
        if "%" not in current:
            return current
        if _INVALID_PERCENT_ESCAPE.search(current):
            raise ApiPathValidationError("API path contains a malformed percent escape")
        try:
            decoded = unquote(current, errors="strict")
        except UnicodeError as exc:
            raise ApiPathValidationError("API path percent encoding is invalid") from exc
        if decoded == current:
            return current
        current = decoded
    raise ApiPathValidationError("API path percent encoding is too deeply nested")


def _contains_unsafe_character(value: str) -> bool:
    # HTTP request targets are emitted as ASCII.  Non-ASCII route text must be
    # explicitly percent encoded, and decoded whitespace/control bytes remain
    # forbidden because intermediaries can interpret them inconsistently.
    return any(
        ord(character) <= 32 or ord(character) == 127 or ord(character) > 126
        for character in value
    )


def _contains_control_or_non_ascii(value: str) -> bool:
    return any(
        ord(character) < 32 or ord(character) == 127 or ord(character) > 126
        for character in value
    )


def validate_api_path(
    value: object,
    *,
    expected_placeholders: frozenset[str] = frozenset(),
    max_length: int = 2_048,
    allow_encoded_path_data: bool = False,
) -> str:
    """Validate one absolute, origin-free API path or path template.

    Only the explicitly declared raw placeholders are accepted.  Encoded and
    multiply encoded braces are decoded before the safety check so they cannot
    hide an additional formatting field or change meaning in a proxy/server.
    """

    if not isinstance(value, str) or not 1 <= len(value) <= max_length:
        raise ApiPathValidationError("API path length is invalid")

    raw_placeholders = frozenset(_PLACEHOLDER.findall(value))
    raw_braces_are_exact = (
        value.count("{") == len(expected_placeholders)
        and value.count("}") == len(expected_placeholders)
    )
    if raw_placeholders != expected_placeholders or not raw_braces_are_exact:
        raise ApiPathValidationError(
            "API path placeholders are invalid", kind="placeholder"
        )

    fully_decoded = _fully_unquote(value)

    if expected_placeholders:
        decoded_placeholders = frozenset(_PLACEHOLDER.findall(fully_decoded))
        if decoded_placeholders != expected_placeholders:
            raise ApiPathValidationError(
                "API path placeholders are invalid", kind="placeholder"
            )

    check_path = value
    for placeholder in expected_placeholders:
        check_path = check_path.replace(f"{{{placeholder}}}", "validated-id")
    decoded_path = _fully_unquote(check_path)
    parsed = urlsplit(check_path)
    if (
        not check_path.startswith("/")
        or check_path.startswith("//")
        or decoded_path.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or "?" in check_path
        or "#" in check_path
        or parsed.query
        or parsed.fragment
        or "\\" in decoded_path
        or "{" in decoded_path
        or "}" in decoded_path
        or _contains_unsafe_character(check_path)
        or _contains_control_or_non_ascii(decoded_path)
        or (
            not allow_encoded_path_data
            and (
                "?" in decoded_path
                or "#" in decoded_path
                or _contains_unsafe_character(decoded_path)
            )
        )
        or any(segment in {".", ".."} for segment in decoded_path.split("/"))
    ):
        raise ApiPathValidationError("API path is not a safe absolute path")
    return value


def validate_base_url_path(path: str) -> None:
    """Reject ambiguous path syntax in an already parsed HTTPS base URL."""

    decoded_path = _fully_unquote(path)
    if (
        "\\" in decoded_path
        or "?" in decoded_path
        or "#" in decoded_path
        or "{" in decoded_path
        or "}" in decoded_path
        or _contains_unsafe_character(path)
        or _contains_unsafe_character(decoded_path)
        or decoded_path.startswith("//")
        or any(segment in {".", ".."} for segment in decoded_path.split("/"))
    ):
        raise ApiPathValidationError("cloud API base URL contains an invalid path")
