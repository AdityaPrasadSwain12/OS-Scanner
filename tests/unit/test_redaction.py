from __future__ import annotations

from app.security import (
    REDACTED,
    TRUNCATED,
    redact_command_line,
    redact_mapping,
    redact_text,
    redact_value,
    sanitize_for_log,
)


def test_redacts_assignments_authorization_jwt_and_url_credentials() -> None:
    source = (
        "password=hunter2 Authorization: Bearer abcdefghijklmnop "
        "jwt=eyJabcdefghijk.eyJabcdefghijk.abcdefghijk "
        "https://alice:correct-horse@example.com/path"
    )
    result = redact_text(source)
    assert "hunter2" not in result
    assert "abcdefghijklmnop" not in result
    assert "correct-horse" not in result
    assert result.count(REDACTED) >= 3


def test_redacts_private_key_blocks() -> None:
    value = (
        "prefix\n-----BEGIN PRIVATE KEY-----\nsecret-material\n-----END PRIVATE KEY-----\nsuffix"
    )
    result = redact_text(value)
    assert "secret-material" not in result
    assert REDACTED in result


def test_redacts_nested_sensitive_keys_without_mutating_input() -> None:
    source = {"username": "alice", "auth": {"api_token": "secret", "note": "safe"}}
    result = redact_mapping(source)
    assert result == {"username": "alice", "auth": {"api_token": REDACTED, "note": "safe"}}
    assert source["auth"]["api_token"] == "secret"


def test_redacts_argv_separate_and_assignment_forms() -> None:
    command = ["client", "--token", "secret-one", "--password=secret-two", "--host", "example.test"]
    result = redact_command_line(command)
    assert result == [
        "client",
        "--token",
        REDACTED,
        f"--password={REDACTED}",
        "--host",
        "example.test",
    ]


def test_cycle_and_depth_are_bounded() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    assert redact_value(cyclic) == [TRUNCATED]
    nested: object = "leaf"
    for _ in range(20):
        nested = [nested]
    assert TRUNCATED in str(redact_value(nested, max_depth=3))


def test_log_sanitization_neutralizes_line_breaks_after_redaction() -> None:
    result = sanitize_for_log({"message": "ok\r\nforged=true", "token": "secret"})
    assert result["message"] == "ok\\r\\nforged=true"
    assert result["token"] == REDACTED
