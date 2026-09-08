from __future__ import annotations

from app.security import REDACTED, redact_command_line, redact_text, redact_value


def test_access_key_and_private_material_never_survive_redaction() -> None:
    access_key = "AKIAABCDEFGHIJKLMNOP"
    private_material = "-----BEGIN RSA PRIVATE KEY-----\nvery-secret\n-----END RSA PRIVATE KEY-----"
    result = redact_text(f"{access_key}\n{private_material}")
    assert access_key not in result
    assert "very-secret" not in result


def test_command_redaction_does_not_interpret_shell_metacharacters() -> None:
    argv = ["tool", "--token", "$(malicious)", "; whoami", "--host", "example.test"]
    result = redact_command_line(argv)
    assert result[2] == REDACTED
    assert result[3] == "; whoami"


def test_security_posture_password_facts_survive_without_weakening_secret_redaction() -> None:
    result = redact_value(
        {
            "local_admin_password_managed": True,
            "password_policy_compliant": False,
            "passwordauthentication": "no",
            "password_required": "actual-secret",
            "password": False,
            "api_token": True,
        }
    )

    assert result == {
        "local_admin_password_managed": True,
        "password_policy_compliant": False,
        "passwordauthentication": "no",
        "password_required": REDACTED,
        "password": REDACTED,
        "api_token": REDACTED,
    }
