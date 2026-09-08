"""Secret hashing, opaque credential issuance, and constant-time token lookup."""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass


def hash_token(token: str, pepper: str) -> str:
    return hmac.new(pepper.encode(), token.encode(), hashlib.sha256).hexdigest()


def token_tenant(token: str, configured: Mapping[str, str], pepper: str) -> str | None:
    candidate = hash_token(token, pepper)
    tenant: str | None = None
    # Evaluate all configured values to avoid leaking which token matched by timing.
    for known, known_tenant in configured.items():
        if hmac.compare_digest(candidate, hash_token(known, pepper)):
            tenant = known_tenant
    return tenant


@dataclass(frozen=True, slots=True)
class CredentialIssuer:
    pepper: str

    def issue_token(self, endpoint_id: str, credential_id: str, generation: int) -> str:
        material = f"{endpoint_id}\x00{credential_id}\x00{generation}".encode()
        secret = hmac.new(self.pepper.encode(), material, hashlib.sha512).digest()
        encoded = base64.urlsafe_b64encode(secret).rstrip(b"=").decode("ascii")
        return f"esc_v1.{credential_id}.{encoded}"

    def issue_enrollment_token(self, grant_id: str) -> str:
        material = f"enrollment\x00{grant_id}".encode()
        secret = hmac.new(self.pepper.encode(), material, hashlib.sha512).digest()
        encoded = base64.urlsafe_b64encode(secret).rstrip(b"=").decode("ascii")
        return f"esc_enroll_v1.{grant_id}.{encoded}"

    def token_hash(self, token: str) -> str:
        return hash_token(token, self.pepper)
