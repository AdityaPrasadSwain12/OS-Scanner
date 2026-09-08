"""Strictly authorized OWASP Amass discovery integration."""

from app.tools.amass.adapter import (
    AmassAdapter,
    AmassRequest,
    AmassScopeError,
    normalize_domain,
    registrable_domain,
)

__all__ = [
    "AmassAdapter",
    "AmassRequest",
    "AmassScopeError",
    "normalize_domain",
    "registrable_domain",
]
