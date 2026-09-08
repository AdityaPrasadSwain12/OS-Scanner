"""Reusable validation helpers for externally supplied identifiers."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str) -> str:
    """Return canonical ASCII DNS form for an authorized domain.

    URLs, wildcards, IP literals, single-label names, and ambiguous DNS syntax are
    rejected. Scope matching is performed separately and never via substring.
    """

    candidate = value.strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253:
        raise ValueError("domain must contain between 1 and 253 characters")
    if "://" in candidate or any(char in candidate for char in "/?#@:*[]"):
        raise ValueError("target must be a DNS domain, not a URL, wildcard, IP, or host:port")
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("domain is not valid IDNA") from exc
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise ValueError("domain must be a valid multi-label DNS name")
    valid_tld = (labels[-1].isalpha() and len(labels[-1]) >= 2) or labels[-1].startswith("xn--")
    if not valid_tld:
        raise ValueError("domain must end in a valid alphabetic top-level label")
    return ascii_domain


def validate_reference(value: str) -> str:
    """Allow non-secret HTTPS references and stable URNs only."""

    reference = value.strip()
    if len(reference) > 2048 or any(ord(character) < 32 for character in reference):
        raise ValueError("invalid reference")
    if reference.startswith("urn:"):
        return reference
    parsed = urlsplit(reference)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("references must be HTTPS URLs without embedded credentials, or URNs")
    return reference
