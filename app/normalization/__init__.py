"""Scanner-owned normalization boundary for all collector data."""

from .merge import merge_inventory
from .native import normalize_native
from .osquery import NormalizationOutcome, fallback_endpoint_identity, normalize_osquery
from .security_tools import (
    normalize_amass,
    normalize_depscan,
    normalize_openscap,
    normalize_osv,
)
from .vulnerability_merge import merge_vulnerabilities

__all__ = [
    "NormalizationOutcome",
    "fallback_endpoint_identity",
    "merge_inventory",
    "merge_vulnerabilities",
    "normalize_amass",
    "normalize_depscan",
    "normalize_native",
    "normalize_openscap",
    "normalize_osquery",
    "normalize_osv",
]
