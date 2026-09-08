"""OWASP dep-scan dependency vulnerability analysis integration."""

from app.tools.depscan.adapter import DepScanAdapter, DepScanMode, DepScanRequest

__all__ = ["DepScanAdapter", "DepScanMode", "DepScanRequest"]
