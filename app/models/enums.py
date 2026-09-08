"""Canonical enumerations shared by scanner components."""

from enum import StrEnum


class OperatingSystemFamily(StrEnum):
    WINDOWS = "WINDOWS"
    LINUX = "LINUX"
    MACOS = "MACOS"
    UNKNOWN = "UNKNOWN"


class ScanType(StrEnum):
    QUICK = "QUICK"
    FULL = "FULL"
    COMPLIANCE = "COMPLIANCE"
    VULNERABILITY = "VULNERABILITY"
    ATTACK_SURFACE = "ATTACK_SURFACE"
    ON_DEMAND = "ON_DEMAND"


class CollectorState(StrEnum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    SKIPPED = "SKIPPED"


class OverallStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class ComplianceStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - compliance outcome, not a credential
    FAIL = "FAIL"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class RiskLevel(StrEnum):
    HEALTHY = "HEALTHY"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ServiceState(StrEnum):
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    PAUSED = "PAUSED"
    UNKNOWN = "UNKNOWN"


class NetworkProtocol(StrEnum):
    TCP = "TCP"
    UDP = "UDP"
    UNKNOWN = "UNKNOWN"


class AssetType(StrEnum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    ENDPOINT = "ENDPOINT"
