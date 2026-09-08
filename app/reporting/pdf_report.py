"""Secure, dependency-free PDF presentation of a canonical assessment.

The renderer accepts only the strict canonical model, uses no HTML, scripts,
network fetches, filesystem assets, or customer templates, and emits a bounded
PDF 1.7 document.  The complete machine-readable evidence remains in JSON;
large PDF tables declare any presentation-only truncation.

The built-in PDF fonts use Windows-1252.  Text outside that encoding is rejected
instead of being silently replaced.  See ``docs/PDF_UNICODE_SUPPORT.md`` for the
requirements to add a licensed, embedded Unicode font safely.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator

from app.models.assessment import CanonicalAssessmentReport
from app.models.base import StrictModel
from app.models.enums import Severity

from .assessment_json import serialize_canonical_assessment, validate_canonical_assessment

_PAGE_WIDTH = 595.0
_PAGE_HEIGHT = 842.0
_LEFT = 36.0
_RIGHT = 36.0
_TOP = 54.0
_BOTTOM = 42.0
_CONTENT_WIDTH = _PAGE_WIDTH - _LEFT - _RIGHT
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SPACE = re.compile(r"\s+")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_NAVY = (0.075, 0.102, 0.180)
_INK = (0.105, 0.137, 0.208)
_MUTED = (0.35, 0.39, 0.48)
_PURPLE = (0.42, 0.12, 0.96)
_LIGHT = (0.965, 0.972, 0.985)
_WHITE = (1.0, 1.0, 1.0)
_BORDER = (0.84, 0.86, 0.91)
_SEVERITY_COLORS = {
    Severity.CRITICAL: (0.80, 0.02, 0.10),
    Severity.HIGH: (0.94, 0.24, 0.05),
    Severity.MEDIUM: (0.91, 0.55, 0.02),
    Severity.LOW: (0.08, 0.43, 0.80),
    Severity.INFO: (0.30, 0.34, 0.42),
}


class PdfRenderError(ValueError):
    """Raised when safe rendering constraints cannot be satisfied."""


class PdfRenderLimitError(PdfRenderError):
    """Raised when a page, row, text, or output bound is exceeded."""


class PdfBranding(StrictModel):
    product_name: str = Field(default="Endpoint Security Scanner", min_length=1, max_length=128)
    organization_name: str = Field(default="Security Operations", min_length=1, max_length=128)
    classification: str = Field(default="CONFIDENTIAL", min_length=1, max_length=64)
    report_title: str = Field(
        default="Endpoint Security Assessment",
        min_length=1,
        max_length=160,
    )

    @field_validator(
        "product_name",
        "organization_name",
        "classification",
        "report_title",
    )
    @classmethod
    def safe_plain_text(cls, value: str) -> str:
        if "\x00" in value or "\r" in value or "\n" in value:
            raise ValueError("PDF branding cannot contain control-line characters")
        return value


class PdfRenderLimits(StrictModel):
    max_pages: int = Field(default=500, ge=1, le=2_000)
    max_rows_per_section: int = Field(default=1_000, ge=1, le=10_000)
    max_cell_characters: int = Field(default=2_048, ge=64, le=16_384)
    max_output_bytes: int = Field(default=50 * 1024 * 1024, ge=1_024, le=512 * 1024 * 1024)


@dataclass(frozen=True, slots=True)
class RenderedPdf:
    content: bytes
    source_json_sha256: str
    pdf_sha256: str
    page_count: int


@dataclass(slots=True)
class _Page:
    commands: list[str]
    section: str


def _clean_text(value: object, *, maximum: int) -> str:
    text = _CONTROL.sub("?", str(value)).replace("\r", " ").replace("\n", " ")
    text = _SPACE.sub(" ", text).strip()
    if len(text) > maximum:
        return f"{text[: maximum - 14]}...<truncated>"
    return text


def _pdf_literal(value: object, *, maximum: int = 16_384) -> str:
    cleaned = _clean_text(value, maximum=maximum)
    try:
        raw = cleaned.encode("cp1252", errors="strict")
    except UnicodeEncodeError as exc:
        unsupported_set: set[int] = set()
        for character in cleaned:
            try:
                character.encode("cp1252", errors="strict")
            except UnicodeEncodeError:
                unsupported_set.add(ord(character))
        unsupported = sorted(unsupported_set)
        encoded = ", ".join(f"U+{codepoint:04X}" for codepoint in unsupported[:8])
        if len(unsupported) > 8:
            encoded = f"{encoded}, and {len(unsupported) - 8} more"
        raise PdfRenderError(
            "PDF body text contains characters unsupported by the built-in "
            f"Windows-1252 font ({encoded}); refusing to replace or omit source text"
        ) from exc
    escaped = bytearray(b"(")
    for byte in raw:
        if byte in (0x28, 0x29, 0x5C):
            escaped.extend(b"\\")
            escaped.append(byte)
        elif byte < 0x20 or byte > 0x7E:
            escaped.extend(f"\\{byte:03o}".encode("ascii"))
        else:
            escaped.append(byte)
    escaped.extend(b")")
    return escaped.decode("ascii")


def _number(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".")


def _color(value: tuple[float, float, float]) -> str:
    return " ".join(_number(item) for item in value)


def _display(value: object | None) -> str:
    if value is None:
        return "Not observed"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


class _Layout:
    def __init__(self, *, limits: PdfRenderLimits, report_id: str) -> None:
        self.limits = limits
        self.report_id = report_id
        self.pages: list[_Page] = []
        self.page: _Page | None = None
        self.y = 0.0

    def new_page(self, section: str, *, cover: bool = False) -> None:
        if len(self.pages) >= self.limits.max_pages:
            raise PdfRenderLimitError(f"PDF exceeds {self.limits.max_pages} pages")
        self.page = _Page(commands=[], section=_clean_text(section, maximum=128))
        self.pages.append(self.page)
        self.y = _PAGE_HEIGHT - _TOP
        if cover:
            return
        self.rect(0, _PAGE_HEIGHT - 35, _PAGE_WIDTH, 35, _NAVY)
        self.text(self.page.section, _LEFT, _PAGE_HEIGHT - 23, size=9, bold=True, color=_WHITE)
        self.y -= 10

    def _active(self) -> _Page:
        if self.page is None:
            raise PdfRenderError("a PDF page has not been initialized")
        return self.page

    def ensure(self, height: float, section: str) -> None:
        if self.y - height < _BOTTOM:
            self.new_page(section)

    def rect(
        self,
        x: float,
        y: float,
        width: float,
        height: float,
        fill: tuple[float, float, float],
        *,
        stroke: tuple[float, float, float] | None = None,
    ) -> None:
        command = f"q {_color(fill)} rg "
        if stroke is not None:
            command += f"{_color(stroke)} RG 0.5 w "
        command += (
            f"{_number(x)} {_number(y)} {_number(width)} {_number(height)} re "
            f"{'B' if stroke is not None else 'f'} Q"
        )
        self._active().commands.append(command)

    def line(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        color: tuple[float, float, float] = _BORDER,
    ) -> None:
        self._active().commands.append(
            f"q {_color(color)} RG 0.5 w {_number(x1)} {_number(y1)} m "
            f"{_number(x2)} {_number(y2)} l S Q"
        )

    def text(
        self,
        value: object,
        x: float,
        y: float,
        *,
        size: float = 9,
        bold: bool = False,
        color: tuple[float, float, float] = _INK,
    ) -> None:
        font = "F2" if bold else "F1"
        self._active().commands.append(
            f"BT /{font} {_number(size)} Tf {_color(color)} rg "
            f"1 0 0 1 {_number(x)} {_number(y)} Tm {_pdf_literal(value)} Tj ET"
        )

    def wrapped_lines(self, value: object, width: float, size: float) -> list[str]:
        text = _clean_text(value, maximum=self.limits.max_cell_characters)
        capacity = max(8, int(width / max(1.0, size * 0.52)))
        if not text:
            return [""]
        words = text.split(" ")
        lines: list[str] = []
        line = ""
        for word in words:
            fragments = [word[index : index + capacity] for index in range(0, len(word), capacity)]
            for fragment in fragments or [""]:
                candidate = f"{line} {fragment}".strip()
                if line and len(candidate) > capacity:
                    lines.append(line)
                    line = fragment
                else:
                    line = candidate
        if line:
            lines.append(line)
        return lines or [""]

    def paragraph(
        self,
        value: object,
        *,
        section: str,
        width: float = _CONTENT_WIDTH,
        size: float = 9,
        leading: float = 12,
        color: tuple[float, float, float] = _INK,
        bold: bool = False,
    ) -> None:
        for line in self.wrapped_lines(value, width, size):
            self.ensure(leading, section)
            self.text(line, _LEFT, self.y, size=size, bold=bold, color=color)
            self.y -= leading
        self.y -= 3

    def heading(self, title: str, *, section: str, level: int = 1) -> None:
        height = 31 if level == 1 else 23
        self.ensure(height, section)
        size = 16 if level == 1 else 11
        if level == 1:
            self.rect(_LEFT, self.y - 4, 4, 19, _PURPLE)
            x = _LEFT + 12
        else:
            x = _LEFT
        self.text(title, x, self.y, size=size, bold=True, color=_NAVY)
        self.y -= height

    def key_values(self, rows: Sequence[tuple[str, object]], *, section: str) -> None:
        for label, value in rows:
            self.ensure(18, section)
            self.text(label, _LEFT, self.y, size=8, bold=True, color=_MUTED)
            self.text(_display(value), _LEFT + 142, self.y, size=8.5, color=_INK)
            self.y -= 15
        self.y -= 4

    def table(
        self,
        headers: Sequence[str],
        widths: Sequence[float],
        rows: Sequence[Sequence[object]],
        *,
        section: str,
    ) -> None:
        if len(headers) != len(widths) or not headers:
            raise PdfRenderError("PDF table columns are inconsistent")
        if not math.isclose(sum(widths), _CONTENT_WIDTH, abs_tol=0.2):
            raise PdfRenderError("PDF table widths must fill the content area")
        shown = rows[: self.limits.max_rows_per_section]

        def header() -> None:
            self.ensure(23, section)
            self.rect(_LEFT, self.y - 15, _CONTENT_WIDTH, 21, _NAVY)
            x = _LEFT + 4
            for label, width in zip(headers, widths, strict=True):
                self.text(label, x, self.y - 8, size=7, bold=True, color=_WHITE)
                x += width
            self.y -= 23

        header()
        for row_index, row in enumerate(shown):
            if len(row) != len(headers):
                raise PdfRenderError("PDF table row has the wrong number of cells")
            wrapped = [
                self.wrapped_lines(value, width - 8, 7.2)
                for value, width in zip(row, widths, strict=True)
            ]
            for lines in wrapped:
                if len(lines) > 18:
                    del lines[17:]
                    lines.append("...<complete value in canonical JSON>")
            line_count = max(len(lines) for lines in wrapped)
            row_height = max(19.0, line_count * 9.0 + 8.0)
            if self.y - row_height < _BOTTOM:
                self.new_page(section)
                header()
            fill = _WHITE if row_index % 2 == 0 else _LIGHT
            self.rect(_LEFT, self.y - row_height + 5, _CONTENT_WIDTH, row_height, fill)
            x = _LEFT + 4
            for lines, width in zip(wrapped, widths, strict=True):
                for line_index, line in enumerate(lines):
                    self.text(line, x, self.y - 7 - line_index * 9, size=7.2, color=_INK)
                x += width
            self.line(
                _LEFT,
                self.y - row_height + 5,
                _LEFT + _CONTENT_WIDTH,
                self.y - row_height + 5,
            )
            self.y -= row_height
        omitted = len(rows) - len(shown)
        if omitted:
            self.paragraph(
                f"{omitted} additional records omitted from the PDF presentation; "
                "the canonical JSON contains the complete dataset.",
                section=section,
                size=8,
                color=_MUTED,
            )
        self.y -= 8


def _endpoint_name(report: CanonicalAssessmentReport) -> str:
    endpoint = report.endpoint_scan.endpoint
    if endpoint is not None:
        return endpoint.display_name or endpoint.hostname
    if report.endpoint_scan.os is not None and report.endpoint_scan.os.hostname:
        return report.endpoint_scan.os.hostname
    return report.endpoint_scan.endpoint_id or "Unknown endpoint"


def _render_cover(
    layout: _Layout,
    report: CanonicalAssessmentReport,
    branding: PdfBranding,
    source_hash: str,
) -> None:
    layout.new_page("Cover", cover=True)
    layout.rect(0, 0, _PAGE_WIDTH, _PAGE_HEIGHT, _NAVY)
    layout.rect(0, _PAGE_HEIGHT - 10, _PAGE_WIDTH, 10, _PURPLE)
    layout.text(branding.organization_name, _LEFT, 785, size=10, bold=True, color=_WHITE)
    layout.text(branding.product_name, _LEFT, 764, size=9, color=(0.70, 0.73, 0.82))
    layout.text(branding.report_title, _LEFT, 655, size=28, bold=True, color=_WHITE)
    layout.text(
        "Canonical endpoint evidence and risk report",
        _LEFT,
        625,
        size=12,
        color=(0.75, 0.78, 0.88),
    )
    layout.rect(_LEFT, 430, _CONTENT_WIDTH, 145, (0.11, 0.14, 0.24), stroke=(0.26, 0.30, 0.43))
    details = (
        ("Endpoint", _endpoint_name(report)),
        ("Endpoint ID", report.endpoint_scan.endpoint_id),
        ("Assessment status", report.summary.status.value),
        ("Completed", report.summary.finished_at.isoformat()),
        ("Report ID", report.report_id),
        ("Source JSON SHA-256", source_hash),
    )
    y = 545.0
    for label, value in details:
        layout.text(label.upper(), _LEFT + 18, y, size=7, bold=True, color=(0.58, 0.62, 0.73))
        layout.text(_display(value), _LEFT + 150, y, size=8.5, color=_WHITE)
        y -= 20
    layout.text(
        f"Health score {report.summary.health_score:.2f} / 100",
        _LEFT,
        355,
        size=18,
        bold=True,
        color=_WHITE,
    )
    layout.text(
        f"{report.summary.finding_count} findings | "
        f"{report.summary.vulnerability_count} vulnerabilities | "
        f"{report.summary.missing_patch_count} missing patches",
        _LEFT,
        327,
        size=9,
        color=(0.75, 0.78, 0.88),
    )
    layout.text(
        branding.classification.upper(),
        _LEFT,
        54,
        size=8,
        bold=True,
        color=(0.75, 0.78, 0.88),
    )
    layout.text(
        "Generated from schema-validated canonical JSON",
        _LEFT,
        36,
        size=7.5,
        color=(0.58, 0.62, 0.73),
    )


def _render_executive_summary(layout: _Layout, report: CanonicalAssessmentReport) -> None:
    section = "Executive Summary"
    layout.new_page(section)
    layout.heading(section, section=section)
    card_width = (_CONTENT_WIDTH - 16) / 5
    x = _LEFT
    for severity in Severity:
        count = report.summary.severity_counts[severity]
        layout.rect(x, layout.y - 48, card_width, 48, _LIGHT, stroke=_BORDER)
        layout.text(severity.value.title(), x + 8, layout.y - 16, size=7.5, color=_MUTED)
        layout.text(
            count,
            x + 8,
            layout.y - 38,
            size=15,
            bold=True,
            color=_SEVERITY_COLORS[severity],
        )
        x += card_width + 4
    layout.y -= 68
    layout.heading("Scan details", section=section, level=2)
    scan = report.endpoint_scan
    os_record = scan.os
    layout.key_values(
        (
            ("Mode", scan.scan_type.value),
            ("Endpoint", _endpoint_name(report)),
            ("Detected OS", os_record.name if os_record else None),
            (
                "OS version / build",
                f"{os_record.version} / {os_record.build or 'Not observed'}"
                if os_record
                else None,
            ),
            ("Started", scan.started_at.isoformat()),
            ("Completed", scan.finished_at.isoformat() if scan.finished_at else None),
            ("Policy", f"{scan.policy_id} {scan.policy_version or ''}".strip()),
            ("Risk level", report.summary.risk_level.value),
        ),
        section=section,
    )
    layout.heading("Local exposure boundary", section=section, level=2)
    layout.rect(
        _LEFT,
        layout.y - 48,
        _CONTENT_WIDTH,
        52,
        (0.99, 0.96, 0.88),
        stroke=(0.92, 0.73, 0.24),
    )
    layout.text(
        "LOCAL LISTENERS ARE NOT REMOTE EXPOSURE",
        _LEFT + 10,
        layout.y - 14,
        size=9,
        bold=True,
        color=(0.50, 0.31, 0.03),
    )
    layout.text(
        f"Observed {report.summary.local_listener_count} endpoint-local sockets; remote "
        "reachability was NOT TESTED.",
        _LEFT + 10,
        layout.y - 33,
        size=8,
        color=(0.40, 0.27, 0.05),
    )
    layout.y -= 66


def _render_coverage(layout: _Layout, report: CanonicalAssessmentReport) -> None:
    section = "Evidence Coverage"
    layout.heading(section, section=section)
    rows = [
        (
            item.name.replace("_", " ").title(),
            item.scope.value.replace("_", " ").title(),
            item.state.value.replace("_", " ").title(),
            "Yes" if item.required else "No",
            _display(item.records_observed),
            item.detail,
        )
        for item in report.coverage.sections
    ]
    layout.table(
        ("Section", "Scope", "State", "Required", "Records", "Evidence statement"),
        (90, 78, 62, 47, 43, 203),
        rows,
        section=section,
    )


def _render_findings(layout: _Layout, report: CanonicalAssessmentReport) -> None:
    section = "Security Findings"
    layout.heading(section, section=section)
    if not report.findings:
        layout.paragraph(
            "No findings were produced by the observed evidence. This is not proof that the "
            "endpoint is free of risk; review the coverage section.",
            section=section,
        )
        return
    rows = []
    for finding in report.findings:
        cvss = finding.evidence.get("cvss_score")
        component = finding.evidence.get("package_name") or finding.evidence.get("update_id")
        rows.append(
            (
                finding.severity.value,
                finding.category.replace("_", " ").title(),
                finding.title,
                _display(component),
                _display(cvss),
                finding.remediation,
            )
        )
    layout.table(
        ("Severity", "Category", "Finding", "Component", "CVSS", "Remediation"),
        (48, 72, 142, 80, 36, 145),
        rows,
        section=section,
    )


def _render_vulnerabilities(layout: _Layout, report: CanonicalAssessmentReport) -> None:
    section = "Package Vulnerabilities"
    layout.heading(section, section=section)
    rows = [
        (
            item.severity.value,
            item.vulnerability_id,
            item.package_name,
            _display(item.installed_version),
            ", ".join(item.fixed_versions) or "Not supplied",
            _display(item.cvss_score),
            ", ".join(_sources_for_pdf(item.evidence)),
        )
        for item in report.endpoint_scan.vulnerabilities
    ]
    if rows:
        layout.table(
            ("Severity", "Advisory", "Package", "Installed", "Fixed", "CVSS", "Source"),
            (48, 80, 92, 67, 100, 36, 100),
            rows,
            section=section,
        )
    else:
        layout.paragraph(
            "No package vulnerabilities were reported. Interpret this result together with "
            "dependency-vulnerability coverage and software identity quality.",
            section=section,
        )


def _sources_for_pdf(evidence: Mapping[str, Any]) -> tuple[str, ...]:
    raw = evidence.get("sources") or evidence.get("source_names")
    if isinstance(raw, list):
        return tuple(str(item) for item in raw[:16])
    source = evidence.get("source_tool") or evidence.get("source")
    return (str(source),) if source else ("Not supplied",)


def _render_patches(layout: _Layout, report: CanonicalAssessmentReport) -> None:
    section = "Patch Status"
    layout.heading(section, section=section)
    missing = [item for item in report.endpoint_scan.updates if not item.installed]
    rows = [
        (
            item.update_id,
            _display(item.title),
            _display(item.category),
            _display(item.severity),
            _display(item.security_update),
            _display(item.reboot_required),
        )
        for item in missing
    ]
    if rows:
        layout.table(
            ("Update", "Title", "Category", "Severity", "Security", "Reboot"),
            (72, 195, 78, 62, 58, 58),
            rows,
            section=section,
        )
    else:
        layout.paragraph(
            "No individually identified missing updates were reported. Verify patch coverage "
            "before interpreting this as current patch compliance.",
            section=section,
        )


def _render_endpoint_posture(layout: _Layout, report: CanonicalAssessmentReport) -> None:
    section = "Endpoint Inventory"
    layout.heading(section, section=section)
    scan = report.endpoint_scan
    if scan.os is not None:
        layout.heading("Operating system", section=section, level=2)
        layout.key_values(
            tuple(
                (key.replace("_", " ").title(), _display(value))
                for key, value in scan.os.model_dump(mode="json", exclude_none=False).items()
            ),
            section=section,
        )
    if scan.security is not None:
        layout.heading("Security posture", section=section, level=2)
        posture = scan.security.model_dump(mode="json", exclude_none=False)
        simple = [
            (key.replace("_", " ").title(), _display(value))
            for key, value in posture.items()
            if not isinstance(value, (dict, list))
        ]
        layout.key_values(tuple(simple), section=section)
        if scan.security.firewall_profiles:
            layout.heading("Firewall profiles", section=section, level=2)
            layout.table(
                ("Profile", "Enabled", "Inbound", "Outbound", "Log blocked"),
                (120, 70, 115, 115, 103),
                [
                    (
                        item.name,
                        _display(item.enabled),
                        _display(item.default_inbound_action),
                        _display(item.default_outbound_action),
                        _display(item.log_blocked),
                    )
                    for item in scan.security.firewall_profiles
                ],
                section=section,
            )
        if scan.security.antivirus_products:
            layout.heading("Antivirus products", section=section, level=2)
            layout.table(
                ("Product", "Enabled", "Real-time", "Current", "Signature version"),
                (155, 68, 78, 68, 154),
                [
                    (
                        item.name,
                        _display(item.enabled),
                        _display(item.real_time_protection_enabled),
                        _display(item.signatures_up_to_date),
                        _display(item.signature_version),
                    )
                    for item in scan.security.antivirus_products
                ],
                section=section,
            )
        if scan.security.encryption_volumes:
            layout.heading("Disk encryption", section=section, level=2)
            layout.table(
                ("Volume", "Status", "Protected", "Method", "Encrypted"),
                (92, 120, 75, 145, 91),
                [
                    (
                        item.mount_point,
                        _display(item.volume_status),
                        _display(item.protection_enabled),
                        _display(item.encryption_method),
                        (
                            f"{item.encryption_percentage:.1f}%"
                            if item.encryption_percentage is not None
                            else "Not observed"
                        ),
                    )
                    for item in scan.security.encryption_volumes
                ],
                section=section,
            )
    if scan.certificates:
        layout.heading("Certificates", section=section, level=2)
        layout.table(
            ("Store", "Subject", "Issuer", "Expires", "Expired", "Private key"),
            (65, 145, 125, 83, 50, 55),
            [
                (
                    item.store,
                    item.subject,
                    _display(item.issuer),
                    item.not_after.isoformat() if item.not_after else "Not observed",
                    _display(item.expired),
                    _display(item.has_private_key),
                )
                for item in scan.certificates
            ],
            section=section,
        )
    layout.heading("Installed software", section=section, level=2)
    layout.table(
        ("Name", "Version", "Vendor", "Package manager", "Architecture"),
        (175, 80, 120, 85, 63),
        [
            (
                item.name,
                _display(item.version),
                _display(item.vendor),
                _display(item.package_manager),
                _display(item.architecture),
            )
            for item in scan.software
        ],
        section=section,
    )


def _render_local_listeners(layout: _Layout, report: CanonicalAssessmentReport) -> None:
    section = "Local Listening Ports"
    layout.heading(section, section=section)
    layout.paragraph(
        "These bindings were observed on the endpoint. The report does not claim that any "
        "listener is reachable from another host.",
        section=section,
        bold=True,
    )
    layout.table(
        (
            "Protocol",
            "Local address",
            "Port",
            "PID",
            "Process",
            "Bind scope",
            "Reachability",
        ),
        (50, 91, 41, 45, 120, 72, 104),
        [
            (
                item.protocol.value,
                item.address,
                item.port,
                _display(item.pid),
                _display(item.process),
                item.bind_scope,
                item.remote_reachability,
            )
            for item in report.endpoint_scan.listening_ports
        ],
        section=section,
    )


def _render_operational_inventory(layout: _Layout, report: CanonicalAssessmentReport) -> None:
    scan = report.endpoint_scan
    section = "Services and Processes"
    layout.heading(section, section=section)
    layout.heading("Services", section=section, level=2)
    layout.table(
        ("Service", "Display name", "State", "Startup", "Account"),
        (130, 150, 63, 80, 100),
        [
            (
                item.name,
                _display(item.display_name),
                item.state.value,
                _display(item.startup_type),
                _display(item.service_account),
            )
            for item in scan.services
        ],
        section=section,
    )
    layout.heading("Processes", section=section, level=2)
    layout.table(
        ("PID", "Process", "Parent", "User", "Executable"),
        (48, 115, 55, 105, 200),
        [
            (
                item.pid,
                item.name,
                _display(item.parent_pid),
                _display(item.user),
                _display(item.executable_path),
            )
            for item in scan.processes
        ],
        section=section,
    )


def _render_identity_and_persistence(
    layout: _Layout,
    report: CanonicalAssessmentReport,
) -> None:
    scan = report.endpoint_scan
    section = "Identity and Persistence"
    layout.heading(section, section=section)
    layout.heading("Local users", section=section, level=2)
    layout.table(
        ("Username", "Enabled", "Administrator", "Guest", "Groups"),
        (125, 62, 85, 62, 189),
        [
            (
                item.username,
                _display(item.enabled),
                _display(item.is_administrator),
                _display(item.is_guest),
                ", ".join(sorted(item.groups)),
            )
            for item in scan.users
        ],
        section=section,
    )
    layout.heading("Persistence and startup", section=section, level=2)
    layout.table(
        ("Name", "Kind", "Location", "User", "Suspicious"),
        (125, 80, 200, 65, 53),
        [
            (
                item.name,
                item.kind,
                _display(item.location),
                _display(item.user),
                _display(item.suspicious),
            )
            for item in scan.persistence
        ],
        section=section,
    )


def _render_provenance(
    layout: _Layout,
    report: CanonicalAssessmentReport,
    source_hash: str,
) -> None:
    section = "Provenance and Limitations"
    layout.heading(section, section=section)
    layout.heading("Evidence integrity", section=section, level=2)
    layout.key_values(
        (
            ("Report ID", report.report_id),
            ("Scan ID", report.endpoint_scan.scan_id),
            ("Endpoint ID", report.endpoint_scan.endpoint_id),
            ("Schema version", report.schema_version),
            ("Scanner version", report.scanner_version),
            ("Source JSON SHA-256", source_hash),
            ("Canonical scan SHA-256", report.provenance.canonical_scan_sha256),
            ("Assessment evidence SHA-256", report.provenance.assessment_evidence_sha256),
        ),
        section=section,
    )
    layout.heading("Collector and analyzer status", section=section, level=2)
    status_rows = [
        (
            "Endpoint",
            item.name,
            item.status.value,
            item.records_collected,
            _display(item.tool_version),
            _display(item.error_message),
        )
        for item in report.endpoint_scan.collectors.values()
    ]
    status_rows.extend(
        (
            "Cloud",
            item.name,
            item.status.value,
            item.records_collected,
            _display(item.tool_version),
            _display(item.error_message),
        )
        for item in report.analysis_tools
    )
    layout.table(
        ("Scope", "Source", "Status", "Records", "Version", "Detail"),
        (55, 105, 62, 55, 75, 171),
        status_rows,
        section=section,
    )
    layout.heading("Limitations", section=section, level=2)
    for limitation in report.limitations:
        layout.paragraph(f"- {limitation}", section=section, size=8.5)


def _pdf_bytes(
    layout: _Layout,
    *,
    report: CanonicalAssessmentReport,
    branding: PdfBranding,
    source_hash: str,
) -> bytes:
    if not layout.pages:
        raise PdfRenderError("PDF has no pages")
    page_count = len(layout.pages)
    objects: dict[int, bytes] = {}
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[3] = (
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding >>"
    )
    objects[4] = (
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
        b"/Encoding /WinAnsiEncoding >>"
    )
    page_numbers: list[int] = []
    next_object = 5
    for index, page in enumerate(layout.pages, start=1):
        page_object = next_object
        content_object = next_object + 1
        next_object += 2
        page_numbers.append(page_object)
        footer = [
            f"q {_color(_BORDER)} RG 0.5 w {_number(_LEFT)} 31 m "
            f"{_number(_PAGE_WIDTH - _RIGHT)} 31 l S Q",
            (
                f"BT /F1 7 Tf {_color(_MUTED)} rg 1 0 0 1 {_number(_LEFT)} 18 Tm "
                f"{_pdf_literal(report.report_id, maximum=128)} Tj ET"
            ),
            (
                f"BT /F1 7 Tf {_color(_MUTED)} rg 1 0 0 1 474 18 Tm "
                f"{_pdf_literal(f'Page {index} of {page_count}', maximum=64)} Tj ET"
            ),
        ]
        stream = ("\n".join((*page.commands, *footer)) + "\n").encode("latin-1")
        objects[content_object] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")
            + stream
            + b"endstream"
        )
        objects[page_object] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            f"/Contents {content_object} 0 R >>"
        ).encode("ascii")
    kids = " ".join(f"{number} 0 R" for number in page_numbers)
    objects[2] = f"<< /Type /Pages /Count {page_count} /Kids [{kids}] >>".encode("ascii")
    info_object = next_object
    created = report.generated_at.astimezone(UTC).strftime("D:%Y%m%d%H%M%SZ")
    objects[info_object] = (
        f"<< /Title {_pdf_literal(branding.report_title, maximum=160)} "
        f"/Author {_pdf_literal(branding.organization_name, maximum=128)} "
        f"/Subject {_pdf_literal('Canonical endpoint security assessment', maximum=128)} "
        f"/Keywords {_pdf_literal('endpoint security, inventory, vulnerability, compliance', maximum=128)} "  # noqa: E501
        f"/Creator {_pdf_literal(branding.product_name, maximum=128)} "
        f"/CreationDate {_pdf_literal(created, maximum=64)} >>"
    ).encode("latin-1")

    output = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0] * (max(objects) + 1)
    for number in range(1, max(objects) + 1):
        offsets[number] = len(output)
        output.extend(f"{number} 0 obj\n".encode("ascii"))
        output.extend(objects[number])
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    document_id = hashlib.sha256(f"{source_hash}:{report.report_id}".encode()).hexdigest()
    output.extend(
        (
            f"trailer\n<< /Size {len(offsets)} /Root 1 0 R /Info {info_object} 0 R "
            f"/ID [<{document_id}> <{document_id}>] >>\n"
            f"startxref\n{xref}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def render_assessment_pdf(
    report: CanonicalAssessmentReport | Mapping[str, Any],
    *,
    branding: PdfBranding | None = None,
    limits: PdfRenderLimits | None = None,
) -> RenderedPdf:
    """Render validated assessment data without interpreting active content."""

    validated = validate_canonical_assessment(report)
    selected_branding = branding or PdfBranding()
    selected_limits = limits or PdfRenderLimits()
    serialized = serialize_canonical_assessment(validated)
    if not _SHA256.fullmatch(serialized.sha256):
        raise PdfRenderError("canonical JSON digest is invalid")
    layout = _Layout(limits=selected_limits, report_id=validated.report_id)
    _render_cover(layout, validated, selected_branding, serialized.sha256)
    _render_executive_summary(layout, validated)
    _render_coverage(layout, validated)
    _render_findings(layout, validated)
    _render_vulnerabilities(layout, validated)
    _render_patches(layout, validated)
    _render_endpoint_posture(layout, validated)
    _render_local_listeners(layout, validated)
    _render_operational_inventory(layout, validated)
    _render_identity_and_persistence(layout, validated)
    _render_provenance(layout, validated, serialized.sha256)
    content = _pdf_bytes(
        layout,
        report=validated,
        branding=selected_branding,
        source_hash=serialized.sha256,
    )
    if len(content) > selected_limits.max_output_bytes:
        raise PdfRenderLimitError(
            f"PDF is {len(content)} bytes; maximum is {selected_limits.max_output_bytes}"
        )
    return RenderedPdf(
        content=content,
        source_json_sha256=serialized.sha256,
        pdf_sha256=hashlib.sha256(content).hexdigest(),
        page_count=len(layout.pages),
    )


class CanonicalAssessmentPdfWriter:
    """Atomically write a rendered assessment PDF with owner-only permissions."""

    @staticmethod
    def validate_destination(output_path: str | os.PathLike[str]) -> Path:
        raw = os.fspath(output_path)
        if not raw or "\x00" in raw:
            raise ValueError("PDF output path is invalid")
        candidate = Path(raw).expanduser()
        if candidate.suffix.casefold() != ".pdf":
            raise ValueError("PDF output must use a .pdf extension")
        if len(candidate.name) > 240 or candidate.name in {".pdf", "..pdf"}:
            raise ValueError("PDF output filename is invalid")
        return candidate.parent.resolve(strict=False) / candidate.name

    def write(
        self,
        report: CanonicalAssessmentReport | Mapping[str, Any],
        output_path: str | os.PathLike[str],
        *,
        branding: PdfBranding | None = None,
        limits: PdfRenderLimits | None = None,
    ) -> Path:
        destination = self.validate_destination(output_path)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.is_symlink():
            raise ValueError("PDF output cannot replace a symbolic link")
        if destination.exists() and not destination.is_file():
            raise ValueError("PDF output destination is not a regular file")
        rendered = render_assessment_pdf(report, branding=branding, limits=limits)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.stem}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary = Path(temporary_name)
        try:
            os.chmod(temporary, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(rendered.content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
            if os.name != "nt":
                directory_descriptor = os.open(destination.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
        return destination


def write_assessment_pdf(
    report: CanonicalAssessmentReport | Mapping[str, Any],
    output_path: str | os.PathLike[str],
    *,
    branding: PdfBranding | None = None,
    limits: PdfRenderLimits | None = None,
) -> Path:
    return CanonicalAssessmentPdfWriter().write(
        report,
        output_path,
        branding=branding,
        limits=limits,
    )


__all__ = [
    "CanonicalAssessmentPdfWriter",
    "PdfBranding",
    "PdfRenderError",
    "PdfRenderLimitError",
    "PdfRenderLimits",
    "RenderedPdf",
    "render_assessment_pdf",
    "write_assessment_pdf",
]
