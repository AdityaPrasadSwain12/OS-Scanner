from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.reporting.assessment_json import serialize_canonical_assessment
from app.reporting.pdf_report import (
    CanonicalAssessmentPdfWriter,
    PdfBranding,
    PdfRenderError,
    PdfRenderLimitError,
    PdfRenderLimits,
    render_assessment_pdf,
)
from tests.unit.test_canonical_assessment import assessment


def test_pdf_is_deterministic_multipage_and_bound_to_exact_canonical_json() -> None:
    report = assessment()

    first = render_assessment_pdf(report)
    second = render_assessment_pdf(report.model_dump(mode="json"))

    assert first == second
    assert first.content.startswith(b"%PDF-1.7")
    assert first.content.endswith(b"%%EOF\n")
    assert first.page_count >= 2
    assert first.content.count(b"/Type /Page ") == first.page_count
    assert first.source_json_sha256 == serialize_canonical_assessment(report).sha256
    assert first.pdf_sha256 == hashlib.sha256(first.content).hexdigest()
    assert first.source_json_sha256.encode() in first.content
    assert b"LOCAL LISTENERS ARE NOT REMOTE EXPOSURE" in first.content
    assert b"remote reachability was NOT TESTED" in first.content


def test_pdf_escapes_endpoint_text_and_never_interprets_it_as_pdf_commands() -> None:
    injected = r"host) Tj /F2 99 Tf (owned"
    rendered = render_assessment_pdf(assessment(hostname=injected))

    assert injected.encode() not in rendered.content
    assert b"host\\) Tj /F2 99 Tf \\(owned" in rendered.content


def test_pdf_preserves_supported_extended_latin_text() -> None:
    rendered = render_assessment_pdf(assessment(hostname="M\u00fcnchen-endpoint"))

    # WinAnsi byte 0xfc is emitted as an octal PDF string escape, not as '?'.
    assert b"M\\374nchen-endpoint" in rendered.content
    assert b"M?nchen-endpoint" not in rendered.content


def test_pdf_refuses_to_replace_non_winansi_evidence_and_json_retains_it() -> None:
    hostname = "\u4e3b\u673a-\u043c\u043e\u0441\u043a\u0432\u0430"
    report = assessment(hostname=hostname)

    serialized = serialize_canonical_assessment(report)
    assert hostname.encode("utf-8") in serialized.content
    with pytest.raises(PdfRenderError, match="refusing to replace or omit source text"):
        render_assessment_pdf(report)


def test_pdf_rejects_noncanonical_data_and_enforces_resource_limits() -> None:
    payload = assessment().model_dump(mode="json")
    payload["unexpected"] = "not allowed"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        render_assessment_pdf(payload)

    with pytest.raises(PdfRenderLimitError, match="pages"):
        render_assessment_pdf(assessment(), limits=PdfRenderLimits(max_pages=1))

    with pytest.raises(PdfRenderLimitError, match="maximum"):
        render_assessment_pdf(
            assessment(),
            limits=PdfRenderLimits(max_output_bytes=1_024),
        )


def test_pdf_writer_is_atomic_and_requires_pdf_extension(tmp_path: Path) -> None:
    writer = CanonicalAssessmentPdfWriter()
    destination = writer.write(
        assessment(),
        tmp_path / "report.pdf",
        branding=PdfBranding(organization_name="Example Security"),
    )

    assert destination.read_bytes().startswith(b"%PDF-1.7")
    assert not list(tmp_path.glob("*.tmp"))
    with pytest.raises(ValueError, match=r"\.pdf"):
        writer.write(assessment(), tmp_path / "report.html")
