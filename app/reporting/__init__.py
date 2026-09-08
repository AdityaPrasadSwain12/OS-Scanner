"""Normalized report creation and serialization."""

from .assessment_json import (
    CanonicalAssessmentJsonWriter,
    SerializedAssessment,
    serialize_canonical_assessment,
    validate_canonical_assessment,
    write_canonical_assessment_json,
)
from .deep_scan_json import DeepScanJsonWriter, write_deep_scan_json
from .json_report import AtomicReportWriter, ReportTooLargeError, serialize_report
from .pdf_report import (
    CanonicalAssessmentPdfWriter,
    PdfBranding,
    PdfRenderError,
    PdfRenderLimitError,
    PdfRenderLimits,
    RenderedPdf,
    render_assessment_pdf,
    write_assessment_pdf,
)

__all__ = [
    "AtomicReportWriter",
    "CanonicalAssessmentJsonWriter",
    "CanonicalAssessmentPdfWriter",
    "DeepScanJsonWriter",
    "PdfBranding",
    "PdfRenderError",
    "PdfRenderLimitError",
    "PdfRenderLimits",
    "RenderedPdf",
    "ReportTooLargeError",
    "SerializedAssessment",
    "render_assessment_pdf",
    "serialize_canonical_assessment",
    "serialize_report",
    "validate_canonical_assessment",
    "write_assessment_pdf",
    "write_canonical_assessment_json",
    "write_deep_scan_json",
]
