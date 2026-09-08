from __future__ import annotations

import json

import pytest

from app.reporting import AtomicReportWriter, ReportTooLargeError, serialize_report


def test_report_serialization_is_deterministic() -> None:
    assert serialize_report({"z": 1, "a": 2}) == b'{"a":2,"z":1}'


def test_report_size_is_bounded() -> None:
    with pytest.raises(ReportTooLargeError):
        serialize_report({"value": "long"}, max_bytes=3)


def test_atomic_writer_does_not_persist_an_oversized_report(tmp_path: object) -> None:
    from pathlib import Path

    directory = Path(str(tmp_path)) / "reports"
    writer = AtomicReportWriter(directory, max_bytes=16)

    with pytest.raises(ReportTooLargeError):
        writer.write("scan-oversized", {"value": "x" * 32})

    assert not (directory / writer.filename_for("scan-oversized")).exists()
    assert not list(directory.glob("*.tmp"))


def test_atomic_writer_sanitizes_filename_and_writes_json(tmp_path: object) -> None:
    from pathlib import Path

    destination = AtomicReportWriter(Path(str(tmp_path))).write("scan/../../id", {"ok": True})
    assert destination.parent == Path(str(tmp_path)).resolve()
    assert json.loads(destination.read_text(encoding="utf-8")) == {"ok": True}


def test_report_filenames_do_not_collide_after_readable_prefix_sanitization(
    tmp_path: object,
) -> None:
    from pathlib import Path

    writer = AtomicReportWriter(Path(str(tmp_path)))

    colon = writer.write("scan:1", {"scan_id": "scan:1"})
    underscore = writer.write("scan_1", {"scan_id": "scan_1"})

    assert colon != underscore
    assert colon.name.startswith("scan_1--")
    assert underscore.name.startswith("scan_1--")
    assert json.loads(colon.read_text(encoding="utf-8")) == {"scan_id": "scan:1"}
    assert json.loads(underscore.read_text(encoding="utf-8")) == {"scan_id": "scan_1"}
