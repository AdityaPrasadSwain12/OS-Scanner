"""Linux OpenSCAP adapter with fail-soft availability and strict inputs."""

from __future__ import annotations

import re
import tempfile
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from app.tools._validation import approved_local_path, clean_text, read_bounded_text
from app.tools.base import ToolAdapter, ToolExecution, ToolState
from app.tools.runner import SafeSubprocessRunner, ToolUnavailableError

_PROFILE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$")
_VERSION_PATTERN = re.compile(r"\b\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9_.-]+)?\b")
_RESULT_STATUS = {
    "pass": "PASSED",
    "fail": "FAILED",
    "error": "ERROR",
    "unknown": "UNKNOWN",
    "notapplicable": "NOT_APPLICABLE",
    "notchecked": "NOT_CHECKED",
    "notselected": "NOT_SELECTED",
    "informational": "INFORMATIONAL",
    "fixed": "FIXED",
}
_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}


@dataclass(frozen=True, slots=True)
class OpenScapRequest:
    content_path: Path
    profile: str


class OpenScapAdapter(
    ToolAdapter[OpenScapRequest, list[dict[str, Any]], list[dict[str, Any]]]
):
    """Evaluate approved local SCAP content without remote resource fetching."""

    name = "openscap"

    def __init__(
        self,
        *,
        approved_roots: tuple[str | Path, ...] = (),
        runner: SafeSubprocessRunner | None = None,
        executable: str = "oscap",
        timeout_seconds: float = 900.0,
        max_result_bytes: int = 20 * 1024 * 1024,
    ) -> None:
        self._approved_roots = tuple(
            Path(item).expanduser().resolve(strict=False) for item in approved_roots
        )
        self._executable = executable
        self._runner = runner or SafeSubprocessRunner(
            (executable,),
            timeout_seconds=timeout_seconds,
            max_output_bytes=2 * 1024 * 1024,
        )
        if max_result_bytes < 1024 or max_result_bytes > 100 * 1024 * 1024:
            raise ValueError("max_result_bytes must be between 1 KiB and 100 MiB")
        self._max_result_bytes = max_result_bytes

    def executable_path(self) -> str | None:
        try:
            resolved = self._runner.resolve(self._executable)
        except (OSError, ValueError):
            return None
        return str(resolved) if resolved is not None else None

    def is_available(self) -> bool:
        return self._runner.is_available(self._executable)

    def version(self, *, timeout_seconds: float = 5.0) -> str | None:
        if not 0 < timeout_seconds <= 60:
            raise ValueError("version timeout must be between 0 and 60 seconds")
        if not self.is_available():
            return None
        try:
            result = self._runner.run(
                self._executable, ("--version",), timeout_seconds=timeout_seconds
            )
        except (OSError, ValueError):
            return None
        if not result.succeeded:
            return None
        combined = f"{result.stdout} {result.stderr}"
        match = _VERSION_PATTERN.search(combined)
        return match.group(0) if match else clean_text(combined, maximum=128) or None

    def validate_input(self, value: OpenScapRequest) -> OpenScapRequest:
        if not isinstance(value, OpenScapRequest):
            raise TypeError("OpenSCAP input must be an OpenScapRequest")
        if not _PROFILE_PATTERN.fullmatch(value.profile):
            raise ValueError("invalid OpenSCAP profile identifier")
        content = approved_local_path(value.content_path, self._approved_roots, require_file=True)
        if content.suffix.casefold() not in {".xml", ".xccdf", ".scap", ".datastream"}:
            raise ValueError("unsupported OpenSCAP content file type")
        if content.stat().st_size > self._max_result_bytes:
            raise ValueError("OpenSCAP content exceeds the configured size limit")
        return replace(value, content_path=content)

    @staticmethod
    def _local_name(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    def _rule_metadata(self, root: ElementTree.Element) -> dict[str, dict[str, Any]]:
        metadata: dict[str, dict[str, Any]] = {}
        for element in root.iter():
            if self._local_name(element.tag) != "Rule" or len(metadata) >= 20_000:
                continue
            rule_id = clean_text(element.attrib.get("id"), maximum=512)
            if not rule_id:
                continue
            title: str | None = None
            remediation: str | None = None
            references: list[str] = []
            for child in element:
                local_name = self._local_name(child.tag)
                content = clean_text(" ".join(child.itertext()), maximum=16_384)
                if local_name == "title" and content and title is None:
                    title = content[:1024]
                elif local_name == "fix" and content and remediation is None:
                    remediation = content
                elif local_name == "reference" and len(references) < 64:
                    href = clean_text(child.attrib.get("href"), maximum=2048)
                    if href and href.startswith("https://"):
                        references.append(href)
            metadata[rule_id] = {
                "title": title,
                "remediation": remediation,
                "references": references,
            }
        return metadata

    def parse(self, output: str) -> list[dict[str, Any]]:
        if len(output.encode("utf-8")) > self._max_result_bytes:
            raise ValueError("OpenSCAP result exceeds the configured size limit")
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", output, flags=re.IGNORECASE):
            raise ValueError("DTD and entity declarations are forbidden in OpenSCAP results")
        try:
            root = ElementTree.fromstring(output)  # noqa: S314 - declarations rejected above
        except (ElementTree.ParseError, RecursionError) as exc:
            raise ValueError("OpenSCAP returned malformed XML") from exc

        metadata = self._rule_metadata(root)
        rules: list[dict[str, Any]] = []
        for element in root.iter():
            if self._local_name(element.tag) != "rule-result":
                continue
            if len(rules) >= 20_000:
                raise ValueError("OpenSCAP result contains too many rules")
            rule_id = clean_text(element.attrib.get("idref"), maximum=512)
            if not rule_id:
                continue
            raw_severity = clean_text(element.attrib.get("severity"), maximum=16).casefold()
            severity = raw_severity if raw_severity in _SEVERITIES else "unknown"
            raw_status = "unknown"
            messages: list[str] = []
            for child in element.iter():
                local_name = self._local_name(child.tag)
                if local_name == "result" and child.text:
                    raw_status = clean_text(child.text, maximum=32).casefold()
                elif local_name in {"message", "instance"} and child.text and len(messages) < 20:
                    message = clean_text(child.text, maximum=1024)
                    if message:
                        messages.append(message)
            rules.append(
                {
                    "rule_id": rule_id,
                    "title": metadata.get(rule_id, {}).get("title"),
                    "status": _RESULT_STATUS.get(raw_status, "UNKNOWN"),
                    "severity": severity.upper(),
                    "evidence": {"messages": messages, "raw_result": raw_status},
                    "remediation": metadata.get(rule_id, {}).get("remediation"),
                    "references": metadata.get(rule_id, {}).get("references", []),
                }
            )
        if not rules:
            raise ValueError("OpenSCAP result did not contain any rule results")
        return rules

    def normalize(self, parsed: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return parsed

    def execute(
        self, value: OpenScapRequest, *, timeout_seconds: float | None = None
    ) -> ToolExecution[list[dict[str, Any]]]:
        try:
            request = self.validate_input(value)
        except (OSError, TypeError, ValueError) as exc:
            return ToolExecution(
                tool=self.name, status=ToolState.FAILED, error=clean_text(exc, maximum=512)
            )
        if not self.is_available():
            return ToolExecution(
                tool=self.name,
                status=ToolState.UNAVAILABLE,
                error="OpenSCAP executable is unavailable",
            )
        with tempfile.TemporaryDirectory(prefix="endpoint-scanner-openscap-") as temporary:
            result_path = Path(temporary) / "results.xml"
            arguments = (
                "xccdf",
                "eval",
                "--profile",
                request.profile,
                "--results",
                str(result_path),
                str(request.content_path),
            )
            try:
                result = self._runner.run(
                    self._executable,
                    arguments,
                    timeout_seconds=timeout_seconds,
                )
            except ToolUnavailableError:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.UNAVAILABLE,
                    error="OpenSCAP executable is unavailable",
                )
            except (OSError, ValueError) as exc:
                return ToolExecution(
                    tool=self.name, status=ToolState.FAILED, error=clean_text(exc, maximum=512)
                )
            if result.timed_out:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.TIMEOUT,
                    duration_seconds=result.duration_seconds,
                    exit_code=result.returncode,
                    error="OpenSCAP evaluation timed out",
                )
            # OpenSCAP uses exit status 2 to report failed rules, not an engine error.
            if result.returncode not in {0, 2}:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.FAILED,
                    duration_seconds=result.duration_seconds,
                    exit_code=result.returncode,
                    error=clean_text(result.stderr, maximum=1024)
                    or "OpenSCAP evaluation failed",
                )
            try:
                if not result_path.is_file():
                    raise ValueError("OpenSCAP did not produce a result document")
                parsed = self.parse(
                    read_bounded_text(result_path, max_bytes=self._max_result_bytes)
                )
                content_text = read_bounded_text(
                    request.content_path, max_bytes=self._max_result_bytes
                )
                if not re.search(
                    r"<!\s*(?:DOCTYPE|ENTITY)\b", content_text, flags=re.IGNORECASE
                ):
                    content_root = ElementTree.fromstring(content_text)  # noqa: S314
                    content_metadata = self._rule_metadata(content_root)
                    for item in parsed:
                        rule_metadata = content_metadata.get(str(item["rule_id"]), {})
                        for key in ("title", "remediation", "references"):
                            if not item.get(key) and rule_metadata.get(key):
                                item[key] = rule_metadata[key]
                normalized = self.normalize(parsed)
            except (ElementTree.ParseError, OSError, RecursionError, ValueError) as exc:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.FAILED,
                    duration_seconds=result.duration_seconds,
                    exit_code=result.returncode,
                    error=clean_text(exc, maximum=512),
                )
            failed_count = sum(item["status"] in {"FAILED", "ERROR"} for item in normalized)
            return ToolExecution(
                tool=self.name,
                status=ToolState.SUCCESS,
                payload=normalized,
                duration_seconds=result.duration_seconds,
                exit_code=result.returncode,
                metadata={
                    "profile": request.profile,
                    "rule_count": len(normalized),
                    "failed_count": failed_count,
                },
            )

    def evaluate(
        self,
        content_path: str | Path,
        profile: str,
        *,
        timeout_seconds: float | None = None,
    ) -> ToolExecution[list[dict[str, Any]]]:
        return self.execute(
            OpenScapRequest(content_path=Path(content_path), profile=profile),
            timeout_seconds=timeout_seconds,
        )
