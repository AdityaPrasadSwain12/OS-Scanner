"""OSV-Scanner adapter for explicitly approved local dependency sources."""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, replace
from math import ceil
from pathlib import Path
from typing import Any

from app.tools._validation import approved_local_path, clean_text, parse_json_document
from app.tools.base import ToolAdapter, ToolExecution, ToolState
from app.tools.runner import SafeSubprocessRunner, ToolUnavailableError

_VERSION_PATTERN = re.compile(r"\b\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9_.-]+)?\b")
_KNOWN_MANIFESTS = {
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
    "go.mod",
    "go.sum",
    "package-lock.json",
    "packages.lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "requirements.txt",
    "uv.lock",
    "yarn.lock",
}
_ALLOWED_SUFFIXES = {
    ".cdx",
    ".gradle",
    ".json",
    ".lock",
    ".mod",
    ".spdx",
    ".sum",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
_SEVERITY_NAMES = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "unknown": "UNKNOWN",
}


def _round_up_tenth(value: float) -> float:
    return ceil((value - 1e-10) * 10.0) / 10.0


def _cvss_base_score(vector: str) -> float | None:
    """Calculate bounded CVSS v2/v3 base scores from standard vectors.

    OSV commonly supplies a vector rather than a numeric value. Unsupported or
    malformed vectors remain unknown instead of being guessed.
    """

    parts = vector.strip().split("/")
    prefix = parts.pop(0).upper() if parts else ""
    try:
        metrics = {
            key.upper(): value.upper()
            for part in parts
            if ":" in part
            for key, value in (part.split(":", 1),)
        }
        if prefix in {"CVSS:3.0", "CVSS:3.1"}:
            scope_changed = metrics["S"] == "C"
            av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[metrics["AV"]]
            ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
            pr = (
                {"N": 0.85, "L": 0.68, "H": 0.50}
                if scope_changed
                else {"N": 0.85, "L": 0.62, "H": 0.27}
            )[metrics["PR"]]
            ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
            confidentiality = {"N": 0.0, "L": 0.22, "H": 0.56}[metrics["C"]]
            integrity = {"N": 0.0, "L": 0.22, "H": 0.56}[metrics["I"]]
            availability = {"N": 0.0, "L": 0.22, "H": 0.56}[metrics["A"]]
            impact_base = 1.0 - (
                (1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability)
            )
            impact = (
                7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02) ** 15
                if scope_changed
                else 6.42 * impact_base
            )
            if impact <= 0:
                return 0.0
            exploitability = 8.22 * av * ac * pr * ui
            combined = impact + exploitability
            if scope_changed:
                combined *= 1.08
            return _round_up_tenth(min(combined, 10.0))

        # CVSS v2 vectors may be prefixed with CVSS:2.0 or omit a prefix.
        if prefix == "CVSS:2.0":
            pass
        elif prefix.startswith("AV:"):
            parts.insert(0, prefix)
            metrics = {
                key.upper(): value.upper()
                for part in parts
                if ":" in part
                for key, value in (part.split(":", 1),)
            }
        else:
            return None
        av = {"L": 0.395, "A": 0.646, "N": 1.0}[metrics["AV"]]
        ac = {"H": 0.35, "M": 0.61, "L": 0.71}[metrics["AC"]]
        authentication = {"M": 0.45, "S": 0.56, "N": 0.704}[metrics["AU"]]
        confidentiality = {"N": 0.0, "P": 0.275, "C": 0.66}[metrics["C"]]
        integrity = {"N": 0.0, "P": 0.275, "C": 0.66}[metrics["I"]]
        availability = {"N": 0.0, "P": 0.275, "C": 0.66}[metrics["A"]]
        impact = 10.41 * (
            1.0 - (1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability)
        )
        if impact <= 0:
            return 0.0
        exploitability = 20.0 * av * ac * authentication
        return round(((0.6 * impact) + (0.4 * exploitability) - 1.5) * 1.176 + 1e-10, 1)
    except (KeyError, ValueError, TypeError, OverflowError):
        return None


@dataclass(frozen=True, slots=True)
class OsvScanRequest:
    source: Path
    recursive: bool = True


class OsvScannerAdapter(
    ToolAdapter[OsvScanRequest, dict[str, Any], list[dict[str, Any]]]
):
    """Run OSV-Scanner against a caller-approved local manifest or directory."""

    name = "osv-scanner"

    def __init__(
        self,
        *,
        approved_roots: tuple[str | Path, ...] = (),
        runner: SafeSubprocessRunner | None = None,
        executable: str | None = None,
        timeout_seconds: float = 300.0,
        max_output_bytes: int = 20 * 1024 * 1024,
    ) -> None:
        if not 1024 <= max_output_bytes <= 100 * 1024 * 1024:
            raise ValueError("OSV output limit must be between 1 KiB and 100 MiB")
        self._approved_roots = tuple(
            Path(item).expanduser().resolve(strict=False) for item in approved_roots
        )
        self._executable_candidates = (
            (executable,) if executable is not None else ("osv-scanner", "osv-scanner.exe")
        )
        self._runner = runner or SafeSubprocessRunner(
            self._executable_candidates,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        self._max_output_bytes = max_output_bytes

    def _find_executable(self) -> str | None:
        return next(
            (
                candidate
                for candidate in self._executable_candidates
                if self._runner.is_available(candidate)
            ),
            None,
        )

    def executable_path(self) -> str | None:
        executable = self._find_executable()
        if executable is None:
            return None
        resolved = self._runner.resolve(executable)
        return str(resolved) if resolved is not None else None

    def is_available(self) -> bool:
        return self._find_executable() is not None

    def version(self, *, timeout_seconds: float = 5.0) -> str | None:
        if not 0 < timeout_seconds <= 60:
            raise ValueError("version timeout must be between 0 and 60 seconds")
        executable = self._find_executable()
        if executable is None:
            return None
        try:
            result = self._runner.run(
                executable, ("--version",), timeout_seconds=timeout_seconds
            )
        except (OSError, ValueError):
            return None
        if not result.succeeded:
            return None
        combined = f"{result.stdout} {result.stderr}"
        match = _VERSION_PATTERN.search(combined)
        return match.group(0) if match else clean_text(combined, maximum=128) or None

    def validate_input(self, value: OsvScanRequest) -> OsvScanRequest:
        return self._validate_input(value, deadline_at=None)

    def _validate_input(
        self, value: OsvScanRequest, *, deadline_at: float | None
    ) -> OsvScanRequest:
        if not isinstance(value, OsvScanRequest):
            raise TypeError("OSV-Scanner input must be an OsvScanRequest")
        source = approved_local_path(value.source, self._approved_roots)
        if source.is_file():
            name = source.name.casefold()
            if name not in _KNOWN_MANIFESTS and source.suffix.casefold() not in _ALLOWED_SUFFIXES:
                raise ValueError("source is not a recognized dependency manifest or SBOM")
            if source.stat().st_size > 100 * 1024 * 1024:
                raise ValueError("dependency source exceeds the configured size limit")
        else:
            self._validate_directory_scope(source, deadline_at=deadline_at)
        return replace(value, source=source)

    def _validate_directory_scope(
        self, source: Path, *, deadline_at: float | None = None
    ) -> None:
        stack = [source]
        visited: set[Path] = set()
        item_count = 0
        while stack:
            directory = stack.pop()
            canonical = directory.resolve(strict=True)
            if canonical in visited:
                continue
            visited.add(canonical)
            if not any(
                canonical == root or canonical.is_relative_to(root)
                for root in self._approved_roots
            ):
                raise PermissionError("dependency tree escapes the approved local roots")
            with os.scandir(canonical) as entries:
                for entry in entries:
                    if deadline_at is not None and time.monotonic() >= deadline_at:
                        raise TimeoutError(
                            "scan deadline exceeded during dependency source validation"
                        )
                    item_count += 1
                    if item_count > 250_000:
                        raise ValueError("dependency tree exceeds the preflight item limit")
                    entry_path = Path(entry.path)
                    if entry.is_symlink():
                        target = entry_path.resolve(strict=True)
                        if not any(
                            target == root or target.is_relative_to(root)
                            for root in self._approved_roots
                        ):
                            raise PermissionError(
                                "dependency tree contains an out-of-scope symbolic link"
                            )
                        if target.is_dir():
                            stack.append(target)
                        elif not target.is_file():
                            raise ValueError("dependency tree contains a special file link")
                    elif entry.is_dir(follow_symlinks=False):
                        stack.append(entry_path)
                    elif not entry.is_file(follow_symlinks=False):
                        raise ValueError("dependency tree contains a special file")

    def parse(self, output: str) -> dict[str, Any]:
        document = parse_json_document(output, max_chars=self._max_output_bytes)
        if not isinstance(document, dict):
            raise ValueError("OSV-Scanner response must be a JSON object")
        results = document.get("results", [])
        if not isinstance(results, list):
            raise ValueError("OSV-Scanner results must be a JSON array")
        if len(results) > 50_000:
            raise ValueError("OSV-Scanner returned too many result groups")
        return document

    @staticmethod
    def _severity(
        vulnerability: dict[str, Any],
    ) -> tuple[str, list[dict[str, str]], float | None]:
        candidates: list[object] = []
        numeric_scores: list[float] = []
        for key in ("database_specific", "ecosystem_specific"):
            value = vulnerability.get(key)
            if isinstance(value, dict):
                candidates.append(value.get("severity"))
                for score_key in ("cvss_score", "cvss"):
                    try:
                        numeric = float(str(value.get(score_key)))
                    except (TypeError, ValueError):
                        continue
                    if 0 <= numeric <= 10:
                        numeric_scores.append(numeric)
        scores: list[dict[str, str]] = []
        raw_scores = vulnerability.get("severity", [])
        if isinstance(raw_scores, list):
            for score in raw_scores[:10]:
                if isinstance(score, dict):
                    score_type = clean_text(score.get("type"), maximum=32)
                    score_value = clean_text(score.get("score"), maximum=256)
                    if score_type or score_value:
                        scores.append({"type": score_type, "score": score_value})
                    parsed_numeric: float | None
                    try:
                        parsed_numeric = float(score_value)
                    except ValueError:
                        parsed_numeric = _cvss_base_score(score_value)
                    if parsed_numeric is not None and 0 <= parsed_numeric <= 10:
                        numeric_scores.append(parsed_numeric)
        cvss_score = max(numeric_scores, default=None)
        for candidate in candidates:
            if isinstance(candidate, str):
                normalized = _SEVERITY_NAMES.get(candidate.casefold())
                if normalized is not None:
                    return normalized, scores, cvss_score
        if cvss_score is not None:
            severity = (
                "CRITICAL"
                if cvss_score >= 9
                else "HIGH"
                if cvss_score >= 7
                else "MEDIUM"
                if cvss_score >= 4
                else "LOW"
                if cvss_score > 0
                else "INFO"
            )
            return severity, scores, cvss_score
        return "UNKNOWN", scores, None

    @staticmethod
    def _affected_versions(vulnerability: dict[str, Any]) -> list[str]:
        versions: set[str] = set()
        affected = vulnerability.get("affected", [])
        if not isinstance(affected, list):
            return []
        for affected_item in affected[:1000]:
            if not isinstance(affected_item, dict):
                continue
            raw_versions = affected_item.get("versions", [])
            if not isinstance(raw_versions, list):
                continue
            for item in raw_versions[:10_000]:
                version = clean_text(item, maximum=256)
                if version:
                    versions.add(version)
        return sorted(versions)[:10_000]

    @staticmethod
    def _exploitability(vulnerability: dict[str, Any]) -> tuple[float | None, bool]:
        values = [
            value
            for key in ("database_specific", "ecosystem_specific")
            if isinstance((value := vulnerability.get(key)), dict)
        ]
        known_exploited = False
        exploitability: float | None = None
        for value in values:
            for key in ("known_exploited", "is_known_exploited", "kev"):
                if type(value.get(key)) is bool:
                    known_exploited = known_exploited or bool(value[key])
            for key in ("exploitability", "exploitability_score"):
                try:
                    score = float(str(value.get(key)))
                except (TypeError, ValueError):
                    continue
                if 0 <= score <= 1:
                    exploitability = max(exploitability or 0, score)
                elif 1 < score <= 10:
                    exploitability = max(exploitability or 0, score / 10)
        return exploitability, known_exploited

    @staticmethod
    def _fixed_versions(vulnerability: dict[str, Any]) -> list[str]:
        versions: set[str] = set()
        affected = vulnerability.get("affected", [])
        if not isinstance(affected, list):
            return []
        for affected_item in affected[:1000]:
            if not isinstance(affected_item, dict):
                continue
            ranges = affected_item.get("ranges", [])
            if not isinstance(ranges, list):
                continue
            for range_item in ranges[:100]:
                if not isinstance(range_item, dict):
                    continue
                events = range_item.get("events", [])
                if not isinstance(events, list):
                    continue
                for event in events[:1000]:
                    if isinstance(event, dict) and "fixed" in event:
                        fixed = clean_text(event["fixed"], maximum=256)
                        if fixed:
                            versions.add(fixed)
        return sorted(versions)[:1000]

    @staticmethod
    def _references(vulnerability: dict[str, Any]) -> list[str]:
        references: list[str] = []
        raw = vulnerability.get("references", [])
        if not isinstance(raw, list):
            return references
        for item in raw[:100]:
            if not isinstance(item, dict):
                continue
            url = clean_text(item.get("url"), maximum=2048)
            if url.startswith("https://"):
                references.append(url)
        return references

    def normalize(self, parsed: dict[str, Any]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        raw_results = parsed.get("results", [])
        assert isinstance(raw_results, list)
        for result in raw_results:
            if not isinstance(result, dict):
                continue
            source = result.get("source") or result.get("target") or {}
            source_path = (
                clean_text(source.get("path"), maximum=4096) if isinstance(source, dict) else ""
            )
            packages = result.get("packages", [])
            if not isinstance(packages, list):
                continue
            for package_entry in packages[:50_000]:
                if not isinstance(package_entry, dict):
                    continue
                package = package_entry.get("package", {})
                if not isinstance(package, dict):
                    package = {}
                package_name = clean_text(package.get("name"), maximum=512)
                package_version = clean_text(package.get("version"), maximum=256)
                ecosystem = clean_text(package.get("ecosystem"), maximum=128)
                vulnerabilities = package_entry.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    continue
                for vulnerability in vulnerabilities[:50_000]:
                    if not isinstance(vulnerability, dict):
                        continue
                    vulnerability_id = clean_text(vulnerability.get("id"), maximum=256)
                    if not vulnerability_id:
                        continue
                    identity = (vulnerability_id, package_name, package_version)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    aliases_raw = vulnerability.get("aliases", [])
                    aliases = (
                        [clean_text(item, maximum=256) for item in aliases_raw[:100]]
                        if isinstance(aliases_raw, list)
                        else []
                    )
                    severity, scores, cvss_score = self._severity(vulnerability)
                    exploitability, known_exploited = self._exploitability(vulnerability)
                    normalized.append(
                        {
                            "vulnerability_id": vulnerability_id,
                            "aliases": [item for item in aliases if item],
                            "package": {
                                "name": package_name,
                                "version": package_version,
                                "ecosystem": ecosystem,
                            },
                            "severity": severity,
                            "severity_scores": scores,
                            "cvss_score": cvss_score,
                            "exploitability": exploitability,
                            "known_exploited": known_exploited,
                            "summary": clean_text(vulnerability.get("summary"), maximum=4096),
                            "details": clean_text(vulnerability.get("details"), maximum=16_384),
                            "fixed_versions": self._fixed_versions(vulnerability),
                            "affected_versions": self._affected_versions(vulnerability),
                            "references": self._references(vulnerability),
                            "source_path": source_path,
                        }
                    )
                    if len(normalized) > 100_000:
                        raise ValueError("normalized vulnerability limit exceeded")
        return normalized

    def execute(
        self,
        value: OsvScanRequest,
        *,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> ToolExecution[list[dict[str, Any]]]:
        try:
            request = self._validate_input(value, deadline_at=deadline_at)
        except TimeoutError as exc:
            return ToolExecution(
                tool=self.name,
                status=ToolState.TIMEOUT,
                error=clean_text(exc, maximum=512),
            )
        except (OSError, TypeError, ValueError) as exc:
            return ToolExecution(
                tool=self.name, status=ToolState.FAILED, error=clean_text(exc, maximum=512)
            )
        executable = self._find_executable()
        if executable is None:
            return ToolExecution(
                tool=self.name,
                status=ToolState.UNAVAILABLE,
                error="OSV-Scanner executable is unavailable",
            )
        arguments = ["scan", "--format=json"]
        if request.recursive and request.source.is_dir():
            arguments.append("--recursive")
        arguments.append(str(request.source))
        if deadline_at is not None:
            remaining = deadline_at - time.monotonic()
            if remaining <= 0:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.TIMEOUT,
                    error="scan deadline exhausted before OSV-Scanner execution",
                )
            timeout_seconds = (
                remaining
                if timeout_seconds is None
                else min(timeout_seconds, remaining)
            )
        try:
            result = self._runner.run(
                executable,
                tuple(arguments),
                timeout_seconds=timeout_seconds,
            )
        except ToolUnavailableError:
            return ToolExecution(
                tool=self.name,
                status=ToolState.UNAVAILABLE,
                error="OSV-Scanner executable is unavailable",
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
                error="OSV-Scanner execution timed out",
            )
        if result.stdout_truncated:
            return ToolExecution(
                tool=self.name,
                status=ToolState.FAILED,
                duration_seconds=result.duration_seconds,
                exit_code=result.returncode,
                error="OSV-Scanner output exceeded the size limit",
            )
        # OSV-Scanner may use a non-zero status when vulnerabilities are present.
        if result.returncode not in {0, 1}:
            return ToolExecution(
                tool=self.name,
                status=ToolState.FAILED,
                duration_seconds=result.duration_seconds,
                exit_code=result.returncode,
                error=clean_text(result.stderr, maximum=1024)
                or "OSV-Scanner execution failed",
            )
        try:
            normalized = self.normalize(self.parse(result.stdout))
        except ValueError as exc:
            return ToolExecution(
                tool=self.name,
                status=ToolState.FAILED,
                duration_seconds=result.duration_seconds,
                exit_code=result.returncode,
                error=str(exc),
            )
        return ToolExecution(
            tool=self.name,
            status=ToolState.SUCCESS,
            payload=normalized,
            duration_seconds=result.duration_seconds,
            exit_code=result.returncode,
            metadata={"source": str(request.source), "vulnerability_count": len(normalized)},
        )

    def scan(
        self,
        source: str | Path,
        *,
        recursive: bool = True,
        timeout_seconds: float | None = None,
        deadline_at: float | None = None,
    ) -> ToolExecution[list[dict[str, Any]]]:
        return self.execute(
            OsvScanRequest(source=Path(source), recursive=recursive),
            timeout_seconds=timeout_seconds,
            deadline_at=deadline_at,
        )
