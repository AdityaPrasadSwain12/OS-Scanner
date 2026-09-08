"""Passive, scope-bound OWASP Amass adapter.

Authorization is data, not an assumption: every request must carry an explicit
authorization decision, authorization identifier, registrable root allowlist,
scope, exclusions, and bounded rate/timeout controls.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import tldextract

from app.tools._validation import clean_text, read_bounded_text
from app.tools.base import ToolAdapter, ToolExecution, ToolState
from app.tools.runner import SafeSubprocessRunner, ToolUnavailableError


class AmassScopeError(ValueError):
    """An Amass request is unauthorized or escapes its declared DNS boundary."""


_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_AUTHORIZATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_VERSION_PATTERN = re.compile(r"\b\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9_.-]+)?\b")
_PUBLIC_SUFFIX_EXTRACTOR = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)


def normalize_domain(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AmassScopeError("domain must be a non-empty canonical string")
    if value.startswith("*.") or any(character in value for character in "/\\:@?#%\x00"):
        raise AmassScopeError("wildcards, URLs, IP notation, and control data are not domains")
    candidate = value[:-1] if value.endswith(".") else value
    try:
        ascii_domain = candidate.encode("idna").decode("ascii").casefold()
    except UnicodeError as exc:
        raise AmassScopeError("domain is not valid IDNA") from exc
    if len(ascii_domain) > 253:
        raise AmassScopeError("domain exceeds the DNS length limit")
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not _LABEL_PATTERN.fullmatch(label) for label in labels):
        raise AmassScopeError("domain is not a valid fully-qualified DNS name")
    top_level = labels[-1]
    if not ((top_level.isalpha() and len(top_level) >= 2) or top_level.startswith("xn--")):
        raise AmassScopeError("domain must end in a valid top-level label")
    try:
        ipaddress.ip_address(ascii_domain)
    except ValueError:
        pass
    else:
        raise AmassScopeError("IP addresses are not accepted by domain discovery")
    return ascii_domain


def registrable_domain(value: str) -> str:
    """Return the eTLD+1 using tldextract's offline PSL snapshot.

    PRIVATE rules are included so multi-tenant hosted zones such as
    ``github.io`` and ``s3.amazonaws.com`` are rejected as authorization roots.
    No network lookup or mutable user cache participates in this decision.
    """

    domain = normalize_domain(value)
    extracted = _PUBLIC_SUFFIX_EXTRACTOR(domain)
    if not extracted.suffix or not extracted.domain:
        raise AmassScopeError("a public suffix is not an authorizable domain")
    registrable = extracted.top_domain_under_public_suffix
    if not registrable or registrable == extracted.suffix:
        raise AmassScopeError("a public suffix is not an authorizable domain")
    return registrable


def _within(domain: str, parent: str) -> bool:
    return domain == parent or domain.endswith(f".{parent}")


@dataclass(frozen=True, slots=True)
class AmassRequest:
    target: str
    authorized_domains: tuple[str, ...]
    authorization_id: str
    authorized: bool = False
    scope: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()
    max_dns_concurrency: int = 1
    max_dns_queries_per_second: int = 1
    timeout_seconds: float = 300.0
    max_assets: int = 25_000


class AmassAdapter(ToolAdapter[AmassRequest, list[dict[str, Any]], list[dict[str, Any]]]):
    """Run Amass in passive enumeration mode and discard every out-of-scope result."""

    name = "amass"

    def __init__(
        self,
        *,
        runner: SafeSubprocessRunner | None = None,
        executable: str | None = "amass",
        maximum_timeout_seconds: float = 3600.0,
        maximum_dns_concurrency: int = 20,
        maximum_dns_queries_per_second: int = 100,
        max_output_bytes: int = 20 * 1024 * 1024,
    ) -> None:
        if maximum_timeout_seconds <= 0 or maximum_timeout_seconds > 86_400:
            raise ValueError("invalid Amass maximum timeout")
        if maximum_dns_concurrency < 1 or maximum_dns_concurrency > 100:
            raise ValueError("invalid Amass DNS concurrency")
        if not 1 <= maximum_dns_queries_per_second <= 10_000:
            raise ValueError("invalid Amass DNS query rate")
        if not 1024 <= max_output_bytes <= 100 * 1024 * 1024:
            raise ValueError("Amass output limit must be between 1 KiB and 100 MiB")
        # Omitting the argument keeps the standalone adapter's documented
        # ``amass`` default. Passing ``None`` is an explicit disable decision
        # from protected scanner configuration and must never trigger PATH
        # discovery.
        self._executable_candidates = (executable,) if executable is not None else ()
        self._runner = runner
        if self._runner is None and self._executable_candidates:
            self._runner = SafeSubprocessRunner(
                self._executable_candidates,
                timeout_seconds=maximum_timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
        self._maximum_timeout = maximum_timeout_seconds
        self._maximum_dns_concurrency = maximum_dns_concurrency
        self._maximum_dns_qps = maximum_dns_queries_per_second
        self._max_output_bytes = max_output_bytes

    def _find_executable(self) -> str | None:
        runner = self._runner
        if runner is None:
            return None
        return next(
            (
                candidate
                for candidate in self._executable_candidates
                if runner.is_available(candidate)
            ),
            None,
        )

    def executable_path(self) -> str | None:
        try:
            executable = self._find_executable()
            runner = self._runner
            if executable is None or runner is None:
                return None
            resolved = runner.resolve(executable)
        except Exception:
            return None
        return str(resolved) if resolved is not None else None

    def is_available(self) -> bool:
        try:
            return self._find_executable() is not None
        except Exception:
            return False

    def version(self, *, timeout_seconds: float = 5.0) -> str | None:
        if not 0 < timeout_seconds <= 60:
            raise ValueError("version timeout must be between 0 and 60 seconds")
        try:
            executable = self._find_executable()
            runner = self._runner
            if executable is None or runner is None:
                return None
            result = runner.run(
                executable, ("-version",), timeout_seconds=timeout_seconds
            )
        except Exception:
            return None
        if not result.succeeded:
            return None
        combined = f"{result.stdout} {result.stderr}"
        match = _VERSION_PATTERN.search(combined)
        return match.group(0) if match else clean_text(combined, maximum=128) or None

    def validate_input(self, value: AmassRequest) -> AmassRequest:
        if not isinstance(value, AmassRequest):
            raise TypeError("Amass input must be an AmassRequest")
        if value.authorized is not True:
            raise AmassScopeError("attack-surface discovery requires explicit authorization")
        if not _AUTHORIZATION_ID_PATTERN.fullmatch(value.authorization_id):
            raise AmassScopeError("a valid authorization identifier is required")
        if not value.authorized_domains or len(value.authorized_domains) > 100:
            raise AmassScopeError("authorized domain allowlist must be non-empty and bounded")

        target = normalize_domain(value.target)
        roots = tuple(dict.fromkeys(normalize_domain(item) for item in value.authorized_domains))
        for root in roots:
            # Calling the resolver rejects bare public/hosted suffixes.  A
            # narrower FQDN (for example ``corp.example.com``) remains a valid
            # authorization boundary and is never widened to ``example.com``.
            registrable_domain(root)
        matching_roots = tuple(root for root in roots if _within(target, root))
        if not matching_roots:
            raise AmassScopeError("target is outside the authorized domain allowlist")

        raw_scope = value.scope or (target,)
        if len(raw_scope) > 100:
            raise AmassScopeError("scope contains too many domains")
        scope = tuple(dict.fromkeys(normalize_domain(item) for item in raw_scope))
        if any(not _within(item, target) for item in scope):
            raise AmassScopeError("scope cannot expand beyond the requested target")
        if any(not any(_within(item, root) for root in roots) for item in scope):
            raise AmassScopeError("scope contains a domain outside the authorization allowlist")

        if len(value.exclusions) > 1000:
            raise AmassScopeError("exclusion list is too large")
        exclusions = tuple(dict.fromkeys(normalize_domain(item) for item in value.exclusions))
        if any(not _within(item, target) for item in exclusions):
            raise AmassScopeError("exclusions must fall within the requested target")
        if any(not any(_within(item, allowed) for allowed in scope) for item in exclusions):
            raise AmassScopeError("exclusions must fall within the requested discovery scope")
        if any(item == target for item in exclusions):
            raise AmassScopeError("the requested target cannot be entirely excluded")

        if not 1 <= value.max_dns_concurrency <= self._maximum_dns_concurrency:
            raise AmassScopeError("requested DNS concurrency exceeds the discovery policy")
        if not 1 <= value.max_dns_queries_per_second <= self._maximum_dns_qps:
            raise AmassScopeError("requested DNS rate exceeds the discovery policy")
        if not 1 <= value.timeout_seconds <= self._maximum_timeout:
            raise AmassScopeError("requested timeout exceeds the discovery policy")
        if not 1 <= value.max_assets <= 100_000:
            raise AmassScopeError("invalid discovered-asset limit")
        return replace(
            value,
            target=target,
            authorized_domains=roots,
            scope=scope,
            exclusions=exclusions,
        )

    @staticmethod
    def _records(document: Any) -> list[dict[str, Any]]:
        if isinstance(document, list):
            if len(document) > 100_000:
                raise ValueError("Amass output contains too many records")
            return [item for item in document if isinstance(item, dict)]
        if isinstance(document, dict):
            assets = document.get("assets") or document.get("results")
            if isinstance(assets, list):
                if len(assets) > 100_000:
                    raise ValueError("Amass output contains too many records")
                return [item for item in assets if isinstance(item, dict)]
            return [document]
        raise ValueError("Amass JSON records must be objects")

    def parse(self, output: str) -> list[dict[str, Any]]:
        if len(output.encode("utf-8")) > self._max_output_bytes:
            raise ValueError("Amass output exceeds the adapter limit")
        stripped = output.strip()
        if not stripped:
            return []
        try:
            return self._records(json.loads(stripped))
        except json.JSONDecodeError:
            records: list[dict[str, Any]] = []
            for line in stripped.splitlines():
                if len(records) > 100_000:
                    raise ValueError("Amass output contains too many records") from None
                line = line.strip()
                if not line:
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    # Plain hostname output is accepted, but still passes strict
                    # DNS and authorization filtering in ``execute``.
                    records.append({"name": line})
                    continue
                records.extend(self._records(value))
            return records

    def normalize(self, parsed: list[dict[str, Any]]) -> list[dict[str, Any]]:
        assets: list[dict[str, Any]] = []
        for record in parsed:
            hostname = record.get("name") or record.get("hostname") or record.get("fqdn")
            if not isinstance(hostname, str):
                continue
            try:
                normalized_hostname = normalize_domain(hostname)
            except AmassScopeError:
                continue
            addresses: list[str] = []
            raw_addresses = record.get("addresses") or record.get("ips") or []
            if isinstance(raw_addresses, list):
                for address_record in raw_addresses[:100]:
                    raw_address = (
                        address_record.get("ip")
                        if isinstance(address_record, dict)
                        else address_record
                    )
                    if not isinstance(raw_address, str):
                        continue
                    try:
                        addresses.append(str(ipaddress.ip_address(raw_address)))
                    except ValueError:
                        continue
            source = clean_text(record.get("source") or record.get("tag"), maximum=128)
            assets.append(
                {
                    "hostname": normalized_hostname,
                    "type": "subdomain",
                    "addresses": sorted(set(addresses)),
                    "source": source or "amass",
                }
            )
        return assets

    @staticmethod
    def _apply_scope(
        assets: list[dict[str, Any]], request: AmassRequest
    ) -> list[dict[str, Any]]:
        selected: dict[str, dict[str, Any]] = {}
        for asset in assets:
            hostname = asset["hostname"]
            assert isinstance(hostname, str)
            if not any(_within(hostname, allowed) for allowed in request.scope):
                continue
            if any(_within(hostname, exclusion) for exclusion in request.exclusions):
                continue
            asset["type"] = "domain" if hostname == request.target else "subdomain"
            selected[hostname] = asset
            if len(selected) > request.max_assets:
                raise ValueError("Amass discovered-asset limit exceeded")
        return [selected[key] for key in sorted(selected)]

    def _execute(self, value: AmassRequest) -> ToolExecution[list[dict[str, Any]]]:
        try:
            request = self.validate_input(value)
        except (TypeError, ValueError) as exc:
            return ToolExecution(
                tool=self.name, status=ToolState.FAILED, error=clean_text(exc, maximum=512)
            )
        executable = self._find_executable()
        if executable is None:
            return ToolExecution(
                tool=self.name,
                status=ToolState.UNAVAILABLE,
                error="Amass executable is unavailable",
                metadata={"authorization_id": request.authorization_id, "target": request.target},
            )
        runner = self._runner
        if runner is None:
            return ToolExecution(
                tool=self.name,
                status=ToolState.UNAVAILABLE,
                error="Amass executable is unavailable",
                metadata={"authorization_id": request.authorization_id, "target": request.target},
            )

        with tempfile.TemporaryDirectory(prefix="endpoint-scanner-amass-") as temporary:
            output_path = Path(temporary) / "assets.jsonl"
            arguments = ["enum", "-passive"]
            for scoped_domain in request.scope:
                arguments.extend(("-d", scoped_domain))
            for excluded_domain in request.exclusions:
                arguments.extend(("-bl", excluded_domain))
            arguments.extend(
                (
                    "-json",
                    str(output_path),
                    "-max-dns-queries",
                    str(request.max_dns_concurrency),
                    "-dns-qps",
                    str(request.max_dns_queries_per_second),
                    "-timeout",
                    str(max(1, math.ceil(request.timeout_seconds / 60))),
                )
            )
            try:
                result = runner.run(
                    executable, tuple(arguments), timeout_seconds=request.timeout_seconds
                )
            except ToolUnavailableError:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.UNAVAILABLE,
                    error="Amass executable is unavailable",
                    metadata={
                        "authorization_id": request.authorization_id,
                        "target": request.target,
                    },
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
                    error="Amass discovery timed out",
                    metadata={
                        "authorization_id": request.authorization_id,
                        "target": request.target,
                    },
                )
            if result.returncode != 0:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.FAILED,
                    duration_seconds=result.duration_seconds,
                    exit_code=result.returncode,
                    error=clean_text(result.stderr, maximum=1024) or "Amass discovery failed",
                    metadata={
                        "authorization_id": request.authorization_id,
                        "target": request.target,
                    },
                )
            try:
                if output_path.is_file():
                    raw_output = read_bounded_text(
                        output_path, max_bytes=self._max_output_bytes
                    )
                else:
                    raw_output = result.stdout
                assets = self._apply_scope(self.normalize(self.parse(raw_output)), request)
            except (OSError, ValueError) as exc:
                return ToolExecution(
                    tool=self.name,
                    status=ToolState.FAILED,
                    duration_seconds=result.duration_seconds,
                    exit_code=result.returncode,
                    error=clean_text(exc, maximum=512),
                )
            return ToolExecution(
                tool=self.name,
                status=ToolState.SUCCESS,
                payload=assets,
                duration_seconds=result.duration_seconds,
                exit_code=result.returncode,
                metadata={
                    "authorization_id": request.authorization_id,
                    "authorized_domains": request.authorized_domains,
                    "target": request.target,
                    "scope": request.scope,
                    "exclusions": request.exclusions,
                    "passive": True,
                    "asset_count": len(assets),
                    "dns_concurrency": request.max_dns_concurrency,
                    "dns_queries_per_second": request.max_dns_queries_per_second,
                },
            )

    def execute(self, value: AmassRequest) -> ToolExecution[list[dict[str, Any]]]:
        """Execute fail-soft while allowing process-control exceptions through."""

        try:
            return self._execute(value)
        except Exception as exc:
            return ToolExecution(
                tool=self.name,
                status=ToolState.FAILED,
                error=clean_text(exc, maximum=512) or "Amass discovery failed",
            )

    def discover(
        self,
        target: str,
        *,
        authorized_domains: tuple[str, ...],
        authorization_id: str,
        authorized: bool = False,
        scope: tuple[str, ...] = (),
        exclusions: tuple[str, ...] = (),
        max_dns_concurrency: int = 1,
        max_dns_queries_per_second: int = 1,
        timeout_seconds: float = 300.0,
        max_assets: int = 25_000,
    ) -> ToolExecution[list[dict[str, Any]]]:
        return self.execute(
            AmassRequest(
                target=target,
                authorized_domains=authorized_domains,
                authorization_id=authorization_id,
                authorized=authorized,
                scope=scope,
                exclusions=exclusions,
                max_dns_concurrency=max_dns_concurrency,
                max_dns_queries_per_second=max_dns_queries_per_second,
                timeout_seconds=timeout_seconds,
                max_assets=max_assets,
            )
        )
