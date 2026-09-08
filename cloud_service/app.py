"""FastAPI application factory for endpoint enrollment, jobs, and evidence ingestion."""

import asyncio
import hashlib
import zlib
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated, Any, cast
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from .artifacts import (
    ArtifactUnavailableError,
    LocalInstallerArtifactStore,
    UnknownArtifactError,
)
from .config import CloudServiceSettings
from .models import (
    CredentialResponse,
    CredentialRotation,
    EndpointEnrollment,
    EnrollmentTokenRequest,
    HealthResponse,
    PlatformScanRequest,
    ScanRejectionUpload,
    ScanStatusUpload,
    ScanUpload,
    canonical_sha256,
    utc_now,
)
from .repository import (
    AnalysisTask,
    CloudRepository,
    CredentialRecord,
    DevicePrincipal,
    EndpointRecord,
    EnrollmentGrantRecord,
    IdempotencyConflict,
    InMemoryRepository,
    NotFoundError,
    OwnershipError,
    RepositoryError,
    ScanRecord,
    StateConflict,
    TaskKind,
)
from .security import CredentialIssuer, token_tenant


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    tenant_id: str
    subject: str


@dataclass(frozen=True, slots=True)
class EnrollmentPrincipal:
    tenant_id: str
    grant_token_hash: str | None = None


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, separator, token = header.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token or len(token) > 4096:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="valid bearer authentication is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if any(ord(character) < 33 or ord(character) == 127 for character in token):
        raise HTTPException(status_code=401, detail="valid bearer authentication is required")
    return token


def _idempotency(value: str | None) -> str:
    if (
        value is None
        or not 1 <= len(value) <= 256
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise HTTPException(status_code=400, detail="a valid Idempotency-Key is required")
    return value


def _record_view(record: ScanRecord, *, include_documents: bool = False) -> dict[str, Any]:
    report_ready = record.final_report is not None
    phase_by_state = {
        "QUEUED": "WAITING_FOR_ENDPOINT",
        "DISPATCHED": "ENDPOINT_COLLECTION",
        "ANALYZING": "CLOUD_ANALYSIS",
        "COMPLETE": "COMPLETE",
        "REJECTED": "REJECTED",
        "EXPIRED": "EXPIRED",
        "FAILED": "FAILED",
    }
    progress_by_state = {
        "QUEUED": 0,
        "DISPATCHED": 15,
        "ANALYZING": 70,
        "COMPLETE": 100,
        "REJECTED": 100,
        "EXPIRED": 100,
        "FAILED": 100,
    }
    value: dict[str, Any] = {
        "scan_id": record.scan_id,
        "job_id": record.job_id,
        "endpoint_id": record.endpoint_id,
        "state": record.state,
        "status": record.state,
        "phase": phase_by_state.get(record.state, "UNKNOWN"),
        "progress_percent": progress_by_state.get(record.state),
        "scan_type": record.job_document.get("scan_type"),
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "endpoint_status": (
            record.terminal_status.get("status") if record.terminal_status else None
        ),
        "report_ready": report_ready,
        "report_summary": (
            record.final_report.get("summary") if record.final_report else None
        ),
        "actions": {
            "json_download_url": (
                f"/api/v1/platform/scans/{record.scan_id}/report.json"
                if report_ready
                else None
            ),
            "pdf_download_url": (
                f"/api/v1/platform/scans/{record.scan_id}/report.pdf"
                if report_ready
                else None
            ),
        },
    }
    if include_documents:
        value["job"] = record.job_document
        value["result"] = record.upload.get("result") if record.upload else None
        value["final_report"] = record.final_report
    return value


class RequestSizeLimitMiddleware:
    def __init__(self, app: Any, maximum: int) -> None:
        self.app = app
        self.maximum = maximum

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        raw_headers = list(scope.get("headers", []))
        headers = {key.lower(): value for key, value in raw_headers}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                declared = int(content_length)
            except ValueError:
                response = JSONResponse(
                    status_code=400, content={"detail": "invalid Content-Length"}
                )
                await response(scope, receive, send)
                return
            if declared > self.maximum:
                response = JSONResponse(status_code=413, content={"detail": "request is too large"})
                await response(scope, receive, send)
                return
        encoding = headers.get(b"content-encoding", b"identity").decode(
            "ascii", errors="ignore"
        ).strip().casefold()
        if encoding not in {"", "identity", "gzip"}:
            response = JSONResponse(
                status_code=415, content={"detail": "unsupported Content-Encoding"}
            )
            await response(scope, receive, send)
            return

        encoded = bytearray()
        while True:
            message = cast(dict[str, Any], await receive())
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                continue
            encoded.extend(message.get("body", b""))
            if len(encoded) > self.maximum:
                response = JSONResponse(
                    status_code=413, content={"detail": "request is too large"}
                )
                await response(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        body = bytes(encoded)
        if encoding == "gzip":
            try:
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                body = decoder.decompress(body, self.maximum + 1)
                if decoder.unconsumed_tail or len(body) > self.maximum:
                    raise OverflowError
                remaining = self.maximum + 1 - len(body)
                if remaining > 0:
                    body += decoder.flush(remaining)
                if len(body) > self.maximum:
                    raise OverflowError
                if not decoder.eof or decoder.unused_data:
                    raise zlib.error("truncated or trailing gzip data")
            except OverflowError:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "decompressed request is too large"},
                )
                await response(scope, receive, send)
                return
            except zlib.error:
                response = JSONResponse(
                    status_code=400, content={"detail": "invalid gzip request body"}
                )
                await response(scope, receive, send)
                return

        forwarded_scope = dict(scope)
        forwarded_scope["headers"] = [
            (key, value)
            for key, value in raw_headers
            if key.lower() not in {b"content-encoding", b"content-length"}
        ] + [(b"content-length", str(len(body)).encode("ascii"))]
        delivered = False

        async def buffered_receive() -> dict[str, Any]:
            nonlocal delivered
            if delivered:
                # Streaming responses keep listening for a disconnect after the
                # request body is delivered. Forward subsequent receives so the
                # listener does not spin forever on synthetic request messages.
                return cast(dict[str, Any], await receive())
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(forwarded_scope, buffered_receive, send)


def create_app(
    settings: CloudServiceSettings | None = None,
    repository: CloudRepository | None = None,
) -> FastAPI:
    config = settings or CloudServiceSettings.from_env()
    if repository is None:
        if config.database_url:
            from .postgres import PostgresRepository

            repository = PostgresRepository(
                config.database_url, run_migrations=config.run_migrations
            )
        else:
            repository = InMemoryRepository()
    repo = repository
    issuer = CredentialIssuer(config.credential_pepper)
    installer_store = LocalInstallerArtifactStore(
        config.installer_artifact_root,
        config.installer_manifest_path,
        config.installer_max_bytes,
    )

    # The reference control plane serves the scanner's reviewed built-in policy.
    # A main platform can replace this with its own versioned tenant assignment
    # repository without changing the endpoint contract.
    from app.core.config import default_policy_path
    from app.policies import (
        PolicyLoader,
        canonical_policy_bytes,
        canonical_policy_document,
    )

    policy = PolicyLoader().load_file(default_policy_path())
    policy_document = canonical_policy_document(policy)
    policy_checksum = hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()
    policy_assignment = {
        "schema_version": "1.0",
        "assignment_id": f"assignment-{policy.policy_id}-{policy.policy_version}",
        "active_policy_id": policy.policy_id,
        "active_policy_version": policy.policy_version,
        "policies": [{"sha256": policy_checksum, "document": policy_document}],
    }

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await repo.startup()
        try:
            yield
        finally:
            await repo.shutdown()

    application = FastAPI(
        title="Endpoint Scanner Cloud Control Plane",
        version="1.0.0",
        docs_url="/docs" if config.environment != "production" else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    application.add_middleware(RequestSizeLimitMiddleware, maximum=config.max_request_bytes)
    application.state.repository = repo
    application.state.settings = config
    application.state.installer_store = installer_store

    @application.middleware("http")
    async def response_controls(request: Request, call_next: Callable[..., Any]) -> Response:
        supplied = request.headers.get("x-request-id")
        request_id = (
            supplied
            if supplied
            and len(supplied) <= 256
            and all(32 < ord(character) < 127 for character in supplied)
            else str(uuid4())
        )
        response = cast(Response, await call_next(request))
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @application.exception_handler(IdempotencyConflict)
    async def idempotency_error(_: Request, exc: IdempotencyConflict) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @application.exception_handler(StateConflict)
    async def state_error(_: Request, exc: StateConflict) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @application.exception_handler(NotFoundError)
    @application.exception_handler(OwnershipError)
    async def missing_error(_: Request, __: RepositoryError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": "resource was not found"})

    @application.exception_handler(RepositoryError)
    async def repository_error(_: Request, __: RepositoryError) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": "repository is unavailable"})

    async def enrollment_principal(request: Request) -> EnrollmentPrincipal:
        token = _bearer(request)
        tenant = token_tenant(token, config.bootstrap_tokens, config.credential_pepper)
        if tenant is not None:
            return EnrollmentPrincipal(tenant)
        token_hash = issuer.token_hash(token)
        grant = await repo.authenticate_enrollment_grant(token_hash, utc_now())
        if grant is None:
            raise HTTPException(status_code=401, detail="invalid enrollment credential")
        return EnrollmentPrincipal(grant.tenant_id, token_hash)

    async def admin_principal(request: Request) -> AdminPrincipal:
        token = _bearer(request)
        tenant = token_tenant(token, config.admin_tokens, config.credential_pepper)
        if tenant is None:
            raise HTTPException(status_code=403, detail="platform authorization is required")
        subject = f"static-admin:{hashlib.sha256(token.encode()).hexdigest()[:16]}"
        return AdminPrincipal(tenant, subject)

    async def device_principal(request: Request) -> DevicePrincipal:
        token = _bearer(request)
        principal = await repo.authenticate_device(issuer.token_hash(token), utc_now())
        if principal is None:
            raise HTTPException(status_code=401, detail="invalid or expired endpoint credential")
        return principal

    AuthenticatedEnrollment = Annotated[EnrollmentPrincipal, Depends(enrollment_principal)]
    AuthenticatedAdmin = Annotated[AdminPrincipal, Depends(admin_principal)]
    AuthenticatedEndpoint = Annotated[DevicePrincipal, Depends(device_principal)]
    IdempotencyKey = Annotated[str | None, Header(alias="Idempotency-Key")]

    async def canonical_platform_report(
        scan_id: str, principal: AdminPrincipal
    ) -> tuple[ScanRecord, Any]:
        record = await repo.get_scan_for_tenant(principal.tenant_id, scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail="scan was not found")
        if record.final_report is None:
            raise HTTPException(status_code=409, detail="final report is not ready")
        try:
            from .reporting import (
                CanonicalReportError,
                CanonicalReportIdentityError,
                canonicalize_stored_report,
            )

            report = canonicalize_stored_report(
                record.final_report,
                expected_scan_id=record.scan_id,
                expected_endpoint_id=record.endpoint_id,
                endpoint_result=(
                    record.upload.get("result")
                    if record.upload and isinstance(record.upload.get("result"), dict)
                    else None
                ),
            )
        except CanonicalReportIdentityError as exc:
            raise HTTPException(
                status_code=409,
                detail="canonical report identity does not match the requested scan",
            ) from exc
        except (ImportError, CanonicalReportError, ValidationError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail="final report does not satisfy the canonical assessment schema",
            ) from exc
        return record, report

    @application.get("/healthz", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @application.get("/readyz", response_model=HealthResponse)
    async def ready() -> HealthResponse:
        if not await repo.ready():
            raise HTTPException(status_code=503, detail="repository is not ready")
        return HealthResponse(status="ok")

    @application.get("/api/v1/policies")
    async def policies(_: AuthenticatedEndpoint) -> dict[str, Any]:
        return policy_assignment

    @application.post("/api/v1/endpoint/enroll", status_code=201)
    async def enroll(
        body: EndpointEnrollment,
        enrollment: AuthenticatedEnrollment,
        idempotency_key: IdempotencyKey = None,
    ) -> dict[str, Any]:
        key = _idempotency(idempotency_key)
        now = utc_now()
        tenant_id = enrollment.tenant_id
        endpoint_id = f"endpoint-{uuid4()}"
        credential_id = f"credential-{uuid4()}"
        token = issuer.issue_token(endpoint_id, credential_id, 1)
        endpoint = EndpointRecord(
            tenant_id=tenant_id,
            endpoint_id=endpoint_id,
            credential_generation=1,
            enrolled_at=now,
            last_seen_at=now,
            **body.model_dump(),
        )
        credential = CredentialRecord(
            tenant_id=tenant_id,
            endpoint_id=endpoint_id,
            credential_id=credential_id,
            token_hash=issuer.token_hash(token),
            generation=1,
            issued_at=now,
            expires_at=now + timedelta(seconds=config.credential_ttl_seconds),
        )
        stored = await repo.enroll_endpoint(
            tenant_id=tenant_id,
            endpoint=endpoint,
            credential=credential,
            enrollment_grant_hash=enrollment.grant_token_hash,
            idempotency_key=key,
            request_hash=canonical_sha256(body.model_dump(mode="json")),
        )
        returned_token = issuer.issue_token(
            stored.endpoint_id, stored.credential_id, stored.generation
        )
        response = CredentialResponse(
            endpoint_id=stored.endpoint_id,
            access_token=returned_token,
            credential_id=stored.credential_id,
            issued_at=stored.issued_at,
            expires_at=stored.expires_at,
            generation=stored.generation,
        )
        return {"credential": response.model_dump(mode="json")}

    @application.post("/api/v1/endpoints/{endpoint_id}/credentials/rotate")
    async def rotate(
        endpoint_id: str,
        body: CredentialRotation,
        principal: AuthenticatedEndpoint,
        idempotency_key: IdempotencyKey = None,
    ) -> dict[str, Any]:
        if endpoint_id != principal.endpoint_id or body.endpoint_id != principal.endpoint_id:
            raise HTTPException(status_code=404, detail="endpoint was not found")
        if (
            body.generation != principal.generation
            or body.credential_id != principal.credential_id
        ):
            raise HTTPException(status_code=409, detail="credential rotation request is stale")
        key = _idempotency(idempotency_key)
        now = utc_now()
        generation = body.generation + 1
        credential_id = f"credential-{uuid4()}"
        token = issuer.issue_token(endpoint_id, credential_id, generation)
        candidate = CredentialRecord(
            tenant_id=principal.tenant_id,
            endpoint_id=principal.endpoint_id,
            credential_id=credential_id,
            token_hash=issuer.token_hash(token),
            generation=generation,
            issued_at=now,
            expires_at=now + timedelta(seconds=config.credential_ttl_seconds),
        )
        stored = await repo.rotate_credential(
            principal=principal,
            expected_generation=body.generation,
            expected_credential_id=body.credential_id,
            credential=candidate,
            overlap_seconds=config.credential_rotation_overlap_seconds,
            idempotency_key=key,
            request_hash=canonical_sha256(body.model_dump(mode="json")),
        )
        returned_token = issuer.issue_token(
            stored.endpoint_id, stored.credential_id, stored.generation
        )
        response = CredentialResponse(
            endpoint_id=stored.endpoint_id,
            access_token=returned_token,
            credential_id=stored.credential_id,
            issued_at=stored.issued_at,
            expires_at=stored.expires_at,
            generation=stored.generation,
        )
        return {"credential": response.model_dump(mode="json")}

    @application.get("/api/v1/scans/next/{endpoint_id}", response_model=None)
    async def next_scan(
        endpoint_id: str, principal: AuthenticatedEndpoint
    ) -> Response | dict[str, Any]:
        if endpoint_id != principal.endpoint_id:
            raise HTTPException(status_code=404, detail="endpoint was not found")
        record = await repo.claim_next_job(principal, utc_now())
        return Response(status_code=204) if record is None else record.job_document

    @application.post("/api/v1/scans", status_code=202)
    async def submit_scan(
        body: ScanUpload,
        principal: AuthenticatedEndpoint,
        idempotency_key: IdempotencyKey = None,
    ) -> dict[str, Any]:
        key = _idempotency(idempotency_key)
        result_endpoint = body.result.get("endpoint_id")
        result_scan = body.result.get("scan_id")
        inventory_endpoint = body.inventory_sync.get("endpoint_id")
        inventory_scan = body.inventory_sync.get("scan_id")
        if (
            result_endpoint != principal.endpoint_id
            or inventory_endpoint != principal.endpoint_id
            or not isinstance(result_scan, str)
            or result_scan != inventory_scan
        ):
            raise HTTPException(status_code=422, detail="scan upload identities do not match")
        upload = body.model_dump(mode="json", exclude_none=True)
        now = utc_now()
        task_kinds: tuple[TaskKind, ...] = ("OSV", "DEPSCAN")
        tasks = tuple(
            AnalysisTask(
                task_id=f"task-{uuid4()}",
                tenant_id=principal.tenant_id,
                endpoint_id=principal.endpoint_id,
                scan_id=result_scan,
                kind=kind,
                state="PENDING",
                attempts=0,
                payload={"scan_id": result_scan},
                created_at=now,
                updated_at=now,
                available_at=now,
            )
            for kind in task_kinds
        )
        record = await repo.ingest_scan(
            principal=principal,
            scan_id=result_scan,
            upload=upload,
            idempotency_key=key,
            request_hash=canonical_sha256(upload),
            tasks=tasks,
        )
        return {
            "scan_id": record.scan_id,
            "status": "accepted",
            "analysis_tasks": ["OSV", "DEPSCAN"],
        }

    @application.post("/api/v1/scans/status", status_code=202)
    async def submit_status(
        body: ScanStatusUpload,
        principal: AuthenticatedEndpoint,
        idempotency_key: IdempotencyKey = None,
    ) -> dict[str, str]:
        if body.endpoint_id != principal.endpoint_id:
            raise HTTPException(status_code=422, detail="status endpoint identity does not match")
        document = body.model_dump(mode="json", exclude_none=True)
        await repo.record_scan_status(
            principal=principal,
            scan_id=body.scan_id,
            status=document,
            idempotency_key=_idempotency(idempotency_key),
            request_hash=canonical_sha256(document),
        )
        return {"scan_id": body.scan_id, "status": "accepted"}

    @application.post("/api/v1/scans/rejections", status_code=202)
    async def submit_rejection(
        body: ScanRejectionUpload,
        principal: AuthenticatedEndpoint,
        idempotency_key: IdempotencyKey = None,
    ) -> dict[str, str]:
        if body.endpoint_id != principal.endpoint_id:
            raise HTTPException(
                status_code=422, detail="rejection endpoint identity does not match"
            )
        document = body.model_dump(mode="json", exclude_none=True)
        await repo.record_rejection(
            principal=principal,
            payload=document,
            idempotency_key=_idempotency(idempotency_key),
            request_hash=canonical_sha256(document),
        )
        return {"status": "accepted"}

    @application.get("/api/v1/scans/{scan_id}")
    async def get_endpoint_scan(scan_id: str, principal: AuthenticatedEndpoint) -> dict[str, Any]:
        record = await repo.get_scan_for_endpoint(principal, scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail="scan was not found")
        return _record_view(record, include_documents=True)

    @application.get("/api/v1/platform/endpoints")
    async def platform_endpoints(
        principal: AuthenticatedAdmin,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0, le=10_000_000)] = 0,
    ) -> dict[str, Any]:
        records = await repo.list_endpoints(principal.tenant_id, limit=limit, offset=offset)
        now = utc_now()
        return {
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "endpoint_id": value.endpoint_id,
                    "hostname": value.hostname,
                    "os_family": value.os_family,
                    "os_version": value.os_version,
                    "architecture": value.architecture,
                    "scanner_version": value.scanner_version,
                    "enrolled_at": value.enrolled_at.isoformat(),
                    "last_seen_at": value.last_seen_at.isoformat(),
                    "last_seen_age_seconds": max(
                        0, int((now - value.last_seen_at).total_seconds())
                    ),
                    "connection_status": (
                        "ONLINE"
                        if (now - value.last_seen_at).total_seconds()
                        <= config.endpoint_online_threshold_seconds
                        else "OFFLINE"
                    ),
                    "online": (
                        (now - value.last_seen_at).total_seconds()
                        <= config.endpoint_online_threshold_seconds
                    ),
                    "can_start_scan": True,
                }
                for value in records
            ]
        }

    @application.get("/api/v1/platform/installers")
    async def platform_installers(_: AuthenticatedAdmin) -> dict[str, Any]:
        """Return only server-allowlisted endpoint artifacts and public metadata."""

        return {"items": installer_store.catalog()}

    @application.post("/api/v1/platform/enrollment-tokens", status_code=201)
    async def platform_create_enrollment_token(
        body: EnrollmentTokenRequest,
        principal: AuthenticatedAdmin,
        idempotency_key: IdempotencyKey = None,
    ) -> dict[str, Any]:
        now = utc_now()
        grant_id = f"enrollment-{uuid4()}"
        token = issuer.issue_enrollment_token(grant_id)
        candidate = EnrollmentGrantRecord(
            tenant_id=principal.tenant_id,
            grant_id=grant_id,
            token_hash=issuer.token_hash(token),
            issued_by=principal.subject,
            issued_at=now,
            expires_at=now + timedelta(seconds=body.expires_in_seconds),
            os_family=body.os_family,
            label=body.label,
        )
        stored = await repo.create_enrollment_grant(
            grant=candidate,
            idempotency_key=_idempotency(idempotency_key),
            request_hash=canonical_sha256(body.model_dump(mode="json")),
        )
        returned_token = issuer.issue_enrollment_token(stored.grant_id)
        return {
            "grant_id": stored.grant_id,
            "enrollment_token": returned_token,
            "issued_at": stored.issued_at.isoformat(),
            "expires_at": stored.expires_at.isoformat(),
            "one_time": True,
            "os_family": stored.os_family,
            "label": stored.label,
            "enrollment_url": "/api/v1/endpoint/enroll",
        }

    @application.get("/api/v1/platform/installers/{artifact_id}/download")
    async def platform_installer_download(
        artifact_id: str, _: AuthenticatedAdmin
    ) -> StreamingResponse:
        try:
            opened = installer_store.open(artifact_id)
        except UnknownArtifactError as exc:
            raise HTTPException(status_code=404, detail="installer artifact was not found") from exc
        except ArtifactUnavailableError as exc:
            raise HTTPException(
                status_code=503, detail="installer artifact is temporarily unavailable"
            ) from exc
        artifact = opened.artifact
        headers = {
            "Content-Disposition": f'attachment; filename="{artifact.definition.filename}"',
            "Content-Length": str(artifact.size_bytes),
            "ETag": f'"{artifact.sha256}"',
            "X-Artifact-SHA256": artifact.sha256,
        }
        return StreamingResponse(
            opened.chunks(),
            media_type=artifact.definition.media_type,
            headers=headers,
        )

    @application.post("/api/v1/platform/scans", status_code=201)
    async def platform_create_scan(
        body: PlatformScanRequest,
        principal: AuthenticatedAdmin,
        idempotency_key: IdempotencyKey = None,
    ) -> dict[str, Any]:
        if body.policy_id != policy.policy_id or body.policy_version not in {
            None,
            policy.policy_version,
        }:
            raise HTTPException(
                status_code=422,
                detail="requested policy is not active in this reference control plane",
            )
        key = _idempotency(idempotency_key)
        now = utc_now()
        scan_id = f"scan-{uuid4()}"
        job_id = f"job-{uuid4()}"
        expires_at = now + timedelta(seconds=body.validity_seconds)
        authorization = {
            "scope_id": f"scope-{uuid4()}",
            "authorized": True,
            "authorization_reference": body.authorization_reference,
            "authorized_by": principal.subject,
            "purpose": body.purpose,
            "valid_from": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "allowed_endpoint_ids": [body.endpoint_id],
            "allowed_domains": [],
            "excluded_domains": [],
            "allow_subdomains": False,
            "allowed_networks": [],
            "excluded_networks": [],
        }
        job: dict[str, Any] = {
            "job_id": job_id,
            "scan_id": scan_id,
            "scan_type": body.scan_type,
            "authorization": authorization,
            "endpoint_id": body.endpoint_id,
            "policy_id": body.policy_id,
            "policy_version": policy.policy_version,
            "approved_collectors": sorted(body.approved_collectors),
            "approved_sources": [],
            "initiated_by": principal.subject,
            "requested_at": now.isoformat(),
            "deadline": expires_at.isoformat(),
            "timeout_seconds": body.timeout_seconds,
            "priority": body.priority,
            "parameters": {},
        }
        # Validate against the endpoint's canonical job model when it is installed.
        try:
            from app.models import ScanJob

            job = ScanJob.model_validate(job).model_dump(mode="json")
        except ImportError:
            pass
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="generated scan job is invalid") from exc
        record = ScanRecord(
            tenant_id=principal.tenant_id,
            endpoint_id=body.endpoint_id,
            scan_id=scan_id,
            job_id=job_id,
            state="QUEUED",
            job_document=job,
            created_at=now,
            updated_at=now,
        )
        stored = await repo.create_scan_job(
            tenant_id=principal.tenant_id,
            record=record,
            idempotency_key=key,
            request_hash=canonical_sha256(body.model_dump(mode="json")),
        )
        response = _record_view(stored, include_documents=True)
        response["message"] = "scan was authorized and queued for the endpoint"
        response["status_url"] = f"/api/v1/platform/scans/{stored.scan_id}"
        return response

    @application.get("/api/v1/platform/scans")
    async def platform_scans(
        principal: AuthenticatedAdmin,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0, le=10_000_000)] = 0,
    ) -> dict[str, Any]:
        return {
            "limit": limit,
            "offset": offset,
            "items": [
                _record_view(item)
                for item in await repo.list_scans(
                    principal.tenant_id, limit=limit, offset=offset
                )
            ]
        }

    @application.get("/api/v1/platform/scans/{scan_id}")
    async def platform_scan_detail(
        scan_id: str, principal: AuthenticatedAdmin
    ) -> dict[str, Any]:
        record = await repo.get_scan_for_tenant(principal.tenant_id, scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail="scan was not found")
        # Platform detail exposes the authorized job and terminal state, but not
        # the potentially multi-megabyte raw evidence upload.  The normalized
        # report has its own authenticated download routes.
        value = _record_view(record)
        value["job"] = record.job_document
        value["terminal_status"] = record.terminal_status
        return value

    @application.get("/api/v1/platform/scans/{scan_id}/report")
    async def platform_report(
        scan_id: str, principal: AuthenticatedAdmin
    ) -> dict[str, Any]:
        lookup = await repo.get_scan_report(principal.tenant_id, scan_id)
        if lookup.state == "NOT_FOUND":
            raise HTTPException(status_code=404, detail="scan was not found")
        if lookup.state == "PENDING" or lookup.report is None:
            raise HTTPException(status_code=409, detail="final report is not ready")
        return lookup.report

    @application.get("/api/v1/platform/scans/{scan_id}/report.json")
    async def platform_report_json(
        scan_id: str, principal: AuthenticatedAdmin
    ) -> Response:
        _, report = await canonical_platform_report(scan_id, principal)
        try:
            from app.reporting.assessment_json import serialize_canonical_assessment

            serialized = serialize_canonical_assessment(report)
        except (ImportError, ValidationError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail="canonical report could not be serialized",
            ) from exc
        return Response(
            content=serialized.content,
            media_type="application/json",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="endpoint-security-{scan_id}.json"'
                ),
                "ETag": f'"{serialized.sha256}"',
                "X-Report-SHA256": serialized.sha256,
            },
        )

    @application.get("/api/v1/platform/scans/{scan_id}/report.pdf")
    async def platform_report_pdf(
        scan_id: str, principal: AuthenticatedAdmin
    ) -> Response:
        _, canonical_report = await canonical_platform_report(scan_id, principal)
        try:
            # Lazy import keeps the control plane usable if reporting is excluded
            # from a deliberately minimal deployment.
            from app.reporting.pdf_report import render_assessment_pdf
        except ImportError as exc:
            raise HTTPException(status_code=503, detail="PDF renderer is unavailable") from exc
        try:
            rendered = await asyncio.to_thread(render_assessment_pdf, canonical_report)
        except (ValidationError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail="final report does not satisfy the canonical PDF schema",
            ) from exc
        return Response(
            content=rendered.content,
            media_type="application/pdf",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="endpoint-security-{scan_id}.pdf"'
                ),
                "ETag": f'"{rendered.pdf_sha256}"',
                "X-PDF-SHA256": rendered.pdf_sha256,
                "X-Source-JSON-SHA256": rendered.source_json_sha256,
                "X-PDF-Page-Count": str(rendered.page_count),
            },
        )

    return application
