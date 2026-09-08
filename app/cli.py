"""Operational CLI for manual scans, service mode, enrollment, and health."""

from __future__ import annotations

import argparse
import json
import os
import signal
import ssl
import sys
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.config_loader import load_settings_file
from app.core import ScannerSettings
from app.enrollment import (
    CredentialStore,
    EnrollmentConfig,
    EnrollmentService,
    OSKeyringCredentialStore,
    ProtectedFileCredentialStore,
    StoredCredentialAuthProvider,
    WindowsDPAPIProtector,
)
from app.local_scan import (
    LocalScanRequest,
    build_local_scan_job,
    default_local_endpoint_id,
)
from app.models import AuthorizationScope, ScanJob, ScanResult, ScanType
from app.normalization import fallback_endpoint_identity
from app.observability import configure_logging
from app.orchestrator import (
    CloudJobSource,
    DeepScanRequest,
    ScannerAgent,
    ScannerOrchestrator,
    load_job_file,
    run_deep_scan,
)
from app.policies import CloudPolicySynchronizer, PolicyLoader
from app.reporting import AtomicReportWriter
from app.scheduling import CooperativeScanScheduler, SchedulePolicy, TriggerType
from app.security import sanitize_for_log
from app.storage import SQLiteStorage
from app.transport import (
    BearerTokenAuthProvider,
    CloudApiClient,
    CloudApiConfig,
    CloudApiRoutes,
    UploadWorker,
)


def _settings(path: Path | None) -> ScannerSettings:
    return load_settings_file(path) if path else ScannerSettings.from_env()


def _bounded_positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if not 1 <= parsed <= 100:
        raise argparse.ArgumentTypeError("value must be between 1 and 100")
    return parsed


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if not 1 <= parsed <= 9_223_372_036_854_775_807:
        raise argparse.ArgumentTypeError("value must be a positive 64-bit integer")
    return parsed


def _client(
    settings: ScannerSettings,
    *,
    endpoint_id: str | None = None,
    allow_anonymous: bool = False,
) -> CloudApiClient:
    if not settings.cloud.base_url:
        raise ValueError("cloud.base_url is required for this command")
    auth: Any = None
    if endpoint_id:
        try:
            store = _credential_store(settings)
            if store.load(endpoint_id) is not None:
                auth = StoredCredentialAuthProvider(store, endpoint_id)
        except (OSError, ValueError, RuntimeError):
            # An explicitly injected service secret remains a secure operational
            # fallback when a desktop keyring is unavailable on a headless host.
            auth = None
    if auth is None:
        token = os.environ.get(settings.cloud.credential_env_var)
        if token:
            auth = BearerTokenAuthProvider(token)
        elif not allow_anonymous:
            raise ValueError(
                f"cloud credential is unavailable; set {settings.cloud.credential_env_var}"
            )
    context = ssl.create_default_context(
        cafile=str(settings.cloud.ca_bundle) if settings.cloud.ca_bundle else None
    )
    config = CloudApiConfig(
        base_url=settings.cloud.base_url,
        allow_insecure_loopback_http=settings.cloud.allow_insecure_loopback_http,
        timeout_seconds=max(
            settings.cloud.connect_timeout_seconds, settings.cloud.read_timeout_seconds
        ),
        connect_timeout_seconds=settings.cloud.connect_timeout_seconds,
        read_timeout_seconds=settings.cloud.read_timeout_seconds,
        max_response_bytes=settings.cloud.max_response_bytes,
        max_request_bytes=settings.cloud.max_request_bytes,
        max_attempts=max(1, min(10, settings.cloud.max_retries + 1)),
        user_agent=f"endpoint-security-scanner/{settings.scanner_version}",
        routes=CloudApiRoutes(**settings.cloud.routes.model_dump(mode="python")),
    )
    return CloudApiClient(config, auth, ssl_context=context)


def _credential_store(settings: ScannerSettings) -> CredentialStore:
    if os.name == "nt":
        return ProtectedFileCredentialStore(
            settings.data_directory / "credentials.json", WindowsDPAPIProtector()
        )
    return OSKeyringCredentialStore()


def _enrollment_config(settings: ScannerSettings) -> EnrollmentConfig:
    return EnrollmentConfig(
        enrollment_path=settings.cloud.routes.enrollment_path,
        rotation_path_template=(
            settings.cloud.routes.credential_rotation_path_template
        ),
    )


def _cmd_validate_job(args: argparse.Namespace) -> int:
    job = load_job_file(args.job)
    job.validate_for_execution()
    print(json.dumps({"valid": True, "scan_id": job.scan_id, "scan_type": job.scan_type.value}))
    return 0


def _print_scan_summary(scanner: ScannerOrchestrator, result: ScanResult) -> int:
    print(
        json.dumps(
            {
                "scan_id": result.scan_id,
                "status": result.status.value,
                "findings": len(result.findings),
                "risk_score": result.risk.score if result.risk else None,
                "report": str(
                    scanner.settings.report_directory
                    / AtomicReportWriter.filename_for(result.scan_id)
                ),
            },
            sort_keys=True,
        )
    )
    return 0 if result.status.value in {"SUCCESS", "PARTIAL"} else 1


def _cmd_scan(args: argparse.Namespace) -> int:
    scanner = ScannerOrchestrator.from_settings(_settings(args.config))
    try:
        result = scanner.execute(load_job_file(args.job))
        return _print_scan_summary(scanner, result)
    finally:
        scanner.storage.close()


def _default_local_endpoint_id() -> str:
    """Compatibility wrapper for callers and tests using the former CLI helper."""

    return default_local_endpoint_id()


def _cmd_local_scan(args: argparse.Namespace) -> int:
    """Run one explicitly authorized scan of the device executing this command."""

    if getattr(args, "authorized", False) is not True:
        raise PermissionError("local scan requires explicit --authorized confirmation")
    settings = _settings(args.config)
    scanner = ScannerOrchestrator.from_settings(settings)
    try:
        endpoint_id = args.endpoint_id or _default_local_endpoint_id()
        request = LocalScanRequest(
            authorized=True,
            scan_type=ScanType(args.scan_type),
            endpoint_id=endpoint_id,
            approved_sources=tuple(getattr(args, "dependency_source", ()) or ()),
            timeout_seconds=int(args.timeout),
            authorization_reference=args.authorization_reference,
            origin="cli",
        )
        return _print_scan_summary(
            scanner,
            scanner.execute(build_local_scan_job(scanner, request)),
        )
    finally:
        scanner.storage.close()


_DEEP_SCAN_COUNT_FIELDS = (
    "scan_count",
    "attack_surface_scan_count",
    "software_count",
    "process_count",
    "service_count",
    "user_count",
    "network_interface_count",
    "listening_port_count",
    "update_count",
    "missing_patch_count",
    "browser_extension_count",
    "persistence_count",
    "compliance_result_count",
    "vulnerability_count",
    "attack_surface_asset_count",
    "finding_count",
)


def _cmd_deep_scan(args: argparse.Namespace) -> int:
    """Run one storage-free deep scan and emit only the final combined JSON."""

    if getattr(args, "authorized", False) is not True:
        raise PermissionError("deep scan requires explicit --authorized confirmation")
    request = DeepScanRequest(
        authorized=True,
        endpoint_id=args.endpoint_id,
        dependency_sources=tuple(args.dependency_source),
        authorized_domains=tuple(args.domain),
        timeout_seconds=int(args.timeout),
        output_path=args.output,
        authorization_reference=args.authorization_reference,
    )
    outcome = run_deep_scan(_settings(args.config), request)
    report = outcome.report
    summary = report.summary
    print(
        json.dumps(
            {
                "report": str(outcome.report_path),
                "report_id": report.report_id,
                "scan_id": report.endpoint_scan.scan_id,
                "status": summary.status.value,
                "completeness": {
                    "complete": report.completeness.complete,
                    "unobserved_endpoint_sections": list(
                        report.completeness.unobserved_endpoint_sections
                    ),
                    "degraded_collectors": list(
                        report.completeness.degraded_collectors
                    ),
                    "unobserved_attack_surface_domains": list(
                        report.completeness.unobserved_attack_surface_domains
                    ),
                },
                "counts": {
                    field: getattr(summary, field) for field in _DEEP_SCAN_COUNT_FIELDS
                },
                "tool_readiness": {
                    readiness.name: {
                        "configured": readiness.configured,
                        "scheduled": readiness.scheduled,
                        "status": readiness.status.value,
                        "version": readiness.version,
                        "records_collected": readiness.records_collected,
                        "detail": readiness.detail,
                    }
                    for readiness in report.tool_readiness
                },
            },
            sort_keys=True,
        )
    )
    return 1 if report.endpoint_scan.status.value == "FAILED" else 0


def _cmd_health(args: argparse.Namespace) -> int:
    scanner = ScannerOrchestrator.from_settings(_settings(args.config))
    try:
        tools = {
            "osquery": scanner.collectors.osquery.health(),
            "openscap": scanner.collectors.openscap.health(),
            "osv-scanner": scanner.collectors.osv_scanner.health(),
            "depscan": scanner.collectors.depscan.health(),
            "amass": scanner.collectors.amass.health(),
        }
        integrity = scanner.storage.check_integrity(quick=True)
        audit_chain = scanner.storage.verify_audit_chain()
        queue = scanner.storage.queue_stats()
        capacity = scanner.storage_maintenance.inspect_capacity()
        within_capacity = (
            capacity.local_bytes <= scanner.settings.retention.max_local_storage_bytes
            and capacity.free_bytes >= scanner.settings.retention.minimum_free_disk_bytes
        )
        healthy = integrity and audit_chain and within_capacity and queue.dead == 0
        payload = {
            "status": "HEALTHY" if healthy else "DEGRADED",
            "scanner_version": scanner.settings.scanner_version,
            "schema_version": scanner.settings.schema_version,
            "database_schema_version": scanner.storage.schema_version,
            "database_integrity": integrity,
            "audit_chain_valid": audit_chain,
            "queue": asdict(queue),
            "storage": {
                "local_bytes": capacity.local_bytes,
                "free_bytes": capacity.free_bytes,
                "max_local_storage_bytes": (
                    scanner.settings.retention.max_local_storage_bytes
                ),
                "minimum_free_disk_bytes": (
                    scanner.settings.retention.minimum_free_disk_bytes
                ),
                "within_capacity": within_capacity,
            },
            "policy": {
                "id": scanner.policy.policy_id,
                "version": scanner.policy.policy_version,
                "checksum": scanner.policy_checksum,
                "rules": len(scanner.policy.rules),
            },
            "tools": {
                name: {
                    "status": health.status.value,
                    "version": health.version,
                    "executable": health.executable,
                    "detail": health.detail,
                }
                for name, health in tools.items()
            },
        }
        print(json.dumps(payload, sort_keys=True))
        return 0 if healthy else 1
    finally:
        scanner.storage.close()


def _cmd_upload(args: argparse.Namespace) -> int:
    settings = _settings(args.config)
    scanner = ScannerOrchestrator.from_settings(settings)
    try:
        scanner.reconcile_terminal_statuses(limit=100)
        worker = UploadWorker(
            scanner.storage,
            _client(settings, endpoint_id=args.endpoint_id),
            metrics=scanner.metrics.sink,
        )
        stats = worker.run_once(limit=args.limit)
        queue = scanner.storage.queue_stats()
        print(json.dumps({**asdict(stats), "queue": asdict(queue)}, sort_keys=True))
        return 0 if stats.dead == 0 and queue.dead == 0 else 1
    finally:
        scanner.storage.close()


def _cmd_requeue_upload(args: argparse.Namespace) -> int:
    """Perform an explicit audited repair of one local dead-letter upload."""

    settings = _settings(args.config)
    scanner = ScannerOrchestrator.from_settings(settings)
    try:
        result = scanner.storage.requeue_dead_upload(
            args.upload_id,
            actor=args.actor,
            reason=args.reason,
            max_attempts=args.max_attempts,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    finally:
        scanner.storage.close()


def _cmd_enroll(args: argparse.Namespace) -> int:
    settings = _settings(args.config)
    token = os.environ.get(args.token_env)
    if not token:
        raise ValueError(f"temporary enrollment token is unavailable in {args.token_env}")
    service = EnrollmentService(
        _client(settings, allow_anonymous=True),
        _credential_store(settings),
        _enrollment_config(settings),
    )
    identity = fallback_endpoint_identity()
    operating_system = identity["os"]
    credential = service.enroll(
        token,
        {
            "hostname": identity["hostname"],
            "os_family": operating_system.family.value,
            "os_version": operating_system.version,
            "architecture": operating_system.architecture,
            "scanner_version": settings.scanner_version,
        },
    )
    storage = SQLiteStorage(settings.database_path)
    try:
        storage.upsert_endpoint(
            credential.endpoint_id,
            {
                "endpoint_id": credential.endpoint_id,
                "hostname": identity["hostname"],
                "os_family": operating_system.family.value,
                "os_version": operating_system.version,
                "scanner_version": settings.scanner_version,
                "credential_generation": credential.generation,
            },
            enrolled_at=credential.issued_at.isoformat(),
        )
    finally:
        storage.close()
    print(
        json.dumps(
            {
                "endpoint_id": credential.endpoint_id,
                "generation": credential.generation,
                "expires_at": credential.expires_at.isoformat(),
            },
            sort_keys=True,
        )
    )
    return 0


def _cmd_rotate(args: argparse.Namespace) -> int:
    settings = _settings(args.config)
    store = _credential_store(settings)
    service = EnrollmentService(
        _client(settings, endpoint_id=args.endpoint_id),
        store,
        _enrollment_config(settings),
    )
    credential = service.rotate(args.endpoint_id)
    print(
        json.dumps(
            {
                "endpoint_id": credential.endpoint_id,
                "generation": credential.generation,
                "expires_at": credential.expires_at.isoformat(),
            },
            sort_keys=True,
        )
    )
    return 0


def _cmd_agent(args: argparse.Namespace) -> int:
    settings = _settings(args.config)
    scanner = ScannerOrchestrator.from_settings(settings)
    try:
        endpoint_id = args.endpoint_id or os.environ.get("SCANNER_ENDPOINT_ID")
        if not endpoint_id:
            enrolled = scanner.storage.list_endpoint_ids(enrolled_only=True, limit=2)
            if len(enrolled) == 1:
                endpoint_id = enrolled[0]
            elif not enrolled:
                raise ValueError(
                    "endpoint identity is unavailable; enroll first or provide --endpoint-id"
                )
            else:
                raise ValueError(
                    "multiple enrolled endpoint identities exist; provide --endpoint-id"
                )
        client = _client(settings, endpoint_id=endpoint_id)
        logger = scanner.logger or configure_logging()
        scanner.reconcile_terminal_statuses(limit=100)
        worker = UploadWorker(
            scanner.storage,
            client,
            logger=logger,
            metrics=scanner.metrics.sink,
        )

        credential_maintenance = None
        try:
            credential_store = _credential_store(settings)
            if credential_store.load(endpoint_id) is not None:
                enrollment = EnrollmentService(
                    client,
                    credential_store,
                    _enrollment_config(settings),
                )

                def maintain_credential() -> bool:
                    if not enrollment.needs_rotation(endpoint_id):
                        return False
                    enrollment.rotate(endpoint_id)
                    return True

                credential_maintenance = maintain_credential
        except (OSError, ValueError, RuntimeError):
            # Environment-injected service credentials do not have a local
            # rotation lifecycle; the secret manager owns their replacement.
            credential_maintenance = None

        scheduler = None
        # The reference cloud accepts only jobs that were authorized and
        # registered by the control plane.  Policy synchronization alone must
        # never manufacture a random endpoint-local scan ID that the server
        # cannot own.  Local scheduling remains an explicit protected setting.
        if settings.scheduling.enabled:
            interval = (
                settings.scheduling.periodic_interval_seconds
                if settings.scheduling.enabled
                else None
            )
            schedule_policy = (
                SchedulePolicy(
                    timedelta(seconds=interval),
                    jitter_ratio=settings.scheduling.jitter_ratio,
                )
                if interval is not None
                else None
            )

            def scheduled_job(trigger: TriggerType, requested_at: Any) -> ScanJob:
                timeout = min(
                    settings.scheduling.timeout_seconds,
                    int(settings.runtime.scan_timeout_seconds),
                )
                deadline = requested_at + timedelta(seconds=timeout)
                authorization = AuthorizationScope(
                    scope_id=settings.scheduling.authorization_scope_id,
                    authorized=True,
                    authorization_reference=settings.scheduling.authorization_reference,
                    authorized_by="protected-local-service-configuration",
                    purpose=f"{trigger.value.casefold()} endpoint security scan",
                    valid_from=requested_at - timedelta(minutes=1),
                    expires_at=deadline + timedelta(minutes=1),
                    allowed_endpoint_ids=frozenset({endpoint_id}),
                )
                scan_type = (
                    ScanType.COMPLIANCE
                    if trigger is TriggerType.POLICY
                    else ScanType(settings.scheduling.scan_type)
                )
                return ScanJob(
                    job_id=f"local-{trigger.value.casefold()}-{uuid4()}",
                    scan_id=str(uuid4()),
                    scan_type=scan_type,
                    authorization=authorization,
                    endpoint_id=endpoint_id,
                    approved_sources=tuple(
                        str(source) for source in settings.scheduling.approved_sources
                    ),
                    policy_id=scanner.policy.policy_id,
                    policy_version=scanner.policy.policy_version,
                    initiated_by=f"local-{trigger.value.casefold()}-scheduler",
                    requested_at=requested_at,
                    deadline=deadline,
                    timeout_seconds=timeout,
                )

            scheduler = CooperativeScanScheduler(
                scheduled_job,
                policy=schedule_policy,
                startup_scan=(settings.scheduling.enabled and settings.scheduling.startup_scan),
            )
        policy_maintenance = None
        if settings.policies.cloud_sync_enabled:
            policy_loader = PolicyLoader(
                max_file_bytes=settings.policies.max_file_bytes,
                max_rules=settings.policies.max_rules,
                max_depth=settings.policies.max_expression_depth,
                allow_symlinks=False,
            )
            policy_maintenance = CloudPolicySynchronizer(
                client,
                policy_loader,
                scanner.install_policy_assignment,
                scanner.record_policy_sync_rejection,
            ).sync
        agent = ScannerAgent(
            scanner,
            CloudJobSource(client, endpoint_id, audit_storage=scanner.storage),
            worker,
            poll_interval_seconds=args.poll_interval,
            jitter_ratio=args.jitter,
            logger=logger,
            metrics=scanner.metrics,
            scheduler=scheduler,
            credential_maintenance=credential_maintenance,
            policy_maintenance=policy_maintenance,
        )

        def stop_agent(_signum: int, _frame: Any) -> None:
            agent.stop()

        signal.signal(signal.SIGTERM, stop_agent)
        if hasattr(signal, "SIGINT"):
            signal.signal(signal.SIGINT, stop_agent)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, lambda _signum, _frame: agent.request_policy_scan())
        if getattr(args, "once", False):
            outcome = agent.run_once()
            queue = scanner.storage.queue_stats()
            print(
                json.dumps(
                    {
                        "online": outcome.online,
                        "scan": (
                            {
                                "scan_id": outcome.scan.scan_id,
                                "status": outcome.scan.status.value,
                                "findings": len(outcome.scan.findings),
                            }
                            if outcome.scan is not None
                            else None
                        ),
                        "uploads": asdict(outcome.uploads),
                        "queue": asdict(queue),
                    },
                    sort_keys=True,
                )
            )
            return 0 if outcome.online and outcome.uploads.dead == 0 and queue.dead == 0 else 1
        agent.run()
    finally:
        scanner.storage.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="endpoint-scanner")
    subcommands = parser.add_subparsers(dest="command", required=True)

    def common(name: str, help_text: str) -> argparse.ArgumentParser:
        command = subcommands.add_parser(name, help=help_text)
        command.add_argument("--config", type=Path)
        return command

    validate = common("validate-job", "validate a bounded authorized scan job")
    validate.add_argument("--job", type=Path, required=True)
    validate.set_defaults(handler=_cmd_validate_job)

    scan = common("scan", "execute one authorized scan job")
    scan.add_argument("--job", type=Path, required=True)
    scan.set_defaults(handler=_cmd_scan)

    local_scan = common(
        "local-scan",
        "scan this device with explicit local authorization and no job file",
    )
    local_scan.add_argument(
        "--authorized",
        action="store_true",
        required=True,
        help="confirm that you own this device or are authorized to scan it",
    )
    local_scan.add_argument(
        "--scan-type",
        choices=(ScanType.QUICK.value, ScanType.FULL.value),
        default=ScanType.FULL.value,
    )
    local_scan.add_argument("--endpoint-id")
    local_scan.add_argument(
        "--dependency-source",
        action="append",
        type=Path,
        default=[],
        help=(
            "approved dependency directory, manifest, lockfile, or SBOM; repeatable and "
            "restricted by tools.approved_dependency_roots"
        ),
    )
    local_scan.add_argument("--timeout", type=int, default=900)
    local_scan.add_argument(
        "--authorization-reference",
        default="local-device-owner-consent",
    )
    local_scan.set_defaults(handler=_cmd_local_scan)

    deep_scan = common(
        "deep-scan",
        "run a storage-free deep endpoint scan and write one combined JSON report",
    )
    deep_scan.add_argument(
        "--authorized",
        action="store_true",
        required=True,
        help="confirm that you own every target or are authorized to scan it",
    )
    deep_scan.add_argument("--endpoint-id")
    deep_scan.add_argument(
        "--dependency-source",
        action="append",
        type=Path,
        default=[],
        help=(
            "dependency directory, manifest, lockfile, or SBOM; repeatable and restricted "
            "by tools.approved_dependency_roots"
        ),
    )
    deep_scan.add_argument(
        "--domain",
        action="append",
        default=[],
        help=(
            "authorized attack-surface DNS root; repeatable and restricted by "
            "discovery.authorized_domains"
        ),
    )
    deep_scan.add_argument("--timeout", type=int, default=1_800)
    deep_scan.add_argument(
        "--authorization-reference",
        default="local-deep-scan-consent",
    )
    deep_scan.add_argument(
        "--output",
        type=Path,
        default=Path("deep-scan-report.json"),
        help="destination for the only persisted scan artifact (.json required)",
    )
    deep_scan.set_defaults(handler=_cmd_deep_scan)

    health = common("health", "validate policy, database, and external-tool health")
    health.set_defaults(handler=_cmd_health)

    upload = common("upload", "drain a bounded batch from the durable upload queue")
    upload.add_argument("--endpoint-id")
    upload.add_argument("--limit", type=_bounded_positive_integer, default=10)
    upload.set_defaults(handler=_cmd_upload)

    requeue = common(
        "requeue-upload",
        "explicitly repair one DEAD outbox item and append a local audit event",
    )
    requeue.add_argument("--upload-id", type=_positive_integer, required=True)
    requeue.add_argument("--actor", required=True)
    requeue.add_argument("--reason", required=True)
    requeue.add_argument("--max-attempts", type=_bounded_positive_integer)
    requeue.set_defaults(handler=_cmd_requeue_upload)

    enroll = common("enroll", "exchange an environment-provided temporary token")
    enroll.add_argument("--token-env", default="SCANNER_ENROLLMENT_TOKEN")
    enroll.set_defaults(handler=_cmd_enroll)

    rotate = common("rotate-credential", "rotate a protected endpoint credential")
    rotate.add_argument("--endpoint-id", required=True)
    rotate.set_defaults(handler=_cmd_rotate)

    agent = common("agent", "run the cloud-triggered endpoint service loop")
    agent.add_argument("--endpoint-id")
    agent.add_argument("--poll-interval", type=float, default=60.0)
    agent.add_argument("--jitter", type=float, default=0.10)
    agent.add_argument(
        "--once",
        action="store_true",
        help="perform one poll/scan/upload iteration and exit (test and diagnostics)",
    )
    agent.set_defaults(handler=_cmd_agent)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, ValueError, RuntimeError) as exc:
        print(
            json.dumps(
                {"status": "ERROR", "error": str(sanitize_for_log(exc))[:2048]},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
