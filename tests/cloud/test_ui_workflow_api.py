from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.reporting.assessment_json import serialize_canonical_assessment
from cloud_service.app import create_app
from cloud_service.artifacts import (
    ArtifactUnavailableError,
    LocalInstallerArtifactStore,
    UnknownArtifactError,
)
from cloud_service.config import CloudServiceSettings
from cloud_service.reporting import canonicalize_stored_report
from cloud_service.repository import InMemoryRepository, ScanRecord
from tests.unit.test_canonical_assessment import assessment

BOOTSTRAP = "bootstrap-token-tenant-a"
ADMIN = "administrator-token-tenant-a"
OTHER_ADMIN = "administrator-token-tenant-b"


def _release(tmp_path: Path) -> tuple[Path, Path, bytes, str]:
    root = tmp_path / "endpoint"
    root.mkdir()
    content = b"MZ" + b"development endpoint scanner artifact"
    executable = root / "endpoint-scanner.exe"
    executable.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "algorithm": "sha256",
                "files": [
                    {
                        "path": "endpoint/endpoint-scanner.exe",
                        "sha256": digest,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return root, manifest, content, digest


def _settings(root: Path, manifest: Path) -> CloudServiceSettings:
    return CloudServiceSettings(
        environment="test",
        credential_pepper="test-credential-pepper-with-at-least-32-characters",
        bootstrap_tokens={BOOTSTRAP: "tenant-a"},
        admin_tokens={ADMIN: "tenant-a", OTHER_ADMIN: "tenant-b"},
        installer_artifact_root=str(root),
        installer_manifest_path=str(manifest),
        installer_max_bytes=1024 * 1024,
    )


def _enroll(client: TestClient) -> dict[str, object]:
    response = client.post(
        "/api/v1/endpoint/enroll",
        headers={
            "Authorization": f"Bearer {BOOTSTRAP}",
            "Idempotency-Key": "ui-enrollment",
        },
        json={
            "hostname": "ui-test-host",
            "os_family": "WINDOWS",
            "os_version": "11",
            "architecture": "x86_64",
            "scanner_version": "1.1.0",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["credential"]


def test_installer_catalog_and_download_are_allowlisted_and_manifest_verified(
    tmp_path: Path,
) -> None:
    root, manifest, content, digest = _release(tmp_path)
    app = create_app(_settings(root, manifest), InMemoryRepository())
    with TestClient(app) as client:
        assert client.get("/api/v1/platform/installers").status_code == 401
        catalog = client.get(
            "/api/v1/platform/installers",
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        assert catalog.status_code == 200
        artifact = catalog.json()["items"][0]
        assert artifact == {
            "artifact_id": "windows-x86_64-portable",
            "display_name": "Windows endpoint scanner (developer portable build)",
            "platform": "WINDOWS",
            "architecture": "x86_64",
            "package_type": "PORTABLE_EXECUTABLE",
            "version": "1.1.0",
            "filename": "endpoint-scanner.exe",
            "media_type": "application/vnd.microsoft.portable-executable",
            "size_bytes": len(content),
            "sha256": digest,
            "available": True,
            "delivery_mode": "DEVELOPMENT_PORTABLE",
            "managed_installer": False,
            "requires_elevation": True,
            "includes_cloud_analysis_tools": False,
            "download_url": (
                "/api/v1/platform/installers/windows-x86_64-portable/download"
            ),
        }
        assert "path" not in artifact

        download = client.get(
            artifact["download_url"],
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        assert download.status_code == 200
        assert download.content == content
        assert download.headers["content-type"].startswith(
            "application/vnd.microsoft.portable-executable"
        )
        assert download.headers["content-disposition"] == (
            'attachment; filename="endpoint-scanner.exe"'
        )
        assert download.headers["x-artifact-sha256"] == digest
        assert download.headers["etag"] == f'"{digest}"'

        unknown = client.get(
            "/api/v1/platform/installers/..%2Fsecret/download",
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        assert unknown.status_code == 404

        (root / "endpoint-scanner.exe").write_bytes(content + b"tampered")
        unavailable = client.get(
            artifact["download_url"],
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        assert unavailable.status_code == 503
        assert "path" not in unavailable.text.casefold()


def test_artifact_store_rejects_request_paths_and_invalid_content(tmp_path: Path) -> None:
    root, manifest, _, _ = _release(tmp_path)
    store = LocalInstallerArtifactStore(root, manifest, 1024 * 1024)
    with pytest.raises(UnknownArtifactError):
        store.open("../endpoint-scanner.exe")

    (root / "endpoint-scanner.exe").write_bytes(b"not-a-portable-executable")
    with pytest.raises(ArtifactUnavailableError):
        store.open("windows-x86_64-portable")


def test_admin_issues_one_time_tenant_enrollment_token(tmp_path: Path) -> None:
    root, manifest, _, _ = _release(tmp_path)
    repository = InMemoryRepository()
    app = create_app(_settings(root, manifest), repository)
    request = {
        "expires_in_seconds": 300,
        "os_family": "WINDOWS",
        "label": "finance-laptop",
    }
    with TestClient(app) as client:
        issued = client.post(
            "/api/v1/platform/enrollment-tokens",
            headers={
                "Authorization": f"Bearer {ADMIN}",
                "Idempotency-Key": "issue-one-time-enrollment",
            },
            json=request,
        )
        assert issued.status_code == 201, issued.text
        grant = issued.json()
        assert grant["one_time"] is True
        assert grant["os_family"] == "WINDOWS"
        assert grant["enrollment_token"].startswith("esc_enroll_v1.")
        assert grant["enrollment_token"] not in repository.enrollment_grants

        issued_replay = client.post(
            "/api/v1/platform/enrollment-tokens",
            headers={
                "Authorization": f"Bearer {ADMIN}",
                "Idempotency-Key": "issue-one-time-enrollment",
            },
            json=request,
        )
        assert issued_replay.status_code == 201
        assert issued_replay.json() == grant

        enrollment_document = {
            "hostname": "one-time-enrolled-host",
            "os_family": "WINDOWS",
            "os_version": "11",
            "architecture": "x86_64",
            "scanner_version": "1.1.0",
        }
        enrollment_headers = {
            "Authorization": f"Bearer {grant['enrollment_token']}",
            "Idempotency-Key": "one-time-enrollment-use",
        }
        enrolled = client.post(
            "/api/v1/endpoint/enroll",
            headers=enrollment_headers,
            json=enrollment_document,
        )
        assert enrolled.status_code == 201, enrolled.text

        replay = client.post(
            "/api/v1/endpoint/enroll",
            headers=enrollment_headers,
            json=enrollment_document,
        )
        assert replay.status_code == 201
        assert replay.json() == enrolled.json()

        reused = client.post(
            "/api/v1/endpoint/enroll",
            headers={
                "Authorization": f"Bearer {grant['enrollment_token']}",
                "Idempotency-Key": "second-device-attempt",
            },
            json={**enrollment_document, "hostname": "second-host"},
        )
        assert reused.status_code == 409


def test_ui_scan_status_detail_and_canonical_json_download_are_tenant_scoped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, manifest, _, _ = _release(tmp_path)
    repository = InMemoryRepository()
    app = create_app(_settings(root, manifest), repository)
    with TestClient(app) as client:
        credential = _enroll(client)
        endpoints = client.get(
            "/api/v1/platform/endpoints",
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        endpoint = endpoints.json()["items"][0]
        assert endpoint["online"] is True
        assert endpoint["connection_status"] == "ONLINE"
        assert endpoint["can_start_scan"] is True

        created = client.post(
            "/api/v1/platform/scans",
            headers={
                "Authorization": f"Bearer {ADMIN}",
                "Idempotency-Key": "ui-create-scan",
            },
            json={
                "endpoint_id": credential["endpoint_id"],
                "scan_type": "FULL",
                "authorization_reference": "ui-authorized-scan",
                "authorized_by": "ignored-client-identity",
            },
        )
        assert created.status_code == 201, created.text
        body = created.json()
        scan_id = body["scan_id"]
        assert body["phase"] == "WAITING_FOR_ENDPOINT"
        assert body["progress_percent"] == 0
        assert body["status_url"] == f"/api/v1/platform/scans/{scan_id}"

        detail = client.get(
            f"/api/v1/platform/scans/{scan_id}",
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        assert detail.status_code == 200
        assert detail.json()["job"]["scan_id"] == scan_id
        assert detail.json()["actions"]["json_download_url"] is None
        assert "result" not in detail.json()

        hidden = client.get(
            f"/api/v1/platform/scans/{scan_id}",
            headers={"Authorization": f"Bearer {OTHER_ADMIN}"},
        )
        assert hidden.status_code == 404

        report = {
            "schema_version": "test-canonical-v1",
            "scan_id": scan_id,
            "endpoint_id": credential["endpoint_id"],
            "status": "SUCCESS",
            "summary": {"finding_count": 1},
            "findings": [{"finding_id": "finding-1", "severity": "LOW"}],
        }

        current = repository.scans[scan_id]
        repository.scans[scan_id] = replace(
            current,
            state="COMPLETE",
            final_report=report,
        )

        ready = client.get(
            f"/api/v1/platform/scans/{scan_id}",
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        assert ready.json()["report_ready"] is True
        assert ready.json()["actions"]["json_download_url"].endswith("report.json")

        downloaded = client.get(
            f"/api/v1/platform/scans/{scan_id}/report.json",
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        assert downloaded.status_code == 422

        canonical = assessment()
        canonical_scan_id = canonical.endpoint_scan.scan_id
        canonical_endpoint_id = str(canonical.endpoint_scan.endpoint_id)
        repository.scans[canonical_scan_id] = ScanRecord(
            tenant_id="tenant-a",
            endpoint_id=canonical_endpoint_id,
            scan_id=canonical_scan_id,
            job_id="job-canonical-download",
            state="COMPLETE",
            job_document={"scan_type": "FULL"},
            created_at=canonical.endpoint_scan.started_at,
            updated_at=canonical.generated_at,
            final_report=canonical.model_dump(mode="json"),
        )
        canonical_download = client.get(
            f"/api/v1/platform/scans/{canonical_scan_id}/report.json",
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        serialized = serialize_canonical_assessment(canonical)
        assert canonical_download.status_code == 200
        assert canonical_download.content == serialized.content
        assert canonical_download.headers["content-disposition"] == (
            f'attachment; filename="endpoint-security-{canonical_scan_id}.json"'
        )
        assert canonical_download.headers["x-report-sha256"] == serialized.sha256

        offloaded: list[str] = []

        async def run_in_thread(
            function: Callable[..., object], *args: object, **kwargs: object
        ) -> object:
            offloaded.append(getattr(function, "__name__", "unknown"))
            return function(*args, **kwargs)

        monkeypatch.setattr("cloud_service.app.asyncio.to_thread", run_in_thread)
        pdf_download = client.get(
            f"/api/v1/platform/scans/{canonical_scan_id}/report.pdf",
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        assert pdf_download.status_code == 200
        assert pdf_download.content.startswith(b"%PDF-1.7")
        assert pdf_download.headers["x-source-json-sha256"] == serialized.sha256
        assert len(pdf_download.headers["x-pdf-sha256"]) == 64
        assert int(pdf_download.headers["x-pdf-page-count"]) >= 2
        assert offloaded == ["render_assessment_pdf"]

        cross_tenant_download = client.get(
            f"/api/v1/platform/scans/{canonical_scan_id}/report.json",
            headers={"Authorization": f"Bearer {OTHER_ADMIN}"},
        )
        assert cross_tenant_download.status_code == 404


def test_legacy_cloud_report_is_upgraded_at_artifact_boundary() -> None:
    canonical = assessment()
    endpoint_scan = canonical.endpoint_scan
    legacy = {
        "schema_version": "1.0",
        "report_type": "CLOUD_ENDPOINT_SECURITY_REPORT",
        "report_id": "cloud-report:scan-canonical-1",
        "analysis_completed_at": canonical.generated_at.isoformat(),
        "endpoint_evidence": {
            "result": endpoint_scan.model_dump(mode="json"),
            "inventory_sync": {},
            "sbom": {},
        },
        "cloud_analysis": {
            "vulnerabilities": [],
            "tools": {
                "OSV": {
                    "status": "SUCCESS",
                    "tool_version": "2.0.0",
                    "finished_at": canonical.generated_at.isoformat(),
                    "duration_seconds": 1.5,
                    "records_accepted": 1,
                    "records_rejected": 0,
                    "warnings": [],
                    "provenance": {"execution_mode": "CLOUD_TOOL_EXECUTION"},
                }
            },
        },
    }

    upgraded = canonicalize_stored_report(
        legacy,
        expected_scan_id=endpoint_scan.scan_id,
        expected_endpoint_id=str(endpoint_scan.endpoint_id),
    )

    assert upgraded.endpoint_scan.scan_id == endpoint_scan.scan_id
    assert upgraded.analysis_tools[0].name == "osv-scanner"
    assert upgraded.coverage.complete is False
    assert next(
        item.state.value
        for item in upgraded.coverage.sections
        if item.name == "dependency_vulnerabilities"
    ) == "OBSERVED"


def test_real_agent_upload_shape_rehydrates_inventory_for_canonical_artifacts() -> None:
    canonical = assessment()
    endpoint_scan = canonical.endpoint_scan
    serialized = endpoint_scan.model_dump(mode="json", exclude_none=True)
    summary_fields = {
        "schema_version",
        "scanner_version",
        "scan_id",
        "endpoint_id",
        "scan_type",
        "timestamp",
        "started_at",
        "finished_at",
        "status",
        "policy_id",
        "policy_version",
        "policy_checksum",
        "authorization_scope_id",
        "findings",
        "risk",
        "collectors",
        "metadata",
    }
    inventory_fields = {
        "endpoint",
        "os",
        "hardware",
        "software",
        "processes",
        "services",
        "users",
        "network_interfaces",
        "listening_ports",
        "security",
        "updates",
        "browser_extensions",
        "certificates",
        "persistence",
        "compliance",
        "vulnerabilities",
        "attack_surface",
    }
    summary_result = {key: value for key, value in serialized.items() if key in summary_fields}
    reconstructed_inventory = {
        key: value for key, value in serialized.items() if key in inventory_fields
    }
    # Repository-only bookkeeping and unknown keys must never leak into ScanResult.
    reconstructed_inventory["collection_completeness"] = {"observed_sections": ["software"]}
    reconstructed_inventory["unexpected_server_field"] = "ignored"
    legacy = {
        "schema_version": "1.0",
        "report_type": "CLOUD_ENDPOINT_SECURITY_REPORT",
        "report_id": "cloud-report:scan-canonical-1",
        "analysis_completed_at": canonical.generated_at.isoformat(),
        "endpoint_evidence": {
            "result": summary_result,
            "inventory_sync": {
                "mode": "full",
                "reconstructed_snapshot": reconstructed_inventory,
            },
            "sbom": {},
        },
        "cloud_analysis": {
            "vulnerabilities": [],
            "tools": {
                "OSV": {
                    "status": "SUCCESS",
                    "tool_version": "2.0.0",
                    "finished_at": canonical.generated_at.isoformat(),
                    "duration_seconds": 1.5,
                    "records_accepted": 0,
                    "records_rejected": 0,
                    "warnings": [],
                    "provenance": {"execution_mode": "CLOUD_TOOL_EXECUTION"},
                }
            },
        },
    }

    upgraded = canonicalize_stored_report(
        legacy,
        expected_scan_id=endpoint_scan.scan_id,
        expected_endpoint_id=str(endpoint_scan.endpoint_id),
        endpoint_result=summary_result,
    )

    assert upgraded.endpoint_scan.software == endpoint_scan.software
    assert upgraded.endpoint_scan.listening_ports == endpoint_scan.listening_ports
    assert upgraded.endpoint_scan.security == endpoint_scan.security
    assert upgraded.endpoint_scan.certificates == endpoint_scan.certificates
    assert upgraded.summary.software_count == 1
    assert upgraded.summary.local_listener_count == 1
    assert upgraded.summary.certificate_count == 1
