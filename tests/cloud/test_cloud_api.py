from __future__ import annotations

import asyncio
import gzip
import json
from datetime import timedelta

from fastapi.testclient import TestClient

from app.storage.snapshots import snapshot_hash
from cloud_service.app import create_app
from cloud_service.config import CloudServiceSettings
from cloud_service.models import utc_now
from cloud_service.repository import InMemoryRepository

BOOTSTRAP = "bootstrap-token-tenant-a"
ADMIN = "administrator-token-tenant-a"


def configured_app() -> tuple[object, InMemoryRepository]:
    repository = InMemoryRepository()
    settings = CloudServiceSettings(
        environment="test",
        credential_pepper="test-credential-pepper-with-at-least-32-characters",
        bootstrap_tokens={BOOTSTRAP: "tenant-a"},
        admin_tokens={ADMIN: "tenant-a"},
    )
    return create_app(settings, repository), repository


def enroll(client: TestClient, key: str = "enrollment-1") -> dict[str, object]:
    response = client.post(
        "/api/v1/endpoint/enroll",
        headers={"Authorization": f"Bearer {BOOTSTRAP}", "Idempotency-Key": key},
        json={
            "hostname": "host-01",
            "os_family": "WINDOWS",
            "os_version": "11",
            "architecture": "x86_64",
            "scanner_version": "1.1.0",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["credential"]


def test_end_to_end_control_plane_and_analysis_lifecycle() -> None:
    app, repository = configured_app()
    with TestClient(app) as client:
        credential = enroll(client)
        token = str(credential["access_token"])
        endpoint_id = str(credential["endpoint_id"])
        assert token not in repository.credentials

        endpoints = client.get(
            "/api/v1/platform/endpoints", headers={"Authorization": f"Bearer {ADMIN}"}
        )
        assert endpoints.status_code == 200
        assert endpoints.json()["items"][0]["endpoint_id"] == endpoint_id

        created = client.post(
            "/api/v1/platform/scans",
            headers={
                "Authorization": f"Bearer {ADMIN}",
                "Idempotency-Key": "create-job-1",
            },
            json={
                "endpoint_id": endpoint_id,
                "scan_type": "FULL",
                "authorization_reference": "approved-change-42",
                "authorized_by": "security-admin",
            },
        )
        assert created.status_code == 201, created.text
        scan_id = created.json()["scan_id"]

        polled = client.get(
            f"/api/v1/scans/next/{endpoint_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert polled.status_code == 200
        assert polled.json()["scan_id"] == scan_id
        assert polled.json()["authorization"]["authorized"] is True
        assert polled.json()["authorization"]["authorized_by"].startswith("static-admin:")
        assert polled.json()["authorization"]["authorized_by"] != "security-admin"

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [],
        }
        accepted = client.post(
            "/api/v1/scans",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "upload-1",
            },
            json={
                "evidence_envelope_version": "1.0",
                "result": {
                    "schema_version": "1.0",
                    "scanner_version": "1.1.0",
                    "scan_id": scan_id,
                    "endpoint_id": endpoint_id,
                    "scan_type": "FULL",
                    "status": "SUCCESS",
                    "policy_id": "enterprise-default",
                    "policy_version": "1.0.0",
                    "authorization_scope_id": polled.json()["authorization"]["scope_id"],
                    "findings": [],
                },
                "inventory_sync": {
                    "scan_id": scan_id,
                    "endpoint_id": endpoint_id,
                    "mode": "full",
                    "snapshot_hash": snapshot_hash({"software": []}),
                    "snapshot": {"software": []},
                },
                "sbom": sbom,
            },
        )
        assert accepted.status_code == 202, accepted.text
        assert accepted.json()["analysis_tasks"] == ["OSV", "DEPSCAN"]

        policies = client.get(
            "/api/v1/policies", headers={"Authorization": f"Bearer {token}"}
        )
        assert policies.status_code == 200
        assert policies.json()["active_policy_id"] == "enterprise-default"

        status_response = client.post(
            "/api/v1/scans/status",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "status-1",
            },
            json={
                "schema_version": "1.0",
                "scanner_version": "1.1.0",
                "scan_id": scan_id,
                "endpoint_id": endpoint_id,
                "target": None,
                "authorization_scope_id": polled.json()["authorization"]["scope_id"],
                "policy_id": "enterprise-default",
                "policy_version": "1.0.0",
                "status": "SUCCESS",
                "requested_at": utc_now().isoformat(),
            },
        )
        assert status_response.status_code == 202, status_response.text

        async def process() -> None:
            for kind in ("OSV", "DEPSCAN"):
                task = await repository.claim_analysis_task(kind, f"{kind}-worker", 60)
                assert task is not None
                await repository.complete_analysis_task(
                    task.task_id,
                    f"{kind}-worker",
                    {"tool": kind.lower(), "status": "SUCCESS", "vulnerabilities": []},
                )
            results = await repository.list_scan_analysis_results(scan_id)
            assert set(results) == {"OSV", "DEPSCAN"}
            await repository.finalize_scan_report(
                scan_id,
                {"scan_id": scan_id, "status": "SUCCESS", "tool_results": results},
            )

        asyncio.run(process())

        report = client.get(
            f"/api/v1/platform/scans/{scan_id}/report",
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        assert report.status_code == 200
        assert report.json()["tool_results"]["OSV"]["status"] == "SUCCESS"


def test_idempotency_rotation_ownership_and_dead_letter_visibility() -> None:
    app, repository = configured_app()
    with TestClient(app) as client:
        first = enroll(client)
        replay = enroll(client)
        assert replay == first

        conflict = client.post(
            "/api/v1/endpoint/enroll",
            headers={
                "Authorization": f"Bearer {BOOTSTRAP}",
                "Idempotency-Key": "enrollment-1",
            },
            json={
                "hostname": "different-host",
                "os_family": "LINUX",
                "os_version": "24.04",
                "architecture": "x86_64",
                "scanner_version": "1.1.0",
            },
        )
        assert conflict.status_code == 409

        rotated = client.post(
            f"/api/v1/endpoints/{first['endpoint_id']}/credentials/rotate",
            headers={
                "Authorization": f"Bearer {first['access_token']}",
                "Idempotency-Key": "rotate-1",
            },
            json={
                "endpoint_id": first["endpoint_id"],
                "generation": first["generation"],
                "credential_id": first["credential_id"],
            },
        )
        assert rotated.status_code == 200, rotated.text
        assert rotated.json()["credential"]["generation"] == 2

        wrong_path = client.get(
            "/api/v1/scans/next/endpoint-not-owned",
            headers={"Authorization": f"Bearer {rotated.json()['credential']['access_token']}"},
        )
        assert wrong_path.status_code == 404

    async def dead_letter() -> None:
        # Direct task lifecycle behavior is checked independently of API job setup.
        now = utc_now()
        from cloud_service.repository import AnalysisTask

        repository.tasks["task-dead"] = AnalysisTask(
            task_id="task-dead",
            tenant_id="tenant-a",
            endpoint_id=str(first["endpoint_id"]),
            scan_id="scan-dead",
            kind="OSV",
            state="PENDING",
            attempts=0,
            payload={},
            created_at=now,
            updated_at=now,
            available_at=now,
        )
        task = await repository.claim_analysis_task("OSV", "worker", 60)
        assert task is not None
        await repository.fail_analysis_task(
            task.task_id, "worker", "safe failure", now + timedelta(seconds=1), True
        )
        result = await repository.list_scan_analysis_results("scan-dead")
        assert result["OSV"]["status"] == "FAILED"
        assert result["OSV"]["error"] == "safe failure"

    asyncio.run(dead_letter())


def test_overlap_credential_cannot_take_over_rotation_generation() -> None:
    app, _ = configured_app()
    with TestClient(app) as client:
        first = enroll(client, "rotation-overlap-enroll")
        endpoint_id = str(first["endpoint_id"])
        first_token = str(first["access_token"])
        first_rotation = client.post(
            f"/api/v1/endpoints/{endpoint_id}/credentials/rotate",
            headers={
                "Authorization": f"Bearer {first_token}",
                "Idempotency-Key": "rotation-overlap-first",
            },
            json={
                "endpoint_id": endpoint_id,
                "generation": first["generation"],
                "credential_id": first["credential_id"],
            },
        )
        assert first_rotation.status_code == 200, first_rotation.text
        second = first_rotation.json()["credential"]

        missing_binding = client.post(
            f"/api/v1/endpoints/{endpoint_id}/credentials/rotate",
            headers={
                "Authorization": f"Bearer {first_token}",
                "Idempotency-Key": "rotation-overlap-missing",
            },
            json={"endpoint_id": endpoint_id, "generation": second["generation"]},
        )
        assert missing_binding.status_code == 422

        stolen_overlap = client.post(
            f"/api/v1/endpoints/{endpoint_id}/credentials/rotate",
            headers={
                "Authorization": f"Bearer {first_token}",
                "Idempotency-Key": "rotation-overlap-takeover",
            },
            json={
                "endpoint_id": endpoint_id,
                "generation": second["generation"],
                "credential_id": second["credential_id"],
            },
        )
        assert stolen_overlap.status_code == 409

        current_rotation = client.post(
            f"/api/v1/endpoints/{endpoint_id}/credentials/rotate",
            headers={
                "Authorization": f"Bearer {second['access_token']}",
                "Idempotency-Key": "rotation-overlap-current",
            },
            json={
                "endpoint_id": endpoint_id,
                "generation": second["generation"],
                "credential_id": second["credential_id"],
            },
        )
        assert current_rotation.status_code == 200, current_rotation.text
        assert current_rotation.json()["credential"]["generation"] == 3


def test_scan_evidence_requires_dispatch_and_exact_provenance_and_status_is_immutable() -> None:
    app, _ = configured_app()
    with TestClient(app) as client:
        credential = enroll(client, "provenance-enroll")
        endpoint_id = str(credential["endpoint_id"])
        token = str(credential["access_token"])
        created = client.post(
            "/api/v1/platform/scans",
            headers={
                "Authorization": f"Bearer {ADMIN}",
                "Idempotency-Key": "provenance-create",
            },
            json={
                "endpoint_id": endpoint_id,
                "scan_type": "FULL",
                "authorization_reference": "approved-provenance-test",
                "authorized_by": "untrusted-request-subject",
            },
        )
        assert created.status_code == 201, created.text
        job = created.json()["job"]
        scan_id = job["scan_id"]

        def evidence(scope_id: str) -> dict[str, object]:
            return {
                "evidence_envelope_version": "1.0",
                "result": {
                    "schema_version": "1.0",
                    "scanner_version": "1.1.0",
                    "scan_id": scan_id,
                    "endpoint_id": endpoint_id,
                    "scan_type": "FULL",
                    "status": "SUCCESS",
                    "policy_id": "enterprise-default",
                    "policy_version": "1.0.0",
                    "authorization_scope_id": scope_id,
                    "findings": [],
                },
                "inventory_sync": {
                    "scan_id": scan_id,
                    "endpoint_id": endpoint_id,
                    "mode": "full",
                    "snapshot_hash": snapshot_hash({"software": []}),
                    "snapshot": {"software": []},
                },
            }

        before_dispatch = client.post(
            "/api/v1/scans",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "provenance-before-dispatch",
            },
            json=evidence(job["authorization"]["scope_id"]),
        )
        assert before_dispatch.status_code == 409

        polled = client.get(
            f"/api/v1/scans/next/{endpoint_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert polled.status_code == 200
        wrong_scope = client.post(
            "/api/v1/scans",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "provenance-wrong-scope",
            },
            json=evidence("scope-wrong"),
        )
        assert wrong_scope.status_code == 409

        accepted = client.post(
            "/api/v1/scans",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "provenance-accepted",
            },
            json=evidence(polled.json()["authorization"]["scope_id"]),
        )
        assert accepted.status_code == 202, accepted.text
        terminal = {
            "schema_version": "1.0",
            "scanner_version": "1.1.0",
            "scan_id": scan_id,
            "endpoint_id": endpoint_id,
            "target": None,
            "authorization_scope_id": polled.json()["authorization"]["scope_id"],
            "policy_id": "enterprise-default",
            "policy_version": "1.0.0",
            "status": "SUCCESS",
            "requested_at": utc_now().isoformat(),
        }
        first_status = client.post(
            "/api/v1/scans/status",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "provenance-status-first",
            },
            json=terminal,
        )
        assert first_status.status_code == 202, first_status.text
        second_status = client.post(
            "/api/v1/scans/status",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "provenance-status-second",
            },
            json=terminal,
        )
        assert second_status.status_code == 409


def test_platform_lists_are_bounded_and_report_poll_is_scoped() -> None:
    app, _ = configured_app()
    with TestClient(app) as client:
        first = enroll(client, "page-enroll-1")
        enroll(client, "page-enroll-2")
        page = client.get(
            "/api/v1/platform/endpoints?limit=1&offset=1",
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        assert page.status_code == 200
        assert page.json()["limit"] == 1
        assert page.json()["offset"] == 1
        assert len(page.json()["items"]) == 1
        assert client.get(
            "/api/v1/platform/endpoints?limit=501",
            headers={"Authorization": f"Bearer {ADMIN}"},
        ).status_code == 422
        assert client.get(
            "/api/v1/platform/scans/not-present/report",
            headers={"Authorization": f"Bearer {ADMIN}"},
        ).status_code == 404

        created = client.post(
            "/api/v1/platform/scans",
            headers={
                "Authorization": f"Bearer {ADMIN}",
                "Idempotency-Key": "page-scan-create",
            },
            json={
                "endpoint_id": first["endpoint_id"],
                "scan_type": "QUICK",
                "authorization_reference": "page-test",
                "authorized_by": "ignored-client-subject",
            },
        )
        assert created.status_code == 201
        pending = client.get(
            f"/api/v1/platform/scans/{created.json()['scan_id']}/report",
            headers={"Authorization": f"Bearer {ADMIN}"},
        )
        assert pending.status_code == 409


def test_oversized_and_unauthenticated_requests_are_rejected() -> None:
    settings = CloudServiceSettings(
        environment="test",
        credential_pepper="test-credential-pepper-with-at-least-32-characters",
        bootstrap_tokens={BOOTSTRAP: "tenant-a"},
        admin_tokens={ADMIN: "tenant-a"},
        max_request_bytes=1024,
    )
    with TestClient(create_app(settings, InMemoryRepository())) as client:
        assert client.get("/api/v1/platform/endpoints").status_code == 401
        response = client.post(
            "/api/v1/endpoint/enroll",
            headers={
                "Authorization": f"Bearer {BOOTSTRAP}",
                "Idempotency-Key": "too-large",
            },
            content=b"x" * 2048,
        )
        assert response.status_code == 413

        compressed_bomb = client.post(
            "/api/v1/endpoint/enroll",
            headers={
                "Authorization": f"Bearer {BOOTSTRAP}",
                "Idempotency-Key": "gzip-bomb",
                "Content-Encoding": "gzip",
                "Content-Type": "application/json",
            },
            content=gzip.compress(b"x" * 2048, mtime=0),
        )
        assert compressed_bomb.status_code == 413


def test_endpoint_gzip_upload_is_decompressed_and_versioned() -> None:
    app, _ = configured_app()
    with TestClient(app) as client:
        credential = enroll(client, "gzip-enrollment")
        endpoint_id = str(credential["endpoint_id"])
        token = str(credential["access_token"])
        created = client.post(
            "/api/v1/platform/scans",
            headers={
                "Authorization": f"Bearer {ADMIN}",
                "Idempotency-Key": "gzip-create",
            },
            json={
                "endpoint_id": endpoint_id,
                "scan_type": "FULL",
                "authorization_reference": "approved-gzip-test",
                "authorized_by": "security-admin",
            },
        )
        scan_id = created.json()["scan_id"]
        polled = client.get(
            f"/api/v1/scans/next/{endpoint_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert polled.status_code == 200
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [],
        }
        document = {
            "evidence_envelope_version": "1.0",
            "result": {
                "schema_version": "1.0",
                "scanner_version": "1.1.0",
                "scan_id": scan_id,
                "endpoint_id": endpoint_id,
                "scan_type": "FULL",
                "status": "SUCCESS",
                "policy_id": "enterprise-default",
                "policy_version": "1.0.0",
                "authorization_scope_id": polled.json()["authorization"]["scope_id"],
                "findings": [],
            },
            "inventory_sync": {
                "scan_id": scan_id,
                "endpoint_id": endpoint_id,
                "mode": "full",
                "snapshot_hash": snapshot_hash({"software": []}),
                "snapshot": {"software": []},
            },
            "sbom": sbom,
        }
        encoded = json.dumps(document, separators=(",", ":")).encode()

        accepted = client.post(
            "/api/v1/scans",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "gzip-upload",
                "Content-Encoding": "gzip",
                "Content-Type": "application/json",
            },
            content=gzip.compress(encoded, mtime=0),
        )

        assert accepted.status_code == 202, accepted.text
