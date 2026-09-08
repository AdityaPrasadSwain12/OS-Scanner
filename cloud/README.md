# Scanner cloud reference stack

This directory is the local integration and deployment reference for the endpoint scanner cloud
control plane. It provides PostgreSQL-backed enrollment, authorized scan jobs, evidence/SBOM
ingestion, isolated OSV-Scanner and OWASP dep-scan analysis, normalized report assembly, and a
local operator dashboard. The dashboard supports package download, short-lived enrollment grants,
authorized scan control, live status, report inspection, and JSON/PDF downloads. Its local bearer
token is a development authentication mechanism, not the production identity design.

## Trust boundaries

- The endpoint agent runs directly on the endpoint, outside Docker. It is the only component that
  inspects the endpoint operating system.
- The API accepts bounded normalized endpoint evidence and CycloneDX SBOM JSON. Uploaded content is
  data, not a command or a caller-selected local path.
- The worker runs tool adapters in its own constrained container. It never has access to the
  endpoint filesystem. Its separate egress network is needed for OSV and vulnerability-database
  updates; production should restrict that egress to approved registries and advisory services.
- PostgreSQL is the durable source of truth and task lease queue. Worker crashes are recovered by
  leases and bounded retry state.
- Redis is intentionally absent from this reference stack because the current API and worker do
  not consume it. A notification/event bus can later wake workers at very large scale, but durable
  task ownership must remain in PostgreSQL (or an equivalently transactional queue).
- Amass is outside this stack by design.

## Local ports

| Component | Default host address | Purpose |
| --- | --- | --- |
| Cloud API | `http://127.0.0.1:8080` | Local endpoint/API integration only |
| Operator dashboard | `http://127.0.0.1:8081` | Enrollment, scan control, status, and JSON/PDF reports |

The API binds to loopback by default. Plain HTTP is only appropriate for the explicit local
development exception. Production must put the API behind a trusted TLS ingress/load balancer,
use HTTPS from every endpoint, restrict proxy trust, and inject secrets from the cloud secret
manager instead of an environment file.

## Start and test

From the repository root in PowerShell:

```powershell
if (-not (Test-Path -LiteralPath .\cloud\.env.local -PathType Leaf)) {
  .\scripts\cloud\Initialize-CloudEnvironment.ps1
}
.\scripts\cloud\Start-Cloud.ps1 -Build
.\scripts\cloud\Test-CloudE2E.ps1
```

The smoke script does not scan the workstation. It enrolls a synthetic endpoint, creates an
explicitly authorized job, simulates that endpoint polling the job, uploads a bounded fixture
result and CycloneDX SBOM, and waits for the final cloud report. Tool analysis is real by default.
The first dep-scan run can take longer while its advisory cache is initialized.

To stop containers while preserving PostgreSQL and tool caches:

```powershell
.\scripts\cloud\Stop-Cloud.ps1
```

To deliberately run the cloud analyzer in fixture mode for a fast transport-only test, set
`SCANNER_ANALYSIS_FIXTURE_MODE=true` in `cloud/.env.local` before starting the stack. Fixture mode is
rejected when `SCANNER_ENVIRONMENT=production`, and fixture output is marked incomplete; it is not
valid vulnerability evidence.

## Local secrets

`Initialize-CloudEnvironment.ps1` creates random local-only values in ignored
`cloud/.env.local`. The important settings are:

- `CLOUD_ENROLLMENT_TOKEN`: one-time bootstrap authority used by the smoke endpoint;
- `CLOUD_ADMIN_TOKEN`: platform authority used to create jobs and read tenant reports;
- `SCANNER_CREDENTIAL_PEPPER`: protects issued endpoint credential hashes;
- `POSTGRES_PASSWORD`: local database credential;
- `SCANNER_ANALYSIS_FIXTURE_MODE`: false for real OSV/dep-scan execution.

Do not reuse these values, commit them, or copy the local Compose secrets pattern into production.

## Images and runtime controls

The Python, nginx, PostgreSQL, and OSV base images are version- and digest-pinned. The cloud and tool
requirements are version-pinned. Runtime containers use non-root users where supported, read-only
filesystems, dropped capabilities, `no-new-privileges`, bounded temporary filesystems, health
checks, named durable volumes, and CPU/memory/PID limits. The dep-scan vulnerability data cache is
stored in the `scanner-tool-cache` volume using `VDB_HOME` so it can be reused after worker restarts.

Release engineering must still rebuild and scan images regularly, generate complete transitive
dependency locks with hashes for each supported architecture, publish an SBOM/provenance record,
sign the images, and deploy immutable digests through the production orchestrator.

## Main-platform integration contract

The main platform should replace the local dashboard authentication boundary while reusing the
versioned scanner-control routes for the installer catalog/download, one-time enrollment grants,
tenant endpoint lists, scan creation/listing, and JSON/PDF report retrieval. It must preserve
admin RBAC and tenant identity instead of exposing a shared browser token. Endpoint installers
enroll with a short-lived, single-use grant and retain only their endpoint credential.

An ingress or API gateway may add a path prefix, rate limits, web-application firewall rules, and
central authentication, but it must preserve request IDs, idempotency keys, response codes, bounded
request bodies, and the `/healthz` and `/readyz` semantics.
