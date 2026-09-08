# End-to-end enterprise workflow

This is the canonical guide to the implemented endpoint-to-cloud design. It explains what runs on
the device, what runs in the cloud, what data is produced, how to test it, and what an enterprise
platform must add before a production rollout.

The implementation is an enterprise-oriented reference, not an independently certified production
release. The current directly runnable endpoint artifact is a standalone Windows executable. The
managed Windows/Debian/macOS builders are unsigned release scaffolding and require approved native
inputs, signing, deployment controls, and target-OS qualification. Runtime E2E results must be
recorded in each target environment; source or configuration checks are not substitutes.

## The short explanation

1. Release engineering builds, signs, and qualifies one managed scanner package for each supported
   endpoint target, then installs it on an authorized endpoint.
2. Enrollment gives that installation its own tenant-bound endpoint credential.
3. The agent makes outbound HTTPS requests to ask the cloud for an authorized scan job.
4. Native collectors and bundled osquery read the endpoint at scan time.
5. The agent converts OS-specific output into one stable schema, evaluates policy/risk, builds a
   CycloneDX SBOM, stores the result locally, and queues it for upload.
6. The cloud validates and stores the evidence, reconstructs full inventory when an upload is a
   delta, and creates durable OSV and dep-scan tasks.
7. Cloud workers analyze the SBOM. They do not access the endpoint filesystem.
8. The normalizer merges endpoint evidence and tool results into one canonical assessment.
9. The local operator dashboard or integrated main platform presents that assessment and offers
   correlated JSON/PDF downloads.

The endpoint user does not separately install Python, Docker, OSV-Scanner, dep-scan, or osquery when
the approved managed package has been built and is used. Amass is not part of this OS-scanner flow.
The standalone Windows executable used by developer tests is not that installer and does not by
itself install a service or bundled osquery.

## The mental model

There are three trust zones:

```text
1. Customer endpoint
   managed agent -> native OS APIs/commands -> osquery
          |
          | outbound authenticated HTTPS only
          v

2. Scanner cloud services
   API -> PostgreSQL -> leased analysis tasks -> OSV/dep-scan workers
                    -> reconstructed inventory -> canonical assessment
          |
          v

3. Main enterprise platform
   login/RBAC -> installer distribution -> scan request -> report/dashboard
```

The cloud cannot obtain detailed local state from an arbitrary computer merely because the user
can see a website. An agent must run on that computer, or a different remote-management technology
must be designed. This project uses the agent model because it gives reliable local visibility,
works behind NAT, and needs no inbound endpoint port.

## What runs where

| Component | Location | Responsibility |
| --- | --- | --- |
| Scanner executable and embedded Python | Endpoint | Lifecycle, authorization checks, collection, normalization, policy, risk, local persistence, upload |
| Native collectors | Endpoint | Fixed bounded read-only OS commands and APIs |
| osquery | Endpoint | Additional scanner-owned inventory queries, including supported browser-extension coverage |
| SQLite | Endpoint | Local jobs, normalized results, snapshots, audit state, and leased upload outbox |
| Cloud API | Cloud | Enrollment, credential rotation, policy assignment, authorized jobs, evidence ingestion, tenant report APIs |
| PostgreSQL | Cloud | Durable tenant/endpoint/job/evidence/inventory/task/report/audit state |
| OSV-Scanner | Cloud worker | Advisory matching against the uploaded CycloneDX SBOM |
| OWASP dep-scan | Cloud worker | A second SBOM vulnerability analysis path and normalized evidence |
| Report assembler | Cloud worker/service code | Cross-tool merge, completeness, provenance, final report |
| Local operator dashboard | Cloud reference stack | Developer artifact download, one-time enrollment, authorized scan control, status/report views, and JSON/PDF downloads |
| Main platform UI/API | Organization platform | Production login, tenant RBAC, approved package distribution, scan controls, and product dashboard |
| OpenSCAP plus content | Optional Linux endpoint extension | Formal SCAP compliance when explicitly packaged/configured |
| Amass | Separate discovery component | Explicitly authorized domain discovery; excluded here |

The local dashboard creates tenant-scoped scan jobs through the platform API; it is not an endpoint
collector and cannot silently install software. Its shared development token and portable EXE are
not production IAM or a signed managed installer. The platform integration endpoints remain the
production boundary.

## Complete lifecycle

### 1. Release engineering builds the endpoint package

The package builders combine the PyInstaller scanner executable with platform configuration,
service definitions, licenses, hashes, and approved native inputs. The baseline managed package
contains osquery. Windows also includes WinSW for the service wrapper.

The builders are offline and input-verifying: they do not fetch a convenient binary from the
Internet during a release. A manifest pins the target, component names, versions, sizes, SHA-256
digests, and license files. Windows, Debian, and macOS packages must be built and tested on native
target runners.

The current repository has a working standalone Windows scanner executable and unsigned native
package-builder scaffolding. It does not contain completed organization installers. A release still
has to supply approved vendor artifacts/licenses/checksums, build on native target runners,
sign/notarize the result, and qualify install/enroll/upgrade/rollback/uninstall on clean machines.

### 2. The authenticated platform distributes the correct package

The main platform should map the logged-in tenant, chosen endpoint OS, architecture, and release
channel to an immutable signed artifact. It should provide:

- the Windows `.exe`, Debian `.deb`, or macOS `.pkg` appropriate for the device;
- its expected digest/signature and release metadata;
- the production API origin and CA policy through managed configuration;
- a short-lived, single-purpose enrollment token.

Production artifact hosting and the logged-in release workflow remain integration responsibilities.
For local development, the operator dashboard lists and downloads the manifest-verified portable
Windows artifact and can issue a short-lived, one-time enrollment grant.

### 3. Installation is safe before enrollment

The installer lays down the scanner, osquery, configuration, policy, and service definition. The
service starts disabled/stopped. A successful enrollment operation under the service identity is
required before the installer helper enables and starts it.

This avoids a half-configured service scanning or repeatedly contacting the wrong tenant. No
endpoint credential, tenant secret, private key, or reusable enrollment token is embedded in the
installer.

### 4. Enrollment creates a device identity

The enrollment helper supplies the temporary token only to the enrollment request. The cloud
records hostname, OS family/version, architecture, and scanner version, then returns a unique
endpoint ID and endpoint credential. The credential is bound to both tenant and endpoint.

Windows stores a managed-package credential with DPAPI protection under the service identity.
Linux/macOS agent code uses the operating-system keyring abstraction, but a reliable unlocked
backend is not guaranteed for a headless systemd/launchd service account. The builders do not
currently install or qualify that backend. A service-safe keyring, vault, TPM-backed design, or
equivalent must be integrated and tested before either platform package is a deployable release.
No plaintext credential fallback should be added. Enrollment also records the endpoint in local
SQLite so the service can recover its identity after restart.

The local Compose stack uses generated static bootstrap/admin tokens to make testing simple. They
do not implement an enterprise grant lifecycle (short expiry, one-time use/replay prevention,
revocation, or administrative device-credential revocation). Production must replace this with
real tenant/IAM authorization, short-lived enrollment issuance, and explicit revocation workflows.

### 5. The agent polls for work

The service opens an outbound HTTPS connection and calls the next-job API. It does not expose a
listening socket. If no job exists, the API returns no content and the agent waits with configured
polling/jitter.

Managed package configurations set `scheduling.enabled: false`, so startup and periodic local scans
do not run by default. The platform/control plane owns scheduling by creating authorized jobs.
Local scheduling remains available only when an administrator deliberately enables the protected
setting; policy synchronization alone does not enable it.

A platform scan request becomes a strict job containing:

- job and scan IDs;
- endpoint ID and scan type;
- affirmative authorization, authorizer, purpose, and reference;
- validity window and execution deadline;
- policy ID/version;
- only scanner-owned collector identifiers for `ON_DEMAND` scans.

Remote input cannot contain a shell command, executable path, arbitrary osquery SQL, local file
path, SCAP content path, or unrestricted network target. The endpoint validates the job and its
authorization window again before running it.

### 6. The endpoint collects current OS evidence

“Current” means read from the device while this bounded scan runs. It is a point-in-time assessment,
not a continuous event stream and not a transactionally simultaneous snapshot of every subsystem.
The start/finish timestamps bound the observation period.

The scanner can normalize these sections when the OS exposes them and permissions allow:

| Section | Typical fields |
| --- | --- |
| Endpoint/OS | Hostname, family, edition/name, version/build, kernel, architecture, machine ID, boot time, uptime, timezone |
| Hardware | CPU, logical/physical cores, memory, disks/free space/encryption, GPU, firmware/BIOS, manufacturer/model, TPM |
| Installed software | Name, version, vendor, package manager, architecture, source, install path/date when available |
| Processes | PID, name, executable path, parent, user, start time, bounded resource fields; native collection avoids command-line arguments |
| Services | Name/display name, state, startup type, executable, service account, security/suspicion flags |
| Users/groups | Local account, enabled/guest/admin state, groups, last login when available; no password hashes |
| Network | Interfaces, MAC/IP/prefix, gateways, DNS, DHCP, up/VPN state |
| Local attack surface | Listening TCP/UDP address/port, owning PID/process, exposure/suspicion flags |
| Security posture | Firewall, antivirus/security agents, encryption, Secure Boot/TPM, UAC, RDP/SSH, SELinux/AppArmor/SIP, audit/lock/update controls |
| Patches/updates | Installed and pending update metadata, security-update flags, install time, reboot requirement |
| Persistence | Startup/service/scheduled or platform persistence metadata, location, executable, user, enabled/suspicious flags |
| Browser extensions | Supported browser extension IDs/names/versions/permissions through configured osquery queries |
| Compliance | Optional OpenSCAP results on Linux when approved executable/content/profile are present |

Collector status is part of the evidence. `SUCCESS`, `PARTIAL`, `FAILED`, `UNAVAILABLE`, `TIMEOUT`,
and `SKIPPED` are not interchangeable. An empty successful query is different from an unobserved
section, so a tool failure cannot silently turn “unknown” into “no issue.”

The scanner intentionally does not collect passwords, password hashes, private keys, browser
passwords/cookies, session tokens, clipboard contents, keystrokes, screenshots, email, or document
contents. It does not install patches or remediate settings.

### 7. Endpoint normalization, policy, risk, and SBOM

Windows, Linux, macOS, and osquery output different shapes. Normalizers validate each record into
versioned typed models, merge compatible evidence, redact sensitive fields, bound list/document
sizes, and retain source/collector provenance.

The endpoint then:

1. compares posture and inventory with the protected baseline;
2. evaluates the versioned enterprise policy using a bounded non-executable rule engine;
3. creates findings with severity, evidence, remediation, references, and first-seen time;
4. calculates a health-oriented score from 0–100 and a separate risk penalty (higher score is
   healthier; higher penalty is worse);
5. builds a CycloneDX SBOM from normalized installed software.

Known package managers are mapped conservatively to Package URLs. Software without enough package
identity remains in inventory but may not be matchable by advisory tools. The cloud cannot browse
endpoint lockfiles after upload; it analyzes the SBOM it receives. Adding source-repository
dependency collection later requires another explicitly scoped collector or platform integration.

### 8. Local transaction and differential synchronization

Before cloud delivery, the agent writes the result, inventory snapshot, audit events, report, and
outbox records to protected local state. This is the durability boundary: a network outage after
collection does not erase the evidence.

The first endpoint inventory upload is `full`. Later uploads are:

- `delta` when only named inventory sections changed;
- `unchanged` when the canonical snapshot hash is the same;
- forced back to `full` when the server rejects a broken hash chain with HTTP 409/412.

Each envelope contains schema/scanner/policy versions, current and previous snapshot hashes,
endpoint/scan IDs, an SBOM plus its canonical SHA-256, and a summarized endpoint result. Large
requests are sent with bounded gzip. Idempotency keys make safe retries repeatable.

### 9. Cloud ingestion and inventory reconstruction

The API authenticates the endpoint credential and independently verifies that endpoint IDs and
scan IDs in the body belong to that principal and authorized job. It validates request bytes,
gzip expansion, JSON structure/depth/counts, evidence envelope version, SBOM checksum, and inventory
hash-chain state.

PostgreSQL stores the accepted evidence and the server’s reconstructed full inventory. A delta is
applied only to the previously accepted snapshot for the same tenant and endpoint. This means a
final report can expose a full reconstructed view without requiring every scan to retransmit every
unchanged section.

The database is required for reliable control-plane state, but it is **not** a CVE database. It
stores tenants, endpoint credentials, jobs, uploads, reconstructed inventory, analysis task leases,
reports, idempotency records, and audit events.

### 10. Durable cloud analysis

An accepted upload creates one OSV task and one dep-scan task. PostgreSQL is the queue source of
truth. Workers claim rows with leases, use bounded timeouts, persist terminal results, retry
transient errors with backoff/jitter, and turn permanent/dead-letter failures into visible degraded
tool results so a report does not wait forever.

Each worker writes the validated SBOM into a private temporary directory and executes a fixed
adapter without a shell. It never mounts or reads the endpoint filesystem. The two tool results are
normalized into the same vulnerability model and merged only when package/version identity and
provider evidence support it.

Normalized vulnerability fields can include:

- provider vulnerability ID and aliases;
- package name/ecosystem and installed/affected/fixed versions;
- severity and CVSS score when supplied by upstream evidence;
- exploitability/known-exploited flags when available;
- summary, references, source evidence, timestamps, and tool version.

OSV/dep-scan may return CVE, GHSA, or other provider IDs. This project has no scanner-owned CVE
database and does not invent or independently validate a CVE/CVSS value that the upstream evidence
did not provide. Finding no advisory match is not proof that a package is safe; coverage depends on
package identity, SBOM quality, advisory freshness, and tool success.

### 11. Stored report and canonical artifacts

After both analysis tasks are terminal, the worker assembles one bounded report with this shape:

```json
{
  "schema_version": "1.0",
  "report_type": "CLOUD_ENDPOINT_SECURITY_REPORT",
  "tenant_id": "...",
  "endpoint_id": "...",
  "scan_id": "...",
  "status": "SUCCESS|PARTIAL|FAILED|FIXTURE",
  "endpoint_evidence": {
    "result": {
      "collectors": {},
      "findings": [],
      "risk": {},
      "metadata": {}
    },
    "inventory_sync": {
      "mode": "full|delta|unchanged",
      "snapshot_hash": "...",
      "reconstructed_snapshot": {}
    },
    "sbom": {
      "bom_format": "CycloneDX",
      "spec_version": "1.6",
      "sha256": "...",
      "component_count": 0
    }
  },
  "cloud_analysis": {
    "vulnerabilities": [],
    "tools": {}
  },
  "summary": {},
  "completeness": {},
  "provenance": {}
}
```

This abbreviated example shows the stable sections, not every field. The final status must always
be interpreted with `completeness`, collector states, rejected records, successful/degraded tools,
and provenance. Authenticated artifact routes validate or upgrade the stored report into the
canonical assessment, then produce deterministic JSON and a paginated PDF that records its source
JSON SHA-256.

### 12. The platform presents and uses the result

The main platform can list/download approved artifacts, issue a one-time enrollment grant, list
endpoints, create a tenant-authorized scan, poll scan detail, and retrieve completed JSON/PDF
through versioned platform routes. A product dashboard can split the assessment into inventory,
patches, posture, findings, software, listeners, vulnerabilities, completeness, and history views.

The platform should retain the raw normalized JSON as the authoritative machine-readable record.
Any later visual or document representation should link to the source scan/report ID and preserve
provenance.

## Failure and offline behavior

| Failure | Behavior |
| --- | --- |
| Endpoint has no network | It cannot receive a new cloud job; queued evidence remains in SQLite. Local work can run only if protected local scheduling was explicitly enabled, which managed configs disable by default. |
| Network fails after a scan | Result/outbox remain durable and retry later with backoff/idempotency |
| Agent exits after receiving a job | A bounded dispatch lease allows an unfinished valid job to be delivered again |
| Optional endpoint collector is missing | Other collectors continue; status/completeness records the gap |
| One native collector fails | Successful evidence is retained; overall result is normally `PARTIAL` |
| Delta chain is inconsistent | API rejects it; endpoint queues one full resynchronization generation |
| Worker crashes | PostgreSQL task lease expires and another worker can reclaim it |
| OSV or dep-scan transient failure | Task retries with bounded exponential backoff/jitter |
| Analysis reaches permanent/dead-letter failure | Final report completes as degraded/`PARTIAL` instead of hanging |
| PostgreSQL is unavailable | `/readyz` fails and API/worker operations stop rather than accepting non-durable work |
| Local disk reaches protected limit | Admission/retention safeguards prevent silent loss and require operator action |

## Why the design is efficient and scalable

- The endpoint performs the work that requires local OS access; heavy advisory analysis runs in
  centrally managed workers.
- Each endpoint makes outbound requests, so the cloud does not maintain inbound device tunnels.
- Full/delta/unchanged inventory synchronization reduces repeated transfer while retaining a
  server-side full view.
- API processes are stateless around PostgreSQL and can be replicated behind a load balancer.
- `FOR UPDATE SKIP LOCKED` task claims and leases allow multiple worker replicas without duplicate
  ownership; workers may also be separated by OSV/dep-scan kind.
- PostgreSQL remains the durable source of truth. Redis is not required for correctness; a future
  event bus may reduce polling latency without replacing transactional ownership.
- Hard time, byte, component, record, depth, node, retry, PID, memory, and CPU limits keep one scan
  from consuming unbounded resources.
- Tool caches live in a named cloud volume, avoiding unnecessary advisory bootstrap work after a
  worker restart.

The Compose file is a single-host reference, not a high-availability production topology. At high
scale use a container orchestrator, multiple API/worker replicas, a managed HA PostgreSQL service
with tested backup/PITR and disaster recovery, a secrets manager, restricted egress, centralized
logs/metrics/traces and audit export, alerting, and capacity/load tests based on real endpoint
inventory sizes. The current endpoint/scan list APIs enforce bounded offset pages, but they are not
a complete large-fleet pagination contract. Add stable keyset cursors before exposing them to large
tenants. Large evidence
retention needs explicit deletion/legal-hold/privacy rules and may require object storage plus
database metadata and/or partitioning instead of keeping every document in JSONB.

## Security properties

- No scan runs without an affirmative, bounded authorization record.
- Tenant/endpoint ownership is checked from authentication, not trusted from JSON fields.
- Endpoint credentials are hashed server-side with a separate pepper and support rotation overlap.
- Production transport requires verified HTTPS; plain HTTP is allowed only for explicit
  development/test loopback configuration.
- Job inputs cannot become arbitrary commands, SQL, binaries, or local paths.
- Requests, gzip bodies, JSON structures, tool inputs/outputs, and reports are bounded.
- Uploads use request IDs, deterministic idempotency keys, checksums, and ordered status delivery.
- Redaction occurs before persistence/upload for protected fields.
- Cloud containers use read-only filesystems where possible, non-root users, dropped capabilities,
  `no-new-privileges`, health checks, tmpfs, and resource limits.
- Collector/tool failures remain visible instead of being converted into false healthy evidence.

Production must add TLS ingress, enterprise OIDC/IAM, tenant RBAC, secret/KMS integration, signed
artifacts/images, egress allowlists, audit export, SIEM/metrics/alerts, backups/PITR, vulnerability
cache governance, and incident-response procedures. The reference API derives the current admin
audit subject server-side from the authenticated static-token fingerprint rather than trusting the
request body's `authorized_by` field. Production auth must keep that server-derived audit identity
property while replacing the token fingerprint with the verified OIDC/service principal.

## Main-platform integration

The clean integration boundary is the cloud API, not imports from the endpoint package.

### Platform responsibilities

1. Authenticate the human/service through the platform’s existing login flow.
2. Resolve tenant membership and RBAC server-side.
3. Authorize installer download and issue a short-lived, one-time enrollment token.
4. Submit a job only after confirming endpoint ownership and scan permission.
5. Let the scanner API derive the immutable audit subject from the authenticated principal; send a
   human-readable ticket/consent value in `authorization_reference`.
6. Poll or consume completion events, then retrieve canonical JSON/PDF.
7. Render a dashboard using the canonical `summary`, `coverage`, endpoint inventory, findings, and
   cloud vulnerabilities.

The existing platform API routes are:

| Method/path | Caller | Purpose |
| --- | --- | --- |
| `POST /api/v1/endpoint/enroll` | Bootstrap-authorized endpoint | Exchange enrollment authority for an endpoint credential |
| `POST /api/v1/endpoints/{endpoint_id}/credentials/rotate` | Endpoint | Rotate its credential |
| `GET /api/v1/scans/next/{endpoint_id}` | Endpoint | Claim an authorized job |
| `POST /api/v1/scans` | Endpoint | Submit evidence, inventory sync, and SBOM |
| `POST /api/v1/scans/status` | Endpoint | Submit terminal endpoint status |
| `POST /api/v1/scans/rejections` | Endpoint | Audit an invalid/unauthorized job rejection |
| `GET /api/v1/policies` | Endpoint | Retrieve the managed policy assignment |
| `GET /api/v1/platform/installers` | Tenant admin/platform backend | List allowlisted release artifacts and integrity metadata |
| `GET /api/v1/platform/installers/{artifact_id}/download` | Tenant admin/platform backend | Download an allowlisted artifact |
| `POST /api/v1/platform/enrollment-tokens` | Tenant admin/platform backend | Issue a short-lived, one-time endpoint enrollment grant |
| `GET /api/v1/platform/endpoints` | Tenant admin/platform backend | List tenant endpoints |
| `POST /api/v1/platform/scans` | Tenant admin/platform backend | Create an authorized scan |
| `GET /api/v1/platform/scans` | Tenant admin/platform backend | List tenant scans |
| `GET /api/v1/platform/scans/{scan_id}/report` | Tenant admin/platform backend | Read final normalized JSON |
| `GET /api/v1/platform/scans/{scan_id}` | Tenant admin/platform backend | Read scan phase, progress, and report readiness |
| `GET /api/v1/platform/scans/{scan_id}/report.json` | Tenant admin/platform backend | Download canonical JSON with SHA-256 metadata |
| `GET /api/v1/platform/scans/{scan_id}/report.pdf` | Tenant admin/platform backend | Download canonical PDF correlated to source JSON |

Example platform-side scan intent:

```json
{
  "endpoint_id": "endpoint-id-from-tenant-inventory",
  "scan_type": "FULL",
  "authorization_reference": "customer-ticket-or-consent-id",
  "authorized_by": "non-authoritative-compatibility-field",
  "purpose": "Approved endpoint assessment",
  "validity_seconds": 1800,
  "timeout_seconds": 900,
  "policy_id": "enterprise-default",
  "priority": 50
}
```

`authorized_by` is currently required by the request schema for compatibility, but the API does not
trust it: it replaces it with the server-derived authenticated admin subject in the job and audit
record. With the local static-token auth this appears as a pseudonymous `static-admin:<fingerprint>`.
Production OIDC/IAM integration should derive a stable tenant-scoped user/service subject instead.

In production, do not put a shared admin token into browser JavaScript. The platform backend or
gateway should convert the authenticated session into a tenant-scoped service call. Preserve
request IDs, idempotency keys, HTTP conflict/retry semantics, and readiness behavior when adding a
gateway or path prefix.

### Adding a future pentest module

The final report is a good planning input because it provides observed software, ports, services,
posture, patches, findings, vulnerability evidence, provenance, and explicit gaps. A future module
should be a separate service after report finalization:

```text
final normalized report
        -> scope/ownership review
        -> explicit pentest authorization and safety policy
        -> approved test plan
        -> isolated execution workers
        -> separate findings/evidence/audit trail
```

Do not turn endpoint scan evidence directly into exploitation commands. Pentesting needs its own
customer authorization, target allowlist, validity window, rate/safety limits, credentials policy,
human approvals, evidence retention, and emergency stop. This separation lets the scanner remain a
read-only evidence collector while future modules evolve independently.

## Test the implementation

All commands below assume Windows PowerShell in the repository root and explicit authorization to
scan the current device.

### A. Install development dependencies

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

### B. Native-only current-device test

```powershell
$scan = .\.venv\Scripts\endpoint-scanner.exe local-scan `
  --authorized `
  --scan-type QUICK | ConvertFrom-Json

$report = Get-Content -Raw $scan.report | ConvertFrom-Json
$report.status
$report.collectors
$report.software | Select-Object -First 10
$report.updates | Select-Object -First 10
$report.listening_ports | Select-Object -First 10
$report.findings
$report.risk
```

Use `--scan-type FULL` for broader native selection. A report may be `PARTIAL` when an expected
optional source is unavailable. Check `metadata.observed_inventory_sections`,
`metadata.unobserved_inventory_sections`, and `collectors` before judging coverage.

### C. Build the standalone Windows executable when needed

```powershell
.\.venv\Scripts\python.exe -m pip install -r .\requirements-build.lock
.\.venv\Scripts\python.exe -m PyInstaller `
  --clean `
  --noconfirm `
  --distpath .\dist\endpoint `
  --workpath .\build\endpoint `
  .\packaging\endpoint\endpoint-scanner.spec

.\dist\endpoint\endpoint-scanner.exe --help
```

This creates a self-contained scanner/Python executable. It is not the full signed installer with
osquery and service enrollment; use the managed package builders for that release artifact.

### D. Start the local cloud

```powershell
.\scripts\cloud\Initialize-CloudEnvironment.ps1
.\scripts\cloud\Start-Cloud.ps1 -Build
docker compose --env-file .\cloud\.env.local -f .\docker-compose.cloud.yml ps
```

The initializer refuses to overwrite an existing environment file unless explicitly forced. Keep
`cloud/.env.local` private.

Do not continue until `docker compose ... ps` shows PostgreSQL, API, worker, and dashboard in the
expected healthy/running state. Record the runtime result in the target environment; successful
source tests do not prove container or advisory-feed operation.

### E. Synthetic transport/cloud-analysis test

```powershell
.\scripts\cloud\Test-CloudE2E.ps1
```

Expected output is JSON containing endpoint/scan IDs, a report status, `fixture_only: true`, and
`live_asset_scanned: false`. The endpoint evidence is synthetic; tool analysis is real unless the
environment was deliberately placed in fixture mode.

### F. Real endpoint-to-cloud test

```powershell
.\scripts\cloud\Test-EndpointAgentE2E.ps1 `
  -Authorized `
  -ScanType QUICK
```

Expected output includes endpoint/scan IDs, endpoint/cloud statuses, vulnerability count, and the
path to `final-cloud-report.json`. This test really scans the computer on which the script runs.

If the PyInstaller executable is not present, use the development entry point:

```powershell
.\scripts\cloud\Test-EndpointAgentE2E.ps1 `
  -Authorized `
  -ScanType QUICK `
  -ScannerExecutable ".venv\Scripts\endpoint-scanner.exe"
```

If a developer-installed osquery is available, explicitly include it:

```powershell
.\scripts\cloud\Test-EndpointAgentE2E.ps1 `
  -Authorized `
  -ScanType FULL `
  -OsqueryExecutable "C:\Program Files\osquery\osqueryi.exe"
```

### G. View the report and stop the stack

Open `http://127.0.0.1:8081` and enter `CLOUD_ADMIN_TOKEN` from `cloud/.env.local`. The local
operator dashboard can download the developer portable EXE, issue a one-time enrollment grant,
start an authorized scan for an online endpoint, poll progress, present the completed assessment,
and download canonical JSON/PDF. It keeps the development token only in that browser tab's session
storage; this is not production IAM.

```powershell
.\scripts\cloud\Stop-Cloud.ps1
```

Named PostgreSQL and tool-cache volumes remain. Do not add Docker’s volume-removal flag unless you
explicitly intend to delete local test history and caches.

### H. Automated verification

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe app cloud_service
.\.venv\Scripts\python.exe -m pytest `
  --cov=app `
  --cov-report=term-missing `
  --cov-fail-under=75
```

Live external-tool tests may skip when their optional executable is not installed on the test
machine. Cloud container E2E tests are the appropriate place to validate the bundled cloud tools.
Passing the Python suite does not substitute for steps D through G. Record the successful E2E output
from the target environment before approving a release.

## Code map and recommended reading order

| Order | Code | What it explains |
| --- | --- | --- |
| 1 | [`app/cli.py`](../app/cli.py) | Commands, enrollment, `agent --once`, service loop construction |
| 2 | [`app/core/config.py`](../app/core/config.py) and [`app/config_loader.py`](../app/config_loader.py) | Protected configuration, limits, TLS, privacy, tool paths |
| 3 | [`app/models/jobs.py`](../app/models/jobs.py) | Authorization and job invariants |
| 4 | [`app/collectors/`](../app/collectors/) | Windows/Linux/macOS native evidence collection |
| 5 | [`app/tools/osquery/`](../app/tools/osquery/) | Approved query registry and bounded execution |
| 6 | [`app/orchestrator/collector_pipeline.py`](../app/orchestrator/collector_pipeline.py) | Scan-type routing, collector isolation, cloud offload behavior |
| 7 | [`app/normalization/`](../app/normalization/) and [`app/models/inventory.py`](../app/models/inventory.py) | Stable typed endpoint schema |
| 8 | [`app/policies/`](../app/policies/) and [`app/analyzers/`](../app/analyzers/) | Findings, baselines, health/risk calculation |
| 9 | [`app/sbom/cyclonedx.py`](../app/sbom/cyclonedx.py) | CycloneDX and package-URL generation |
| 10 | [`app/orchestrator/scanner.py`](../app/orchestrator/scanner.py) | Transactional scan lifecycle and evidence envelope |
| 11 | [`app/storage/`](../app/storage/) and [`app/transport/`](../app/transport/) | SQLite snapshots/outbox, retries, HTTPS, full-resync recovery |
| 12 | [`app/enrollment/`](../app/enrollment/) | Endpoint credential issuance/storage/rotation client logic |
| 13 | [`cloud_service/app.py`](../cloud_service/app.py) | API authentication, routes, ingestion limits |
| 14 | [`cloud_service/repository.py`](../cloud_service/repository.py), [`cloud_service/postgres.py`](../cloud_service/postgres.py), and [`cloud_service/sql/`](../cloud_service/sql/) | Durable jobs, inventory reconstruction, tasks, audit, PostgreSQL implementation |
| 15 | [`cloud_service/worker.py`](../cloud_service/worker.py) and [`cloud_service/analysis.py`](../cloud_service/analysis.py) | OSV/dep-scan leases, retry/dead-letter, merge, final report |
| 16 | [`docker-compose.cloud.yml`](../docker-compose.cloud.yml) and [`cloud/Dockerfile`](../cloud/Dockerfile) | Local cloud topology and container controls |
| 17 | [`scripts/cloud/`](../scripts/cloud/) | Repeatable local initialization and E2E validation |
| 18 | [`packaging/endpoint/`](../packaging/endpoint/) | Windows/Debian/macOS managed package builders |
| 19 | [`dashboard/`](../dashboard/) | Local developer download, enrollment grant, scan control, report views, and JSON/PDF; not production IAM |

## Honest production-release gaps

The core end-to-end behavior is implemented and testable, but every release still needs a recorded
Compose and real-endpoint E2E result in its target environment. These are external or
organization-specific requirements, not things the scanner can safely guess:

- approved osquery/WinSW vendor bytes, licenses, checksums, and redistribution decisions;
- Authenticode/timestamping, Apple Developer ID/notarization/stapling, Debian repository signing,
  container signing, release SBOM/provenance, and secure signing-key custody;
- an integrated and qualified headless service-safe keyring/vault/TPM-backed credential design for
  Linux/macOS; the current builders do not make those service installs deployable by themselves;
- production TLS ingress, URL/CA/proxy policy, OIDC/IAM/RBAC, WAF/rate limits, short-lived
  single-use enrollment grants, bootstrap-token expiry/replay/revocation, and endpoint-credential
  administrative revocation;
- managed PostgreSQL HA/backups/PITR, secrets manager/KMS, restricted tool egress/cache refresh,
  logs/metrics/traces, audit export, alerting, disaster recovery, and load/capacity qualification;
- bounded cursor pagination for large fleet/scan listings, plus evidence retention/deletion/
  legal-hold policy and object storage or partitioning for long-term/high-volume evidence;
- MDM/SCCM/Jamf/apt deployment, least-privilege collection permissions, upgrade/rollback/uninstall,
  privacy/retention/legal-hold approval, and clean-machine tests for every OS/architecture;
- production product-dashboard identity/session integration and approved package-distribution UX;
- a separately authorized pentest execution service if the organization chooses to add one.

Calling the architecture “enterprise-ready” should mean these controls have been completed and
approved in the target organization—not only that the source code compiles or that a runbook
exists. A successful Docker E2E is necessary validation, but it is not by itself production
certification.

## A 60-second explanation for another person

“In the target production workflow, we install one organization-signed agent on each approved
endpoint. That agent contains the scanner runtime and osquery, so users do not install scanner
dependencies. It polls our cloud over outbound HTTPS and runs only an explicitly authorized, fixed
scan. Native collectors read OS, hardware, software,
process, service, user, network, listener, posture, patch, and persistence evidence. The agent
normalizes everything, records gaps, evaluates policy/risk, builds an SBOM, saves locally, and
uploads reliably. In the cloud, PostgreSQL owns jobs and task leases. OSV and dep-scan workers
analyze the SBOM, then a normalizer creates one tenant-bound JSON report containing endpoint
evidence, vulnerabilities, completeness, and provenance. Our main authenticated platform controls
downloads and scans and displays that report. Amass and any future pentesting remain separate,
explicitly authorized services.”
