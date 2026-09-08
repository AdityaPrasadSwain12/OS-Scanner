# Enterprise Endpoint Security Scanner

This repository implements authorized Windows, Linux, and macOS collector code plus a
PostgreSQL-backed cloud analysis stack. The endpoint agent reads live operating-system evidence,
normalizes it, evaluates policy, creates a CycloneDX SBOM, and uploads through a durable outbox.
Cloud workers run OSV-Scanner and OWASP dep-scan against that SBOM and assemble one canonical
assessment. The operator dashboard can start an authorized scan and download that assessment as
JSON or PDF. A standalone Windows executable is available for development testing;
organization-signed managed installers are release artifacts that still require the inputs and
controls listed below.

The endpoint does **not** need Docker, OSV-Scanner, dep-scan, or a separate Python installation.
The current portable EXE embeds the scanner and Python runtime and uses native collectors. A future
approved managed package also supplies osquery as a signed, verified release input. OSV-Scanner and
dep-scan remain in the Docker/cloud worker; Amass remains outside this workflow.

## Implemented architecture

```text
Browser operator dashboard
   | authenticated download, enrollment grant, scan command, reports
   v
Cloud API ---- PostgreSQL durable state <---- analysis worker replicas
   |                    |                         | OSV-Scanner
   |                    |                         | OWASP dep-scan
   |                    +---- canonical assessment+
   |
   | outbound polling and authenticated evidence/SBOM upload
   ^
Endpoint agent
   | native read-only collectors
   | optional osquery enrichment in a future managed package
   | endpoint normalization, policy, risk, SBOM
   +---- local SQLite report/outbox for offline recovery
```

The cloud reference deployment includes the API, PostgreSQL, worker, and a local operator
dashboard. It supports the development workflow, but its static bearer-token login is not a
replacement for production OIDC, tenant RBAC, session controls, and audit integration.

Managed endpoint configurations disable local startup/periodic scheduling. The platform creates an
authorized cloud job and the agent polls for it. Local scheduling exists only as an explicitly
enabled protected configuration option; it is not the managed-service default.

| Component | Runs where | Separate endpoint installation? |
| --- | --- | --- |
| Scanner, embedded Python, native collectors | Endpoint | No; included in the managed package |
| osquery | Endpoint | No; included in the managed package release input |
| OSV-Scanner and OWASP dep-scan | Cloud worker | No |
| PostgreSQL durable job/evidence store | Cloud | No |
| Docker | Cloud host or developer workstation | No |
| OpenSCAP/content | Optional Linux endpoint extension | Only when that optional capability is enabled |
| Amass | Separate client/platform discovery component | Excluded from this workflow |

## PowerShell quick start

Run these commands from the repository root. Use only a computer you own or are explicitly
authorized to scan.

### 1. Prepare the source-development environment (optional for the portable EXE)

Python 3.12+ is required for source tests. The dashboard-to-portable-EXE workflow does not require
a separate endpoint Python installation. Docker Desktop with Compose v2 is required for the local
cloud stack.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

### 2. Test native collection on this computer

This test needs no cloud and no external security tool:

```powershell
$scan = .\.venv\Scripts\endpoint-scanner.exe local-scan `
  --authorized `
  --scan-type QUICK | ConvertFrom-Json

$scan
Get-Content -Raw $scan.report
```

The JSON file under `data/reports/` contains the live point-in-time evidence, collector status,
completeness gaps, policy findings, and risk result. `PARTIAL` is valid when an optional collector
such as osquery is unavailable; it must not be presented as complete coverage.

The standalone PyInstaller executable can run the same test without the development Python
environment:

```powershell
$scan = .\dist\endpoint\endpoint-scanner.exe local-scan `
  --authorized `
  --scan-type QUICK | ConvertFrom-Json
Get-Content -Raw $scan.report
```

### 3. Start the local cloud stack

```powershell
if (-not (Test-Path -LiteralPath .\cloud\.env.local -PathType Leaf)) {
  .\scripts\cloud\Initialize-CloudEnvironment.ps1
}
.\scripts\cloud\Start-Cloud.ps1 -Build
docker compose --env-file .\cloud\.env.local -f .\docker-compose.cloud.yml ps
Invoke-RestMethod http://127.0.0.1:8080/readyz
```

The API is at `http://127.0.0.1:8080` and the dashboard is at
`http://127.0.0.1:8081`. Loopback HTTP is a development-only exception; production endpoints
require verified HTTPS. Do not run initialization again with `-Force` after enrolling devices,
because replacing local tokens and the credential pepper invalidates the existing development
trust state.

### 4. Connect, download, enroll, and scan through the UI

Load the administrator token into a PowerShell variable without printing it, put it on the
clipboard only long enough to paste it into the dashboard, and open the UI:

```powershell
$adminLine = Get-Content -LiteralPath .\cloud\.env.local |
  Where-Object { $_ -like 'CLOUD_ADMIN_TOKEN=*' } |
  Select-Object -First 1
$adminToken = $adminLine.Split('=', 2)[1]
Set-Clipboard -Value $adminToken
Start-Process 'http://127.0.0.1:8081'
```

In the browser, paste the token and select **Connect**. Download the Windows EXE and create a
15-minute one-time Windows enrollment grant. Select **Copy setup command** first and run it in
elevated PowerShell; when its hidden token prompt appears, return to the dashboard, select
**Copy token**, paste it, and press Enter. The current downloadable EXE is a developer portable
artifact: it does not install a Windows service or contain osquery. The UI does not currently
publish Linux or macOS packages.

Follow [Local dashboard, agent, and report workflow](docs/UI_LOCAL_WORKFLOW.md) to create the
loopback endpoint configuration, verify the downloaded file, enroll it, and run the continuous
agent. Once the endpoint is online, select **Start scan**, choose `QUICK` or `FULL`, supply an
authorization reference, confirm authorization, and submit. Keep the agent terminal running.

The dashboard polls active jobs, renders the completed assessment, and exposes **Download JSON**
and **Download PDF**. Both authenticated downloads are derived from the canonical assessment; the
PDF records the source JSON SHA-256. A `PARTIAL` result is not a failed transport—it means one or
more required evidence sections or tools were not fully observed.

The canonical JSON preserves UTF-8 text. The current dependency-free PDF body font is limited to
Windows-1252 and fails closed for other scripts instead of changing evidence to `?`; see
[PDF Unicode support](docs/PDF_UNICODE_SUPPORT.md) for the reviewed production extension path.

### 5. Optional automated end-to-end checks

The synthetic cloud test exercises the transport and real cloud analyzer path without scanning the
workstation:

```powershell
.\scripts\cloud\Test-CloudE2E.ps1
```

The real-endpoint harness performs enrollment, job creation, one agent collection cycle, upload,
analysis polling, and JSON retrieval:

```powershell
.\scripts\cloud\Test-EndpointAgentE2E.ps1 -Authorized -ScanType FULL
```

OSV-Scanner and dep-scan execute in the worker by default. The first dep-scan analysis can take
longer while its advisory cache initializes. To add osquery enrichment to this developer-only
harness, explicitly pass a separately approved executable with `-OsqueryExecutable`; ordinary
end users should wait for the signed managed package rather than install it themselves.

### 6. Stop without deleting local data

```powershell
.\scripts\cloud\Stop-Cloud.ps1
Remove-Variable adminToken, adminLine -ErrorAction SilentlyContinue
Set-Clipboard -Value ([string]::Empty)
```

The stop script preserves the PostgreSQL and analysis-cache volumes. To inspect service logs before
stopping:

```powershell
docker compose --env-file .\cloud\.env.local -f .\docker-compose.cloud.yml logs --tail 200 api worker dashboard
```

For the exact UI workflow, API verification commands, evidence boundaries, and production
integration checklist, use [docs/UI_LOCAL_WORKFLOW.md](docs/UI_LOCAL_WORKFLOW.md).

The automated Python checks, the standalone endpoint scan, and a Docker runtime E2E prove different
layers. Record each result separately; a passing unit suite is not evidence that Docker, advisory
feeds, or a real endpoint completed successfully.

## Managed endpoint packages

Production-oriented, unsigned builder scaffolding exists for:

- Windows x86-64 Inno Setup `.exe` with WinSW, scanner runtime, and osquery;
- Debian amd64/arm64 `.deb` with systemd, scanner runtime, and osquery;
- macOS arm64/x86-64 `.pkg` with launchd, scanner runtime, and osquery.

They are designed to verify pre-approved offline inputs, generate content hashes, install the
service stopped, and start it only after successful enrollment under the service identity. The
repository does not supply the approved osquery/WinSW binaries, licenses, signing identities, or
completed signed installers. Build and qualify each package on its native operating system; these
builders do not download or silently trust vendor binaries. See
[managed endpoint packaging](packaging/endpoint/README.md).

The current `dist/endpoint/endpoint-scanner.exe` is a working standalone scanner executable, not a
signed organization installer: it does not by itself install the service, bundled osquery, or
perform managed enrollment. A browser can download it but cannot silently install it, grant
administrator rights, or start a local service. Exact managed-package size depends on the approved
osquery/WinSW artifacts; inspect the artifact actually being released:

```powershell
Get-Item .\dist\endpoint\endpoint-scanner.exe | Select-Object FullName, Length
Get-FileHash .\dist\endpoint\endpoint-scanner.exe -Algorithm SHA256
```

## Production status

The repository provides a functional reference implementation with enterprise-oriented trust,
durability, isolation, completeness, and scaling boundaries. It is not an organization-approved
production release until the organization supplies and validates:

- code-signed/notarized endpoint packages and signed container images with SBOM/provenance;
- approved osquery/WinSW inputs, licenses, native clean-machine qualification, and rollback;
- a qualified non-interactive credential store for dedicated Linux/macOS service accounts; the
  builders do not currently provide or qualify a headless keyring backend;
- TLS ingress with certificate/CA/proxy policy, real OIDC/IAM and tenant RBAC, and managed session,
  token, device-credential revocation, and audit lifecycles; local static admin/bootstrap tokens are
  development references only;
- managed HA PostgreSQL, backups/PITR, secrets/KMS, restricted worker egress, metrics/logs/traces,
  audit export, monitoring, alerting, capacity tests, and disaster-recovery exercises;
- keyset cursors beyond the implemented bounded offset pages for large endpoint and scan lists,
  plus approved evidence retention, deletion, legal-hold, and privacy policies;
- object storage and/or database partitioning when evidence volume exceeds the bounded JSONB
  reference design;
- MDM/SCCM/Jamf deployment, least-privilege read permissions, proxy/CA policy, upgrade, rollback,
  and uninstall qualification.

The local API derives the scan audit subject from the authenticated admin token fingerprint and
does not trust the caller-supplied `authorized_by` label. Production IAM must preserve that property
while deriving the subject from a verified user or service identity.

The PostgreSQL database is a control/evidence database, not a scanner-owned CVE database. OSV and
dep-scan use their configured upstream advisory sources and caches and may return CVE, GHSA, or
other provider IDs. The report preserves those source identifiers without inventing them.

Local listening sockets are not proof of external exposure. Because this workflow has no remote
network scanner, the canonical report sets remote reachability to `NOT_TESTED`; firewall, ACL, NAT,
VPN, and proxy paths remain outside this evidence.

Read [End-to-end enterprise workflow](docs/END_TO_END_ENTERPRISE_WORKFLOW.md) for the full lifecycle,
data model, code map, main-platform integration, failure behavior, scaling model, and test matrix.
Cloud deployment details are in [cloud/README.md](cloud/README.md).
