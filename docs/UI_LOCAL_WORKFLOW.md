# Local dashboard, agent, and report workflow

This runbook is the exact local-development path for an authorized Windows endpoint:

```text
Dashboard -> manifest-verified EXE download -> one-time enrollment grant
          -> endpoint agent polls outbound -> authorized scan job
          -> native endpoint collection and normalization -> evidence + CycloneDX SBOM upload
          -> Docker OSV/dep-scan workers -> canonical assessment -> dashboard + JSON + PDF
```

Use it only on a computer you own or are explicitly authorized to assess.

## What is available now

| Capability | Current local state |
| --- | --- |
| Windows download | Windows x86-64 developer portable EXE |
| Windows service installation | Not provided by the portable EXE |
| Linux/macOS dashboard download | Not yet published |
| Endpoint collection | Native, read-only OS collectors in the endpoint process |
| osquery | Not included in the portable EXE; optional if a developer supplies an approved path |
| OSV-Scanner and OWASP dep-scan | Installed and executed only in the Docker worker |
| Report outputs | Canonical JSON and PDF downloads from authenticated routes |
| Remote network reachability | `NOT_TESTED`; no remote network scanner is in this workflow |

The browser can download a package and request an enrollment grant. It cannot silently install an
EXE, approve UAC, register a service, or give a process access to the operating system. In this
developer workflow, the operator starts the portable agent from an authorized PowerShell session
and keeps that process running. A production release replaces that manual step with an
organization-signed installer deployed by the user or an enterprise tool such as Intune/SCCM.

Tool placement follows what each tool can actually observe. Native collectors and osquery must run
on the endpoint because they query local operating-system state; a future managed package bundles
osquery, so the user does not install it separately. OSV-Scanner and dep-scan can run in cloud
workers because they analyze the uploaded SBOM/package identities rather than the live filesystem.
OpenSCAP remains an optional Linux endpoint extension when approved SCAP content is configured.
Amass is a separate, authorized external-asset discovery component and is not part of this endpoint
assessment flow.

## 1. Prerequisites

Required for this workflow:

- Windows x86-64 for the current endpoint artifact;
- Docker Desktop with the Compose v2 command available;
- PowerShell;
- internet access for the initial image build and advisory/cache updates;
- sufficient Docker resources for PostgreSQL, API, dashboard, and the analysis worker.

Python is not required on the endpoint for the downloaded EXE. Python 3.12+ is needed only for
source development and the Python test suite.

For the broadest Windows inventory, start the endpoint PowerShell session with approved
administrator rights. Without sufficient read permission, the scanner continues where safe and
reports affected sections as degraded or unobserved. Do not bypass endpoint security policy to
obtain elevation.

Open PowerShell in the repository, then run these checks serially:

```powershell
$ProjectRoot = 'C:\path\to\OS-Scanner'
Set-Location -LiteralPath $ProjectRoot
$repo = (Get-Location).Path

docker version
docker compose version

if (-not (Test-Path -LiteralPath .\dist\endpoint\endpoint-scanner.exe -PathType Leaf)) {
  throw 'The developer endpoint executable is missing.'
}
if (-not (Test-Path -LiteralPath .\dist\manifest.json -PathType Leaf)) {
  throw 'The release manifest is missing.'
}
```

If Docker cannot report a server version, start or repair Docker Desktop before continuing.

## 2. Create local secrets once

Generate the ignored local environment file only when it does not already exist:

```powershell
if (-not (Test-Path -LiteralPath .\cloud\.env.local -PathType Leaf)) {
  .\scripts\cloud\Initialize-CloudEnvironment.ps1
}
```

Do not use `-Force` after enrolling an endpoint. Replacing the credential pepper or tokens makes
existing local credentials unusable. The generated values are development secrets; do not commit,
reuse, or deploy them.

## 3. Build and start the local stack

```powershell
.\scripts\cloud\Start-Cloud.ps1 -Build

docker compose `
  --env-file .\cloud\.env.local `
  -f .\docker-compose.cloud.yml `
  ps

$ready = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/readyz' -TimeoutSec 10
$ready
```

Expected addresses:

- dashboard: `http://127.0.0.1:8081`;
- API: `http://127.0.0.1:8080`.

Plain HTTP is accepted only for this explicit loopback development configuration. Never expose
these ports on a non-loopback interface without production TLS, authentication, and network
controls.

## 4. Connect the dashboard without printing its token

Load the admin token into memory and copy it only long enough to paste into the dashboard:

```powershell
$adminLine = Get-Content -LiteralPath .\cloud\.env.local |
  Where-Object { $_ -like 'CLOUD_ADMIN_TOKEN=*' } |
  Select-Object -First 1
if (-not $adminLine) { throw 'CLOUD_ADMIN_TOKEN is missing.' }

$adminToken = $adminLine.Substring('CLOUD_ADMIN_TOKEN='.Length)
Set-Clipboard -Value $adminToken
Start-Process 'http://127.0.0.1:8081'
```

In the browser:

1. Paste the value into **Local administrator token**.
2. Select **Connect**.
3. Return to PowerShell and clear the clipboard:

```powershell
Set-Clipboard -Value ([string]::Empty)
```

The dashboard stores the token in that tab's session storage. Closing the tab clears that browser
session. A clipboard history manager may retain copied values, so this pattern is only a local
developer convenience, not a production authentication design.

## 5. Download and verify the portable Windows EXE

In **Deploy an endpoint scanner**, select **Download EXE**. Save it as
`endpoint-scanner.exe` in the normal Downloads directory. If the browser chose another name, use
that exact path in `$scannerExe` below.

```powershell
$scannerExe = Join-Path $env:USERPROFILE 'Downloads\endpoint-scanner.exe'
if (-not (Test-Path -LiteralPath $scannerExe -PathType Leaf)) {
  throw "Downloaded scanner not found at $scannerExe"
}

$releaseManifest = Get-Content -Raw -LiteralPath .\dist\manifest.json | ConvertFrom-Json
$manifestEntry = $releaseManifest.files |
  Where-Object { $_.path -eq 'endpoint/endpoint-scanner.exe' } |
  Select-Object -First 1
if (-not $manifestEntry) { throw 'The EXE is absent from the release manifest.' }

$actualHash = (Get-FileHash -LiteralPath $scannerExe -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedHash = ([string]$manifestEntry.sha256).ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
  throw 'Downloaded EXE SHA-256 does not match the release manifest. Do not run it.'
}

Get-Item -LiteralPath $scannerExe | Select-Object FullName, Length
$actualHash
```

The API also verifies this manifest hash before serving the file. The local comparison verifies
the bytes that arrived in Downloads. The artifact is not code-signed; do not bypass organizational
application-control or SmartScreen policy to run it.

## 6. Create the endpoint's loopback configuration

The portable EXE does not silently rewrite configuration. Create a separate development state
directory and a minimal JSON configuration:

```powershell
$endpointRunRoot = Join-Path $repo 'data\ui-endpoint'
$endpointState = Join-Path $endpointRunRoot 'state'
$endpointConfig = Join-Path $endpointRunRoot 'scanner.local.json'
New-Item -ItemType Directory -Path $endpointRunRoot -Force | Out-Null

$endpointConfiguration = [ordered]@{
  environment = 'development'
  data_directory = $endpointState
  log_level = 'INFO'
  cloud = [ordered]@{
    base_url = 'http://127.0.0.1:8080'
    allow_insecure_loopback_http = $true
    offload_vulnerability_analysis = $true
    connect_timeout_seconds = 5
    read_timeout_seconds = 30
    max_retries = 5
  }
  scheduling = [ordered]@{
    enabled = $false
    startup_scan = $false
    periodic_interval_seconds = $null
  }
}

[IO.File]::WriteAllText(
  $endpointConfig,
  ($endpointConfiguration | ConvertTo-Json -Depth 20),
  [Text.UTF8Encoding]::new($false)
)

& $scannerExe health --config $endpointConfig
if ($LASTEXITCODE -ne 0) { throw 'Endpoint configuration or local scanner health check failed.' }
```

`offload_vulnerability_analysis` prevents the endpoint from invoking OSV-Scanner or dep-scan.
Those tools remain in Docker. The endpoint still generates the normalized inventory and CycloneDX
SBOM required by the worker.

## 7. Generate and use a one-time enrollment grant

In the dashboard:

1. Select **Windows** under **Enroll this installation**.
2. Optionally enter a device label.
3. Select **Generate one-time token**.
4. Select **Copy setup command** and paste it into an elevated PowerShell window.
5. When PowerShell displays the hidden token prompt, return to the dashboard and select
   **Copy token**. Paste it into the prompt and press Enter. The grant expires after 15 minutes and
   can enroll one endpoint.

That generated command verifies elevation and the published EXE hash, writes the loopback
development configuration, performs a scanner health check, enrolls the endpoint, clears temporary
secret material, and starts the foreground polling agent. Keep that PowerShell window open and
continue at step 9. The manual commands below are the equivalent transparent path for operators
who want to inspect each action separately.

The optional label is retained with the short-lived enrollment grant for control-plane context;
the current endpoint list is keyed and displayed by the hostname reported during enrollment. A
future main-platform identity schema can promote that label to a persistent display name.

For the manual path, exchange the copied grant for an endpoint credential. The token is supplied
via the process environment and is removed even if enrollment fails:

```powershell
$env:SCANNER_ENROLLMENT_TOKEN = Get-Clipboard
try {
  $enrollmentOutput = @(& $scannerExe enroll --config $endpointConfig)
  if ($LASTEXITCODE -ne 0) { throw 'Endpoint enrollment failed.' }
}
finally {
  Remove-Item Env:\SCANNER_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
  Set-Clipboard -Value ([string]::Empty)
}

$enrollment = $enrollmentOutput[-1] | ConvertFrom-Json
$endpointId = [string]$enrollment.endpoint_id
if (-not $endpointId) { throw 'Enrollment did not return an endpoint ID.' }
$enrollment | Select-Object endpoint_id, generation, expires_at
```

The endpoint credential is stored under the configured endpoint state directory. Do not copy that
state directory to another device. Refresh the dashboard and verify that the endpoint appears as
`ONLINE`.

## 8. Keep the endpoint agent running

For the current portable build, use the same authorized PowerShell window and leave this command
running:

```powershell
& $scannerExe agent `
  --config $endpointConfig `
  --endpoint-id $endpointId `
  --poll-interval 5 `
  --jitter 0.10
```

This agent initiates outbound requests to the API. The server does not open an inbound connection
to the endpoint. A production service normally uses a longer managed polling interval and jitter;
five seconds is convenient for a single local test.

If you need more PowerShell commands while the agent runs, open another PowerShell window and set
the repository location again. Stop the developer agent with `Ctrl+C` after the test.

## 9. Start the authorized scan in the UI

In the dashboard:

1. Select **Refresh** until the endpoint is `ONLINE`.
2. Select **Start scan** for that endpoint.
3. Choose `QUICK` for a faster validation or `FULL` for the broadest enabled endpoint collection.
4. Enter a meaningful authorization reference, such as an approved ticket or local test ID.
5. Confirm that the endpoint is in scope and select **Start authorized scan**.

Keep the agent terminal running. The normal state sequence is:

```text
QUEUED -> DISPATCHED -> ANALYZING -> COMPLETE
```

The dashboard refreshes active scans approximately every five seconds. `ANALYZING` can take longer
on the first run while dep-scan initializes its vulnerability data cache. A terminal `FAILED`,
`REJECTED`, or `EXPIRED` state must be investigated; it is not a clean scan.

## 10. Inspect and download the report in the UI

When **Report ready** appears:

1. Open the report.
2. Review the overview, evidence coverage, findings, endpoint inventory, and raw JSON tabs.
3. Select **Download JSON** for the canonical machine-readable assessment.
4. Select **Download PDF** for the paginated human-readable assessment.

The JSON and PDF endpoints require the same tenant-scoped admin authentication as the dashboard.
The PDF contains the SHA-256 of its canonical source JSON so the two artifacts can be correlated.
Canonical JSON retains UTF-8 text. Until the approved embedded-font work described in
[PDF Unicode support](PDF_UNICODE_SUPPORT.md) is completed, the PDF renderer refuses characters
outside Windows-1252 rather than silently corrupting endpoint evidence.

## 11. Verify scan state and artifacts from PowerShell

This is an optional independent check of what the UI is displaying. Run it in another PowerShell
window after starting a scan:

```powershell
$ProjectRoot = 'C:\path\to\OS-Scanner'
Set-Location -LiteralPath $ProjectRoot

$adminLine = Get-Content -LiteralPath .\cloud\.env.local |
  Where-Object { $_ -like 'CLOUD_ADMIN_TOKEN=*' } |
  Select-Object -First 1
$adminToken = $adminLine.Substring('CLOUD_ADMIN_TOKEN='.Length)
$apiHeaders = @{ Authorization = "Bearer $adminToken"; Accept = 'application/json' }

$scanList = Invoke-RestMethod `
  -Uri 'http://127.0.0.1:8080/api/v1/platform/scans?limit=100&offset=0' `
  -Headers $apiHeaders `
  -TimeoutSec 30
$scanRecord = $scanList.items |
  Sort-Object { [DateTimeOffset]$_.created_at } -Descending |
  Select-Object -First 1
if (-not $scanRecord) { throw 'No scan exists.' }
$scanId = [string]$scanRecord.scan_id

$deadline = [DateTimeOffset]::UtcNow.AddMinutes(60)
do {
  $scanState = Invoke-RestMethod `
    -Uri "http://127.0.0.1:8080/api/v1/platform/scans/$scanId" `
    -Headers $apiHeaders `
    -TimeoutSec 30
  [pscustomobject]@{
    scan_id = $scanState.scan_id
    state = $scanState.state
    phase = $scanState.phase
    progress_percent = $scanState.progress_percent
    report_ready = $scanState.report_ready
  }
  if ($scanState.report_ready) { break }
  if ($scanState.state -in @('FAILED', 'REJECTED', 'EXPIRED')) {
    throw "Scan entered terminal state $($scanState.state)."
  }
  if ([DateTimeOffset]::UtcNow -ge $deadline) { throw 'Timed out waiting for the report.' }
  Start-Sleep -Seconds 5
} while ($true)

$artifactDirectory = Join-Path $PWD 'data\downloaded-reports'
New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null
$jsonPath = Join-Path $artifactDirectory "endpoint-security-$scanId.json"
$pdfPath = Join-Path $artifactDirectory "endpoint-security-$scanId.pdf"

$jsonResponse = Invoke-WebRequest `
  -Uri "http://127.0.0.1:8080/api/v1/platform/scans/$scanId/report.json" `
  -Headers $apiHeaders `
  -OutFile $jsonPath `
  -PassThru
$pdfResponse = Invoke-WebRequest `
  -Uri "http://127.0.0.1:8080/api/v1/platform/scans/$scanId/report.pdf" `
  -Headers $apiHeaders `
  -OutFile $pdfPath `
  -PassThru

$jsonHash = (Get-FileHash -LiteralPath $jsonPath -Algorithm SHA256).Hash.ToLowerInvariant()
$pdfHash = (Get-FileHash -LiteralPath $pdfPath -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedJsonHash = ([string]$jsonResponse.Headers['X-Report-SHA256']).ToLowerInvariant()
$sourceJsonHash = ([string]$pdfResponse.Headers['X-Source-JSON-SHA256']).ToLowerInvariant()
if ($jsonHash -ne $expectedJsonHash -or $jsonHash -ne $sourceJsonHash) {
  throw 'JSON integrity or PDF source correlation check failed.'
}

$report = Get-Content -Raw -LiteralPath $jsonPath | ConvertFrom-Json
$report.summary
$report.coverage | Select-Object complete, degraded_sources
$report.coverage.sections |
  Where-Object { $_.state -ne 'OBSERVED' } |
  Select-Object name, scope, state, detail
$report.limitations

[pscustomobject]@{
  json = $jsonPath
  json_sha256 = $jsonHash
  pdf = $pdfPath
  pdf_sha256 = $pdfHash
  pdf_pages = $pdfResponse.Headers['X-PDF-Page-Count']
}

Remove-Variable adminToken, adminLine -ErrorAction SilentlyContinue
```

Do not judge scan depth only by the finding count. Zero findings means no finding matched the
evidence that was successfully observed; it does not mean every section was observed or that the
endpoint has no risk. Read `coverage`, collector/analyzer statuses, provenance, and `limitations`.

## Evidence and normalization model

The endpoint and cloud have different responsibilities:

| Stage | Responsibility |
| --- | --- |
| Native endpoint collectors | Read live OS identity, hardware, software, updates, processes, services, users, interfaces, local listeners, persistence, certificates, and available security posture |
| Endpoint normalization | Convert platform-specific records into strict cross-platform models, deduplicate records, retain collector status, evaluate local policy, and build a CycloneDX SBOM |
| Durable endpoint outbox | Retain scan evidence locally across temporary network failure and retry bounded uploads |
| Cloud API and PostgreSQL | Authenticate the endpoint, enforce tenant/job ownership, store job/evidence/task state, and expose tenant-scoped status/report routes |
| OSV/dep-scan worker | Analyze supplied package identities/SBOM against configured advisory sources; it cannot inspect the endpoint filesystem |
| Canonical assessment builder | Merge endpoint and cloud findings; derive severity/category counts, risk, coverage, limitations, and provenance hashes |
| JSON/PDF serializers | Emit machine-readable and human-readable representations of the canonical assessment |

Actual fields vary by operating system, OS version, installed software, privileges, and collector
availability. The scanner deliberately records a gap rather than fabricating a value.

Coverage states have precise meanings:

- `OBSERVED`: an authoritative source completed for that section; an observed list may legitimately
  contain zero records;
- `PARTIAL`: some evidence exists, but a required source or subsection was degraded;
- `NOT_OBSERVED`: no authoritative observation was produced;
- `NOT_APPLICABLE`: the section does not apply to the endpoint;
- `NOT_TESTED`: the scanner did not perform that class of test.

`coverage.complete` can be true only when every required section is `OBSERVED` and no required
collector/analyzer is degraded. Local listening ports are socket bindings observed on the endpoint.
They do not prove reachability through Windows Firewall, a network firewall, ACL, NAT, VPN, or
proxy, so `summary.remote_reachability` remains `NOT_TESTED` and
`remotely_reachable_port_count` remains null.

Package-vulnerability results are limited by package identity quality. OSV/dep-scan can only match
the package names, ecosystems, versions, PURLs, and SBOM components that the endpoint supplies. An
upstream match may include CVE, GHSA, or another provider identifier; the scanner preserves the
provider's identifiers and does not invent a CVE.

The privacy model excludes password material, password hashes, private keys, browser secrets,
clipboard data, document contents, and screenshots. Process command-line transmission is disabled
by default.

## Code map

| Area | Important files |
| --- | --- |
| Dashboard behavior and presentation | `dashboard/index.html`, `dashboard/app.js`, `dashboard/styles.css`, `dashboard/nginx.conf` |
| Local containers and tool placement | `docker-compose.cloud.yml`, `cloud/Dockerfile` |
| Installer catalog, grants, jobs, and report HTTP routes | `cloud_service/app.py`, `cloud_service/artifacts.py`, `cloud_service/models.py` |
| Durable tenant/job/evidence/task state | `cloud_service/repository.py`, `cloud_service/postgres.py`, `cloud_service/sql/` |
| Cloud OSV/dep-scan execution and report assembly | `cloud_service/worker.py`, `cloud_service/analysis.py`, `cloud_service/reporting.py` |
| Endpoint CLI, polling, scan orchestration, and upload | `app/cli.py`, `app/orchestrator/agent.py`, `app/orchestrator/scanner.py`, `app/transport/` |
| Native platform evidence collection | `app/collectors/windows/`, `app/collectors/linux/`, `app/collectors/macos/` |
| Cross-platform normalization and vulnerability merge | `app/normalization/` |
| CycloneDX generation | `app/sbom/cyclonedx.py` |
| Canonical model and JSON/PDF artifacts | `app/models/assessment.py`, `app/reporting/assessment_json.py`, `app/reporting/pdf_report.py` |
| Future signed endpoint packages | `packaging/endpoint/` |

The boundary is intentional: dashboard input creates a bounded authorization document; it never
becomes an arbitrary endpoint command. The endpoint accepts only registered scan types and
collector names, and cloud analyzers receive uploaded evidence/SBOM rather than endpoint filesystem
access.

## Troubleshooting

### The dashboard cannot connect

```powershell
Invoke-RestMethod -Uri 'http://127.0.0.1:8080/healthz' -TimeoutSec 10
Invoke-RestMethod -Uri 'http://127.0.0.1:8080/readyz' -TimeoutSec 10
docker compose --env-file .\cloud\.env.local -f .\docker-compose.cloud.yml ps
```

Re-copy `CLOUD_ADMIN_TOKEN` if the API is ready but returns 401. Do not paste the endpoint
enrollment token into the administrator field.

### The EXE download is unavailable

```powershell
$expected = (Get-Content -Raw .\dist\manifest.json | ConvertFrom-Json).files |
  Where-Object { $_.path -eq 'endpoint/endpoint-scanner.exe' } |
  Select-Object -ExpandProperty sha256
$actual = (Get-FileHash .\dist\endpoint\endpoint-scanner.exe -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject]@{ expected = $expected; actual = $actual; matches = ($expected -eq $actual) }
```

The catalog intentionally refuses a missing, oversized, wrong-type, symlinked, or hash-mismatched
artifact.

### The endpoint stays offline or a scan stays queued

- confirm the continuous `agent` command is still running;
- confirm its configuration uses `http://127.0.0.1:8080` with the loopback exception enabled;
- confirm enrollment completed and `$endpointId` matches the dashboard endpoint;
- refresh the dashboard after one polling interval;
- inspect API and agent errors without copying tokens into logs.

### Analysis takes a long time or fails

```powershell
docker compose `
  --env-file .\cloud\.env.local `
  -f .\docker-compose.cloud.yml `
  logs --tail 200 worker api
```

The first dep-scan run can populate a large cache. A failed analyzer is surfaced as degraded
coverage; it must not be represented as a clean vulnerability result.

### The report is `PARTIAL`

Inspect `coverage.sections`, `coverage.degraded_sources`, `analysis_tools`, and endpoint collector
statuses in the canonical JSON. With the current portable EXE, osquery is not bundled, so evidence
that depends on that optional enrichment may be absent. Missing privileges or unsupported OS APIs
can also reduce coverage.

## Stop the local environment

Stop the agent first with `Ctrl+C`, then run:

```powershell
.\scripts\cloud\Stop-Cloud.ps1
Remove-Variable adminToken, adminLine -ErrorAction SilentlyContinue
Set-Clipboard -Value ([string]::Empty)
```

The stop script preserves the PostgreSQL database and analysis cache. It does not uninstall the
portable EXE because that file was never installed as a service.

## Main-platform and production integration boundaries

The main platform can replace the local dashboard while retaining these versioned contracts:

- authenticated installer catalog and download;
- short-lived, one-time enrollment-grant issuance after tenant authorization;
- tenant endpoint list and online status;
- authorized, idempotent scan creation and scan-status retrieval;
- tenant-scoped canonical JSON and PDF report downloads.

Keep these responsibilities separate:

```text
Main platform identity/RBAC/audit
        -> scanner control API and durable job state
        -> endpoint outbound poll, collection, normalization, SBOM upload
        -> isolated cloud analyzer workers
        -> canonical report API
        -> platform dashboard/report retention
```

For production, do not expose the shared local admin token to browsers. Map the platform's verified
OIDC/service identity and tenant authorization to the scanner API, preserve idempotency keys and
audit subjects, and issue enrollment grants only after an authorized installer request. Serve
signed immutable packages from controlled object storage or a release service while preserving the
opaque artifact IDs and integrity metadata.

The signed endpoint packages still need approved osquery/WinSW inputs, native packaging on each
supported OS, code signing/notarization, least-privilege service configuration, secure credential
storage, proxy/CA support, upgrade/rollback/uninstall, and clean-machine qualification. The current
portable EXE is not a substitute for that release work.

The cloud deployment still needs production TLS ingress, real IAM/RBAC, device credential
revocation, secrets/KMS, signed images, restricted worker egress, managed HA PostgreSQL with
backup/PITR, approved retention/legal hold, object-storage strategy, observability/alerting,
capacity testing, disaster recovery, and vulnerability-feed governance. Until those controls and
native installers are qualified, describe this repository as a functional local reference—not as
a perfect or certified enterprise product.
