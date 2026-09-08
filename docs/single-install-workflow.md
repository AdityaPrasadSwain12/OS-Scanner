# Single-install endpoint workflow

This page answers the installation question directly. The complete implemented lifecycle and test
commands are in [`END_TO_END_ENTERPRISE_WORKFLOW.md`](END_TO_END_ENTERPRISE_WORKFLOW.md).

## Direct answer

Yes, one endpoint scanner package must run on every computer whose local OS details you want to
collect. No, a normal endpoint user does not separately install Python, osquery, Docker,
OSV-Scanner, or OWASP dep-scan when the approved managed package is used.

The reason an endpoint agent is required is simple: a cloud website cannot safely see another
computer's installed software, local processes, services, users, encryption state, pending patches,
or listening ports. The agent reads those facts locally and sends normalized evidence outward to
the cloud. It opens no inbound endpoint port.

```text
Cloud platform                              Customer endpoint
--------------                              -----------------
login + tenant/RBAC                         install managed package once
choose endpoint/type/policy                         |
        |                                            | enroll device identity
        +---- authorized job over HTTPS ------------>|
                                                     | native + osquery scan
                                                     | normalize/policy/risk/SBOM
        |<---- durable evidence/status upload --------+
        |
PostgreSQL -> OSV/dep-scan workers -> canonical assessment -> dashboard + JSON/PDF
```

## What is installed and where

| Component | Location | Who installs/manages it? |
| --- | --- | --- |
| Scanner executable and embedded Python runtime | Every endpoint | Included in the managed package |
| Native collectors | Every endpoint | Scanner code; uses fixed OS-provided commands/APIs |
| osquery | Every endpoint in the baseline managed release | Included/configured by the package; no user action |
| SQLite state/outbox | Endpoint | Created automatically by the agent |
| OpenSCAP plus approved SCAP content | Optional supported Linux endpoints | Enterprise packaging/configuration only when formal compliance is enabled |
| OSV-Scanner | Cloud worker | Cloud image/operator |
| OWASP dep-scan | Cloud worker | Cloud image/operator |
| PostgreSQL | Cloud | Cloud operator/managed database service |
| Docker/container runtime | Cloud or developer workstation | Cloud/platform operator, never the endpoint user |
| Amass | Separate discovery component | Excluded from this OS-scanner workflow |

The managed-package builders are implemented under [`packaging/endpoint/`](../packaging/endpoint/):

- Windows x86-64 Inno Setup `.exe` with WinSW, scanner runtime, and osquery;
- Debian amd64/arm64 `.deb` with systemd, scanner runtime, and osquery;
- macOS arm64/x86-64 `.pkg` with launchd, scanner runtime, and osquery.

They verify offline pinned vendor inputs, install the service stopped, and start it only after
successful enrollment under the service identity. Organization signing/notarization, approved
osquery/WinSW bytes and licenses, and native clean-machine qualification remain release-pipeline
responsibilities. The standalone `dist/endpoint/endpoint-scanner.exe` is usable, but it is not the
complete signed service installer.

## What the endpoint collects

Native Windows, Linux, and macOS collectors use bounded read-only operations to normalize:

- OS identity, version/build/kernel, architecture, hostname, boot time, uptime, and timezone;
- CPU, memory, disks, GPU/firmware/device details, encryption and TPM where exposed;
- installed applications/packages and their available version/package-manager identity;
- processes, services, local users/groups, and security agents where supported;
- interfaces, IP/MAC, gateway/DNS/DHCP details, VPN state, and listening TCP/UDP ports;
- firewall, antivirus/MAC controls, encryption, Secure Boot, UAC, RDP/SSH, audit, screen lock,
  automatic-update, reboot, and other platform posture;
- installed/pending updates and security-relevant persistence metadata;
- supported browser-extension and enrichment tables through the bundled osquery registry.

The agent evaluates a versioned policy, produces findings/remediation and a health-oriented risk
score, creates a CycloneDX SBOM from normalized software, and records collector/completeness status.
Permissions still matter: an unavailable section remains explicitly unobserved rather than
becoming a false empty or healthy result.

The scanner does not collect passwords, password hashes, private keys, browser secrets, clipboard,
screenshots, email, or document contents. It does not install patches or automatically remediate.

## What the cloud adds

The endpoint upload contains a summarized result, full/delta/unchanged inventory synchronization,
and a checksummed CycloneDX SBOM. PostgreSQL reconstructs the tenant endpoint's full inventory and
creates durable analysis tasks. OSV-Scanner and dep-scan workers analyze only the uploaded SBOM; they
never access the endpoint filesystem.

The canonical assessment contains endpoint findings/risk/collector provenance, reconstructed
inventory, SBOM identity, merged cloud vulnerabilities, per-tool status, summary, completeness, and
provenance. Upstream tools may report CVE, GHSA, CVSS, or other provider evidence. The scanner owns
no CVE database and does not invent missing identifiers. Authenticated routes deliver the same
canonical assessment as deterministic JSON and a paginated PDF correlated to its source JSON hash.

## Test the current computer without cloud

Use only a computer you own or are authorized to assess. In Windows PowerShell from the repository
root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"

$scan = .\.venv\Scripts\endpoint-scanner.exe local-scan `
  --authorized `
  --scan-type QUICK | ConvertFrom-Json

$scan
Get-Content -Raw $scan.report
```

Use `FULL` after the quick canary. With defaults, the SQLite database is
`data/scanner.sqlite3` and JSON reports are under `data/reports/`. Inspect:

1. `collectors` for success/failure/timeout/skip state;
2. `metadata.observed_inventory_sections` and `unobserved_inventory_sections`;
3. OS/hardware/software/process/service/user/network/listener evidence;
4. `security`, `updates`, browser extensions, and `persistence`;
5. `findings` and `risk`.

`PARTIAL` can be a valid useful result when an optional or permission-limited source is missing. It
must not be presented as complete coverage.

## Test the complete endpoint-to-cloud path

Docker Desktop with Compose is required on the development/cloud computer, not on the endpoint in
production:

```powershell
.\scripts\cloud\Initialize-CloudEnvironment.ps1
.\scripts\cloud\Start-Cloud.ps1 -Build
.\scripts\cloud\Test-CloudE2E.ps1

.\scripts\cloud\Test-EndpointAgentE2E.ps1 `
  -Authorized `
  -ScanType QUICK
```

The synthetic test validates transport, PostgreSQL, real cloud tools by default, and report
assembly without scanning the workstation. The endpoint-agent test really scans the current
computer, runs one `agent --once` cycle, uploads it, waits for both tools, and writes
`cloud/.e2e-agent/<run-id>/final-cloud-report.json`.

The local operator dashboard is at `http://127.0.0.1:8081`; use the generated local admin token
from ignored `cloud/.env.local`. It can download the developer portable Windows EXE, issue a
one-time enrollment grant, start an authorized scan for an online endpoint, poll status, present
the result, and download canonical JSON/PDF. The shared token and portable EXE are not production
IAM or a signed managed installer. Local plain HTTP is an explicit loopback development exception;
production endpoints require verified HTTPS.

Stop without deleting database/tool-cache volumes:

```powershell
.\scripts\cloud\Stop-Cloud.ps1
```

## Test on another authorized system

For a development-only native test, copy the target-native standalone executable and run
`local-scan --authorized`. For the real enterprise workflow:

1. Build the managed package on a native release runner using approved osquery/WinSW inputs.
2. Sign/notarize it and publish its immutable digest/provenance through the enterprise channel.
3. Install the correct Windows `.exe`, Debian `.deb`, or macOS `.pkg` as an administrator.
4. Set the final HTTPS API/CA configuration; never embed a token in the installer/config file.
5. Supply a short-lived enrollment token to the protected enrollment helper.
6. Confirm the service runs under its dedicated identity and polls outbound.
7. Create one explicitly authorized platform job and verify canonical JSON/PDF and completeness.

Do not copy another device's SQLite directory or credential. Every device enrolls separately and
receives its own tenant-bound endpoint identity.

See [`packaging/endpoint/README.md`](../packaging/endpoint/README.md) for exact native build and
enrollment commands.

## Main-platform integration

The implemented reference API supports endpoint enrollment/rotation/polling/upload and tenant
platform routes to list endpoints, create/list scans, and retrieve the final report. The product
platform should:

1. authenticate the user and enforce tenant RBAC server-side;
2. authorize and host the correct signed installer download;
3. issue a short-lived enrollment token;
4. submit bounded scan intent with the operator and customer authorization reference;
5. retrieve/render canonical JSON/PDF through its backend, not a shared browser admin token;
6. preserve completeness, collector states, tool provenance, and tenant audit identity.

The local token map, operator dashboard, and portable artifact are development adapters.
Production needs OIDC/IAM, secrets/KMS, TLS ingress, managed HA PostgreSQL/backups, worker egress
controls, monitoring, signed images/packages, MDM/SCCM/Jamf/apt deployment, least-privilege
permissions, and rollback testing.

## Where optional capabilities fit

- **osquery:** bundled in the baseline managed package and configured by absolute protected path;
  it enriches native inventory but never accepts remote SQL.
- **OpenSCAP:** optional Linux endpoint capability requiring approved binary, content, and profile.
- **OSV-Scanner and dep-scan:** cloud workers in the central workflow; endpoints upload the SBOM.
- **Amass:** separate authorized-domain discovery component, not an OS collector or endpoint-package
  dependency.

This placement gives the user one simple endpoint install while letting the organization update and
scale advisory analysis centrally.
