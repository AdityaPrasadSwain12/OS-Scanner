# Operations guide

> **Current-state notice:** This guide covers detailed endpoint operations plus the implemented
> cloud reference stack. Start with
> [Enterprise end-to-end workflow](END_TO_END_ENTERPRISE_WORKFLOW.md) for the canonical topology,
> serial test commands, integration boundary, and current production gaps.

This guide is for the team packaging, deploying, and operating the endpoint agent. Replace all
sample paths, identities, domains, policy references, certificate authorities, retention periods,
and limits with approved organization values.

## Production ownership

Assign named owners for:

- cloud API authorization, tenancy, idempotency, snapshot application, and credential issuance;
- scanner package, Python dependencies, platform compatibility, and any enabled optional tools or
  SCAP content;
- endpoint service identities and least-privilege read grants;
- policy and local baseline review/change approval;
- certificate/CA lifecycle and secret/keyring availability;
- database/report backup, retention, legal hold, deletion, and recovery;
- logs, metrics integration, alerting, SIEM export, and outbox dead-letter response.

The repository provides the endpoint implementation, tenant-bound cloud API, PostgreSQL schema,
durable OSV/dep-scan worker, canonical JSON/PDF generation, Docker Compose reference deployment,
local operator dashboard, service templates, and offline managed-package builders. The dashboard
supports artifact download, one-time enrollment grants, authorized scan control, status polling,
report presentation, and JSON/PDF downloads. It does not provide already signed/notarized
installers, approved vendor binary redistribution, enterprise OIDC/IAM, production TLS ingress, a
managed HA database, Prometheus/OpenTelemetry server, backup scheduler, or an enterprise records
system. Its shared local token and portable EXE are development adapters, not production IAM or a
signed managed installer.

## Recommended filesystem layout

Keep code/tools/config/state separate and writable by the smallest possible principals.

Linux:

```text
/opt/endpoint-scanner/bin/         read-only self-contained scanner runtime
/opt/endpoint-scanner/tools/       read-only bundled osquery
/etc/endpoint-scanner/config.yaml  root-owned 0600/0640 configuration
/etc/endpoint-scanner/policies/    root-owned reviewed policy documents
/usr/share/xml/scap/...            approved read-only SCAP content
/var/lib/endpoint-scanner/         service-owned 0700 database and reports
```

macOS:

```text
/Library/Application Support/EndpointScanner/bin/        read-only scanner runtime
/Library/Application Support/EndpointScanner/tools/      read-only bundled osquery
/Library/Application Support/EndpointScanner/config.yaml protected configuration
/Library/Application Support/EndpointScanner/policies/   reviewed policies
/Library/Application Support/EndpointScanner/state/      service-owned state
/Library/Logs/EndpointScanner/                            service logs
```

Windows:

```text
C:\Program Files\Endpoint Scanner\         read-only scanner, osquery, wrapper, helpers
C:\ProgramData\EndpointScanner\config.yaml protected configuration
C:\ProgramData\EndpointScanner\policies\   reviewed policies
C:\ProgramData\EndpointScanner\state\      service-owned database/reports/credential file
```

Do not grant the service account write access to its executable, optional tool binaries, policies,
SCAP content, service definition, shell startup locations, or configuration. Some posture checks
need privileged read access. Grant specific rights only; when deliberately withheld, accept the
resulting `PARTIAL`/`FAILED` collector evidence rather than running everything as administrator.

## Install and qualify the scanner

1. Build the scanner executable and native package on a reviewed native runner for each target OS
   and architecture. PyInstaller is not a cross-compiler.
2. Supply the approved, license-reviewed osquery binary and (on Windows) WinSW as offline release
   inputs. Pin their sizes and SHA-256 values in the release-controlled input manifest. The package
   builders verify but never download them.
3. Run the matching builder under `packaging/endpoint/`. It stages the scanner with its Python
   runtime, osquery, managed configuration, service integration, and enrollment helper as one
   Windows installer, Debian package, or macOS package.
4. Keep `cloud.offload_vulnerability_analysis: true`. OSV-Scanner and OWASP dep-scan run in the
   managed cloud worker container and are not installed on endpoints. OpenSCAP/SCAP content remains
   an optional approved Linux endpoint capability. Amass is a separate client/platform component
   and is not part of this package or the central OS scan workflow.
5. Run `endpoint-scanner health` as the final service identity and execute one authorized
   endpoint-to-cloud canary on every qualified OS/architecture.
6. Run fixture tests plus live compatibility, upgrade, rollback, offline/outbox, and permission
   tests on controlled representative images.
7. Generate and verify artifact/content manifests. The repository helpers validate file sets,
   paths, sizes, and digests; they do not establish a cryptographic publisher identity.
8. Authenticode-sign/timestamp Windows artifacts, sign the Debian repository/release metadata, and
   sign/notarize/staple macOS artifacts through the organization's protected release process.

For developer-native scanning, installing the wheel or standalone scanner executable is sufficient
for the built-in OS collectors. That convenience mode is not the full managed service package.
Endpoint users should receive the managed package and must not separately install Python, osquery,
OSV-Scanner, dep-scan, Docker, or Amass.

Do not silently replace an approved optional-tool version. Tool table/schema/CLI changes can turn a
successful command into incomplete evidence. Qualify upgrades with healthy, empty, malformed,
permission-denied, oversized, and timeout cases.

## Configure

Copy [the example](../config/scanner.example.yaml) to a protected location. Important deployment
decisions are summarized below.

| Section | Operational decision |
| --- | --- |
| `runtime` | Maximum total scan/subprocess time, concurrency, output bytes, inventory records, and policy operations. |
| `retention` | Scan/report/succeeded-outbox age, count/batch limits, legal holds, scanner bytes, and free-space reserve. |
| `policies` | Local trusted policy path, cloud sync, symlink decision, parser size/rule/depth bounds. |
| `cloud` | HTTPS origin/base path, cloud-analysis offload, route map, CA, connect/read limits, request/response size, retries, credential env-var name. Loopback HTTP is development/test only. |
| `discovery` | Separate Amass compatibility-path kill switch, protected DNS roots, passive mode, concurrency/QPS, duration, and asset cap; disabled for the central OS workflow. |
| `scheduling` | Startup/periodic behavior, jitter, type/timeout, protected OSV sources, local scope/reference. |
| `tools` | Managed osquery path/subset, optional OpenSCAP content, and compatibility-only local OSV/dep-scan/Amass paths. |
| `analysis` | Opt-in allowlists, required agents/services, OS catalog, administrator limit, approved posture, stale threshold. |
| `risk` | Severity penalties, weights, acknowledgement factor, age saturation, and score bands. |
| `privacy` | Non-relaxable collection/redaction controls. |

Configuration parsing fails on unknown keys. Validate a candidate through `health` in staging
before deployment. Optional tool fields are empty in the example and core endpoint scanning does
not depend on them.

The complete setting-name map is:

```text
scanner_version, schema_version, environment, data_directory, log_level

runtime:
  subprocess_timeout_seconds, scan_timeout_seconds, max_concurrency,
  max_tool_output_bytes, max_inventory_records, max_policy_operations

retention:
  retention_days, report_retention_days, succeeded_upload_retention_days,
  max_completed_scans, max_report_files, maintenance_batch_size,
  max_local_storage_bytes, minimum_free_disk_bytes, legal_hold_scan_ids

policies:
  directory, cloud_sync_enabled, max_file_bytes, max_rules,
  max_expression_depth, allow_symlinks

cloud:
  base_url, offload_vulnerability_analysis, allow_insecure_loopback_http,
  tls_verify, ca_bundle, connect_timeout_seconds, read_timeout_seconds,
  max_response_bytes, max_request_bytes, max_retries, credential_env_var, routes

cloud.routes:
  enrollment_path, credential_rotation_path_template, scan_submit_path,
  scan_status_path, scan_lookup_path_template, next_scan_path_template,
  policies_path, heartbeat_path, attack_surface_jobs_path, scan_rejections_path

privacy:
  redact_logs, redact_command_lines, transmit_process_command_lines,
  collect_passwords, collect_password_hashes, collect_private_keys,
  collect_browser_secrets, collect_clipboard, collect_document_contents,
  collect_screenshots

discovery:
  enabled, passive_only, authorized_domains, max_dns_concurrency,
  max_dns_queries_per_second, max_discovered_assets, timeout_seconds

scheduling:
  enabled, startup_scan, periodic_interval_seconds, jitter_ratio, scan_type,
  timeout_seconds, approved_sources, authorization_scope_id,
  authorization_reference

tools:
  osquery_executable, enabled_osquery_queries, osv_scanner_executable,
  depscan_executable,
  approved_dependency_roots, openscap_executable, approved_scap_content_roots,
  default_scap_content, default_scap_profile, amass_executable

analysis:
  enforce_administrator_allowlist, enforce_port_allowlist,
  enforce_service_allowlist, enforce_persistence_allowlist,
  enforce_browser_extension_allowlist, enforce_os_support_catalog,
  approved_administrator_accounts, allowed_listening_ports,
  approved_service_names, approved_persistence_names,
  approved_browser_extension_ids, required_security_agent_names,
  required_security_service_names, supported_os_releases,
  approved_security_posture, maximum_administrator_accounts,
  stale_scan_after_days

risk:
  severity_penalties, exploitability_weight, asset_criticality_weight,
  exposure_weight, compliance_impact_weight, age_weight,
  age_saturation_days, acknowledged_multiplier, healthy_minimum,
  low_minimum, medium_minimum, high_minimum
```

Pydantic bounds and cross-field rules in `app/core/config.py` are authoritative. In particular,
`tls_verify` cannot be false and prohibited privacy flags cannot be true.

### Cloud paths

`cloud.base_url` may include an API gateway prefix. Every route under `cloud.routes` is locally
configurable. Template routes must keep exactly their documented placeholder. For example:

```yaml
cloud:
  base_url: https://security.example.com/endpoint-control
  routes:
    next_scan_path_template: /v2/agents/{endpoint_id}/next-scan
    scan_submit_path: /v2/agent-results
```

The wire paths become `/endpoint-control/v2/...`. Settings reject origins/routes with credentials,
queries, fragments, traversal, backslashes, control characters, unknown placeholders, or missing
required placeholders.

Production and staging origins must use HTTPS with certificate/hostname verification. The
`allow_insecure_loopback_http` flag is accepted only in `development`/`test`, only for exact
loopback hosts, and only when explicitly true; it exists for the local Docker E2E script and must
not be copied into a production package.

### Local baselines

Allowlist enforcement is opt-in and cannot be enabled with an empty list. Start in observe-only
mode, measure actual inventory, approve the desired set, then enable enforcement. Keep these
concepts separate:

- `approved_security_posture` is the approved configuration baseline and drives
  `configuration_drift`;
- previous snapshots drive delta synchronization and scan age, not approval;
- policy YAML converts normalized facts into findings;
- risk settings determine prioritization, not collection.

Exact OS lifecycle support requires protected entries such as `LINUX:24.04` or
`WINDOWS:10.0.26100`; the scanner does not fetch a vendor lifecycle feed.

## Operate the cloud reference stack

The implemented Compose topology contains PostgreSQL, the FastAPI control plane, a worker image
with OSV-Scanner and OWASP dep-scan, and a local operator dashboard. PostgreSQL owns endpoint
credentials, tenant-bound jobs/uploads, reconstructed inventory, idempotency, analysis leases,
reports, and audit. It is operational state, not a CVE database. Redis is not required.

For an authorized local test from the repository root:

```powershell
.\scripts\cloud\Initialize-CloudEnvironment.ps1
.\scripts\cloud\Start-Cloud.ps1 -Build
docker compose --env-file .\cloud\.env.local -f .\docker-compose.cloud.yml ps
.\scripts\cloud\Test-CloudE2E.ps1
.\scripts\cloud\Test-EndpointAgentE2E.ps1 -Authorized -ScanType QUICK
```

The last command scans the computer on which it runs, uploads normalized evidence/SBOM, waits for
the two cloud tools, and saves the final JSON report under the ignored local E2E state directory.
Use it only on a device you are authorized to assess. The synthetic cloud test does not scan the
host. For detailed expectations and report inspection, use the canonical workflow linked above.

The dashboard at `http://127.0.0.1:8081` is for local verification and keeps the supplied admin
token only in tab session storage. It can download the developer portable EXE, issue one-time
enrollment grants, create authorized scans, poll progress, present the assessment, and download
canonical JSON/PDF. It is not a replacement for platform login, RBAC, a tenant-scoped
backend-for-frontend, or signed managed-package delivery.

Stop the local containers without deleting PostgreSQL/tool-cache volumes:

```powershell
.\scripts\cloud\Stop-Cloud.ps1
```

For production, place replicated API instances behind verified TLS ingress; run multiple leased
workers; use managed HA PostgreSQL with backups/PITR; put tokens, pepper, and database credentials
in a secrets manager; restrict tool egress; export audit/metrics/logs; sign images; and perform load,
recovery, and tenant-isolation tests. Compose is a single-host reference, not an HA topology.

## Enrollment and credentials

### Enroll as the runtime principal

The protected credential belongs to the service identity. Enroll as that identity or use a
deployment-approved secret injection. Otherwise the service may not read what an interactive
administrator stored.

Linux, from a root shell through the approved privileged-access workflow:

```bash
read -r -s SCANNER_ENROLLMENT_TOKEN && export SCANNER_ENROLLMENT_TOKEN
/usr/sbin/endpoint-scanner-enroll
unset SCANNER_ENROLLMENT_TOKEN
```

On macOS use the same protected token pattern with
`/usr/local/sbin/endpoint-scanner-enroll`.

Windows, in elevated PowerShell:

```powershell
$env:SCANNER_ENROLLMENT_TOKEN = '<temporary-value>'
& "$env:ProgramFiles\Endpoint Scanner\Enroll-And-Start.ps1"
Remove-Item Env:\SCANNER_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
```

The package helpers transfer the token through protected short-lived state so enrollment executes
as the service identity, then enable/start the previously disabled service. The temporary token is
an authorization header only and is not saved. Enrollment persists the returned endpoint identity
in SQLite after saving the credential.

### Credential stores

- Windows uses a DPAPI-protected atomic file bound to the Windows security principal. Back up or
  move it only with a documented DPAPI/service-identity recovery design.
- Linux/macOS use the runtime account's native Python `keyring` backend. Null, fail, plaintext, and
  zero-priority backends are rejected. A headless service must have a non-interactive Secret
  Service/KWallet/Keychain-equivalent session available before startup.
- A bearer token injected through the environment variable named by
  `cloud.credential_env_var` is the explicit fallback. Protect the service environment file/secret
  channel and let the external secret manager rotate it.

The agent checks a stored credential every iteration and rotates within 24 hours of expiry. It
requires the current credential to be unexpired and accepts only the same endpoint with a strictly
higher generation. Manual rotation remains available:

```bash
endpoint-scanner rotate-credential --config /etc/endpoint-scanner/config.yaml \
  --endpoint-id endpoint-123
```

Alert before the rotation margin, on repeated 401/403, and on rotation failures. Re-enroll after
expiry or server-side revocation.

## Service deployment

For production package construction, follow the
[managed-package guide](../packaging/endpoint/README.md) and its verified-input contract.
[deployment/README.md](../deployment/README.md) contains lower-level service templates that remain
useful for review or custom deployments; using a template alone is not equivalent to building the
managed package.

### systemd

The provided unit runs as `endpoint-scanner`, uses `NoNewPrivileges`, private temporary/devices,
read-only system/home protections, a `0077` umask, and only
`/var/lib/endpoint-scanner` as writable state. Install the tmpfiles entry and unit, then:

```bash
systemd-tmpfiles --create /etc/tmpfiles.d/endpoint-scanner.conf
systemctl daemon-reload
systemctl enable --now endpoint-scanner.service
systemctl status endpoint-scanner.service
```

Validate that hardening does not hide required approved tool/content paths. Add narrowly scoped
`ReadOnlyPaths`, device, or capability exceptions only after testing and review.

### launchd

The template uses a non-login `_endpointscanner` account and fixed application/log paths. Create the
account/group, state/log directories, protected keyring access, and permissions before loading the
LaunchDaemon. Customize the bundle label and paths, then sign/notarize the package externally.

### Windows service

The managed Windows builder verifies and packages the approved WinSW executable, scanner runtime,
osquery, descriptor, configuration, ACL helper, and enrollment helper. It installs the service as
`LocalService` but leaves it stopped until enrollment succeeds as that same identity. If checks
need more read access, use a dedicated managed service account rather than `LocalSystem`; grant
`Log on as a service` and only required ACL/WMI/registry rights.

The lower-level templates alone do not install WinSW, create users, register permissions, or sign
anything. The managed builders also intentionally emit unsigned artifacts; signing remains a
protected release-pipeline operation.

## Scheduling behavior

There are five trigger concepts:

- `CLOUD`: one authenticated job returned by the configured next-job route;
- `MANUAL`: an administrator invokes `scan --job`;
- `STARTUP`: one protected local job when agent scheduling starts;
- `PERIODIC`: protected interval plus or minus configured jitter;
- `POLICY`: one coalesced `COMPLIANCE` job after active cloud policy identity changes or SIGHUP.

`scheduling.enabled` controls startup/periodic scans. Cloud policy sync alone still creates a
policy-trigger scheduler so activation can request compliance even when periodic scheduling is off.
Local jobs bind the enrolled endpoint ID, protected scope/reference, a short validity/deadline, and
the current policy version. A scheduled `VULNERABILITY` scan requires `approved_sources`, and every
source must remain under a configured dependency root.

The agent prioritizes a cloud job when one is returned; local startup, then policy, then periodic is
the fallback order. It runs one scan at a time in the process. Fleet jitter reduces simultaneous
polls/scans but does not replace cloud capacity planning.

## Policy operations

### Local policy

The default wheel contains `enterprise-default.yaml`. A configured path may be one file or a
directory merged by the loader. Protect it from service writes. Health startup validates schema,
rule uniqueness, expressions, references, bounds, and checksum before scans.

### Cloud assignment

With `policies.cloud_sync_enabled`, the authenticated policies route returns a complete assignment.
The scanner validates every document and checksum before one atomic installation. New membership
revokes omitted cloud versions from job resolution. It retains cached unassigned rows as provenance
but does not register them for future jobs. Restart revalidates active assigned documents before
use.

An active ID/version change records `POLICY_ACTIVATED` with assignment ID, prior/new identity,
checksum, and rule count, then requests one policy scan. Invalid content records a restart-stable
fingerprint/reason and leaves the prior policy active.

Policy rollback should be an approved assignment that reactivates an immutable prior document or a
new reviewed version. Reusing the same policy ID/version with different content is an idempotency
conflict, not a rollback mechanism.

## Manual operations

Validate and execute one job:

```bash
endpoint-scanner validate-job --job /secure/jobs/job.json
endpoint-scanner scan --config /etc/endpoint-scanner/config.yaml \
  --job /secure/jobs/job.json
```

Inspect health:

```bash
endpoint-scanner health --config /etc/endpoint-scanner/config.yaml
```

Attempt a bounded queue drain:

```bash
endpoint-scanner upload --config /etc/endpoint-scanner/config.yaml \
  --endpoint-id endpoint-123 --limit 10
```

The report path printed by `scan` uses the actual collision-resistant file name:

```text
<sanitized-scan-id-prefix>--<sha256-of-original-scan-id>.json
```

Do not edit SQLite or queue payloads manually. Use supported APIs, a controlled copy, and a tested
runbook.

## Storage, backup, and retention

SQLite is at `<data_directory>/scanner.sqlite3` with WAL and shared-memory companions while open.
Reports are under `<data_directory>/reports`. Use the SQLite backup API or stop the service cleanly;
do not copy only the live main database while ignoring WAL.

The storage API includes a consistent online `backup()` primitive but the CLI does not expose a
backup command. Integrate it through reviewed operations code, validate a restore, encrypt backups,
and manage their retention separately from live storage.

Maintenance runs before each new scan and in bounded batches:

- succeeded uploads older than `succeeded_upload_retention_days` may be removed;
- completed/failed scans beyond `retention_days` or `max_completed_scans` may be removed only if
  safely delivered and not protected;
- reports beyond `report_retention_days` or `max_report_files` may be removed;
- legal-hold scan IDs, each endpoint's latest snapshot, and scans/reports associated with pending,
  in-flight, or dead queue items are protected;
- child snapshots are rebased to full when an old predecessor is removed;
- audit rows and endpoint identities are retained by built-in maintenance.

After pruning, admission fails if database+WAL+SHM+reports exceed `max_local_storage_bytes` or
filesystem free space is below `minimum_free_disk_bytes`. This protects a reserve but does not cap
logs, backups, or external tools outside scanner-owned measurement.

Legal holds are configured by exact scan ID and directly protect local scan records/reports. Manage
the list through an audited protected configuration process, export evidence centrally, test count
limits, and coordinate release with records/legal owners. The built-in hold does not freeze
succeeded outbox rows, logs, backups, or an external SIEM.

## Differential delivery and dead letters

The queue stores exact bytes, payload hash, request ID, idempotency key, attempt count, lease, next
attempt, error, and causal links. In-request HTTPS retry and cross-iteration outbox retry are
separate. The worker calculates a lease long enough for every configured connect/read/backoff
attempt and claims one item immediately before send.

Endpoint results/status are ordered per endpoint. A delta rejected with 409/412 is superseded by
one full snapshot from local content-addressed storage. Downstream messages wait for that full
replacement. If the full snapshot is unavailable or the recovery itself conflicts, the row becomes
dead according to bounded retry rules.

Monitor at minimum:

- pending/in-flight/dead counts and oldest pending age;
- retry rate by HTTP/transport class;
- 401/403 and credential rotation failures;
- 409/412 and full-resync success/failure;
- database/report bytes and free-space reserve;
- scan/collector duration and status;
- policy rejection/cache rejection/activation;
- audit-chain verification and database integrity.

Never directly edit or discard a dead result. Preserve evidence, diagnose and correct the cause,
then use the upload ID from the structured `upload_failed` event for an explicit audited repair:

```powershell
.\dist\endpoint\endpoint-scanner.exe requeue-upload `
  --config "$env:ProgramData\EndpointScanner\config.yaml" `
  --upload-id 42 `
  --actor "security-operator@example.com" `
  --reason "Approved incident INC-42 after API repair" `
  --max-attempts 8

.\dist\endpoint\endpoint-scanner.exe upload `
  --config "$env:ProgramData\EndpointScanner\config.yaml" `
  --endpoint-id endpoint-123
```

`requeue-upload` accepts only an unresolved `DEAD` row, preserves its exact payload,
idempotency/causal links, resets its bounded retry budget, and appends a hash-chained local audit
event. Descendants remain blocked until that predecessor actually succeeds; this is a repair, not
an ordering bypass. A superseded delta must be repaired through its replacement upload.

## Logs, metrics, and audit

Application logs are JSON lines. Scan loggers bind scan ID, endpoint ID, scanner version, scope ID,
status, duration, finding count, and queue size. Sensitive keys, bearer-like values, and command-line
patterns are redacted and line/control characters are sanitized. Avoid debug logs on production
inventory unless the privacy owner approves them.

Metrics are emitted through an abstraction (`Noop`, `InMemory`, or callback sink). A deployment must
connect the callback to its telemetry system. This repository does not listen on a metrics port.

Audit events include job rejection/start/complete/failure, policy activation/rejection/cache
rejection, retention, and other lifecycle actions with IDs, subjects, scope, outcomes, versions,
checksums, and sanitized details. Verify the local hash chain and export/anchor it because local
administrator compromise can replace the whole database.

## Upgrade and rollback

1. Drain or measure the outbox; do not require it to be empty if the outage is being handled.
2. Create and verify a consistent encrypted database backup and preserve required reports/audit.
3. Stage the new scanner, policy, Python dependency set, external tools, and SCAP content together.
4. Verify manifest/signatures through the organization's trust process.
5. Run lint/type/tests, live compatibility, `health`, database migration, and one authorized canary
   scan on each platform.
6. Roll out gradually while watching visibility, duration, queue, storage, and finding deltas.

Migrations are forward-only and checksum verified. Do not start older code against a database whose
migrations it does not know. Binary rollback after a schema upgrade requires restoring a consistent
pre-upgrade backup or using a release explicitly compatible with the newer schema. Never use a
destructive SQLite downgrade.

## Troubleshooting

| Symptom | Likely cause | Safe action |
| --- | --- | --- |
| `health` cannot open database | permissions, corruption, newer/changed migration | stop concurrent writers, verify owner/path, preserve files, run controlled integrity/restore; do not delete first |
| `StorageCapacityError` before scan | byte ceiling or free-space reserve | inspect queue/legal holds/reports, export evidence, restore delivery, expand approved storage, or change reviewed limits |
| osquery `SKIPPED` | binary is not installed/configured or scan did not select it | acceptable for developer native-only mode; for a managed package, verify the verified osquery payload and protected absolute path |
| osquery `UNAVAILABLE` | an explicitly configured optional path cannot run | verify the protected path and permissions, or remove the configuration if the adapter is not enabled |
| many osquery query failures | installed table/schema incompatibility | inspect per-query status, compare qualified version, update adapter/tool only through release testing |
| `PARTIAL` with empty current list | contributor failed/unobserved | inspect collector status and completeness; do not interpret as authoritative removal |
| OpenSCAP unavailable | non-Linux host, missing content/profile/root, permissions | expect `SKIPPED` off Linux; validate approved content path/profile and service read rights on Linux |
| endpoint OSV/dep-scan is `SKIPPED` with cloud location | `offload_vulnerability_analysis` is enabled | expected managed behavior; inspect cloud tool state and final report instead of installing tools on the endpoint |
| cloud OSV/dep-scan degraded | tool timeout/output/advisory-cache/network failure or task exhausted retries | inspect worker/task logs and health, preserve the terminal degraded result, repair tool/cache/egress, and submit a new authorized scan if re-analysis is required |
| Amass rejected | separate discovery flow is disabled, unauthorized, excluded, or incompatible | handle it in the separately authorized discovery component; never widen scope or install it on endpoints as a workaround |
| cloud TLS failure | untrusted/expired certificate, hostname/clock/CA problem | repair certificate, DNS, time, or protected CA bundle; never disable verification |
| repeated 401/403 | expired/revoked/wrong-principal credential | inspect rotation logs/store ownership; rotate if unexpired or re-enroll as runtime identity |
| policy sync rejected | schema/checksum/identity/rule error | keep current policy, inspect server-side original by logged fingerprint, publish a corrected complete assignment |
| delta receives 409/412 | cloud previous hash differs | allow automatic one-generation full resync; investigate repeated recovery conflicts/server atomicity |
| outbox `DEAD` grows | permanent 4xx, request too large, exhausted outage, missing full snapshot | preserve payload, fix API/config/size cause, use the approved audited `requeue-upload` command for the logged unresolved upload ID; never edit SQLite directly |
| service starts but local scan never runs | scheduling disabled, startup false, interval not due, cloud job wins priority | inspect scheduling config and agent logs; do not run a second unmanaged overlapping scheduler |
| Linux/macOS keyring error | no secure backend/session for service account | provision a secure non-interactive backend or approved environment secret fallback |
| Windows credential unreadable | enrollment and service used different DPAPI principals | re-enroll under the service identity or use approved managed secret injection |

## Incident handling

If scanner compromise or credential exposure is suspected:

1. isolate the endpoint according to the incident plan without destroying local evidence;
2. revoke the endpoint credential and pending authorization server-side;
3. preserve database, WAL/SHM, reports, service logs, package/tool hashes, configuration, and audit
   chain with documented custody;
4. compare artifacts with externally signed release records;
5. rotate/re-enroll only after trust is restored;
6. review cloud idempotency/result history for unauthorized jobs or uploads;
7. restore from a verified image/package and re-establish baselines;
8. document any visibility gap; do not convert it into a healthy conclusion.

The scanner assesses and reports. Remediation actions belong to separately authorized change or
incident-response systems.
