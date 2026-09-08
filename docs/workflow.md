# End-to-end workflow

> **Current-state notice:** This file retains detailed endpoint execution semantics. The canonical
> endpoint-plus-cloud workflow, test commands, and code map are in
> [Enterprise end-to-end workflow](END_TO_END_ENTERPRISE_WORKFLOW.md). That document takes
> precedence over any remaining compatibility-mode detail here.

This document describes the code path as implemented. The scanner can execute a manual job file,
one cloud-polled job, or one job synthesized from protected local scheduling settings. All three
paths converge on the same strict `ScanJob` and `ScannerOrchestrator` lifecycle.

## Production sequence

```text
Authenticated platform        Cloud API/PostgreSQL             Endpoint agent
          |                            |                              |
          | authorize tenant job       |                              |
          +--------------------------->|                              |
          |                            |<---- outbound job poll -------+
          |                            |----- bounded job ------------>|
          |                            |                     validate authorization
          |                            |                     native + bundled osquery
          |                            |                     normalize/policy/risk/SBOM
          |                            |                     SQLite/report/outbox
          |                            |<---- idempotent upload --------+
          |                            |                              |
          |                    reconstruct inventory                  |
          |                    lease OSV + dep-scan tasks              |
          |                    merge normalized results                |
          |<----------- canonical assessment                         |
```

The repository implements the endpoint, tenant-bound cloud API, PostgreSQL persistence/task leases,
OSV/dep-scan workers, canonical JSON/PDF generation, local Compose deployment, managed package
builders, and a local operator dashboard. The dashboard provides developer artifact download,
one-time enrollment grants, authorized scan control, status/report views, and JSON/PDF downloads.
Its shared local token and portable EXE are development adapters, not production IAM or a signed
managed installer. The product platform must still supply its real human authentication,
RBAC/approval, tenant sessions, and approved release distribution. The builders require approved
osquery/WinSW vendor inputs and emit unsigned artifacts; signing, notarization, redistribution
approval, and clean-platform qualification remain external release steps.

## Agent iteration order

`endpoint-scanner agent` runs one cooperative loop. There is no overlapping scan within that
process. Each iteration performs these operations in order:

1. **Credential maintenance.** If a protected stored credential exists and expires within 24
   hours, the agent requests a rotation. A failure is logged and the current token may still be
   usable. An environment-injected credential has no local rotation lifecycle.
2. **Outbox attempt.** The worker reconciles and sends a bounded number of already queued messages.
   Network failure changes queue state; it does not delete payloads.
3. **Policy synchronization.** When `policies.cloud_sync_enabled` is true, the agent fetches and
   validates the current assignment. An active policy identity change requests one coalesced policy
   scan. Invalid assignments are rejected without replacing the current policy.
4. **Cloud job poll.** If still online, it requests at most one job for the bound endpoint. HTTP 204
   or an empty body means no job.
5. **Local trigger fallback.** Only when no cloud job was returned, the scheduler offers the first
   due trigger in priority order: startup, policy-change, then periodic.
6. **Single execution.** At most one chosen job enters the orchestrator.
7. **Immediate delivery attempt.** Newly committed result/status messages get an immediate bounded
   outbox opportunity.
8. **Jittered wait.** The next poll delay is the configured agent poll interval plus or minus its
   jitter ratio.

A bounded cloud operation can delay a local trigger, but it cannot wait forever: HTTP connect/read
and retry limits apply. If policy/job calls are offline, a due protected local job can still run and
its output stays in SQLite until delivery succeeds.

Service managers supervise process restarts. SIGTERM/SIGINT request a cooperative stop. On systems
with SIGHUP, that signal requests one coalesced policy scan.

## Job parsing and rejection

Local files are bounded regular JSON files. Cloud responses are also bounded by the transport. The
job loader rejects:

- invalid UTF-8 or JSON, duplicate keys, non-finite numbers, excessive depth/node count, or size;
- unknown model fields, malformed identifiers, invalid timestamps, or unsupported parameters;
- a false authorization flag, missing reference, or invalid authorization window;
- endpoint work whose endpoint is absent from the allowlist;
- attack-surface work whose target is excluded/outside the domain allowlist;
- `ATTACK_SURFACE` with an endpoint or endpoint work with an external target;
- `ON_DEMAND` without collector identifiers;
- a job for a different endpoint than the polling agent.

Malformed cloud documents are not echoed into logs or audit. The durable rejection contains a
bounded reason, safe scan ID if recoverable, endpoint ID, and SHA-256 of the original body. Its
idempotency key is derived from that digest, including across restarts.

Immediately before work, `validate_for_execution()` checks `authorized`, `valid_from`,
`expires_at`, `not_before`, and `deadline` again. Policy resolution is also fail closed: an explicit
ID/version must be in the current validated local registry.

## Total execution budget

The job budget is the minimum of `job.timeout_seconds`, `runtime.scan_timeout_seconds`, and the
remaining absolute job deadline. The orchestrator establishes a monotonic deadline and checks it
through collection, external-tool version probes, policy evaluation, reporting, and the final
SQLite/outbox transaction. Policy evaluation also has `runtime.max_policy_operations`.

Native commands and external adapters receive the remaining time. osquery tasks that start after
budget exhaustion return timeout status. A timeout while the final transaction is open raises and
rolls the transaction back. This is a wall-clock bound, not a CPU quota; OS service controls and
canary performance limits remain useful defense in depth.

## Scan-type routing

| Scan type | Native categories | osquery | Optional tool stage |
| --- | --- | --- | --- |
| `QUICK` | inventory, posture | optional compatible enrichment | none |
| `FULL` | inventory, posture, patches, persistence | compatible enrichment | optional Linux OpenSCAP; cloud OSV/dep-scan after SBOM upload |
| `COMPLIANCE` | inventory, posture | optional compatible enrichment | optional Linux OpenSCAP |
| `VULNERABILITY` | inventory, patches | compatible enrichment | cloud OSV/dep-scan after SBOM upload |
| `ATTACK_SURFACE` | none | none | separate passive Amass compatibility path, excluded from the central OS workflow |
| `ON_DEMAND` | requested `inventory`, `posture`, `patches`, `persistence` | requested registry IDs | requested `openscap`; vulnerability analysis is marked for cloud execution when offload is enabled |

The installed platform filters registry entries before execution. A requested incompatible or
locally disabled `ON_DEMAND` query fails closed. For regular scan types, a configured
`enabled_osquery_queries` set narrows the normal selection.

## Endpoint collection

### Native platform adapter

The scanner detects Windows, Linux, or macOS and creates one native adapter. This adapter is the
self-contained core scanner: it uses fixed, read-only commands already supplied by the operating
system and does not require a separately installed security tool. Each platform collects OS,
hardware, installed software/packages, processes, services, users/groups where supported, network
interfaces, and listening ports, then adds platform security, patch, and persistence evidence.

- Windows gathers firewall, Defender/antivirus, BitLocker, Secure Boot, TPM, UAC, RDP, update
  policy/state, local security controls/users, installed and pending updates, reboot state, Run
  items, scheduled tasks, and startup-folder metadata where supported.
- Linux gathers enabled firewall state across supported backends, SELinux enforcement, AppArmor
  enforcement profiles, effective SSH indicators, automatic updates, encryption indicators,
  security agents, sudo/password controls, running kernel, available updates, reboot state, systemd
  persistence, and cron metadata where supported.
- macOS gathers firewall, FileVault, SIP, Gatekeeper, automatic updates, remote login, screen
  sharing, hardware security state, lock screen, audit service, update state, and launch persistence
  where supported.

These are observations, not configuration changes. A permission failure is explicit. A false value
is emitted only when a command can support that conclusion; otherwise the field remains `null`.

### Optional osquery registry, batching, and cache

The managed installer includes an approved platform-specific osquery binary and configures its
absolute path. A source/developer or native-only installation may leave it unset; no PATH discovery
implicitly enables it. When configured, the job selects identifiers and the scanner looks up
source-owned SQL. Registry definitions carry
platforms, row limits, category, optional singleton batch columns, and optional cache TTL.

Singleton definitions are grouped into bounded CTE batches. The scanner expects exactly one
combined row, validates every generated alias/count, reconstructs each query's own row set, and
records `batched` metadata. Incompatible batch execution falls back to individual registry queries.
Non-batch queries run under `runtime.max_concurrency` with the remaining deadline.

Selected stable hardware queries use a bounded five-minute in-memory cache. Cache identity contains
query SQL and an executable path/size/mtime fingerprint. Cache hits still produce a normal query
status with zero execution duration and `cache_hit=true` metadata. The cache is lost at process
restart and never stores dynamic process/listener/service evidence.

### Normalization and tri-state completeness

Every successful or permitted partial query has a payload list, including an empty list. A missing,
failed, unavailable, or timed-out query does not. Normalizers use that distinction:

```text
successful payload [records] -> authoritative records
successful payload []        -> authoritative empty section
no successful payload        -> unobserved section
```

For a composite section, all selected contributing queries must be observed before the section is
authoritative. For example, a successful Debian-package query plus a failed RPM-package query does
not authorize the software section to erase earlier RPM facts. The current result exposes detailed
query statuses and observed/unobserved section metadata. Snapshot storage carries forward only
last-known sections that were not freshly observed and labels them in `collection_completeness`.

Native inventory is independently authoritative section by section. A successful native empty
section is authoritative, while a failed native check can still be supplied by successful osquery
enrichment. If malformed rows have to be discarded, that check becomes `PARTIAL` and the affected
section is not authoritative, so it cannot erase last-known good inventory. Native and osquery
models are merged field-wise using source-independent identities for software, processes, services,
users, interfaces, listeners, updates, and persistence. If no explicit osquery executable was
configured, its status is `SKIPPED`; this does not reduce an otherwise successful native scan to
`PARTIAL`. A binary found on `PATH` is not enough to enable it.

## Endpoint and cloud tool workflows

### OpenSCAP

OpenSCAP runs only for Linux when selected. `default_scap_content` must resolve inside an
`approved_scap_content_roots` directory and a local profile must be configured. The adapter writes
results to a secure temporary directory, invokes `oscap xccdf eval`, bounds XML, and parses result,
severity, rule title, evidence, HTTPS references, and remediation/fix text from the approved
content/result artifacts.

For a normal `FULL` scan, missing content/profile is `SKIPPED`; an explicitly requested
`COMPLIANCE` stage that cannot run remains visible as `UNAVAILABLE`. Windows/macOS yield `SKIPPED`.
OpenSCAP failure does not erase native or osquery evidence.

### OSV-Scanner

In the managed workflow, `cloud.offload_vulnerability_analysis` is true. The endpoint does not run
OSV-Scanner or dep-scan and records their endpoint collector status as `SKIPPED` with
`execution_location=cloud`. It instead builds a bounded CycloneDX SBOM from normalized software,
adds package URLs only for recognized ecosystems, hashes the canonical document, and uploads the
SBOM in the authenticated evidence envelope.

An accepted cloud upload creates one durable OSV task and one durable dep-scan task in PostgreSQL.
Workers lease tasks, write only the validated SBOM to a private temporary directory, invoke fixed
tool arguments without a shell, bound output/time, normalize provider evidence, and delete the
temporary directory. Endpoint users do not install OSV-Scanner or dep-scan.

The endpoint adapters remain available for explicitly configured compatibility/local workflows.
There, every source must resolve at or below a protected dependency root. That is not the managed
package default and is not needed for the central end-to-end test.

The project does not maintain its own CVE database. Provider IDs/aliases, affected/fixed versions,
references, known-exploited indicators, CVSS vectors/scores, and severity appear only when OSV or
dep-scan supplies that evidence. No advisory match is not proof that a component is safe.

### Amass

Amass is a separate, explicitly authorized client/platform discovery component. It is not bundled
in the managed endpoint package, not installed by endpoint users, and not run by the central
OSV/dep-scan worker. The existing compatibility adapter remains a separate path:

```text
canonical target
  -> authenticated authorization domain check
  -> protected local authorized_domains check
  -> passive Amass with exact target, rate/concurrency/timeout/exclusions
  -> bounded parse
  -> exact target/subdomain and exclusion filter again
  -> normalized AttackSurfaceAsset records
```

The adapter uses the offline public-suffix snapshot used by `tldextract` for scope reasoning and
does not perform a live suffix-list fetch. It never broadens to a sibling registrable domain and
never starts port scanning or exploitation. The configured asset cap is at most 100,000.

Do not present Amass output as part of the endpoint OS report unless a later platform integration
adds its own authorization, lifecycle, storage, and report-joining contract.

## Baseline analysis

Normalized facts are classified only by protected settings:

- administrator, listener, service, persistence, and browser-extension allowlists are opt-in and
  cannot be enforced empty;
- the exact `FAMILY:version` lifecycle catalog controls `os.supported` only when enabled;
- required security agents must be both observed installed and running;
- required services are checked for presence, enabled state where knowable, and running state;
- maximum administrator count, guest state, and suspicious classification enrich security posture;
- an approved posture object compares only explicitly configured fields.

`security.configuration_drift` refers only to mismatches against that approved posture object. The
previous endpoint snapshot is not an approved baseline. Previous state is used for synchronization,
last-known completeness, and `scan_age_days`/`scan_stale`.

## Policy assignment and evaluation

Local startup loads a bounded policy from the configured file/directory or the package default.
Cloud sync can supply a strict assignment with 1-64 complete policy documents, canonical SHA-256
digests, and one active identity. All documents validate before any change. Installation is atomic:
previous cloud membership is revoked, new immutable documents/provenance are cached, and one policy
is activated. After commit, the in-memory registry contains only the current assignment. Restart
revalidates the cache and excludes unassigned stale cloud versions.

For the selected policy, each enabled platform/scan-type-applicable rule evaluates its bounded
condition tree. Missing telemetry does not satisfy either positive or negative comparisons. A
collector-visibility rule can report missing evidence separately. Evidence fields are redacted and
bounded; collection evidence includes a count and at most 20 matching samples.

Finding identity is stable for `(subject, policy_id, rule_id)`, while `scan_id` identifies the
current occurrence. The earliest stored `first_seen_at` is reused for recurring findings. The
current implementation produces at most one finding per rule and subject, even when several
collection items match; matched-item count/sample remains in evidence. It does not automatically
resolve an earlier finding that no longer matches.

## Risk calculation

The score is health-oriented: `100` is healthiest and findings subtract a penalty. For each active
finding, the engine adds:

```text
severity base
+ base * exploitability_weight * finding.exploitability
+ base * asset_criticality_weight * job asset criticality
+ base * exposure_weight * max(scan exposure, finding exposure)
+ base * compliance_impact_weight * compliance impact
+ base * age_weight * saturated finding age
```

Acknowledged findings first reduce the severity base by the configured multiplier. Resolved and
suppressed findings are excluded. The raw penalty is capped at 100; `score = 100 - risk_penalty`.
Default bands are `HEALTHY >= 85`, `LOW >= 70`, `MEDIUM >= 50`, `HIGH >= 30`, otherwise `CRITICAL`.
The result includes counts and every factor contribution so the score can be explained.

## Local commit and reporting

Before collection, bounded maintenance applies retention and checks disk admission. The final
transaction stores:

- job lifecycle and history;
- complete normalized result and content hash;
- endpoint projection;
- findings and collector projections;
- content-addressed snapshot and section diff;
- scan-result and terminal-status outbox messages;
- completion audit with duration, policy checksum, tool versions, collector states, and report name.

The JSON report is serialized deterministically with non-finite values forbidden, bounded by
`cloud.max_request_bytes`, written through an fsynced temporary file, and atomically replaced with
owner-only permissions where supported. Its collision-resistant filename is
`<readable-prefix>--<sha256(scan_id)>.json`.

The first endpoint snapshot is full. Later snapshots are delta or unchanged. Point-in-time process
inventory is retained in the full local result but excluded from snapshot sync. Volatile endpoint,
posture, compliance, and vulnerability timestamps are removed before comparison.

## Offline and causal delivery

The queue provides at-least-once delivery. Exact payload bytes and idempotency key survive restart.
An item is leased immediately before send; a crashed lease returns to pending until its bounded
attempt limit, then becomes `DEAD`.

An unresolved dead predecessor is never silently skipped. After an operator fixes its root cause,
the protected `requeue-upload` command can reset that one row's bounded retry budget and append a
hash-chained audit event. Its exact payload, idempotency key, and causal links remain unchanged, so
later evidence stays blocked until the repaired predecessor is accepted.

Result and terminal-status messages for an endpoint form one causal stream. A later row cannot be
claimed until its predecessor, or the predecessor's full-resync replacement, succeeds. HTTP 409 or
412 on an ordinary delta creates exactly one replacement from the stored full snapshot. The
replacement has `previous_hash: null`, and subsequent messages wait behind it.

The HTTP client retries only safe methods or requests carrying an idempotency key. It recognizes
408, 425, 429, and selected 5xx responses, honors bounded `Retry-After`, and uses exponential
backoff/jitter. The durable queue provides a second retry layer across iterations/restarts. TLS and
authentication errors are retryable in the outbox so trust-store repair or credential rotation can
recover; certificate verification is never disabled.

Connect timeout and read timeout are distinct. The read timeout is also an absolute timer that
shuts down a slow-drip response, not just a per-byte idle timeout. Response and decompressed gzip
sizes are bounded. Redirects are not followed because the client sends directly with
`http.client.HTTPSConnection`.

## Cloud ingestion, analysis, and final report

The cloud API authenticates the endpoint credential, derives its tenant/endpoint ownership on the
server, validates the evidence envelope and SBOM checksum, and applies inventory synchronization
transactionally. `full` stores the complete snapshot, `delta` applies only against its declared
prior hash, and `unchanged` retains the current view. The final report can therefore include a full
reconstructed snapshot even when the latest endpoint upload was a delta.

PostgreSQL is both persistent control-plane storage and the durable analysis queue. Worker claims
use leases so a crashed worker can be replaced. Transient errors retry with bounded backoff and
jitter; permanent/dead-letter errors become terminal degraded tool results so report creation does
not hang. Redis is not required for correctness.

After both OSV and dep-scan are terminal, the normalizer merges validated package/vulnerability
identities and writes one tenant-bound report with endpoint evidence, reconstructed inventory,
SBOM provenance, cloud vulnerabilities, tool statuses, summary, completeness, and provenance. The
authoritative machine-readable artifact is bounded canonical JSON, with a correlated paginated PDF
for human review. The dashboard under `dashboard/` exercises package download, enrollment, scan
control, status, and report retrieval locally. A production UI should reuse those platform routes
through its authenticated backend rather than expose the local shared admin token in browser code.

## Retention and high-water behavior

Maintenance runs before every new non-duplicate scan. It deletes only bounded batches. It retains:

- every endpoint's latest snapshot;
- scan IDs in `retention.legal_hold_scan_ids`;
- scans and reports referenced by pending, in-flight, or dead outbox work;
- the append-only audit chain and endpoint identities.

It may purge old succeeded queue rows and old/overflow safely delivered scans/reports. When an old
snapshot is removed, a retained child is converted to an initial/full baseline. If scanner-owned
bytes still exceed `max_local_storage_bytes`, or filesystem free space is below
`minimum_free_disk_bytes`, a new scan fails admission rather than consuming the protected reserve.

## Interpreting completion

Collector execution and security outcome are different:

```text
osquery       SUCCESS
native        SUCCESS
OpenSCAP      UNAVAILABLE
endpoint      PARTIAL
cloud OSV     SUCCESS
cloud dep-scan SUCCESS
final report  PARTIAL
```

This means the successful evidence is useful but compliance visibility is incomplete. It does not
mean every finding is uncertain. Conversely, overall `SUCCESS` means every applicable collector
executed; it does not mean the endpoint is secure. Findings and risk answer that separate question.

If the trusted lifecycle fails, the scanner records a sanitized failure state/audit and queues a
deterministic failed terminal status when storage remains usable. Reconciliation on future service
or upload startup repairs missing terminal-status outbox rows after an interrupted failure.
