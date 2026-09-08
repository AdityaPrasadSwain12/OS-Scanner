# Architecture and trust boundaries

> **Current-state notice:** This document explains the detailed trust boundaries behind the
> implemented endpoint and cloud components. For the canonical end-to-end deployment, testing
> sequence, and code map, read
> [Enterprise end-to-end workflow](END_TO_END_ENTERPRISE_WORKFLOW.md). If an older endpoint-only
> statement conflicts with that document, the canonical workflow takes precedence.

## Purpose and non-goals

The system has two implemented execution planes. The endpoint agent accepts a narrowly described
job from the authenticated cloud API or creates one from protected local scheduling configuration.
It gathers host facts through reviewed adapters, converts them to a stable schema, evaluates local
policy/risk, commits them to SQLite, builds a CycloneDX SBOM, and delivers an evidence envelope
reliably. The cloud API enforces tenant/endpoint identity, stores jobs and evidence in PostgreSQL,
reconstructs full inventory from full/delta/unchanged uploads, and assigns durable OSV-Scanner and
OWASP dep-scan tasks. Workers merge those results into a canonical assessment used by dashboard,
JSON, and PDF representations.

The control plane implements the technical enrollment, endpoint authentication, tenant binding,
job authorization contract, ingestion, task leasing, and report APIs. A production platform must
still connect those APIs to its own human login, OIDC/IAM, RBAC, approval, and installer-download
flow. This repository includes a local operator dashboard with developer artifact download,
one-time enrollment grants, authorized scan control, status polling, assessment presentation, and
canonical JSON/PDF downloads. Its shared local bearer token is not production IAM, and the current
portable EXE is not a signed managed installer. Managed installer builders exist, but approved
vendor inputs, signing/notarization credentials, and organization-specific release approval remain
external. Exploitation, remediation, and central Amass execution are outside this OS-scanner
workflow.

The architecture is designed around seven invariants:

1. no scan executes without explicit, current authorization;
2. cloud intent cannot widen protected local trust decisions;
3. no remote command, shell, raw SQL, executable, policy code, or arbitrary path is accepted;
4. missing telemetry remains unknown rather than becoming a false secure or empty result;
5. tool failure is isolated and visible;
6. local evidence is committed before dependence on cloud delivery;
7. every result is traceable to job, scope, scanner, schema, policy, tools, and collector status.

## Component map

| Layer | Main code | Responsibility |
| --- | --- | --- |
| Configuration | `app/core/config.py`, `app/config_loader.py` | Validate protected limits, tool/content paths, baselines, schedule, retention, TLS origin, and privacy invariants. |
| Job boundary | `app/models/jobs.py`, `app/orchestrator/job_loader.py` | Parse bounded unique-key JSON and enforce scan-type, target, authorization, and time invariants. |
| Agent | `app/orchestrator/agent.py`, `app/scheduling/` | Credential maintenance, queued delivery, policy sync, cloud polling, local triggers, and single-scan cooperative execution. |
| Orchestrator | `app/orchestrator/scanner.py` | Revalidate, resolve policy, enforce the total deadline, analyze, persist, report, audit, and queue. |
| Collection routing | `app/orchestrator/collector_pipeline.py` | Select native categories, osquery IDs, and optional tools; isolate boundaries; track completeness. |
| Native collection | `app/collectors/windows/`, `linux/`, `macos/` | Self-contained core OS/hardware/software/process/service/user/network/listener inventory plus posture, patch/update, and persistence checks. |
| Managed osquery enrichment | `app/tools/osquery/` | Scanner-owned platform-aware SQL registry, scalar batching, bounded parallel execution, cache, parsing, and status; the managed package supplies the binary. |
| Compliance | `app/tools/openscap/` | Linux XCCDF evaluation of an approved local SCAP content/profile pair. |
| Vulnerability adapters | `app/tools/osv_scanner/`, `app/tools/depscan/` | Fixed, bounded adapters used by cloud workers by default; protected endpoint execution remains compatibility-only. |
| Separate discovery adapter | `app/tools/amass/` | Passive authorized DNS discovery compatibility path, excluded from the central OS workflow. |
| Normalization | `app/normalization/` | Convert validated tool/native records into Pydantic inventory and security artifacts. |
| Baseline analysis | `app/analyzers/posture.py` | Apply opt-in local allowlists, requirements, lifecycle catalog, and approved posture. |
| Policy | `app/policies/` | Load bounded versioned documents; evaluate a non-executable condition tree; create deterministic findings. |
| Risk | `app/analyzers/risk.py` | Produce a configurable health score, risk penalty, counts, and factor breakdown. |
| Persistence | `app/storage/` | Migrations, complete results, projections, snapshots, retention, audit, policy cache, and upload queue. |
| Reporting | `app/reporting/` | Canonical deterministic JSON and paginated PDF artifacts with source-integrity correlation. |
| Transport | `app/transport/` | Verified HTTPS, bounded I/O, authentication abstraction, retries, causal outbox delivery, and full-resync recovery. |
| Enrollment | `app/enrollment/` | Temporary-token exchange, credential validation/storage, expiry, and rotation. |
| Observability | `app/observability/` | Structured redacted logging and replaceable metrics sinks. |
| Cloud API | `cloud_service/app.py`, `cloud_service/security.py` | Enrollment, tenant-bound endpoint/admin authentication, authorized jobs, bounded evidence ingestion, policies, status, and report routes. |
| Cloud state | `cloud_service/postgres.py`, `cloud_service/sql/` | Durable endpoint/job/upload state, inventory reconstruction, idempotency, analysis leases, reports, and audit in PostgreSQL. |
| Cloud analysis | `cloud_service/worker.py`, `cloud_service/analysis.py` | Lease OSV/dep-scan tasks, execute fixed adapters, retry/dead-letter safely, normalize/merge vulnerabilities, and finalize reports. |
| Deployment | `docker-compose.cloud.yml`, `cloud/` | Reference single-host PostgreSQL, API, worker, and dashboard containers with pinned build inputs and runtime hardening. |
| Managed packages | `packaging/endpoint/` | Offline-verified Windows, Debian, and macOS builders for the scanner runtime, osquery, service wrapper/definition, configuration, and enrollment helper. |
| Local operator dashboard | `dashboard/` | Developer artifact download, one-time enrollment grants, authorized scan control, status, assessment views, and JSON/PDF downloads; not enterprise IAM. |

Each external tool is behind a narrow adapter with availability, version, input validation,
execution, parsing, normalization, and health concepts. The managed endpoint package bundles
osquery. With `cloud.offload_vulnerability_analysis: true`, which is the managed-package default,
OSV-Scanner and dep-scan execute only in cloud workers; endpoint users do not install them.
OpenSCAP remains an optional Linux endpoint integration. Amass remains a separately authorized
platform/client component and is excluded from the central endpoint-vulnerability workflow.
Replacing a tool should affect its adapter and normalizer rather than policy, risk, storage, or
transport.

## Data flow

```text
Authenticated platform / admin
             |
       authorized scan job
             v
Cloud API <--- outbound HTTPS poll --- Endpoint agent + bundled osquery
   |                                      |
PostgreSQL                           native/osquery/optional SCAP
   |                                      |
job, identity, audit                  normalization + policy/risk
   |                                      |
   |                               SQLite + local JSON + outbox
   |                                      |
   +<---- evidence + inventory sync + CycloneDX SBOM
   |
inventory reconstruction + durable analysis tasks
   +----------------------+----------------------+
   |                                             |
OSV-Scanner worker                         dep-scan worker
   +----------------------+----------------------+
                          |
             normalized vulnerability merge
                          |
                  canonical assessment
                          |
             platform API / operator dashboard
```

No inbound endpoint listener or cloud filesystem mount is required. Cloud workers analyze the
uploaded SBOM; they do not reach back into the endpoint. PostgreSQL is the durable queue and state
source of truth. The reference Compose topology does not require Redis.

Collection is sequential by major stage so deadline and failure handling remain understandable.
Within osquery, approved singleton queries that declare a safe scalar projection can be composed
into one scanner-generated CTE statement. A batch is bounded by SQL bytes and projected fields.
Any query that cannot be safely batched runs independently, with a configured thread limit. If a
batch is incompatible with the installed osquery version, it falls back to the original controlled
queries; it never accepts remote SQL.

Selected stable hardware queries have a five-minute TTL. Cache keys include the query definition
and an executable fingerprint; the cache is bounded by entry count and bytes. Dynamic process,
service, listener, posture, and similar evidence is not cached.

## Trust boundaries

### 1. Job and authorization boundary

`ScanJob` is strict: unknown fields fail. It binds one scan ID, scan type, policy selector,
authorization record, timeout, optional absolute deadline, and exactly one subject form:

- endpoint scans require an endpoint ID in `allowed_endpoint_ids` and forbid an external target;
- `ATTACK_SURFACE` requires a canonical authorized domain and forbids an endpoint ID.

Authorization must be `true`, active at execution time, and contain a non-empty reference. Domain
exclusions override allowlists. `not_before` and `deadline` are also enforced. A polled malformed or
cross-endpoint job is rejected through a sanitized durable message containing only a safe scan ID,
reason code, and SHA-256 of the raw document; raw untrusted content is not put in audit or logs.

Protected local scheduled jobs construct the same model with a local scope ID/reference and the
single enrolled endpoint ID. Scheduling is therefore not a bypass around validation.

### 2. Local trust boundary

Only protected configuration may decide:

- the bundled/approved osquery path and registry subset;
- approved dependency and SCAP roots, content, and profile;
- optional local compatibility-mode vulnerability paths and sources;
- the separate discovery kill switch, domain roots, rate, concurrency, timeout, and asset cap;
- analysis allowlists, required agents/services, OS catalog, and posture baseline;
- risk weights, resource limits, retention, legal holds, and cloud origin/CA/route map;
- local scheduled scan type, cadence, authorization label, and any compatibility-mode sources.

Cloud jobs can select from these decisions but cannot create new trusted material. API routes are
locally configurable safe absolute paths; route templates accept only their exact documented
`endpoint_id` or `scan_id` placeholder and are joined beneath the optional base-path prefix.

### 3. Process boundary

Every process uses an argv array with `shell=False`, a sanitized environment, an allowlisted and
resolved executable, bounded arguments, no stdin, bounded stdout/stderr readers, and a timeout.
Relative/empty `PATH` entries are removed. POSIX timeouts kill the process group; Windows uses a new
process group and a fixed `taskkill.exe /T /F` tree termination before direct kill fallback. Native
adapters use only source-owned command templates and validated parameters.

### 4. Untrusted output boundary

Native command, osquery, OpenSCAP, cloud OSV/dep-scan, and separately invoked Amass output is not
trusted merely because its source is approved.
Adapters impose byte/row/record/depth limits, strict JSON/XML parsing, bounded strings, allowed
status/severity values, canonical domains/addresses, and Pydantic validation. Malformed rows are
rejected or surfaced as warnings; truncated output is a failure, not partial truth.

### 5. Policy boundary

Policies are data, not executable Python. The loader rejects symlinks unless explicitly allowed,
oversized files, YAML anchors/aliases/tags, duplicate keys, excessive depth/rule count, unknown
fields, duplicate rule IDs, invalid references, and malformed condition trees. Operators are limited
to equality, inequality, containment, existence, numeric ordering, `AND`, `OR`, and `any_item`.
Evaluation has an operation budget and the scan's absolute monotonic deadline.

### 6. Storage and cloud boundary

SQLite uses foreign keys, WAL, full synchronous mode by default, a serialized connection,
transactions/savepoints, integrity checking on open, and forward-only migration checksums. The
outbox stores exact request bytes, a payload hash, request ID, idempotency key, retry state, lease,
and causal links. Delivery uses TLS certificate and hostname verification and TLS 1.2 or newer.

The local audit chain is tamper-evident, not remotely immutable. A host administrator who controls
the database can replace the whole chain; export or anchor important events externally for stronger
assurance.

Cloud persistence uses PostgreSQL as the durable source of truth. Tenant identity comes from the
authenticated credential mapping rather than request body fields. Evidence uploads, decompressed
gzip bodies, reconstructed snapshots, analysis attempts, and final reports are bounded and
validated. Analysis rows use leases and retry/dead-letter state so another worker can recover a
crashed task. PostgreSQL stores vulnerability evidence; it is not a scanner-owned CVE database.
OSV/dep-scan provider IDs, aliases, CVSS values, and fixed versions are retained only when upstream
tool evidence supplies them.

Production requires verified HTTPS. Plain HTTP is accepted only for an explicitly enabled
development/test loopback origin. The static bootstrap/admin token maps in the reference deployment
are integration seams for platform IAM, not the intended browser authentication model.

### 7. Packaging and release boundary

The offline builders under `packaging/endpoint/` verify manifest identity, paths, sizes, and
SHA-256 values before staging the scanner runtime, osquery, platform service integration, and
configuration. They deliberately do not download vendor software. Endpoints therefore receive one
managed installation and do not separately install Python, osquery, OSV-Scanner, dep-scan, Amass,
or Docker.

The builders emit unsigned artifacts. Approved osquery/WinSW bytes and licenses, Authenticode,
Apple signing/notarization, Debian repository signing, installer publication, MDM/SCCM/Jamf rollout,
and secure signing-key custody are external release controls. A builder existing in the repository
must not be represented as an already signed, qualified enterprise release.

## Collection completeness and merge semantics

Inventory has three evidence states:

1. **observed with values** - a selected source succeeded and returned records;
2. **observed empty** - a selected source succeeded and returned no records;
3. **unobserved** - the required query/source was missing, failed, unavailable, timed out, or was
   not selected.

Composite sections such as software, users, services, hardware, interfaces, persistence, and
browser extensions become authoritative only when every selected platform contributor succeeded or
returned a permitted partial payload. An authoritative empty list is retained as empty. An
unobserved section is omitted from the current authoritative set.

`metadata.observed_inventory_sections` and `unobserved_inventory_sections` record this decision.
When the endpoint snapshot is built, prior last-known values are carried forward only for currently
unobserved sections, while a `collection_completeness` block records that they were not freshly
observed. This prevents a failed package query from looking like every package was removed. The
complete per-scan result and collector status still show the actual current visibility gap.

Native inventory is the default source and each successful check establishes authority only for
its own section. Optional osquery models merge field by field and can enrich or recover a native
section that was not observed, without replacing known fields with `None`.

## Policy provenance and activation

The scanner starts with a bundled or explicitly configured local policy. When cloud sync is
enabled, the configured `cloud.routes.policies_path` may return an assignment containing 1-64
documents and one active
ID/version. The scanner:

1. validates the strict assignment schema and unique document checksums;
2. loads every document through the same hardened `PolicyLoader`;
3. canonicalizes the validated bundle and verifies its supplied SHA-256;
4. rejects duplicate policy identities and an active identity not in the assignment;
5. in one SQLite transaction, marks earlier cloud documents unassigned, immutably caches the new
   documents with `source=cloud`, updates policy provenance, and activates exactly one;
6. only after commit, swaps the in-memory registry to the new assignment.

A newly assigned set therefore revokes job access to stale cloud versions even though their cached
documents remain for provenance. Restart reconstructs only the valid active assignment. Corrupt
cache content is rejected and audited; a usable local policy is the fallback when no valid cloud
assignment is active. Invalid remote content does not replace the current policy, and its audit
record contains a fingerprint and sanitized reason rather than the document.

An active ID/version change requests one coalesced `COMPLIANCE` scan. Assignment membership changes
that keep the same active identity update the cache/revocation state but do not create a policy
trigger.

## Baseline, previous state, and drift

These are deliberately separate concepts:

- **Approved baseline:** `analysis.approved_security_posture` is protected local configuration.
  Only configured fields are compared. A mismatch sets `security.configuration_drift` and records
  the field names. Empty configuration means drift is unknown, not false.
- **Allowlist classification:** opt-in administrator, port, service, persistence, and browser
  allowlists mark unexpected observations. Empty allowlists cannot be enabled.
- **Previous snapshot:** content-addressed prior inventory is used for full/delta/unchanged cloud
  synchronization and scan-age calculation. It is not treated as an approved configuration.

Volatile timestamps and point-in-time process telemetry are excluded from differential snapshot
comparison so ordinary churn does not masquerade as configuration drift.

## Persistence, retention, and admission

The local transaction records the normalized result, indexed findings and collector statuses,
endpoint state, a content-addressed inventory snapshot, upload intents, terminal status, scan
history, and completion audit. JSON report writing is atomic and bounded; its name combines a
readable sanitized prefix with the full SHA-256 of the original scan ID.

Before a new scan enters collection, maintenance:

- purges old succeeded uploads in a bounded batch;
- prunes old/overflow completed scan records only after preserving legal holds, each endpoint's
  latest snapshot, and scans referenced by pending, in-flight, or dead uploads;
- rebases a retained child snapshot to a full baseline if its predecessor is pruned;
- prunes old/overflow report files except legal holds and active/dead outbox evidence;
- measures the database, WAL, shared-memory file, and reports;
- rejects new scan admission if the configured scanner byte ceiling is exceeded or filesystem free
  space is below the protected reserve.

Audit rows and endpoint identities are intentionally retained by this maintenance path. Legal-hold
configuration directly protects scan records and reports; it is not a substitute for external
evidence export, backup, or enterprise records governance.

## Differential and causal delivery

The first endpoint snapshot queues `mode=full`. Later snapshots queue `delta` with changed section
values and hashes, or `unchanged`. The complete local result is always retained. Because a delta
depends on the prior cloud hash, scan-result and scan-status messages are linked into one opaque
per-endpoint causal stream. A later message is claimable only after its predecessor succeeds.

If the cloud returns 409 or 412 for a delta, the worker atomically marks it superseded and creates
one full-resync message from the exact stored snapshot with `previous_hash=null`. Downstream causal
messages wait for that replacement. A conflict on the full-resync itself follows normal bounded
dead-letter handling; it cannot recursively create more recovery generations.

After authenticated ingestion, the cloud transaction applies the full/delta/unchanged payload to
the endpoint's tenant-bound current snapshot and queues one OSV and one dep-scan task. Workers lease
those rows from PostgreSQL, retry transient failures with bounded backoff, and persist a visible
degraded terminal tool result for permanent failure so report generation cannot wait forever. When
both tools are terminal, the normalizer writes the stored normalized report. Authenticated artifact
routes validate or upgrade it into one canonical assessment, serialize authoritative
machine-readable JSON, and render a PDF carrying the source JSON SHA-256.

Queue leases are calculated to cover all in-request retries and backoff. One item is claimed just
before it is sent, preventing a slow earlier request from expiring leases for a batch. Transport has
separate connect and read limits, and the read limit is an absolute response deadline: a server
cannot keep the connection alive indefinitely by slowly sending bytes. Offline/network/TLS/auth
failures remain bounded and retry later with the same idempotency key; an auth failure is not
immediately retried with the same token, allowing proactive rotation first.

## Failure and status semantics

`SKIPPED` means a source was intentionally inapplicable, such as OpenSCAP on Windows. `UNAVAILABLE`
means an applicable source could not run. `PARTIAL` means useful evidence exists but visibility is
incomplete. `FAILED` at collector level means that source failed; at overall level it means no
applicable collector produced usable evidence or the trusted lifecycle failed.

A failure after job acceptance records a sanitized failure audit and terminal job state. Terminal
status upload intents are deterministic and reconciled on later startup/upload operations after an
interruption. Reusing a `scan_id` with identical committed content reuses the result and repairs its
report/outbox; different content is an idempotency conflict.

## Extension rules

When adding a collector or tool:

1. keep job input to a controlled identifier, never command text;
2. add protected local path/root/rate settings where trust is required;
3. use the safe runner and remaining scan deadline;
4. validate and bound every untrusted output field;
5. normalize to scanner models and explicitly mark observed sections;
6. return a collector status for every selected source;
7. add policy rules as data, not collector-side judgments;
8. update snapshot identity/volatile-field logic where appropriate;
9. add parser, injection, timeout, malformed-output, completeness, and offline tests;
10. update the cloud and data contracts before release.
