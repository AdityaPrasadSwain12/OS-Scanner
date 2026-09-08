# Data and persistence model

## Validation principles

Scanner-owned models derive from strict Pydantic bases. Unknown fields are rejected, strings and
collections are bounded, non-finite numbers are forbidden, timestamps are timezone-aware, and
cross-field invariants are checked. Tool output is normalized into these models before policy,
storage, reporting, or upload.

Every versioned artifact carries `schema_version` and `scanner_version`. The package defaults are
schema `1.0` and scanner `1.0.0`; policy and external-tool versions are independent. Do not infer
schema compatibility from the scanner version alone.

JSON storage uses deterministic UTF-8 encoding with sorted keys and compact separators. SHA-256 of
canonical JSON supplies immutable content identity and idempotency conflict detection.

## Job model

`ScanJob` describes one immutable work request:

| Field | Meaning |
| --- | --- |
| `job_id`, `scan_id` | Bounded trace/idempotency identifiers. |
| `scan_type` | `QUICK`, `FULL`, `COMPLIANCE`, `VULNERABILITY`, `ATTACK_SURFACE`, or `ON_DEMAND`. |
| `authorization` | Affirmative decision, scope ID/reference, active window, and endpoint/domain/network bounds. |
| `endpoint_id` or `target` | Exactly one subject form, selected by scan type. |
| `policy_id`, `policy_version` | Active policy selection; an explicit version must be currently validated and assigned. |
| `approved_collectors` | Controlled identifiers for `ON_DEMAND`, never commands or SQL. |
| `approved_sources` | OSV source paths, still constrained by protected local roots. |
| `requested_at`, `not_before`, `deadline`, `timeout_seconds` | Scheduling and execution bounds. |
| `priority` | Validated metadata; the single-job agent does not implement a priority queue. |
| `parameters` | Bounded object limited to asset criticality and attack-surface scope/exclusions. |

`AuthorizationScope` contains `authorized`, `authorization_reference`, `authorized_by`, `purpose`,
`valid_from`, `expires_at`, allowed endpoint IDs/domains/networks, excluded domains/networks, and
the subdomain decision. Exclusions take precedence. Network lists are modeled for future scoped
integrations; the current scanner does not implement arbitrary IP-range scanning.

## Scan result

`ScanResult` is the complete per-scan record:

```json
{
  "schema_version": "1.0",
  "scanner_version": "1.0.0",
  "scan_id": "scan-001",
  "endpoint_id": "endpoint-123",
  "scan_type": "FULL",
  "timestamp": "2026-08-30T10:00:15Z",
  "started_at": "2026-08-30T10:00:00Z",
  "finished_at": "2026-08-30T10:00:15Z",
  "status": "PARTIAL",
  "policy_id": "enterprise-default",
  "policy_version": "1.0.0",
  "policy_checksum": "<64 lowercase hex characters>",
  "authorization_scope_id": "scope-001",
  "endpoint": {},
  "os": {},
  "hardware": {},
  "software": [],
  "processes": [],
  "services": [],
  "users": [],
  "network_interfaces": [],
  "listening_ports": [],
  "security": {},
  "updates": [],
  "browser_extensions": [],
  "persistence": [],
  "compliance": [],
  "vulnerabilities": [],
  "attack_surface": [],
  "findings": [],
  "risk": {},
  "collectors": {},
  "metadata": {}
}
```

An attack-surface result has `target` in metadata/SQLite provenance and forbids `endpoint_id` and
`endpoint`. Endpoint results require them. Nested compliance, vulnerability, finding, and risk
records must carry the same `scan_id`. Collector dictionary keys must equal each status object's
`name`.

### Endpoint and inventory

- `Endpoint`: ID, hostname, OS family, machine ID, manufacturer/model, asset criticality, tags,
  and last-seen time.
- `OperatingSystem`: family/name/version/build/kernel/architecture, hostname/machine ID, boot time,
  uptime, timezone, and optional lifecycle support result.
- `Hardware`: CPU, memory, disks, GPUs, motherboard, firmware, manufacturer/model, and TPM.
- `Software`: name/version/vendor/path/install date/package manager/architecture/source.
- `Process`: PID/name/path/parent/user/start time/resource values and an optional redacted command
  line. Current registry queries do not collect command lines for upload.
- `Service`: identity/display/state/startup/path/account plus analyzed security flags.
- `User`: username, stable UID/SID where available, tri-state enabled state, groups, administrator,
  guest, and last login.
- `NetworkInterface`: canonical MAC/IP data, prefix, gateways, DNS, DHCP lease metadata, link state,
  and VPN indicator.
- `ListeningPort`: protocol/address/port/PID/process, exposure, and analyzed suspicious flag.
- `UpdateInfo`: update ID/title/version/category, installed state/time, tri-state security provenance,
  and reboot requirement.
- `PersistenceItem` and `BrowserExtension`: bounded metadata plus analyzed suspicious/risky flag.

Unknown is represented by `null`, not a guessed boolean. For example, a Windows KB without reliable
category provenance has `security_update: null`, not `false`.

### Security posture

`SecurityPosture` holds tri-state controls such as firewall, antivirus freshness, disk encryption,
Secure Boot, TPM, UAC, RDP, SELinux/AppArmor, SSH settings, automatic updates, pending security
updates/reboot, SIP, remote login/screen sharing, security agents/services, accounts, password and
lock controls, audit logging, approved-posture drift, suspicious classifications, and scan age.

`controls` is bounded explanatory metadata, such as required service names, missing/stopped agents,
administrator limit, lifecycle release key, kernel package observations, and approved-posture drift
field names. A missing field means no reliable conclusion was available.

### Collector status

Every selected evidence source records:

- collector name and `SUCCESS`, `PARTIAL`, `FAILED`, `UNAVAILABLE`, `TIMEOUT`, or `SKIPPED`;
- start/finish/duration where available;
- tool version and record count;
- bounded, redacted error code/message;
- bounded metadata such as query category, batch/cache indicators, or query count.

Failed and timed-out sources require an error description. `SKIPPED` means inapplicable or
intentionally omitted and does not by itself reduce overall status.

### Completeness metadata

The result's metadata contains `observed_inventory_sections` and
`unobserved_inventory_sections`. These describe which top-level sections were authoritative in this
scan. Snapshot payloads add:

```json
{
  "collection_completeness": {
    "observed_sections": ["os", "software"],
    "unobserved_sections": ["services", "users"]
  }
}
```

An observed empty list is authoritative. An unobserved section may carry a last-known prior value in
the snapshot so a collection failure does not appear as mass removal. The complete current result,
collector map, and completeness lists preserve the fact that the value was not refreshed.

## Compliance, vulnerabilities, and attack surface

`ComplianceResult` contains rule/profile IDs, title, status, normalized severity, bounded evidence,
remediation, references, and evaluation time. OpenSCAP statuses normalize to pass, fail, error,
unknown, or not-applicable forms represented by the model enum; raw status can remain in evidence.

`Vulnerability` contains advisory ID, package/ecosystem and installed version, affected/fixed
versions, aliases, severity, optional CVSS score, exploitability, known-exploited flag, summary,
references, evidence, and detection time. These facts come from validated OSV-Scanner output; the
scanner does not own an advisory database.

`AttackSurfaceAsset` contains canonical hostname/IP, type, root domain, addresses, bounded DNS
records, in-scope flag, source, and discovery time. Non-IP hostnames must be the root or a descendant
of the root. Endpoint asset types are forbidden in this collection.

## Findings and risk

`Finding` contains the requested audit fields: stable ID, scan/rule IDs, title, severity, category,
description, endpoint/asset, bounded redacted evidence, remediation, validated references,
detected/first-seen time, status, exploitability, exposure, compliance impact, and tags.

The ID is deterministic for `(endpoint-or-asset, policy_id, rule_id)`. It is intentionally not
per-scan or per-matched-item. A recurring rule reuses its earliest stored `first_seen_at`; current
`scan_id` and `detected_at` identify the current occurrence. Collection rules include matched count
and a bounded sample in evidence. The scanner does not automatically mark an absent prior finding
resolved; lifecycle workflow belongs to the consuming platform/operator.

`RiskScore` contains health score, risk penalty, level, severity counts, factor contributions,
policy version, and calculation time. `100` is healthiest. Default bands are:

| Score | Level |
| --- | --- |
| 85-100 | `HEALTHY` |
| 70-84.99 | `LOW` |
| 50-69.99 | `MEDIUM` |
| 30-49.99 | `HIGH` |
| 0-29.99 | `CRITICAL` |

All thresholds and factor weights are protected configuration.

## Policy documents

A `PolicyBundle` has schema version, policy ID, semantic `x.y.z` policy version, description, and a
unique rule list. Each rule declares applicability, a condition tree, evidence fields,
remediation/references, severity/category, and optional risk modifiers.

Cloud assignment documents add an assignment ID, active policy identity, 1-64 `{sha256, document}`
items, and strict schema version `1.0`. The SHA-256 is calculated over the canonical, fully validated
`PolicyBundle`, not raw YAML/JSON formatting.

Cached policy rows record identity, checksum, canonical document, `bundled`/`local`/`cloud` source,
received/activated times, active flag, and current cloud-assignment membership (`assigned`). A new
cloud assignment marks earlier cloud membership false before marking the new set true. Exactly one
policy document and one policy-version row can be active.

## SQLite schema

Forward-only migrations currently create these logical groups:

| Table | Purpose |
| --- | --- |
| `schema_migrations` | Applied migration number/name/checksum. |
| `endpoints` | Current endpoint projection and enrollment/last-seen metadata. |
| `scan_jobs`, `scan_history` | Immutable job identity and lifecycle events. |
| `result_payloads`, `scan_results` | Content-addressed complete results and indexes. |
| `findings` | Latest stored occurrence for each stable finding ID. |
| `collector_status` | Per-scan evidence-source projection. |
| `inventory_payloads`, `inventory_snapshots` | Deduplicated snapshot content, predecessor, and section diff. |
| `upload_queue` | Exact payload, request/idempotency identity, attempts, lease, causal and resync links. |
| `policy_versions`, `policy_documents` | Policy provenance, immutable canonical content, membership, and activation. |
| `schema_versions` | Active logical result-schema provenance. |
| `audit_log` | Hash-linked audit events. |

SQLite uses foreign keys, WAL, full synchronous mode by default, busy timeout, trusted-schema
hardening where available, and nested savepoints. Opening the database applies missing known
migrations and runs `quick_check`; an unknown newer migration or changed migration checksum fails.

### Idempotency invariants

- one canonical job per `scan_id`; different job content is a conflict;
- one complete result and endpoint snapshot per `scan_id`;
- immutable policy content per `(policy_id, version)`;
- one outbox payload/method/route per idempotency key;
- one full-resync generation per rejected differential upload;
- deterministic start/reject/complete/failure audit event IDs where restart idempotency is needed.

## Snapshot and differential schema

Snapshots contain stable endpoint inventory rather than the whole result. Process telemetry is
excluded. Known volatile timestamps/scan IDs are removed from endpoint, posture, compliance, and
vulnerability sections. Unordered collections are canonicalized before hashing.

The upload envelope always carries endpoint/scan/schema/policy/scanner identity, `snapshot_hash`,
and `previous_hash`:

- `full`: first or rebased snapshot plus complete `snapshot`;
- `delta`: section change descriptors, current changed `sections`, and `removed_sections`;
- `unchanged`: hashes and mode only.

Section descriptors contain event name, before/after hashes, and added/removed/modified counts. A
delta is applicable only when the receiver's current hash equals `previous_hash`.

## Retention and deletion relationships

Bounded maintenance can remove safely delivered old/overflow scan records and unreferenced content
payloads. It never selects legal holds, the latest endpoint snapshot, or a scan referenced by a
pending/in-flight/dead outbox row. If a retained snapshot loses its predecessor, it is rewritten as
an initial full baseline. Reports follow independent age/count limits but protect legal holds and
active/dead queue evidence. Succeeded outbox rows follow their own retention period.

Audit events and endpoint identities are retained by built-in maintenance. Legal holds are a local
configuration control over scan records/reports; enterprise export, backup, deletion approval, and
external records governance remain deployment responsibilities.

## Audit integrity

Each audit event hashes canonical event content together with the previous event hash. Chain
verification detects row modification, deletion, insertion, and reordering within the retained
chain. This is tamper-evidence, not proof against a host administrator who replaces the entire
database. Export or externally anchor required events.

## Cloud storage guidance

The receiver should store raw versioned envelopes before transforming them, enforce tenant and
endpoint ownership independently of endpoint assertions, deduplicate by idempotency key, validate
snapshot prerequisites atomically, preserve policy/tool provenance, encrypt sensitive inventory,
and apply organization retention/access controls. See [Cloud API contract](cloud-api.md).
