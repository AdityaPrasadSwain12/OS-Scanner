# Teaching guide

Use this guide to explain the scanner to engineers, security analysts, auditors, managers, or a
customer technical team. You can present it from top to bottom or use the audience-specific outline
near the end.

The current canonical architecture is documented in
[`END_TO_END_ENTERPRISE_WORKFLOW.md`](END_TO_END_ENTERPRISE_WORKFLOW.md). The cloud API,
PostgreSQL inventory/task/report store, OSV/dep-scan workers, local operator dashboard, canonical
JSON/PDF artifacts, and managed-package builders are implemented. The dashboard's shared local
token is not production IAM, the portable EXE is not a signed installer, packages still require
organization signing/vendor inputs, and Amass remains a separate discovery component.

## The thirty-second explanation

Install one managed endpoint agent on the computer being assessed. It receives one narrowly authorized job
from a cloud API, protected local schedule, or explicit local command. It confirms that the endpoint
is allowed, detects the OS, and uses fixed read-only commands already available on that OS for its
core inventory and security scan. It converts evidence to one versioned model, applies organization
baselines and policy, calculates an explainable health score, saves locally, and queues verified
HTTPS delivery. The managed package bundles the scanner/Python runtime and osquery. Cloud workers
run OSV-Scanner and dep-scan over its SBOM; OpenSCAP is an optional Linux extension.

It is an assessment and evidence module. It does not exploit systems, steal credentials, remediate
settings, or install patches. The included cloud stack and local dashboard exercise artifact
download, one-time enrollment, authorized scan control, report presentation, and JSON/PDF download;
the organization's authenticated product integration remains a platform concern.

## Seven ideas to remember

1. **Authorization travels with the job.** The request includes a decision, reference, scope ID,
   active window, and endpoint/domain bounds. A target name alone is not permission.
2. **Local trust remains local.** The endpoint controls tools, paths, query IDs, roots, rates,
   baselines, risk, routes, retention, and schedules. The cloud cannot widen them through a job.
3. **Collection and judgment are separate.** Tools collect facts; normalizers standardize them;
   baselines classify them; policies create findings; risk prioritizes findings.
4. **Unknown is not false or empty.** A successful empty query and a failed query have different
   meanings. Completeness metadata preserves that difference.
5. **Partial evidence is useful and honest.** One failed source does not erase the rest, but the
   report records the visibility gap.
6. **Offline does not mean lost.** SQLite commits evidence and an idempotent outbox before cloud
   delivery succeeds.
7. **A chain of provenance matters.** Job, authorization, scanner/schema/policy/tool versions,
   collector statuses, report, snapshot hashes, audit, and request identity travel together.

## A useful analogy

Think of a regulated inspection center:

- the authorization scope is the work order naming exactly what may be inspected and until when;
- protected endpoint configuration is the facility rulebook and equipment allowlist;
- the native collector is the standard inspection station included with the agent;
- bundled osquery and optional OpenSCAP are specialist endpoint stations;
- cloud OSV/dep-scan workers are the advisory-analysis laboratory;
- a separate Amass component is a different authorized discovery facility;
- normalization is the common evidence form every station must complete;
- completeness marks which sections were actually inspected;
- the baseline is the organization's approved specification;
- policy rules are the inspection criteria;
- findings are failed criteria with evidence and remediation guidance;
- risk is the priority summary, not a replacement for the evidence;
- SQLite is the local case file and outgoing mailroom;
- HTTPS plus idempotency is tracked, duplicate-safe delivery.
- PostgreSQL is the cloud case/queue record, and canonical JSON plus its correlated PDF are the
  machine-readable and human-readable signed-off evidence forms.

If one inspection station is broken, the product is not declared safe. The report says which
inspection succeeded and which visibility is missing.

## Vocabulary

| Term | Plain-language meaning |
| --- | --- |
| Job | One immutable request to assess one endpoint or authorized domain. |
| Authorization scope | Who/what approved the work, its validity period, and exact asset bounds. |
| Collector | Component that gathers one category of raw evidence. |
| Tool adapter | Safe wrapper around an external tool and its untrusted output. |
| Normalization | Conversion of OS/tool-specific records into shared Pydantic models. |
| Observed section | A selected source successfully established values or an authoritative empty set. |
| Unobserved section | Evidence was not selected or could not be reliably collected. |
| Baseline | Protected organization expectation or allowlist. |
| Policy | Versioned data conditions that turn facts into findings. |
| Finding | Evidence-backed policy match with severity and remediation. |
| Health score | `100` is healthiest; active findings subtract a configurable risk penalty. |
| Snapshot | Stable, content-addressed endpoint inventory used for synchronization. |
| Delta | Changed snapshot sections that require a specific previous cloud hash. |
| Idempotency | Repeating the same request does not create a different/duplicate operation. |
| Causal order | A later endpoint state message waits until its predecessor succeeds. |
| Legal hold | Protected scan ID that built-in retention will not prune from scan records/reports. |

## Where jobs come from

There are four execution entry points:

1. `endpoint-scanner local-scan --authorized` constructs a bounded job for the current device.
2. `endpoint-scanner scan --job ...` reads a protected manual JSON file.
3. The agent polls the configured next-job route and accepts zero or one authenticated cloud job.
4. The agent creates a local job for startup, periodic, or policy-change triggers from protected
   scheduling settings.

All paths construct the same `ScanJob`, so local scheduling is not a shortcut around authorization.
A locally scheduled job names the enrolled endpoint, a protected scope/reference, current policy,
short validity/deadline, and configured scan type/sources.

The cloud path is preferred when a job arrives. With no cloud job, local trigger order is startup,
then policy change, then periodic. The process executes at most one scan at a time.

## Explain authorization in layers

```text
Layer 1  cloud proves customer ownership and operator approval
Layer 2  job model binds subject, decision, reference, scope, and active window
Layer 3  polling agent rejects another endpoint's job
Layer 4  execution rechecks time and policy availability
Layer 5  protected endpoint paths/roots/queries/rates can only narrow work
Layer 6  a separate Amass workflow adds its own domain allowlist and post-parse filter
```

For endpoint work, the endpoint ID must be explicitly listed. For attack surface, the canonical
domain must be allowed, exclusions win, and an endpoint ID is forbidden. Domain parameters such as
scope/exclusions are valid only for `ATTACK_SURFACE` and must themselves remain authorized.

Malformed cloud jobs are acknowledged by a hash and small reason, never by echoing raw content into
logs. This avoids turning a rejection path into a secret/log-injection path.

## Explain each tool's role

### Native adapters: the self-contained endpoint scanner

One Windows, Linux, or macOS adapter runs fixed source-owned commands already present on the OS. It
collects OS and hardware, installed software/packages, processes, services, local accounts,
interfaces, listening ports, firewall, encryption, Secure Boot/security hardware, antivirus or MAC
controls, SSH/remote access, update state, audit/lock controls, and persistence metadata where the
platform exposes them safely.

The job selects a category (`inventory`, `posture`, `patches`, `persistence`), not a command.
Arguments are fixed and the subprocess runner never uses a shell. Missing privileges are reported
instead of being interpreted as a disabled or enabled control.

### osquery: bundled managed-package enrichment

In the managed-package baseline, osquery is bundled and configured by a protected absolute path. In
source/developer use it remains optional. It adds structured OS/hardware, software/packages,
processes, services, users/groups,
interfaces/routes/DNS, listeners, disks, startup/scheduled/cron, and browser-extension evidence where
its platform tables support them.

The scanner owns every SQL statement. A job can request an identifier such as `os_info`, never SQL.
Definitions specify platform and row limit. Compatible one-row queries can be combined into a
bounded scanner-generated statement; other queries run in bounded parallel. Selected stable
hardware results may be cached for five minutes using the query and executable fingerprint.
Dynamic evidence is not cached.

### OpenSCAP: Linux compliance

OpenSCAP evaluates a locally approved SCAP content file/profile. It supplies rule semantics,
evidence, references, and fixes/remediation from approved compliance content. It is selected for
Linux `FULL`/`COMPLIANCE` or explicit `ON_DEMAND`. Missing content or binary is visible
`UNAVAILABLE`; another OS is `SKIPPED`.

### OSV-Scanner: dependency vulnerabilities

In the central workflow, OSV-Scanner runs in a cloud worker against the checksummed CycloneDX SBOM
uploaded by the endpoint. It contributes advisory, package, installed/affected/fixed version,
severity/CVSS when supplied, exploitability, known-exploited, and reference data. A protected local
source adapter still exists for the database-free/developer deep-scan path, but endpoint users do
not install OSV for managed cloud operation.

### OWASP dep-scan: second cloud advisory path

dep-scan runs in the cloud worker image against the same validated SBOM. Its output is normalized
and merged with OSV only when package/version and provider evidence support it. PostgreSQL stores
the task/result/report state but is not a CVE database; upstream tools own advisory data/caches and
may return CVE, GHSA, CVSS, or other provider evidence.

### Amass: separate passive discovery

Amass is excluded from the central OS-scanner API/package flow. Its existing separate
`ATTACK_SURFACE` adapter requires the exact domain to pass the job scope and protected local roots.
The adapter forces passive mode, enforces local DNS concurrency/QPS/timeout/asset limits,
applies exclusions, parses bounded output, and filters every asset to the target again. It does not
turn discoveries into scans or exploits.

## Scan types in plain language

| Type | Use it for | Important boundary |
| --- | --- | --- |
| `QUICK` | frequent core inventory and posture | native/osquery endpoint collection; cloud analysis follows its uploaded SBOM |
| `FULL` | broad native endpoint assessment | optional OpenSCAP is Linux/config dependent; OSV/dep-scan are cloud workers |
| `COMPLIANCE` | native posture and compliance-focused evidence | optional OpenSCAP adds Linux benchmark rules |
| `VULNERABILITY` | native software/update assessment | cloud workers analyze the resulting SBOM |
| `ATTACK_SURFACE` | separate passive authorized DNS discovery | excluded from the implemented OS-scanner platform routes |
| `ON_DEMAND` | a narrow approved collector set | identifiers must exist and be locally enabled/compatible |

The scan type selects evidence, not authorization. A quick scan still needs the same authorization
discipline.

## Walk through an endpoint scan

Use these steps when explaining the system:

1. The job is strictly parsed and checked against endpoint authorization.
2. The requested policy ID/version is resolved from currently validated local state.
3. A total monotonic deadline is calculated from job timeout, local scan limit, and absolute job
   deadline.
4. The scanner creates/reuses the idempotent job record and runs storage retention/admission.
5. A hash-chained `SCAN_STARTED` audit event is committed.
6. The OS chooses one native adapter; scan type chooses native categories, bundled osquery query
   IDs, and any configured endpoint extension.
7. Optional tool version probes and every collection action use the remaining deadline.
8. Adapters bound and validate raw output; normalizers construct typed records.
9. The pipeline marks top-level sections observed or unobserved.
10. Protected baselines classify unexpected administrators, ports, services, persistence,
    extensions, agents/services, OS support, and approved posture.
11. A bounded versioned policy creates findings; missing telemetry does not satisfy comparison
    rules.
12. Recurring stable findings reuse `first_seen_at`; the current occurrence keeps the current scan
    ID/time.
13. The risk engine calculates a health score and factor breakdown.
14. The complete report is atomically written with a collision-resistant file name.
15. One SQLite transaction stores result/projections/snapshot, builds the SBOM, queues the versioned
    result/SBOM/status envelope, finishes the job, and records completion provenance.
16. The outbox attempts HTTPS delivery now and on later iterations until success/dead state.
17. PostgreSQL reconstructs inventory and leases OSV/dep-scan tasks; the normalizer assembles the
    canonical assessment when both tasks are terminal, and authenticated routes serialize JSON/PDF.

If the same scan ID is replayed with the same canonical job and an existing result, the scanner
reuses it and repairs report/outbox artifacts. A different job/result under the same identity is a
conflict.

## Walk through attack-surface discovery

This is a separate Amass/client workflow, not a branch served by the implemented central
OS-scanner API or included managed package.

```text
authorized domain
  -> canonicalize
  -> job allowlist/exclusion/current-window check
  -> protected local discovery enablement and root check
  -> passive Amass with bounded QPS/concurrency/time/results
  -> parse untrusted records
  -> exact domain/subdomain and exclusion filter again
  -> normalized attack-surface assets
  -> policy/risk/result/audit/report/outbox
```

There is no endpoint identity or endpoint collector in this branch. Discovery is still authorized
security work even in passive mode; it can expose customer relationships and create contractual or
privacy consequences.

## Teach tri-state completeness with one example

Suppose an endpoint previously reported 1,000 packages.

```text
Case A: package query succeeds and returns []
        -> software is observed empty
        -> removals are real for this evidence source

Case B: Debian query succeeds, RPM query times out
        -> composite software is unobserved
        -> last-known software remains in the sync snapshot
        -> current result says the RPM query timed out
        -> completeness says software was not refreshed
```

Without this distinction, a collection outage would look like mass uninstallation and create false
drift. The scanner preserves two truths: what the current collectors established and what the last
known synchronization baseline contained.

An empty field in the Pydantic `ScanResult` alone is not enough to judge coverage; always read
collector status and completeness metadata.

## Teach baseline versus previous snapshot

This is a common source of confusion:

```text
Approved posture baseline        Previous inventory snapshot
--------------------------       ---------------------------
protected desired state          last observed state
explicit fields only             content-addressed full inventory
creates configuration_drift      creates full/delta/unchanged sync
empty means no drift decision    absent means first/full snapshot
```

For example, `approved_security_posture: {firewall_enabled: true}` means an observed false firewall
is configuration drift. The fact that the firewall was also false yesterday is irrelevant to
approval. Conversely, Chrome 139 yesterday and Chrome 140 today is a snapshot software change, not
automatically a policy violation. A policy or approved baseline must decide whether it is bad.

Previous snapshot time also supports `scan_age_days` and the stale-scan rule. Volatile timestamps
and processes are excluded from snapshot comparison to prevent constant churn.

## Teach policy with an example

Policy is validated data, not code scattered through collectors:

```yaml
- id: WIN-FIREWALL-001
  title: Windows Firewall must be enabled
  severity: HIGH
  category: endpoint_security
  platforms: [WINDOWS]
  condition:
    field: security.firewall_enabled
    operator: equals
    value: false
  evidence_fields: [security.firewall_enabled]
  remediation: Enable every applicable Windows Firewall profile.
```

The collector only says whether the firewall was observed enabled. The rule decides what becomes a
finding. If the field is missing, `equals false` does not match. A visibility rule may separately
flag collector failure.

Supported condition concepts are `equals`, `not_equals`, `contains`, `not_contains`, `exists`,
`not_exists`, `greater_than`, `less_than`, `AND`, `OR`, and `any_item`. Policy evaluation cannot run
Python, templates, shell, or arbitrary expressions and is bounded by depth, rule count, operation
count, and total deadline.

Finding identity is one stable finding per subject, policy, and rule. If five vulnerable packages
match a high-vulnerability rule, the finding evidence reports the matched count and a bounded
sample; it does not create five independent lifecycle IDs. A downstream system needing per-package
case lifecycle should derive that separately from normalized vulnerabilities.

## Teach cloud policy assignment

The local policy is always validated first. An authenticated cloud assignment can replace the
currently assigned cloud set, but it must be complete:

1. strict assignment schema and 1-64 documents;
2. every document passes the hardened policy loader;
3. SHA-256 is recalculated over canonical validated content;
4. every policy ID/version is unique and the active identity is present;
5. one transaction revokes old membership, caches new content/provenance, and activates one policy;
6. memory changes only after commit.

Omitted old cloud versions remain stored for provenance but cannot be selected by a future job.
Restart revalidates cached assigned content. Invalid sync keeps the existing policy and stores only a
fingerprint/reason audit, not raw policy text. An active version change requests one coalesced
compliance scan.

This is authenticated/checksummed assignment, not a bundled policy-signature system. Organizations
requiring separately signed policy documents must add that verification before installation.

## Teach findings versus scan status

These answer different questions:

- **Collector/overall status:** Did applicable evidence sources execute?
- **Finding/risk:** What undesirable facts did the policy observe?

Example:

```text
native posture       SUCCESS
osquery aggregate    SUCCESS
OpenSCAP             UNAVAILABLE
endpoint scan        PARTIAL
cloud OSV            SUCCESS
cloud dep-scan       SUCCESS
cloud report         PARTIAL
critical findings    2
```

`PARTIAL` means compliance visibility is missing; other evidence, cloud advisory results, and the
two findings remain valid.
Likewise, `SUCCESS` can contain critical findings. It means collection succeeded, not security is
healthy.

`SKIPPED` differs from `UNAVAILABLE`: OpenSCAP on Windows is inapplicable and skipped; OpenSCAP on a
selected Linux compliance scan with missing configured content is unavailable.

## Teach the risk score

The score starts at 100 and subtracts a capped penalty. Default severity bases are Critical 40,
High 25, Medium 12, Low 5, and Info 1. Each active finding adds its base and weighted contributions
for exploitability, asset criticality, exposure, compliance impact, and age. Acknowledged findings
use a lower base; resolved/suppressed findings are excluded.

Illustrative high finding:

```text
base severity       25.000
exploitability       1.875  (25 x 0.25 x 0.3)
asset criticality    4.000  (25 x 0.20 x 0.8)
exposure             1.500  (25 x 0.20 x 0.3)
compliance impact    0.000
age                  0.000
total penalty       32.375
health score        67.625
default level       MEDIUM
```

This is not a probability of compromise. Multiple findings accumulate, exposure uses the larger of
scan/finding exposure, compliance findings default to full compliance impact unless explicitly
configured, and age grows to a saturation point. The stored factor map makes the result auditable.
All weights/bands are protected configuration.

## Teach local storage and reports

SQLite stores complete normalized results plus useful projections and content-addressed inventory.
WAL, foreign keys, transactions, full synchronous mode, integrity checking, and checksum-verified
migrations support crash consistency. The final scan transaction also queues result and status,
keeping local persistence and delivery intent together.

Reports use deterministic strict JSON and an fsynced atomic replace. The file name is:

```text
<sanitized first 48 characters>--<full SHA-256 of original scan ID>.json
```

The hash prevents `scan:1` and `scan_1` (which sanitize similarly) from overwriting each other.

Audit rows link each event hash to the previous event. This detects changes within the chain, but a
host administrator can replace the entire database. Export or anchor audit externally when stronger
assurance is required.

## Teach differential synchronization

The complete local result always exists. Only inventory transfer is optimized:

```text
scan 1: no previous snapshot     -> full
scan 2: Chrome 139 -> Chrome 140 -> delta with software section and hashes
scan 3: stable inventory         -> unchanged with hashes
```

Each envelope names `snapshot_hash` and `previous_hash`. The implemented PostgreSQL repository
applies a delta only if its current tenant/endpoint hash is exactly the prerequisite, then stores a
server-managed reconstructed full snapshot. The delta carries complete current values for changed
sections, plus removal names and before/after hashes/counts.

Processes are point-in-time evidence and do not enter snapshot sync. Known volatile timestamps are
also removed. This lowers bandwidth and false changes without weakening the complete local result.

## Teach offline, idempotency, and causal order

There are two retry layers:

1. the HTTPS client retries an idempotent request during one call;
2. the SQLite outbox retries across agent iterations and restarts.

The worker leases one row immediately before send. The lease covers all configured connect/read
attempts and backoff. If the process dies, an expired lease returns to pending until the retry limit.
The same exact payload and idempotency key are reused because the server may have committed even
when the endpoint lost the response.

Endpoint result and terminal status form a causal stream. A later message waits for its predecessor.
If the cloud says a delta prerequisite is wrong (409/412), the scanner supersedes it with exactly one
full snapshot whose `previous_hash` is null; later messages wait for that replacement. It does not
create an infinite resync loop.

Network, TLS, and authentication failures remain durable. Authentication is retried later rather
than immediately with the same token so proactive rotation can happen first. The response-read
timer is absolute, preventing a server from keeping an operation alive by slowly sending bytes.

At-least-once endpoint delivery requires duplicate-safe server behavior. Local idempotency alone is
not sufficient.

## Teach retention and disk safety

Before a new scan, maintenance deletes only bounded, safe candidates:

- old succeeded queue rows;
- old/overflow completed scans that are delivered and not protected;
- old/overflow reports that are not held or associated with active/dead outbox evidence.

It preserves legal-hold scan IDs, each endpoint's latest snapshot, and pending/in-flight/dead scan
evidence. If pruning removes a snapshot prerequisite, its retained child becomes a new full
baseline. Audit and endpoint identities remain.

After pruning, a new scan is rejected if scanner database/WAL/SHM/reports exceed the configured byte
ceiling or free space falls below the reserve. This is safer than filling the host disk. It does not
measure unrelated logs/backups/tools, so operators still monitor the whole filesystem.

## Teach enrollment and rotation

Enrollment exchanges an environment-only temporary token for a structured endpoint credential. The
temporary token stays in the authorization header and is never saved. Windows protects stored
credentials with DPAPI; Linux/macOS require a secure native keyring backend. The service must run as
the same principal that owns the credential.

Every agent iteration checks whether a stored credential expires within 24 hours. Rotation uses the
current unexpired token and accepts only the same endpoint with a higher generation. An expired
credential needs re-enrollment. An environment-injected token is allowed as a protected deployment
fallback, but its rotation belongs to the external secret manager.

## Explain what is and is not delivered

Included in this repository:

- scanner models, collectors, adapters, normalization, policy/risk, SQLite/outbox, transport,
  enrollment, scheduling, CLI, service templates, tests, and documentation;
- a bundled 50-rule default policy;
- CycloneDX SBOM generation and cloud-offload evidence envelopes;
- FastAPI control-plane routes, PostgreSQL persistence/inventory reconstruction, durable OSV and
  dep-scan workers, canonical JSON/PDF report assembly, and a hardened local Compose stack;
- a local operator dashboard for developer download, one-time enrollment, scan control, report
  presentation, and artifact downloads, plus synthetic/real-endpoint E2E scripts;
- a standalone PyInstaller scanner plus Windows/Debian/macOS managed-package builders with
  approved-input and content-hash verification.

Not included:

- the organization's production customer IAM/RBAC/session integration, billing, or approved
  signed-package distribution workflow;
- exploitation, password attacks, remote shell, arbitrary scanning, or remediation execution;
- organization-approved osquery/WinSW vendor inputs/licenses, OpenSCAP content, or separate Amass
  deployment;
- signed/notarized production installers or signed container releases (builders/scaffolding exist);
- cryptographic signature verification for release manifests or policy assignments;
- a Prometheus listener, OpenTelemetry exporter, SIEM backend, or alert policy;
- an operator command to replay/delete dead outbox rows or a CLI database-backup command;
- server-side finding resolution/case workflow.

These are explicit integration responsibilities, not hidden TODO capabilities that the agent
pretends to provide.

## A safe demonstration

Use fixtures or an isolated, explicitly authorized lab. Never demonstrate Amass against an
unapproved domain.

1. Show configuration and identify protected local decisions.
2. Run health:

   ```bash
   endpoint-scanner health --config /secure/config.yaml
   ```

3. Run the simple native scan on the authorized lab device:

   ```bash
   endpoint-scanner local-scan --authorized --scan-type QUICK
   ```

4. Show a cloud/manual job's authorization before its scan type.
5. Validate it without execution:

   ```bash
   endpoint-scanner validate-job --job /secure/job.json
   ```

6. Change the endpoint ID outside the allowlist and show rejection.
7. Run fixture/security tests rather than live reconnaissance:

   ```bash
   pytest tests/security tests/integration/test_orchestrator.py
   ```

8. On the lab endpoint, inspect the CLI summary, collision-resistant
   report name, collectors, completeness, findings, and risk factors.
9. Disconnect cloud access, run a protected local scan, and show the pending queue in health.
10. Restore access and run a bounded upload; show idempotent delivery.
11. Run an unchanged second scan and explain full/delta/unchanged behavior.
12. Simulate one collector failure and show that last-known snapshot data is preserved while the
    current result remains partial/unobserved.

For the implemented full pipeline on Windows PowerShell, start the local Compose stack, run the
synthetic cloud test, then explicitly authorize the current-device test:

```powershell
.\scripts\cloud\Initialize-CloudEnvironment.ps1
.\scripts\cloud\Start-Cloud.ps1 -Build
.\scripts\cloud\Test-CloudE2E.ps1
.\scripts\cloud\Test-EndpointAgentE2E.ps1 -Authorized -ScanType QUICK
```

The harness writes its final report under
`cloud/.e2e-agent/<run-id>/final-cloud-report.json`. The dashboard at
`http://127.0.0.1:8081` uses only local development credentials and can also drive enrollment,
authorized scans, status, report presentation, and canonical JSON/PDF downloads.

Do not put production tokens, customer domains, usernames, software paths, or raw result files in
recorded slides.

## Frequently asked questions

### Do endpoint users have to install the external tools?

No. The managed package includes the scanner/Python runtime and osquery. OpenSCAP remains an
optional enterprise-packaged Linux extension. OSV-Scanner and dep-scan run in cloud workers, Docker
runs only on cloud/development infrastructure, and Amass belongs to a separate discovery component.
The standalone development executable does not itself bundle osquery.

### Can the cloud run any command or SQL?

No. It can request a scan type and controlled identifiers. Executables, SQL registry, native
commands, source/content roots, routes, and baselines are protected endpoint configuration/code.

### Does `SUCCESS` mean the host is secure?

No. It means applicable collection succeeded. Findings and risk describe observed security posture.

### Does no finding prove no vulnerability?

No. It means no loaded rule matched available normalized evidence. Check collector/completeness,
SBOM/package identity, cloud OSV/dep-scan status, policy version, and authorization scope.

### Why carry last-known values after a failure?

Only the synchronization snapshot carries an unobserved prior section, labeled as not refreshed.
This prevents false deletion. The complete current result still shows the failure and does not claim
fresh observation.

### Is configuration drift simply any change since yesterday?

No. Drift means mismatch with `approved_security_posture`. Yesterday-versus-today differences are
snapshot change events used for synchronization.

### Why is 100 called healthy?

The value is a health score, not raw risk. Active findings subtract `risk_penalty`; both values and
the factor breakdown are present.

### Why persist before upload?

Endpoints and APIs go offline. Local commit prevents evidence loss and enables retry, differential
comparison, forensic support, and idempotency.

### Can the server just accept deltas in arrival order?

No. It must atomically check `previous_hash`. Local causal ordering reduces errors but cannot cover
server restore, multi-agent mistakes, or manual replay. A mismatch asks for full resync.

### Is the audit chain immutable?

It is tamper-evident inside the retained database. A privileged host attacker can replace the
entire file/chain. Export or anchor it for stronger assurance.

### Does passive Amass need authorization?

Yes. Passive discovery still processes customer asset relationships and can affect contracts,
privacy, and third-party services. The separate component remains opt-in, scoped, bounded, and
audited; it is not part of the central OS-scanner package/API flow.

### Why no automatic remediation?

Assessment and change have different approval and failure boundaries. Automatically changing
firewalls, accounts, updates, or persistence can disrupt systems or exceed authorization. Findings
provide guidance; a separately governed remediation system should execute approved changes.

### Are releases and tools already enterprise-signed?

No. The repository now has a working standalone Windows scanner and native managed-package builders
that verify approved offline inputs. Release engineering must still acquire/approve vendor
tools/licenses, build on each native architecture, sign/notarize packages and images, publish
SBOM/provenance, qualify clean-machine upgrades/rollback, and enforce signature trust.

## Audience-specific presentation plan

For a 20-minute mixed audience:

1. purpose and non-goals - 2 minutes;
2. authorization and local-trust layers - 3 minutes;
3. tool roles and scan types - 3 minutes;
4. normalize -> completeness -> baseline -> policy -> risk - 5 minutes;
5. SQLite -> snapshot -> causal outbox -> HTTPS - 4 minutes;
6. operations/residual responsibilities - 2 minutes;
7. questions - 1 minute.

For auditors, emphasize authorization provenance, unknown-vs-empty semantics, policy checksum/source,
privacy exclusions, audit limits, legal holds, and server idempotency. For engineers, emphasize
adapter boundaries, batching/cache, deadlines, normalization, SQLite transactions, causal recovery,
and extension rules. For managers, emphasize that partial coverage is measurable, offline work is
durable, the cloud reference stack works end to end, and organization IAM/signing/operations remain
separately owned.

## Final explanation to reuse

The enterprise value is not merely the number of fields collected. It is the preservation of
context around every fact: who authorized the scan, which local controls constrained it, which tools
and queries actually succeeded, what remained unknown, which schema and policy interpreted the
evidence, why the findings and score exist, where the complete record was stored, and whether the
cloud received it in the correct order. PostgreSQL then reconstructs inventory, cloud workers add
OSV/dep-scan evidence, and the canonical assessment preserves completeness/provenance across JSON,
PDF, and dashboard views. That chain makes the scanner safer, explainable, repeatable, and
operationally useful.
