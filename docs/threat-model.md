# Threat model

## Scope

This model covers the endpoint scanner, its protected configuration, local state/reports,
credentials, external-tool processes, authenticated cloud channel, and passive domain-discovery
boundary. The cloud control plane, customer ownership proof, installer/signing infrastructure,
external tools themselves, and downstream analytics require their own threat models.

The scanner is an assessment component, not an exploitation or remediation engine.

## Security objectives

1. Execute only current, explicitly authorized endpoint/domain work.
2. Prevent a cloud job or untrusted file from becoming arbitrary command, SQL, path, policy code, or
   Internet scanning.
3. Preserve confidentiality of credentials and avoid collecting prohibited personal/secrets data.
4. Bound CPU-adjacent work, wall time, output, records, memory, disk, and network requests.
5. Keep successful evidence usable while representing missing visibility honestly.
6. Preserve local evidence and idempotent delivery across outage/crash.
7. Make lifecycle, versions, authorization, policy, collection gaps, and delivery auditable.
8. Fail closed when trusted configuration, policy, storage capacity, TLS, or scope is invalid.

## Assets

- endpoint credential and temporary enrollment token;
- authorization metadata and policy assignment;
- endpoint inventory, vulnerabilities, compliance evidence, findings, and reports;
- customer domains and discovered DNS relationships;
- protected executable/content/root/route/baseline/risk/schedule configuration;
- SQLite result, snapshot, queue, policy, and audit state;
- scanner package, external tools, SCAP content, dependency set, and release provenance;
- cloud API identity, TLS trust, idempotency, and endpoint snapshot state.

## Trust assumptions

- The endpoint OS, Python runtime, and service identity are initially trusted enough to enforce
  filesystem and process controls.
- Protected local configuration is writable only by approved administrators/deployment tooling.
- The cloud authenticates users, proves customer ownership, and issues jobs/policies/credentials
  within tenant boundaries.
- Approved external binaries and content are acquired and verified by release engineering.
- The configured CA/trust store correctly identifies the intended cloud API.
- Server idempotency and differential hash checks are transactional.

A host administrator or kernel compromise can read process memory, change binaries/configuration,
or replace the entire local database/audit chain. The scanner does not claim to defend against that
level without external EDR, code integrity, secret hardware, or audit anchoring.

## Entry points

- YAML/JSON configuration file and small environment-variable allowlist;
- local job JSON and cloud-polled job body;
- cloud policy assignment and individual policy documents;
- enrollment/rotation/result/status/policy/job/rejection HTTP messages;
- stdout/stderr/files emitted by osquery, OpenSCAP, OSV-Scanner, Amass, and native commands;
- SQLite database/WAL and report directory;
- command-line options, service manager signals, and protected local schedule;
- external binary paths, dependency/SCAP roots, and domain roots.

## Threats and controls

### Unauthorized endpoint or domain

**Threat:** An operator or compromised cloud requests an asset outside customer authority, uses an
expired decision, or expands from one domain to siblings.

**Controls:** Strict job model; affirmative boolean; non-empty reference; active validity window;
endpoint/domain allowlists; exclusions override allows; exact subject form by scan type; execution
revalidation; polling endpoint binding; local discovery kill switch and second domain-root allowlist;
passive exact-target Amass; offline public-suffix reasoning; parsed-result scope filter.

**Residual risk:** The endpoint cannot independently prove customer ownership. A compromised cloud
can authorize an endpoint it controls or a locally allowed domain. Keep local roots narrow, require
short scopes, and audit cloud approval.

### Command, SQL, and path injection

**Threat:** A job, configuration value, or tool record reaches a shell/interpreter or escapes an
approved root.

**Controls:** No remote command field; scanner-owned osquery registry; `ON_DEMAND` identifiers only;
`shell=False`; validated argv and sanitized environment; resolved allowlisted executable;
fixed native command templates; no stdin; source/content resolution beneath approved roots;
symlink rejection at sensitive file boundaries; safe cloud route/base-path validation and exact
template placeholders; canonical domain validation.

**Residual risk:** An approved external binary or root content can itself be malicious. Protect
paths from service writes, verify artifacts, and isolate service privileges.

### Malicious or malformed tool output

**Threat:** A compromised tool emits invalid JSON/XML, nested bombs, oversized records, control
characters, traversal-like values, non-finite numbers, or secrets.

**Controls:** bounded stdout/stderr; truncation is failure; strict JSON/XML parsing; node/depth/row
limits; bounded strings/collections; Pydantic normalization; domain/IP/reference validation;
redaction before evidence/log/report boundaries; inventory record cap.

**Residual risk:** Valid-looking output may be semantically false. Preserve tool version/source and
qualify approved binaries; correlate important facts with independent controls.

### Resource exhaustion and orphan processes

**Threat:** Expensive queries, hung tools, policy expressions, slow network, huge results, or child
processes exhaust endpoint resources.

**Controls:** total monotonic scan deadline; per-command remaining timeout; bounded concurrency;
query batching; bounded TTL cache; output/row/inventory/request/response limits; policy expression
depth/rule/operation limits; passive discovery QPS/concurrency/asset cap; POSIX process-group and
Windows process-tree termination; absolute slow-drip read deadline; bounded retries/backoff; local
storage high-water/free-space admission.

**Residual risk:** A permitted process can consume high CPU before its timeout and database writes
can contend with other host activity. Use OS resource controls, canary measurements, conservative
limits, and fleet jitter.

### False empty or false healthy conclusion

**Threat:** A failed collector returns an empty list that looks like software/users/vulnerabilities
were removed, or `SUCCESS` is interpreted as secure.

**Controls:** tri-state observed/empty/unobserved semantics; composite section completeness;
collector/query statuses; observed/unobserved metadata; last-known carry-forward only for snapshot
sync; visibility policy rules; `PARTIAL` aggregation; risk/findings separate from execution status.

**Residual risk:** A successful tool can still omit a table/record because of OS support or
permissions. Review source coverage and live compatibility; absence of a finding is not proof of
absence.

### Policy injection, rollback, or stale assignment

**Threat:** Malicious YAML executes code, an oversized expression causes denial of service, content
changes under an existing version, a partial assignment activates, or revoked cloud policy remains
selectable.

**Controls:** safe non-executable schema; anchors/aliases/tags and duplicate keys rejected;
file/rule/depth/operation bounds; strict operators/paths/references; canonical validated bundle
SHA-256; complete assignment validation before transaction; immutable ID/version content; exactly
one active policy; source/assignment provenance; prior cloud membership revocation; post-commit
in-memory swap; revalidation on restart; sanitized fingerprint-only rejection audit.

**Residual risk:** HTTPS/authentication and SHA-256 do not equal a separately signed policy. If
policy signing is required, add an enterprise signature verification boundary before installation.

### Credential disclosure or downgrade

**Threat:** Enrollment token is logged/stored, endpoint token is plaintext, an insecure keyring is
accepted, or rotation returns an attacker-controlled endpoint/generation.

**Controls:** temporary token only in auth header/environment; settings store only env-var name;
redacted logs/models; DPAPI-protected Windows file; native keyring on Linux/macOS; null/fail/plaintext
backend rejection; credential length/time validation; endpoint binding; strictly increasing
generation; proactive 24-hour rotation; expiry enforcement; environment secret fallback is
explicit.

**Residual risk:** Tokens exist in process memory and a service environment may be readable by
privileged users. Use short lifetimes, restricted service identities, secret manager injection,
server revocation, and endpoint binding.

### TLS interception, redirect, or slow-drip response

**Threat:** An attacker intercepts API traffic, redirects credentials, returns decompression bombs,
or keeps a connection open indefinitely.

**Controls:** HTTPS-only origin; certificate and hostname verification forced; TLS 1.2 minimum;
optional enterprise CA; direct `HTTPSConnection` without redirect following; safe local route map;
distinct connect/read limits; timer-enforced absolute read deadline; response and decompressed size
bounds; strict media/JSON handling; reserved-header protection.

**Residual risk:** Compromise of the configured CA, DNS/control plane, or endpoint trust store can
defeat server identity. Operate CA rotation and certificate monitoring independently.

### Replay, duplication, and out-of-order differential state

**Threat:** A lost response creates duplicates; a later delta arrives before its base; a cloud
restore loses state; a lease expires during long retries.

**Controls:** canonical payload hash and stable idempotency key; at-least-once queue; lease sized for
the full retry budget; claim-one-before-send; deterministic terminal reconciliation; per-endpoint
causal predecessor links; server previous-hash contract; one-generation full resync on 409/412;
subsequent messages wait on success/replacement.

**Residual risk:** Correctness still depends on server-side transactional idempotency and hash
checks. A full-resync conflict becomes dead rather than looping; operators must investigate.

### Local evidence tampering, corruption, or disk exhaustion

**Threat:** Crash/corruption loses results, an attacker edits records, or an offline endpoint fills
disk and disrupts the host.

**Controls:** WAL, foreign keys, full synchronous mode, atomic transactions/savepoints, integrity
check on open, checksum-verified migrations, content-addressed payloads, atomic fsynced reports,
owner-only permissions, consistent backup API, bounded retention, legal holds, queue-aware pruning,
snapshot rebasing, byte/free-space admission, hash-chained audit.

**Residual risk:** A local administrator can replace all evidence. Storage measurement excludes
logs/backups/tools. Legal holds cover built-in scan/report pruning, not every external artifact.
Export evidence, monitor total filesystem use, and test restore/hold procedures.

### Privacy leakage

**Threat:** Inventory, command lines, errors, tool output, or rejected cloud documents expose
credentials or unnecessary personal data.

**Controls:** prohibited collection flags are literal false; process command-line transmission is
off; source queries avoid command lines; sensitive-key/pattern redaction; bounded sanitized errors;
raw invalid jobs/policies omitted from audit; no document/email/cookie/clipboard/screenshot/key
collection; only metadata needed for assessment is normalized.

**Residual risk:** Hostnames, usernames, software paths, services, addresses, and findings remain
sensitive business/personal data. Apply access control, encryption, minimization, retention, and
regional requirements on endpoint/cloud.

### Supply-chain compromise

**Threat:** Scanner wheel, Python dependency, external tool, SCAP content, service wrapper, or
policy is substituted.

**Controls:** bounded trusted paths; unsafe writable POSIX executables rejected; package data keeps
the default policy inside the wheel; version provenance; dependency version locks; deterministic
SHA-256 manifest generation and strict manifest verification; release/test gates.

**Residual risk:** Repository lock files are not complete hash-pinned multi-platform locks, the
generated manifest has no built-in signature validation, and no signed installer/tool package is
provided. Release engineering must resolve, scan, sign, verify, and distribute the actual artifact
set.

### Observability leakage or blind spots

**Threat:** Logs leak secrets or operations miss partial scans, dead uploads, policy rejection, or
storage pressure.

**Controls:** structured redacted JSON logs; bounded fields; scan/scope/version context; metrics
abstraction; health command; collector statuses; queue stats; audit events and chain verification.

**Residual risk:** No metrics listener, SIEM backend, alert rules, or external audit anchor is
bundled. A deployment must connect sinks and define actionable SLOs/alerts.

## Abuse cases explicitly rejected

- arbitrary shell/PowerShell/SQL from a cloud job;
- arbitrary IP-range or unrestricted Internet scanning;
- active probing/exploitation of Amass discoveries;
- password cracking, credential theft, persistence installation, malware, spyware, or keylogging;
- automatic patch installation, file deletion, or security-setting remediation;
- collection of passwords, hashes, private keys, browser secrets/cookies, screenshots, clipboard,
  email, personal-document contents, or keystrokes;
- disabling TLS verification;
- empty enforced allowlists, unbounded discovery, or OSV/SCAP paths outside local roots.

## Security acceptance checklist

Before production and after trust-boundary changes:

1. review authorization abuse cases and server ownership evidence;
2. run SAST, dependency/SBOM/secret scans, artifact signature and manifest verification;
3. fuzz config/job/policy/tool parsers within resource budgets;
4. test command/path/domain/route injection and symlink races;
5. test TLS interception, redirect responses, invalid CA, slow drip, gzip bomb, and response limits;
6. test duplicate/replayed/out-of-order jobs and idempotency keys against the real cloud API;
7. test delta prerequisite mismatch and full-resync recovery across cloud restore;
8. trace least-privilege permissions and process-tree termination on every OS;
9. test tri-state completeness with mixed success/failure and prior snapshots;
10. exercise offline queue, auth rotation, expired credentials, disk reserve, legal holds, database
    corruption, power loss, backup, and restore;
11. qualify exact external-tool/content versions on supported OS releases;
12. run canary performance/false-positive measurement and an independent penetration test of the
    combined endpoint/cloud deployment.
