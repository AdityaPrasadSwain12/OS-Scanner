# Cloud API contract

The repository now includes a working reference server in [`cloud_service/`](../cloud_service/), a
PostgreSQL implementation, durable OSV/dep-scan workers, and the local Compose deployment. This
document describes the endpoint wire contract and the routes implemented by that reference stack.
For the complete current architecture, read
[`END_TO_END_ENTERPRISE_WORKFLOW.md`](END_TO_END_ENTERPRISE_WORKFLOW.md).

The reference service enforces tenant/endpoint binding, credential issuance and rotation,
idempotency, inventory reconstruction, analysis-task durability, and report assembly. A production
main platform must replace local bootstrap/admin token maps with its own customer ownership,
OIDC/IAM/RBAC, approval, secret-management, and installer-distribution controls. The Compose
operator dashboard exercises the workflow locally; its shared development bearer token is not a
production identity or session design.

## Origin and route configuration

`cloud.base_url` must be HTTPS and may contain a safe path prefix. It cannot contain credentials,
query, fragment, path traversal, backslashes, or control characters. Every API path is a protected
local `cloud.routes` setting:

| Setting | Default | Used by |
| --- | --- | --- |
| `enrollment_path` | `/api/v1/endpoint/enroll` | `enroll` command |
| `credential_rotation_path_template` | `/api/v1/endpoints/{endpoint_id}/credentials/rotate` | agent/rotation command |
| `scan_submit_path` | `/api/v1/scans` | result outbox |
| `scan_status_path` | `/api/v1/scans/status` | terminal-status outbox |
| `scan_lookup_path_template` | `/api/v1/scans/{scan_id}` | optional client helper |
| `next_scan_path_template` | `/api/v1/scans/next/{endpoint_id}` | agent job poll |
| `policies_path` | `/api/v1/policies` | agent policy sync |
| `heartbeat_path` | `/api/v1/heartbeat` | optional client helper |
| `attack_surface_jobs_path` | `/api/v1/attack-surface/jobs` | optional client helper |
| `scan_rejections_path` | `/api/v1/scans/rejections` | invalid-job outbox |

The reference API implements enrollment, rotation, next-job polling, evidence/status/rejection
submission, policy retrieval, endpoint scan lookup, and the platform routes documented below.
Heartbeat and attack-surface helper routes remain optional client integration points and are not
dependencies of the implemented service loop. Amass/authorized-domain discovery is separate from
this OS-scanner cloud workflow.

Routes must be safe absolute paths. Template routes must contain exactly the declared `endpoint_id`
or `scan_id` placeholder and no other placeholder. Identifiers are URL encoded before substitution.
The route is joined beneath the base path, so:

```text
base_url:  https://security.example/endpoint-control
route:     /api/v1/scans
wire URL:  https://security.example/endpoint-control/api/v1/scans
```

Routes are never supplied by a scan job. Organizations may change all of them to match an API
gateway without changing scanner code.

## Common transport requirements

The scanner requires:

- HTTPS with certificate and hostname verification; TLS verification cannot be disabled;
- TLS 1.2 or newer and an optional protected enterprise CA bundle;
- bearer or replaceable header-based endpoint authentication;
- `X-Request-ID` on every request;
- `Idempotency-Key` on retryable POSTs and all durable outbox messages;
- `Accept: application/json`, bounded JSON responses, and optional bounded gzip;
- no redirects to a different endpoint; the client does not follow redirects;
- strict request/response byte limits;
- distinct connect timeout and absolute response-read deadline;
- exponential retry/backoff with jitter for safe/idempotent requests on 408, 425, 429, 500, 502,
  503, and 504; bounded `Retry-After` is honored.

The absolute read deadline includes response headers and body. Slowly sending bytes does not extend
it. Gzip is checked both on the wire and after decompression.

The server should return JSON media types for non-empty JSON responses. A 2xx with an empty body is
valid where the operation needs no response document. Avoid using redirects for version changes;
update protected route configuration instead.

## Authentication model

Three credential contexts exist:

1. **Temporary enrollment token:** bearer token used only in the enrollment request. It is never in
   request JSON or persistent credential storage.
2. **Stored endpoint credential:** bearer access token with issue/expiry time, generation, optional
   refresh token, and optional credential ID. The endpoint checks expiry before use.
3. **Injected endpoint credential:** protected environment-secret fallback selected by
   `cloud.credential_env_var`. Its lifecycle is owned by the deployment secret manager.

The agent proactively rotates a stored credential within 24 hours of expiry. HTTP 401/403 is not
retried immediately with the same credential; a durable outbox attempt is scheduled later so
rotation can occur. An already expired credential cannot rotate and requires re-enrollment.

The cloud must independently bind credentials to tenant and endpoint. Never trust a request body
`endpoint_id` without checking the authenticated principal.

## Endpoint enrollment

`POST <enrollment_path>` uses the temporary bearer token and an idempotency key. The body is:

```json
{
  "hostname": "host-01",
  "os_family": "LINUX",
  "os_version": "24.04",
  "architecture": "x86_64",
  "scanner_version": "1.1.0"
}
```

Return either the credential object directly or under `credential`:

```json
{
  "credential": {
    "endpoint_id": "endpoint-123",
    "access_token": "opaque-secret",
    "refresh_token": "optional-opaque-secret",
    "credential_id": "credential-789",
    "issued_at": "2026-08-30T10:00:00Z",
    "expires_at": "2026-09-30T10:00:00Z",
    "generation": 1
  }
}
```

Times must be parseable and expiry must follow issue time. Secrets are bounded non-empty values
without control characters. The CLI stores the credential only after complete validation and then
upserts the enrolled endpoint projection locally.

## Credential rotation

`POST <credential_rotation_path_template>` uses the current unexpired endpoint credential and an
idempotency key:

```json
{
  "endpoint_id": "endpoint-123",
  "generation": 1,
  "credential_id": "credential-789"
}
```

`credential_id` is mandatory. The server binds both it and `generation` to the authenticated
credential and to the endpoint's current generation before rotating. An older token may remain
usable for ordinary delivery during the configured overlap, but it cannot rotate again after a
newer generation exists. Return the enrollment credential shape for the same endpoint with a
strictly higher generation. The endpoint atomically replaces its protected value after validation;
idempotent replay returns the already-created generation.

## Poll one scan job

`GET <next_scan_path_template>` is authenticated for the substituted endpoint. Return:

- HTTP 204 or an empty 2xx body when no work is available; or
- one strict JSON `ScanJob` object.

Do not return a list. The agent runs at most one cloud job per iteration. A minimal endpoint job is:

```json
{
  "job_id": "job-001",
  "scan_id": "scan-001",
  "scan_type": "QUICK",
  "authorization": {
    "scope_id": "scope-001",
    "authorized": true,
    "authorization_reference": "change-001",
    "authorized_by": "security-operations",
    "valid_from": "2026-08-30T10:00:00Z",
    "expires_at": "2026-08-30T10:30:00Z",
    "allowed_endpoint_ids": ["endpoint-123"]
  },
  "endpoint_id": "endpoint-123",
  "policy_id": "enterprise-default",
  "timeout_seconds": 900
}
```

The cloud may also include an explicit validated `policy_version`, scanner-owned
`approved_collectors`, initiator, timing, priority, and bounded parameters. The implemented
platform route always emits an empty `approved_sources` list: it cannot nominate an endpoint path.
Cloud-side OSV/dep-scan analyze the uploaded SBOM. The server issues unique scan/job IDs and never
reuses a scan ID for different canonical content.

The authorization decision must come from cloud-side customer ownership and role/approval logic.
The endpoint model is defense in depth, not the source of truth.

## Invalid job rejection

Malformed JSON, invalid job schema/scope, or a cross-endpoint job produces a durable
`POST <scan_rejections_path>` with an idempotency key derived from the raw body hash:

```json
{
  "endpoint_id": "endpoint-123",
  "scan_id": "scan-001",
  "reason": "INVALID_OR_UNAUTHORIZED_JOB",
  "document_sha256": "<64 lowercase hex characters>"
}
```

`reason` is `INVALID_JSON` or `INVALID_OR_UNAUTHORIZED_JOB`. `scan_id` is null unless a safe bounded
identifier could be recovered. The endpoint does not return the raw body, validation details, or
credentials. The server must deduplicate the idempotency key and move/quarantine the bad job so it
does not poll forever.

## Policy assignment

`GET <policies_path>` returns `null`/an empty body for no change, or a complete assignment:

```json
{
  "schema_version": "1.0",
  "assignment_id": "assignment-2026-08-30",
  "active_policy_id": "enterprise-default",
  "active_policy_version": "1.1.0",
  "policies": [
    {
      "sha256": "<canonical validated bundle SHA-256>",
      "document": {
        "schema_version": "1.0",
        "policy_id": "enterprise-default",
        "policy_version": "1.1.0",
        "rules": []
      }
    }
  ]
}
```

The illustrative `rules` array must contain at least one valid rule in an actual response. An
assignment contains 1-64 documents, unique document checksums and policy identities, and exactly one
active identity present in the list. Each checksum is SHA-256 over canonical JSON of the fully
validated `PolicyBundle`, not the original textual formatting.

The server response replaces current cloud assignment membership. Omitting an older document
revokes it for future explicit-version jobs. The endpoint caches documents atomically, records
`source=cloud` provenance, restores the active assignment offline, and triggers a policy scan only
when active ID/version changes. It does not accept a partial patch document.

Invalid policy content remains inactive and is audited only by assignment fingerprint and sanitized
reason. The server should alert on repeated rejection and retain its own original document for
diagnosis; the endpoint intentionally does not.

## Submit endpoint scan result

`POST <scan_submit_path>` is a durable outbox request. Endpoint results use:

```json
{
  "evidence_envelope_version": "1.0",
  "result": {
    "schema_version": "1.0",
    "scanner_version": "1.1.0",
    "scan_id": "scan-001",
    "endpoint_id": "endpoint-123",
    "scan_type": "FULL",
    "timestamp": "2026-08-30T10:00:15Z",
    "started_at": "2026-08-30T10:00:00Z",
    "finished_at": "2026-08-30T10:00:15Z",
    "status": "PARTIAL",
    "policy_id": "enterprise-default",
    "policy_version": "1.1.0",
    "policy_checksum": "<64 lowercase hex characters>",
    "authorization_scope_id": "scope-001",
    "findings": [],
    "risk": {},
    "collectors": {},
    "metadata": {}
  },
  "inventory_sync": {
    "endpoint_id": "endpoint-123",
    "scan_id": "scan-001",
    "schema_version": "1.0",
    "policy_version": "1.1.0",
    "scanner_version": "1.1.0",
    "snapshot_hash": "<content hash>",
    "previous_hash": "<prior content hash or null>",
    "mode": "unchanged"
  },
  "sbom": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": []
  },
  "sbom_sha256": "<SHA-256 of canonical SBOM JSON>"
}
```

The `result` summary always includes findings, risk, collectors, completeness/tool metadata, and
timing. Inventory synchronization has three modes:

- `full`: includes complete normalized `snapshot`;
- `delta`: includes change descriptors, current values under `sections`, and
  `removed_sections`;
- `unchanged`: contains identity/hashes only.

The API validates the evidence-envelope version, endpoint/scan ownership, bounded JSON structure,
and canonical SBOM checksum before accepting work. The upload may be bounded gzip; both compressed
and decompressed sizes are enforced.

The first snapshot and an automatic rebase use `full`. The cloud must apply a delta atomically only
when its current endpoint hash equals `previous_hash`, then verify/record `snapshot_hash`. Return
HTTP 409 or 412 specifically for a prerequisite mismatch. The endpoint then creates one durable
full-resync request from the exact stored snapshot with `previous_hash: null`. Do not use 409/412
for an unrelated terminal-status or validation error because those codes have this recovery meaning
for scan-state uploads.

After accepting `full`, `delta`, or `unchanged`, the PostgreSQL repository stores a server-managed
`reconstructed_snapshot` in the accepted inventory envelope. A delta is applied only to the exact
previous tenant/endpoint hash. This reconstructed full view is carried into the final report.

The endpoint library still contains a separately authorized `ATTACK_SURFACE`/Amass adapter, but the
implemented OS-scanner platform routes neither create nor ingest those jobs. Run Amass through a
separate client/platform discovery component with its own authorization and data contract.

## Cloud analysis and final report

An accepted endpoint envelope creates two PostgreSQL-leased analysis tasks: `OSV` and `DEPSCAN`.
Workers execute the configured cloud binaries against a private temporary copy of the validated
SBOM, persist retry/dead-letter state, normalize their results, and finalize the scan when both
tasks are terminal. Endpoint users do not install those tools.

The final report is retrieved for dashboard presentation from
`GET /api/v1/platform/scans/{scan_id}/report`. It contains
`endpoint_evidence`, reconstructed `inventory_sync`, SBOM identity, normalized merged
`cloud_analysis.vulnerabilities`, per-tool status/provenance, `summary`, `completeness`, and report
provenance. The authenticated `.json` and `.pdf` artifact routes validate or upgrade this stored
data into the canonical assessment shared by both downloads. The PDF records its source JSON
SHA-256. Upstream tools may supply CVE, GHSA, CVSS, or other provider evidence; the scanner owns no
CVE database and invents no missing identifier.

## Terminal scan status

After the result intent, the endpoint queues `POST <scan_status_path>`:

```json
{
  "schema_version": "1.0",
  "scanner_version": "1.1.0",
  "scan_id": "scan-001",
  "endpoint_id": "endpoint-123",
  "target": null,
  "authorization_scope_id": "scope-001",
  "policy_id": "enterprise-default",
  "policy_version": "1.1.0",
  "policy_checksum": "<64 lowercase hex characters>",
  "status": "PARTIAL",
  "requested_at": "2026-08-30T09:59:55Z"
}
```

Terminal values are `SUCCESS`, `PARTIAL`, or `FAILED`. Endpoint result and status rows share a
per-endpoint causal chain, so the status is not claimable until the result or its full-resync
replacement succeeds. Interrupted failures are reconciled into a missing deterministic status
intent on later agent/upload startup.

## Idempotency and causal ordering

The cloud must durably map each idempotency key to the logical operation and payload result for at
least the scanner's retry/retention window. The same key and same content must return the original
successful response. The same key with different content must be rejected and alerted.

Endpoint state uploads are serialized by endpoint. Do not assume HTTP arrival order from scan time
alone. Validate each `previous_hash` transactionally and persist the new hash together with its
accepted snapshot. A later delta/status waits locally, but server-side prerequisite checking remains
required for multi-agent, restore, replay, or operational error cases.

At-least-once delivery means a server can commit a request while the endpoint loses the response.
Idempotency is therefore correctness, not only optimization.

## Retry and error response guidance

- 2xx: accepted/idempotently replayed.
- 204: no cloud job or no response document.
- 400/404/422: permanent request/schema/route error; endpoint outbox becomes dead after the
  non-retryable response.
- 401/403: credential issue; endpoint schedules later durable retry so rotation/re-enrollment can
  intervene.
- 409/412: use for inventory prerequisite conflict as described above.
- 408/425/429/500/502/503/504: transient; optionally include `Retry-After`.

Every response/log should preserve `X-Request-ID`. The cloud should alert on rejection, dead-letter,
policy checksum, authorization, and repeated full-resync failures without logging bearer tokens or
sensitive inventory.

## Optional client helpers

The transport class exposes helpers for scan lookup, heartbeat, and attack-surface job submission
using their configured routes. The current endpoint service loop does not call them. Do not design a
server dependency on those calls unless a separate integration explicitly invokes them.

## Main-platform routes

The reference API also exposes tenant-admin routes used by a backend-for-frontend or platform
service, never by an unauthenticated browser:

| Method/path | Purpose |
| --- | --- |
| `GET /api/v1/platform/installers` | List allowlisted, integrity-checked endpoint artifacts |
| `GET /api/v1/platform/installers/{artifact_id}/download` | Download an allowlisted artifact after tenant-admin authentication |
| `POST /api/v1/platform/enrollment-tokens` | Issue a short-lived, one-time endpoint enrollment grant |
| `GET /api/v1/platform/endpoints` | List endpoints for the authenticated tenant |
| `POST /api/v1/platform/scans` | Create one bounded authorized endpoint job |
| `GET /api/v1/platform/scans` | List tenant scans and state/report readiness |
| `GET /api/v1/platform/scans/{scan_id}` | Retrieve bounded job/status/progress detail |
| `GET /api/v1/platform/scans/{scan_id}/report` | Retrieve the final normalized JSON report |
| `GET /api/v1/platform/scans/{scan_id}/report.json` | Download the canonical assessment JSON with integrity metadata |
| `GET /api/v1/platform/scans/{scan_id}/report.pdf` | Download the canonical PDF correlated to its source JSON hash |

The local operator dashboard uses the generated development admin token in browser session storage.
It lists and downloads the current developer artifact, issues one-time enrollment grants, creates
authorized scan jobs, polls status, presents completed evidence, and downloads canonical JSON/PDF.
This shared local token and portable artifact are development adapters, not production IAM or a
signed managed installer. A real platform must map its authenticated user/session to a
tenant-scoped authorization decision and keep privileged service credentials server-side.

## Server-side acceptance checklist

The reference implementation supplies the mechanisms below; before production, verify them under
the organization's real IAM, infrastructure, retention, and load model:

1. authenticates and authorizes endpoint identity for every route;
2. creates jobs only from customer-owned, currently approved scopes;
3. stores and compares idempotency keys transactionally;
4. validates result schema/scanner/policy versions before analytics;
5. applies deltas only against the exact previous hash and supports full rebase;
6. treats completeness and collector state separately from empty inventory;
7. preserves raw versioned envelopes and policy/tool provenance;
8. quarantines invalid jobs so polling cannot repeat them forever;
9. implements credential expiry, rotation overlap, revocation, and audit;
10. encrypts sensitive endpoint data and applies tenant access, retention, deletion, and legal hold;
11. propagates request IDs into logs/traces without secrets;
12. load-tests concurrent idempotent replay, retry storms, and fleet jitter.

Production deployment also requires verified TLS ingress, managed HA PostgreSQL/backups, a secret
manager/KMS, restricted worker egress and advisory-cache governance, image signing/SBOM/provenance,
central monitoring/audit export, and capacity qualification. PostgreSQL is the control/evidence
database, not a vulnerability database.
