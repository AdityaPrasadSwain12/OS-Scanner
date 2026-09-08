# Deep Scan Workflow

## What is implemented now

The supported `deep-scan` CLI performs one explicitly authorized, point-in-time `FULL` scan of the local endpoint. It can also scan approved dependency inputs and run passive discovery for separately authorized domains. It writes one normalized JSON report.

The implementation is genuinely storage-free while it runs: `StatelessScanner` keeps child results in process memory and creates no SQLite database, queue, or child report files. The only scan artifact it persists is the caller-selected combined JSON file.

This standalone command does not install a managed service, use the cloud control plane/dashboard,
render PDF, or execute pentests. The repository's separate managed workflow provides the local
operator dashboard, cloud analysis, and canonical JSON/PDF routes; signed Windows/macOS/Linux
installers and pentest execution still require separate release/integration work.

## Point-in-time collection

A deep scan is a bounded observation of a live system, not continuous monitoring or a forensic disk image. Processes, services, packages, and listeners can change while collection runs. The endpoint scan runs first and any authorized domain scans run afterward, with timestamps on each result.

- An empty, successfully observed section means the collector found no records in its collection window.
- An unobserved, skipped, unavailable, partial, timed-out, or failed section does not prove that no records or vulnerabilities exist.
- `SUCCESS` means scheduled collection completed; it does not mean the endpoint is secure.
- `completeness.complete` means the required sections were observed without scheduled tool gaps. It is not a guarantee of universal coverage.

Administrator/root privileges can improve coverage. Reduced permissions can produce fewer records or explicit partial results.

## Data sources and operating-system coverage

| Source | Where it applies | Current behavior | Important limit |
| --- | --- | --- | --- |
| Native collectors | Windows, Linux, macOS | Collect OS/endpoint identity, hardware where exposed, installed software/packages, processes, services, users/groups, networking/listeners, security posture, OS update/patch observations, and supported persistence evidence | No built-in universal CVE database, dependency graph, browser-extension collection, or exploitability proof |
| osquery | Windows, Linux, macOS, subject to available tables | Runs only scanner-owned registered queries to enrich inventory, including supported browser-extension tables, updates, listeners, persistence, and related evidence | No arbitrary SQL and no automatic CVE matching |
| OpenSCAP | Linux only in this repository | Evaluates an approved local SCAP/XCCDF content file/profile; normalizes rule result, severity, references, evidence, and remediation | Requires applicable content; compliance severity is not automatically CVSS |
| OSV-Scanner | Cross-platform tool; inputs must be approved | Scans requested manifests, lockfiles, SBOMs, or source directories and normalizes advisories, aliases, affected/fixed versions, references, and supplied ratings | It does not derive a complete dependency graph from general installed-software inventory |
| OWASP dep-scan | Adapter supports Windows, Linux, macOS tool binaries | A configured tool is scheduled once in fixed `LIVE_OS` mode. Each requested approved directory is also scanned in `SOURCE` mode, and each approved CycloneDX JSON input in `SBOM` mode. CycloneDX VDR findings are normalized and merged with OSV evidence | Coverage depends on supported evidence and the tool's vulnerability data |
| OWASP Amass | External discovery, not endpoint inventory | Runs passive, bounded discovery for each explicitly authorized and allowlisted DNS domain; results remain separate `ATTACK_SURFACE` scans | Does not inspect local software, patches, files, or prove exploitability |

Native patch evidence reflects OS-provided update state. OSV-Scanner, dep-scan, and OpenSCAP use their source data/content. The scanner does not own or maintain a central advisory or CVE database. When a source supplies CVE, GHSA, OSV, CVSS, known-exploited, fixed-version, or reference data, the normalizer preserves it with provenance. Missing identifiers or scores are not invented. Native patch rows alone are not automatically correlated to a CVE.

## Storage-free execution and output

```text
explicit local request
  -> preflight authorization, endpoint, sources, domains, timeout, and output
       invalid authorization/scope -> reject without a scan or new report
       valid request -> initialize policy/scanner and construct audited child jobs
  -> collect and analyze one FULL endpoint result in memory
  -> run approved dependency modes and merge normalized vulnerability aliases/evidence
  -> collect each authorized domain into a separate in-memory ATTACK_SURFACE result
       child exception/global timeout -> bounded terminal FAILED child result
  -> calculate tool readiness, completeness, findings, and risk
  -> atomically write one combined UTF-8 JSON report
```

No persistent scanner database or child report is created. The JSON writer requires a `.json` destination, applies final redaction, enforces a byte bound, rejects symbolic-link destinations, uses atomic replacement, and requests owner-only permissions where supported.

The JSON can contain sensitive host inventory, users, services, addresses, and listeners. Protect it as restricted security data and apply encryption, tenant access, and retention controls when it is later uploaded.

## Normalization, provenance, readiness, and completeness

All collectors map evidence into the common `ScanResult` model. The combined report contains endpoint and separately scoped domain results; normalized inventory, compliance, vulnerability, attack-surface, finding, and risk structures; collector state, duration, version, record count, and bounded/redacted diagnostics; summary counts; and required, observed, and unobserved sections.

The top-level `audit_context` binds the report to the authorization decision and every child job.
It contains the bounded/redacted authorization reference, authorizer, purpose, validity window,
allowed endpoint/domain/network scope, exclusions, and subdomain decision. Its `jobs` array records
each child's `job_id`, `scan_id`, scan type, initiator, request time, deadline, and endpoint or
domain target. Report validation requires exactly one endpoint job, unique child job/scan IDs, a
matching audit entry for every child result, and targets and execution times within the recorded
authorization scope and window.

Invalid affirmative authorization or protected dependency/domain scope is a preflight rejection:
no child scan runs and no new combined report is written. Once preflight and scanner/policy
initialization succeed and child jobs have been constructed, an exception raised by a child scan,
including a global execution `TimeoutError`, is normalized instead of disappearing. The child has
terminal overall status `FAILED`; its `deep-scan` collector is `TIMEOUT` with
`DEEP_SCAN_TIMEOUT` or `FAILED` with `DEEP_SCAN_EXECUTION_FAILED`; all inventory sections are
marked unobserved, completeness is false, and the final combined JSON retains the child's audit
identity. Failures before child construction and failures while atomically writing the final file
cannot be represented by that file and are returned to the caller.

OSV and dep-scan vulnerability records are deterministically merged using affected package identity and advisory aliases while retaining source provenance. Unknown values remain `null` or explicitly unobserved rather than being guessed.

`tool_readiness` distinguishes configuration from scheduling. Native, osquery, and dep-scan are scheduled for the endpoint scan; missing configured executables therefore appear as readiness gaps for optional scheduled tools. OpenSCAP is scheduled on Linux and requires approved content/profile. OSV-Scanner is scheduled when dependency sources are requested. Amass is scheduled when domains are requested. A scheduled tool that is not `SUCCESS` adds `tool:<name>` to degraded collectors and makes the aggregate report incomplete/partial. Collector statuses explain `SKIPPED`, `UNAVAILABLE`, `PARTIAL`, `TIMEOUT`, or `FAILED` rather than treating missing coverage as success.

The deep scan always requires vulnerability observation; Linux additionally requires compliance observation. Native inventory can therefore succeed while the overall report honestly remains partial because optional vulnerability or compliance evidence was unavailable.

The current `browser_extensions` section is supplied by osquery rather than a native collector. It
is required by `deep-scan`, so an unconfigured, unavailable, incompatible, or failed osquery path
leaves that section unobserved and makes the aggregate report `PARTIAL`. The scanner does not turn
missing browser-extension visibility into an authoritative empty list.

## Authorization and protected configuration

The CLI requires `--authorized`. Dependency inputs must exist inside `tools.approved_dependency_roots`. Domains must be canonical, included in the request, and allowed by `discovery.authorized_domains`; discovery must be enabled and passive. Commands, tool arguments, osquery query IDs, limits, and parsers are scanner-owned. The request cannot supply arbitrary shell commands, SQL, remote URLs, executable paths, SCAP paths, or pentest payloads.

Start from [config/deep-scan.example.yaml](../config/deep-scan.example.yaml). Copy it to a protected local file and set only the absolute executable paths, approved roots/content, profiles, and domain allowlists that the organization has authorized. Leaving an optional executable as `null` disables its adapter but may still produce a readiness gap when that capability is scheduled.

## External prerequisites

| Capability | Local prerequisite |
| --- | --- |
| Native scan | This Python package/runtime and sufficient OS permissions |
| osquery | Configured `osqueryi` executable; optionally selected scanner-owned query IDs |
| OpenSCAP | Linux `oscap`, applicable trusted content under an approved root, and an exact profile |
| OSV-Scanner | Configured executable, approved dependency root, and a requested source |
| dep-scan | Configured executable and its required vulnerability data; `LIVE_OS` needs no requested dependency root, while `SOURCE`/`SBOM` inputs must be approved |
| Amass | Enabled passive discovery, allowlisted owned domains, configured executable, and required DNS/network/API access |

Optional binaries are not bundled in the Python wheel and are not enabled just because they are on `PATH`; their paths must be configured. Pin and qualify tool/content/advisory versions through the enterprise release process. OpenSCAP content is distribution/version specific, vulnerability coverage depends on current supported evidence, and Amass sources have independent availability and rate limits.

The integration test suite is offline and mocked by default. A dep-scan executable can be checked
with the opt-in live health test by setting `SCANNER_RUN_LIVE_TOOLS=1` and an approved absolute
`SCANNER_LIVE_DEPSCAN_EXECUTABLE` path. The deeper stateless orchestration qualification is gated
again by `SCANNER_RUN_LIVE_ENDPOINT_ORCHESTRATION=1` and
`SCANNER_LIVE_ENDPOINT_AUTHORIZED=1`; it constructs no domain job and retains no JSON report or
scanner database. These smoke tests do not replace per-OS/version compatibility, privilege,
performance, advisory freshness, false-positive, and false-negative qualification before an
enterprise rollout.

## Run and verify the current deep scan

These commands assume Python 3.12 or newer and that the repository has already been installed into `.venv` with `pip install -e .`. Copy the safe template first, then edit the copy for approved tools and scopes.

PowerShell:

```powershell
Set-Location 'C:\path\to\OS_Scanner'
Copy-Item .\config\deep-scan.example.yaml .\config\deep-scan.local.yaml

$result = & .\.venv\Scripts\python.exe -m app.cli deep-scan `
  --config .\config\deep-scan.local.yaml `
  --authorized `
  --output .\deep-scan-report.json | ConvertFrom-Json

$result
$report = Get-Content -LiteralPath $result.report -Raw -Encoding UTF8 | ConvertFrom-Json
$report.completeness
$report.tool_readiness
```

Linux or macOS shell:

```bash
cd /path/to/OS_Scanner
cp config/deep-scan.example.yaml config/deep-scan.local.yaml

./.venv/bin/python -m app.cli deep-scan \
  --config ./config/deep-scan.local.yaml \
  --authorized \
  --output ./deep-scan-report.json

python -m json.tool ./deep-scan-report.json >/dev/null
```

To request approved dependency and domain work, repeat the corresponding options:

```powershell
$result = & .\.venv\Scripts\python.exe -m app.cli deep-scan `
  --config .\config\deep-scan.local.yaml `
  --authorized `
  --dependency-source 'C:\ApprovedProjects\Application' `
  --domain 'example.com' `
  --authorization-reference 'change-ticket-1234' `
  --timeout 1800 `
  --output .\deep-scan-report.json | ConvertFrom-Json
```

The dependency path must fall under a configured approved root. The domain must be present in the protected discovery allowlist. The command prints a small JSON execution summary to stdout; the full combined report is at its `report` path. Review `completeness`, `tool_readiness`, and collector statuses before interpreting zero counts.

## Later cloud-agent and dashboard integration

```text
Endpoint agent                                      Cloud platform
--------------                                      --------------
Enroll with a short-lived bootstrap token           Authentication, tenant RBAC, endpoint registry
Poll outbound HTTPS for allowlisted jobs             Authorized job queue and policy assignment
Collect native endpoint evidence                     Idempotent JSON/SBOM ingestion and history
Run endpoint-required osquery/OpenSCAP                Isolated OSV/dep-scan analysis workers
Upload through a durable outbox                       Authorized Amass discovery workers
                                                      Dashboard, JSON/PDF exports
```

A cloud container cannot directly see an endpoint's Registry, processes, files, services, patch state, or listeners. An installed agent must collect live host evidence. OSV-Scanner and dep-scan can later run centrally when the endpoint uploads sufficient manifests or an SBOM. Amass naturally fits an isolated cloud discovery worker. OpenSCAP must run where it can inspect the Linux target state.

The repository provides collection, normalization, JSON reporting, endpoint transport/outbox foundations, optional adapters, and a CycloneDX exporter. Production cloud services still require tenant isolation, enrollment and credential rotation, ingestion validation, central storage, dashboards, monitoring, retention, signed installers, and safe update/rollback channels.

## Later pentest integration

```text
normalized scan evidence
  -> candidate applicability and priority
  -> explicit approval for target, method, and time window
  -> isolated validation/pentest worker
  -> separately normalized result and immutable audit trail
```

Software versions, missing patches, listeners, configuration posture, advisory aliases, supplied CVSS, and known-exploited signals can prioritize validation; they do not prove exploitability. Future pentest workers should use catalogued bounded tests, tenant RBAC, approvals, rate limits, kill switches, and audit events. No pentest executor exists in the current module.

## Official tool references

- [osquery local shell](https://osquery.readthedocs.io/en/stable/introduction/using-osqueryi/)
- [OpenSCAP user manual](https://static.open-scap.org/openscap-1.4.1/oscap_user_manual.html)
- [OSV-Scanner usage](https://google.github.io/osv-scanner/usage/)
- [OSV-Scanner supported artifacts](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)
- [OSV-Scanner output](https://google.github.io/osv-scanner/output/)
- [OWASP dep-scan project](https://owasp.org/www-project-dep-scan/)
- [OWASP dep-scan repository](https://github.com/owasp-dep-scan/dep-scan)
- [OWASP Amass documentation](https://owasp-amass.github.io/docs/)
