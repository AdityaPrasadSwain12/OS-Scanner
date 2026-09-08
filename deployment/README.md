# Service deployment templates

These files are starting points for running `endpoint-scanner agent`; they are not installers.
They do not install Python, the scanner wheel, a secure keyring, a service wrapper, users, ACLs,
certificates, or credentials. They are not signed. The scanner wheel is the only application
required for core service-mode endpoint collection. Optional osquery, OpenSCAP, OSV-Scanner,
Amass, and SCAP content are separate only when those enrichment capabilities are enabled.

Before enabling a service:

1. build, verify, and externally sign the scanner/package through the organization release process;
2. install a protected configuration with the correct HTTPS origin/routes/CA and least-privilege
   local roots/baselines;
3. create a dedicated service account and state/report/log directories;
4. enroll as that runtime principal or configure an approved protected environment credential;
5. install qualified optional tools/content at protected fixed paths only if enabled;
6. run `endpoint-scanner health` as the runtime principal;
7. run `endpoint-scanner local-scan --authorized --scan-type QUICK` as a native canary and confirm
   collector completeness, report, SQLite, queue, and
   cloud idempotency.

Some posture commands require elevated read permissions. Grant only the specific permissions needed
by the approved policy. If access is withheld, the collector should remain visibly partial/failed;
do not hide the status or infer a healthy value.

## Linux systemd

`systemd/endpoint-scanner.service` runs as the dedicated `endpoint-scanner` account. It enables
`NoNewPrivileges`, private temporary/devices, system/home/kernel/control-group protections,
SUID/personality/realtime restrictions, `UMask=0077`, and makes only
`/var/lib/endpoint-scanner` writable. `systemd/endpoint-scanner.tmpfiles` creates state/report
directories with mode `0700`.

Customize installation/configuration paths and review hardening against required read-only
tool/content locations. Install approximately as:

```bash
install -o root -g root -m 0644 deployment/systemd/endpoint-scanner.service \
  /etc/systemd/system/endpoint-scanner.service
install -o root -g root -m 0644 deployment/systemd/endpoint-scanner.tmpfiles \
  /etc/tmpfiles.d/endpoint-scanner.conf
systemd-tmpfiles --create /etc/tmpfiles.d/endpoint-scanner.conf
systemctl daemon-reload
systemctl enable --now endpoint-scanner.service
```

The optional `/etc/endpoint-scanner/environment` is read by systemd. If it carries an injected
credential, protect it as a secret; prefer a service credential provider supported by the deployment.
For stored credentials, provision a secure non-interactive native keyring for this exact account.

## macOS launchd

`macos/com.example.endpoint-scanner.plist` uses the non-login `_endpointscanner` user/group, a fixed
virtual-environment path, RunAtLoad, failure keep-alive, and log files under
`/Library/Logs/EndpointScanner`.

Customize the reverse-DNS label and paths. The installer must create the account/group and protect
application/config/policy/state/log paths. Configure Keychain access for this service identity or an
approved secret injection; an interactive user's keychain is not automatically available to a
LaunchDaemon. Validate with `plutil`, then sign/notarize the final installer/package externally.

## Windows WinSW

`windows/endpoint-scanner.xml` is a WinSW-compatible descriptor. It runs the virtual-environment
entry point as built-in `LocalService`, restarts after failure, and rolls wrapper logs. WinSW itself
is not included.

Customize `%BASE%`, configuration/state ACLs, wrapper name, endpoint identity, and log policy. Use a
dedicated managed service account when `LocalService` lacks required read access; avoid
`LocalSystem`. The DPAPI-protected credential is bound to the principal that enrolled, so enroll as
the runtime identity or use approved managed secret injection. Sign the final wrapper/package with
the organization's Authenticode process.

## Scheduling and shutdown

The `agent` command supports authenticated cloud jobs, protected startup and periodic scans,
coalesced policy-change scans, proactive credential rotation, and jitter. It executes at most one
scan at a time in its process. SIGTERM/SIGINT request cooperative shutdown; SIGHUP requests a policy
scan where that signal exists. Service-manager restart handles unexpected process failure.

Do not add a second scheduler unless its concurrency, duplicate scan IDs, authorization, and
resource interactions have been explicitly designed and tested.

Docker files in the repository are for CI/test isolation only. The production endpoint agent does
not require or use Docker.

See [the operations guide](../docs/operations.md) for enrollment, retention, backup, policy rollout,
monitoring, upgrades, and troubleshooting.
