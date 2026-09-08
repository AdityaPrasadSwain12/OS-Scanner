# Managed endpoint packages

This directory turns the Python agent into native, self-contained endpoint packages. It is an
offline release build: the scripts never download vendor software, and installed endpoints never
download a runtime or tool. Each package contains:

- the scanner and its Python runtime as one PyInstaller executable;
- a platform/architecture-specific `osqueryi` binary;
- a managed configuration that uploads evidence and a CycloneDX SBOM for cloud-side OSV and
  dep-scan analysis;
- a service definition and an enrollment helper;
- verified vendor license texts, the approved-input receipt, and package-content hashes.

OSV-Scanner, OWASP dep-scan, Amass, Docker, and a separate Python installation are not put on the
endpoint. The service is installed in a stopped/disabled state. Only a successful enrollment run
under the service identity enables and starts it.

## Trust and input contract

Copy the matching file in `manifests/` to release-controlled metadata and replace every `PIN_*`
value. Record the exact vendor version, byte size, SHA-256, license expression, license file size,
and license SHA-256. Review the vendor signature/checksum and license before approving the
manifest. Then calculate the manifest's own SHA-256 and supply that independently to the build.

`tools/verify_inputs.py` requires the approved manifest hash, rejects placeholder hashes, unknown
or missing components, duplicate JSON keys, traversal, absolute paths, symlinks, over-sized files,
and digest/size mismatches. It copies verified bytes to a newly created stage and emits
`verified-inputs.json`. Package builders consume only that stage. A changed manifest or binary
therefore requires a new explicit approval.

Expected offline input layouts are shown by each example manifest. Windows requires `osquery` and
`winsw`; Linux and macOS require `osquery`. Scanner source and Python dependencies come from this
repository and the already provisioned, platform-native build environment.

## Native build commands

Install the hash-locked release build environment from an internal artifact repository before
disconnecting network access. It needs Python 3.12, the project runtime dependencies, and the exact
PyInstaller versions in the repository's `requirements-build.lock`. Builds must run natively for
their target OS and architecture; PyInstaller is not a cross-compiler.

Windows x86-64 also needs Inno Setup 6:

```powershell
$manifestHash = (Get-FileHash .\approved\windows-x86_64.json -Algorithm SHA256).Hash
pwsh .\packaging\endpoint\windows\build.ps1 `
  -Manifest .\approved\windows-x86_64.json `
  -ManifestSha256 $manifestHash `
  -ArtifactRoot D:\approved-endpoint-inputs `
  -Version 1.1.0 `
  -OutputDirectory .\dist\endpoint
```

Debian amd64 or arm64 needs `dpkg-deb`, GNU coreutils, and util-linux. Use an approved release
epoch so payload timestamps are controlled:

```bash
manifest_hash=$(sha256sum approved/linux-x86_64.json | cut -d ' ' -f 1)
./packaging/endpoint/linux/build.sh \
  --manifest approved/linux-x86_64.json \
  --manifest-sha256 "$manifest_hash" \
  --artifact-root /srv/approved-endpoint-inputs \
  --version 1.1.0 \
  --output-dir dist/endpoint \
  --source-date-epoch 1788307200
```

macOS arm64 or x86-64 needs Xcode Command Line Tools (`pkgbuild`, `plutil`):

```bash
manifest_hash=$(shasum -a 256 approved/macos-arm64.json | cut -d ' ' -f 1)
./packaging/endpoint/macos/build.sh \
  --manifest approved/macos-arm64.json \
  --manifest-sha256 "$manifest_hash" \
  --artifact-root /Volumes/ApprovedInputs \
  --version 1.1.0 \
  --output-dir dist/endpoint \
  --source-date-epoch 1788307200
```

Every command refuses to overwrite an existing output and produces a sibling `.sha256` file. The
status is `BUILT_UNSIGNED` by design; signing is a separate protected release-pipeline operation.

## Install, configure, enroll, start

Before enrollment, replace the example HTTPS origin in the installed `config.yaml`, install the
organization CA bundle if applicable, and validate tenant-specific policy. Never put an enrollment
token, device credential, private key, or tenant secret in this file or installer.

On Windows, install the generated `.exe` as administrator. It creates the WinSW service as
`LocalService` with Manual start and protects state/config ACLs. In an elevated PowerShell process:

```powershell
$env:SCANNER_ENROLLMENT_TOKEN = '<one-time token from the platform>'
& "$env:ProgramFiles\Endpoint Scanner\Enroll-And-Start.ps1"
Remove-Item Env:\SCANNER_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
```

The helper uses an ACL-protected short-lived file and a one-time scheduled task so enrollment runs
as `LocalService`; the resulting endpoint credential is protected by DPAPI for that same identity.
The token is not placed in task arguments, service XML, installer metadata, or logs.

On Debian, install with `dpkg -i`. Configure `/etc/endpoint-scanner/config.yaml`, then enter a root
shell through the organization's privileged-access workflow and run:

```bash
read -r -s SCANNER_ENROLLMENT_TOKEN && export SCANNER_ENROLLMENT_TOKEN
/usr/sbin/endpoint-scanner-enroll
unset SCANNER_ENROLLMENT_TOKEN
```

The helper moves the token through a mode-0600 temporary file in `/run`, drops to the dedicated
service account, enrolls, creates the service condition marker, and only then enables/starts
systemd. The package's `postinst` never starts the service.

On macOS, configure `/Library/Application Support/EndpointScanner/config.yaml`, then run the same
protected root-shell pattern with `/usr/local/sbin/endpoint-scanner-enroll`. The LaunchDaemon ships
with `Disabled=true`; successful service-account enrollment enables, bootstraps, and starts it.

## Verification after installation

Confirm the service identity, executable/config ACLs, package hash, and `verified-inputs.json`.
Then verify enrollment and one authorized platform job end to end: the agent polls over TLS,
collects native and osquery evidence, queues it durably, uploads the normalized result and SBOM,
and receives a cloud report after OSV/dep-scan workers finish. A degraded collector must remain
visible as degraded; packaging must never turn missing permission or tool evidence into a healthy
result.

## External release inputs and honest production gaps

These files are production-oriented build scaffolding, not signed release artifacts. A release
still requires:

- approved osquery and WinSW binaries, vendor checksums/signatures, exact versions, and license
  texts; this repository intentionally does not fetch or redistribute them;
- Authenticode certificates and timestamping for the Windows agent, WinSW wrapper, and installer;
  an APT repository signing key for Debian; Apple Developer ID Installer/Application identities,
  hardened-runtime assessment, notarization, and stapling for macOS;
- a legal EULA/proprietary notice plus a complete generated third-party notice/SBOM for the bundled
  Python runtime and libraries (the current receipt covers the supplied native tools only);
- a qualified non-interactive secure keyring for the dedicated Linux/macOS service account. The
  application rejects null/plaintext backends, so enrollment intentionally fails without one;
- final platform URL, CA trust, tenant enrollment issuance, MDM/SCCM/Jamf deployment policy,
  least-privilege read grants, proxy behavior, rollback strategy, and native clean-VM tests;
- architecture-specific CI runners and reproducibility comparison. PyInstaller and native package
  tooling must run on each target OS; this Windows workspace cannot truthfully emit/test macOS or
  Debian installers.

Least-privilege service identities may not be allowed to read every user profile or protected OS
setting. Grant only approved read permissions through enterprise policy; the report's completeness
and collector statuses identify anything that remains unobserved.
