[CmdletBinding()]
param(
    [string]$BaseUrl = "http://127.0.0.1:8080",
    [string]$EnvironmentPath = "cloud/.env.local",
    [int]$TimeoutSeconds = 3600
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$envFile = Join-Path $root $EnvironmentPath
if (-not (Test-Path -LiteralPath $envFile)) { throw "Missing $envFile" }
$values = @{}
foreach ($line in [IO.File]::ReadAllLines($envFile)) {
    if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
        $key, $value = $line.Split("=", 2)
        $values[$key] = $value
    }
}
$enrollmentToken = $values["CLOUD_ENROLLMENT_TOKEN"]
$adminToken = $values["CLOUD_ADMIN_TOKEN"]
if (-not $enrollmentToken -or -not $adminToken) { throw "Local tokens are missing from $envFile" }

function Invoke-Json {
    param([string]$Method, [string]$Path, [string]$Token, [object]$Body, [string]$IdempotencyKey)
    $headers = @{ Authorization = "Bearer $Token"; Accept = "application/json"; "X-Request-ID" = [guid]::NewGuid().ToString() }
    if ($IdempotencyKey) { $headers["Idempotency-Key"] = $IdempotencyKey }
    $parameters = @{ Method = $Method; Uri = "$BaseUrl$Path"; Headers = $headers; TimeoutSec = 30 }
    if ($null -ne $Body) {
        $parameters.ContentType = "application/json"
        $parameters.Body = $Body | ConvertTo-Json -Depth 40 -Compress
    }
    return Invoke-RestMethod @parameters
}

$readinessDeadline = [DateTimeOffset]::UtcNow.AddSeconds([Math]::Min(300, $TimeoutSeconds))
do {
    try { Invoke-RestMethod "$BaseUrl/readyz" -TimeoutSec 3 | Out-Null; break } catch { Start-Sleep -Seconds 2 }
} while ([DateTimeOffset]::UtcNow -lt $readinessDeadline)
if ([DateTimeOffset]::UtcNow -ge $readinessDeadline) { throw "Cloud API did not become ready" }

$suffix = [guid]::NewGuid().ToString("N").Substring(0, 12)
$enrollment = Invoke-Json POST "/api/v1/endpoint/enroll" $enrollmentToken @{
    hostname = "fixture-$suffix"; os_family = "LINUX"; os_version = "fixture";
    architecture = "x86_64"; scanner_version = "1.1.0"
} "smoke-enroll-$suffix"
$credential = if ($enrollment.credential) { $enrollment.credential } else { $enrollment }
$endpointId = $credential.endpoint_id
$endpointToken = $credential.access_token
if (-not $endpointId -or -not $endpointToken) { throw "Enrollment response did not contain a credential" }

$created = Invoke-Json POST "/api/v1/platform/scans" $adminToken @{
    endpoint_id = $endpointId; scan_type = "FULL";
    authorization_reference = "local-authorized-fixture-$suffix";
    authorized_by = "local-e2e-smoke";
    purpose = "Validate transport and cloud analysis without scanning a live asset";
    validity_seconds = 900; timeout_seconds = 300
} "smoke-create-$suffix"
$scanId = $created.scan_id
if (-not $scanId -and $created.job) { $scanId = $created.job.scan_id }
if (-not $scanId) { throw "Platform scan response did not contain scan_id" }

$job = Invoke-Json GET "/api/v1/scans/next/$([uri]::EscapeDataString($endpointId))" $endpointToken $null $null
if ($job.scan_id -ne $scanId) { throw "Endpoint did not receive the created authorized scan job" }
$scopeId = $job.authorization.scope_id

$resultText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "fixtures/endpoint-result.json"))
$result = $resultText.Replace("{{SCAN_ID}}", $scanId).Replace("{{ENDPOINT_ID}}", $endpointId).Replace("{{SCOPE_ID}}", $scopeId) | ConvertFrom-Json
$sbom = Get-Content (Join-Path $PSScriptRoot "fixtures/cyclonedx-sbom.json") -Raw | ConvertFrom-Json
$inventorySnapshot = @{ software = @(@{ name = "requests"; version = "2.32.5"; package_manager = "pypi" }) }
# app.storage.snapshots hashes normalized JSON with sorted object keys and no whitespace.
$canonicalInventory = '{"software":[{"name":"requests","package_manager":"pypi","version":"2.32.5"}]}'
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $inventoryHash = [BitConverter]::ToString(
        $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonicalInventory))
    ).Replace("-", "").ToLowerInvariant()
}
finally {
    $sha256.Dispose()
}
$upload = @{ result = $result; inventory_sync = @{
    endpoint_id = $endpointId; scan_id = $scanId; schema_version = "1.0";
    policy_version = "1.0.0"; scanner_version = "1.1.0";
    snapshot_hash = $inventoryHash; previous_hash = $null; mode = "full";
    snapshot = $inventorySnapshot
}; sbom = $sbom }
Invoke-Json POST "/api/v1/scans" $endpointToken $upload "smoke-upload-$suffix" | Out-Null

$reportDeadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
do {
    try {
        $report = Invoke-Json GET "/api/v1/platform/scans/$([uri]::EscapeDataString($scanId))/report" $adminToken $null $null
        if ($report) { break }
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -notin 404, 409, 425) { throw }
    }
    Start-Sleep -Seconds 2
} while ([DateTimeOffset]::UtcNow -lt $reportDeadline)
if (-not $report) { throw "Timed out waiting for normalized report $scanId" }

[pscustomobject]@{
    endpoint_id = $endpointId
    scan_id = $scanId
    report_status = $report.status
    fixture_only = $true
    live_asset_scanned = $false
} | ConvertTo-Json -Depth 5
