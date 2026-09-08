[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][switch]$Authorized,
    [string]$BaseUrl = "http://127.0.0.1:8080",
    [string]$EnvironmentPath = "cloud/.env.local",
    [string]$ScannerExecutable = "dist/endpoint/endpoint-scanner.exe",
    [string]$OutputRoot = "cloud/.e2e-agent",
    [ValidateSet("QUICK", "FULL", "COMPLIANCE", "VULNERABILITY")]
    [string]$ScanType = "FULL",
    [string]$OsqueryExecutable,
    [ValidateRange(60, 86400)][int]$TimeoutSeconds = 3600
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if (-not $Authorized) {
    throw "Refusing to scan this device without explicit -Authorized consent."
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$envFile = (Resolve-Path (Join-Path $root $EnvironmentPath)).Path
$scannerPath = (Resolve-Path (Join-Path $root $ScannerExecutable)).Path
if (-not (Test-Path -LiteralPath $scannerPath -PathType Leaf)) {
    throw "Scanner executable was not found: $scannerPath"
}
if ($OsqueryExecutable) {
    $OsqueryExecutable = (Resolve-Path -LiteralPath $OsqueryExecutable).Path
    if (-not (Test-Path -LiteralPath $OsqueryExecutable -PathType Leaf)) {
        throw "osquery executable was not found."
    }
}

$values = @{}
foreach ($line in [IO.File]::ReadAllLines($envFile)) {
    if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
        $key, $value = $line.Split("=", 2)
        $values[$key] = $value
    }
}
$enrollmentToken = $values["CLOUD_ENROLLMENT_TOKEN"]
$adminToken = $values["CLOUD_ADMIN_TOKEN"]
if (-not $enrollmentToken -or -not $adminToken) {
    throw "Local cloud credentials are missing from the environment file."
}

function Invoke-Json {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Token,
        [object]$Body,
        [string]$IdempotencyKey
    )
    $headers = @{
        Authorization = "Bearer $Token"
        Accept = "application/json"
        "X-Request-ID" = [guid]::NewGuid().ToString()
    }
    if ($IdempotencyKey) { $headers["Idempotency-Key"] = $IdempotencyKey }
    $parameters = @{
        Method = $Method
        Uri = "$BaseUrl$Path"
        Headers = $headers
        TimeoutSec = 30
    }
    if ($null -ne $Body) {
        $parameters.ContentType = "application/json"
        $parameters.Body = $Body | ConvertTo-Json -Depth 64 -Compress
    }
    Invoke-RestMethod @parameters
}

$readinessDeadline = [DateTimeOffset]::UtcNow.AddSeconds([Math]::Min(300, $TimeoutSeconds))
do {
    try {
        Invoke-RestMethod "$BaseUrl/readyz" -TimeoutSec 3 | Out-Null
        break
    }
    catch {
        Start-Sleep -Seconds 2
    }
} while ([DateTimeOffset]::UtcNow -lt $readinessDeadline)
if ([DateTimeOffset]::UtcNow -ge $readinessDeadline) {
    throw "Cloud API did not become ready before the test deadline."
}

$runId = [guid]::NewGuid().ToString("N")
$runRoot = Join-Path (Join-Path $root $OutputRoot) $runId
$dataRoot = Join-Path $runRoot "endpoint-data"
New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
$configPath = Join-Path $runRoot "endpoint-config.json"
$reportPath = Join-Path $runRoot "final-cloud-report.json"

$tools = @{}
if ($OsqueryExecutable) { $tools.osquery_executable = $OsqueryExecutable }
$config = @{
    environment = "development"
    data_directory = $dataRoot
    log_level = "INFO"
    policies = @{ cloud_sync_enabled = $true }
    cloud = @{
        base_url = $BaseUrl
        allow_insecure_loopback_http = $true
        offload_vulnerability_analysis = $true
        connect_timeout_seconds = 5
        read_timeout_seconds = 30
        max_retries = 3
    }
    scheduling = @{
        enabled = $false
        startup_scan = $false
        periodic_interval_seconds = $null
    }
    tools = $tools
}
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText(
    $configPath,
    ($config | ConvertTo-Json -Depth 20),
    $utf8
)

$originalEnrollmentToken = [Environment]::GetEnvironmentVariable(
    "SCANNER_ENROLLMENT_TOKEN", "Process"
)
try {
    $env:SCANNER_ENROLLMENT_TOKEN = $enrollmentToken
    $enrollmentOutput = @(& $scannerPath enroll --config $configPath)
    if ($LASTEXITCODE -ne 0) { throw "Endpoint enrollment failed." }
}
finally {
    if ($null -eq $originalEnrollmentToken) {
        Remove-Item Env:SCANNER_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    }
    else {
        $env:SCANNER_ENROLLMENT_TOKEN = $originalEnrollmentToken
    }
}
$enrollment = $enrollmentOutput[-1] | ConvertFrom-Json
$endpointId = $enrollment.endpoint_id
if (-not $endpointId) { throw "Enrollment response did not contain an endpoint ID." }

$created = Invoke-Json POST "/api/v1/platform/scans" $adminToken @{
    endpoint_id = $endpointId
    scan_type = $ScanType
    authorization_reference = "local-real-endpoint-test-$runId"
    authorized_by = "local-e2e-operator"
    purpose = "Authorized end-to-end scan of the device running the endpoint agent"
    validity_seconds = $TimeoutSeconds
    timeout_seconds = [Math]::Min(900, $TimeoutSeconds)
} "real-endpoint-create-$runId"
$scanId = $created.scan_id
if (-not $scanId -and $created.job) { $scanId = $created.job.scan_id }
if (-not $scanId) { throw "Platform response did not contain a scan ID." }

$agentOutput = @(
    & $scannerPath agent --once --config $configPath --endpoint-id $endpointId
)
if ($LASTEXITCODE -ne 0) { throw "Endpoint agent iteration failed." }
$agentSummary = $agentOutput[-1] | ConvertFrom-Json
if (-not $agentSummary.online) { throw "Endpoint agent could not reach the cloud API." }
if (-not $agentSummary.scan -or $agentSummary.scan.scan_id -ne $scanId) {
    throw "Endpoint agent did not execute the authorized cloud scan."
}
if ($agentSummary.uploads.dead -ne 0) {
    throw "Endpoint upload queue contains a dead-letter item."
}

# The scan remains durable when a transient network/server error schedules a
# retry. Drain that exact fresh endpoint outbox before waiting for analysis so
# the harness cannot spend an hour polling a report whose evidence is local.
$uploadDeadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
$queue = $agentSummary.queue
while (($queue.pending + $queue.in_flight) -gt 0) {
    if ([DateTimeOffset]::UtcNow -ge $uploadDeadline) {
        throw "Timed out draining the endpoint upload queue for $scanId."
    }
    Start-Sleep -Seconds 2
    $uploadOutput = @(
        & $scannerPath upload --config $configPath --endpoint-id $endpointId --limit 10
    )
    $uploadExitCode = $LASTEXITCODE
    $uploadSummary = $uploadOutput[-1] | ConvertFrom-Json
    if ($uploadExitCode -ne 0 -or $uploadSummary.dead -ne 0 -or $uploadSummary.queue.dead -ne 0) {
        throw "Endpoint upload queue entered a dead-letter state."
    }
    $queue = $uploadSummary.queue
}

$report = $null
$reportDeadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
do {
    try {
        $report = Invoke-Json GET `
            "/api/v1/platform/scans/$([uri]::EscapeDataString($scanId))/report" `
            $adminToken $null $null
        if ($report) { break }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -notin 404, 409, 425) { throw }
    }
    Start-Sleep -Seconds 2
} while ([DateTimeOffset]::UtcNow -lt $reportDeadline)
if (-not $report) { throw "Timed out waiting for normalized cloud report $scanId." }

[IO.File]::WriteAllText(
    $reportPath,
    ($report | ConvertTo-Json -Depth 100),
    $utf8
)
[pscustomobject]@{
    endpoint_id = $endpointId
    scan_id = $scanId
    endpoint_scan_status = $agentSummary.scan.status
    cloud_report_status = $report.status
    vulnerability_count = $report.summary.vulnerability_count
    fixture_mode = $report.completeness.fixture_mode
    report = $reportPath
    endpoint_data = $dataRoot
} | ConvertTo-Json -Depth 10
