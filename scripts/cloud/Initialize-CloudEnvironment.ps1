[CmdletBinding()]
param(
    [string]$OutputPath = "cloud/.env.local",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$resolvedRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$target = Join-Path $resolvedRoot $OutputPath
if ((Test-Path -LiteralPath $target) -and -not $Force) {
    throw "Environment file already exists: $target. Use -Force to replace it."
}

function New-HexSecret([int]$Bytes) {
    $buffer = New-Object byte[] $Bytes
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($buffer) } finally { $generator.Dispose() }
    return ($buffer | ForEach-Object { $_.ToString("x2") }) -join ""
}

$parent = Split-Path -Parent $target
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$content = @(
    "# Generated local-development values. Do not commit or reuse in production."
    "SCANNER_ENVIRONMENT=development"
    "CLOUD_BIND_ADDRESS=127.0.0.1"
    "CLOUD_API_PORT=8080"
    "CLOUD_DASHBOARD_PORT=8081"
    "CLOUD_TENANT_ID=tenant-local"
    "POSTGRES_DATABASE=scanner"
    "POSTGRES_USER=scanner"
    "POSTGRES_PASSWORD=$(New-HexSecret 24)"
    "CLOUD_ENROLLMENT_TOKEN=$(New-HexSecret 32)"
    "CLOUD_ADMIN_TOKEN=$(New-HexSecret 32)"
    "SCANNER_CREDENTIAL_PEPPER=$(New-HexSecret 48)"
    "SCANNER_ANALYSIS_FIXTURE_MODE=false"
) -join [Environment]::NewLine
[IO.File]::WriteAllText($target, $content + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
Write-Host "Generated local cloud environment: $target"
