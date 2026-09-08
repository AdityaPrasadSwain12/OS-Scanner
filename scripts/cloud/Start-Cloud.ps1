[CmdletBinding()]
param([switch]$Build)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$envFile = Join-Path $root "cloud/.env.local"
if (-not (Test-Path -LiteralPath $envFile)) {
    & (Join-Path $PSScriptRoot "Initialize-CloudEnvironment.ps1")
}
$arguments = @("compose", "--env-file", $envFile, "-f", (Join-Path $root "docker-compose.cloud.yml"), "up", "-d", "--wait")
if ($Build) { $arguments += "--build" }
& docker @arguments
if ($LASTEXITCODE -ne 0) { throw "docker compose failed with exit code $LASTEXITCODE" }
Write-Host "API:       http://127.0.0.1:8080"
Write-Host "Dashboard: http://127.0.0.1:8081"
Write-Host "Local tokens are in cloud/.env.local; they were not printed."

