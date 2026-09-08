[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$envFile = Join-Path $root "cloud/.env.local"
if (-not (Test-Path -LiteralPath $envFile)) {
    throw "Missing cloud/.env.local; there is no generated local stack configuration."
}
& docker compose --env-file $envFile -f (Join-Path $root "docker-compose.cloud.yml") down
if ($LASTEXITCODE -ne 0) { throw "docker compose down failed with exit code $LASTEXITCODE" }
Write-Host "Cloud containers stopped. Named database and analysis-cache volumes were preserved."
