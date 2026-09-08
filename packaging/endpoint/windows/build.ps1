#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][System.IO.FileInfo]$Manifest,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ManifestSha256,
    [Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$ArtifactRoot,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?$')][string]$Version,
    [Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$OutputDirectory,
    [string]$Python = 'python',
    [string]$InnoCompiler = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows -or -not [Environment]::Is64BitOperatingSystem) {
    throw 'Build the Windows x86_64 installer on 64-bit Windows.'
}
if (-not $Manifest.Exists) { throw 'Approved input manifest does not exist.' }
if (-not $ArtifactRoot.Exists) { throw 'Offline artifact root does not exist.' }
if (-not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
    throw 'Inno Setup 6 compiler is required on the release build machine.'
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$identifier = [Guid]::NewGuid().ToString('N')
$buildRoot = Join-Path $projectRoot "build\endpoint-packages\windows-$Version-$identifier"
$verified = Join-Path $buildRoot 'verified'
$stage = Join-Path $buildRoot 'stage'
$pyinstallerDist = Join-Path $buildRoot 'scanner-dist'
$pyinstallerWork = Join-Path $buildRoot 'pyinstaller-work'
New-Item -ItemType Directory -Path $buildRoot, $stage -ErrorAction Stop | Out-Null
if (-not $OutputDirectory.Exists) {
    New-Item -ItemType Directory -Path $OutputDirectory.FullName | Out-Null
}
$expectedInstaller = Join-Path $OutputDirectory.FullName `
    "endpoint-scanner-$Version-windows-x86_64.exe"
if (Test-Path -LiteralPath $expectedInstaller) {
    throw 'Refusing to overwrite an existing installer.'
}

& $Python (Join-Path $projectRoot 'packaging\endpoint\tools\verify_inputs.py') `
    --manifest $Manifest.FullName `
    --manifest-sha256 $ManifestSha256.ToLowerInvariant() `
    --artifact-root $ArtifactRoot.FullName `
    --stage-dir $verified `
    --target windows-x86_64 `
    --require-component osquery `
    --require-component winsw
if ($LASTEXITCODE -ne 0) { throw 'Native input verification failed.' }

& $Python -m PyInstaller --noconfirm --clean `
    --distpath $pyinstallerDist --workpath $pyinstallerWork `
    (Join-Path $projectRoot 'packaging\endpoint\endpoint-scanner.spec')
if ($LASTEXITCODE -ne 0) { throw 'Standalone scanner build failed.' }

Copy-Item -LiteralPath (Join-Path $pyinstallerDist 'endpoint-scanner.exe') -Destination $stage
Copy-Item -LiteralPath (Join-Path $verified 'components\osquery\osqueryi.exe') `
    -Destination (New-Item -ItemType Directory -Path (Join-Path $stage 'tools\osquery')).FullName
Copy-Item -LiteralPath (Join-Path $verified 'components\winsw\EndpointScannerService.exe') `
    -Destination $stage
Copy-Item -LiteralPath (Join-Path $verified 'licenses') -Destination $stage -Recurse
Copy-Item -LiteralPath (Join-Path $verified 'verified-inputs.json') -Destination $stage
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\endpoint\config\windows.yaml') `
    -Destination (Join-Path $stage 'config.yaml')
Copy-Item -LiteralPath (Join-Path $projectRoot 'app\policies\defaults\enterprise-default.yaml') `
    -Destination $stage
foreach ($name in @(
    'EndpointScannerService.xml', 'Configure-Acls.ps1',
    'Enroll-LocalService.ps1', 'Enroll-And-Start.ps1'
)) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $stage
}

$contentLines = Get-ChildItem -LiteralPath $stage -File -Recurse | Sort-Object FullName | ForEach-Object {
    $relative = [System.IO.Path]::GetRelativePath($stage, $_.FullName).Replace('\', '/')
    $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
    "$digest *$relative"
}
[System.IO.File]::WriteAllLines((Join-Path $stage 'PACKAGE-CONTENTS.sha256'), $contentLines)

& $InnoCompiler "/DAppVersion=$Version" "/DStageDir=$stage" `
    "/DOutputDir=$($OutputDirectory.FullName)" `
    (Join-Path $PSScriptRoot 'endpoint-scanner.iss')
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $expectedInstaller -PathType Leaf)) {
    throw 'Inno Setup did not produce the expected installer.'
}
$packageHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $expectedInstaller).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText("$expectedInstaller.sha256", "$packageHash *$([IO.Path]::GetFileName($expectedInstaller))`n")
[pscustomobject]@{
    status = 'BUILT_UNSIGNED'
    installer = $expectedInstaller
    sha256 = $packageHash
    build_root = $buildRoot
} | ConvertTo-Json -Compress
