#Requires -RunAsAdministrator
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$base = Join-Path $env:ProgramData 'EndpointScanner'
$state = Join-Path $base 'state'
$logs = Join-Path $base 'logs'
$policies = Join-Path $base 'policies'
$config = Join-Path $base 'config.yaml'

foreach ($directory in @($base, $state, $logs, $policies)) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
}

& "$env:SystemRoot\System32\icacls.exe" $base '/inheritance:r' `
    '/grant:r' 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' `
    'BUILTIN\Administrators:(OI)(CI)(F)' `
    'NT AUTHORITY\LOCAL SERVICE:(RX)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to protect the endpoint scanner directory.' }

foreach ($writable in @($state, $logs)) {
    & "$env:SystemRoot\System32\icacls.exe" $writable `
        '/grant:r' 'NT AUTHORITY\LOCAL SERVICE:(OI)(CI)(M)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to protect $writable." }
}

& "$env:SystemRoot\System32\icacls.exe" $policies `
    '/grant:r' 'NT AUTHORITY\LOCAL SERVICE:(OI)(CI)(RX)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to protect the policy directory.' }

if (Test-Path -LiteralPath $config -PathType Leaf) {
    & "$env:SystemRoot\System32\icacls.exe" $config '/inheritance:r' `
        '/grant:r' 'NT AUTHORITY\SYSTEM:(F)' 'BUILTIN\Administrators:(F)' `
        'NT AUTHORITY\LOCAL SERVICE:(R)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to protect the scanner configuration.' }
}
