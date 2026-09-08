#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$ConfigFile = (Join-Path $env:ProgramData 'EndpointScanner\config.yaml'),
    [ValidateRange(30, 300)][int]$TimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
$serviceName = 'EndpointSecurityScanner'
$installRoot = Join-Path $env:ProgramFiles 'Endpoint Scanner'
$scanner = Join-Path $installRoot 'endpoint-scanner.exe'
$worker = Join-Path $installRoot 'Enroll-LocalService.ps1'
$state = Join-Path $env:ProgramData 'EndpointScanner\state'
$token = [Environment]::GetEnvironmentVariable('SCANNER_ENROLLMENT_TOKEN', 'Process')
if ([string]::IsNullOrWhiteSpace($token)) {
    throw 'Set SCANNER_ENROLLMENT_TOKEN in this elevated process before enrollment.'
}
if (-not (Test-Path -LiteralPath $scanner -PathType Leaf)) { throw 'Scanner is not installed.' }
if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) { throw 'Config file is missing.' }

$identifier = [Guid]::NewGuid().ToString('N')
$tokenFile = Join-Path $state ".enrollment-$identifier.token"
$resultFile = Join-Path $state ".enrollment-$identifier.result.json"
$taskName = "EndpointScannerEnrollment-$identifier"
try {
    [System.IO.File]::WriteAllText($tokenFile, $token)
    Remove-Item Env:\SCANNER_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    $token = $null
    & "$env:SystemRoot\System32\icacls.exe" $tokenFile '/inheritance:r' `
        '/grant:r' 'NT AUTHORITY\SYSTEM:(F)' 'BUILTIN\Administrators:(F)' `
        'NT AUTHORITY\LOCAL SERVICE:(M)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to protect the temporary enrollment token.' }

    $arguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned',
        '-File', ('"{0}"' -f $worker),
        '-TokenFile', ('"{0}"' -f $tokenFile),
        '-ResultFile', ('"{0}"' -f $resultFile),
        '-ScannerExecutable', ('"{0}"' -f $scanner),
        '-ConfigFile', ('"{0}"' -f $ConfigFile)
    ) -join ' '
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' `
        -LogonType ServiceAccount -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit `
        (New-TimeSpan -Seconds $TimeoutSeconds) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal `
        -Settings $settings | Out-Null
    Start-ScheduledTask -TaskName $taskName

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not (Test-Path -LiteralPath $resultFile -PathType Leaf)) {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Endpoint enrollment timed out.' }
        Start-Sleep -Milliseconds 250
    }
    $result = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
    if ([int]$result.exit_code -ne 0) {
        throw "Endpoint enrollment failed: $($result.detail)"
    }

    Set-Service -Name $serviceName -StartupType Automatic
    Start-Service -Name $serviceName
    [pscustomobject]@{
        status = 'ENROLLED_AND_STARTED'
        service = $serviceName
        detail = $result.detail
    } | ConvertTo-Json -Compress
}
finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tokenFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $resultFile -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\SCANNER_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    $token = $null
}
