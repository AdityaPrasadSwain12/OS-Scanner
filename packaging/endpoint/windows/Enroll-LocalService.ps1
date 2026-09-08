[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TokenFile,
    [Parameter(Mandatory = $true)][string]$ResultFile,
    [Parameter(Mandatory = $true)][string]$ScannerExecutable,
    [Parameter(Mandatory = $true)][string]$ConfigFile
)

$ErrorActionPreference = 'Stop'
$exitCode = 2
$detail = 'enrollment did not run'
try {
    $token = [System.IO.File]::ReadAllText($TokenFile).Trim()
    Remove-Item -LiteralPath $TokenFile -Force
    if ([string]::IsNullOrWhiteSpace($token)) { throw 'Enrollment token is empty.' }
    $env:SCANNER_ENROLLMENT_TOKEN = $token
    $token = $null
    $output = & $ScannerExecutable enroll --config $ConfigFile 2>&1
    $exitCode = $LASTEXITCODE
    $detail = ($output | Out-String).Trim()
}
catch {
    $detail = $_.Exception.Message
}
finally {
    Remove-Item Env:\SCANNER_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $TokenFile -Force -ErrorAction SilentlyContinue
    $record = @{ exit_code = $exitCode; detail = $detail } | ConvertTo-Json -Compress
    [System.IO.File]::WriteAllText($ResultFile, $record)
}
exit $exitCode
