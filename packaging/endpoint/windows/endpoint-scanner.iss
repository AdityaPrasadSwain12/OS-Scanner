#ifndef AppVersion
  #error AppVersion must be provided by the build script
#endif
#ifndef StageDir
  #error StageDir must be provided by the build script
#endif
#ifndef OutputDir
  #error OutputDir must be provided by the build script
#endif

[Setup]
AppId={{954FEE8D-721E-4B85-91C5-C6B05D70AF63}
AppName=Enterprise Endpoint Security Scanner
AppVersion={#AppVersion}
AppPublisher=Endpoint Security Scanner Engineering
DefaultDirName={autopf}\Endpoint Scanner
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
OutputDir={#OutputDir}
OutputBaseFilename=endpoint-scanner-{#AppVersion}-windows-x86_64
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=no
RestartApplications=no
UninstallDisplayName=Enterprise Endpoint Security Scanner
VersionInfoVersion={#AppVersion}

[Dirs]
Name: "{commonappdata}\EndpointScanner"
Name: "{commonappdata}\EndpointScanner\state"
Name: "{commonappdata}\EndpointScanner\logs"
Name: "{commonappdata}\EndpointScanner\policies"

[Files]
Source: "{#StageDir}\endpoint-scanner.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\EndpointScannerService.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\EndpointScannerService.xml"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\Configure-Acls.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\Enroll-LocalService.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\Enroll-And-Start.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\tools\osquery\osqueryi.exe"; DestDir: "{app}\tools\osquery"; Flags: ignoreversion
Source: "{#StageDir}\licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#StageDir}\verified-inputs.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\PACKAGE-CONTENTS.sha256"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\config.yaml"; DestDir: "{commonappdata}\EndpointScanner"; Flags: onlyifdoesntexist
Source: "{#StageDir}\enterprise-default.yaml"; DestDir: "{commonappdata}\EndpointScanner\policies"; Flags: onlyifdoesntexist

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File ""{app}\Configure-Acls.ps1"""; Flags: runhidden waituntilterminated
Filename: "{app}\EndpointScannerService.exe"; Parameters: "install"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; Check: not ScannerServiceExists

[UninstallRun]
Filename: "{app}\EndpointScannerService.exe"; Parameters: "stop"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated skipifdoesntexist ignoreerrors; Check: ScannerServiceExists; RunOnceId: "StopScannerService"
Filename: "{app}\EndpointScannerService.exe"; Parameters: "uninstall"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated skipifdoesntexist ignoreerrors; Check: ScannerServiceExists; RunOnceId: "RemoveScannerService"

[Code]
function ScannerServiceExists(): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query EndpointSecurityScanner', '',
    SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;
