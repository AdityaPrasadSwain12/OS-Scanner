"""Dependency-free Windows inventory, posture, patch, and persistence checks."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from pathlib import Path

from app.collectors.base import NativeCheckResult, NativeCollector, NativeCommand
from app.collectors.parsers import (
    csv_rows,
    hotfix_json,
    json_value,
    registry_startup,
    registry_values,
)
from app.tools._validation import parse_json_document
from app.tools.runner import SafeSubprocessRunner

_POWERSHELL_PREFIX = ("-NoLogo", "-NoProfile", "-NonInteractive", "-Command")
_MAX_INVENTORY_RECORDS = 20_000
_MAX_JSON_NODES = 200_000


def _validate_json_shape(value: object, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    """Reject unexpectedly deep or broad PowerShell JSON before normalization."""

    if depth > 8:
        raise ValueError("Windows inventory JSON exceeds the nesting limit")
    counter = nodes if nodes is not None else [0]
    counter[0] += 1
    if counter[0] > _MAX_JSON_NODES:
        raise ValueError("Windows inventory JSON exceeds the node limit")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Windows inventory JSON contains a non-string key")
            _validate_json_shape(item, depth=depth + 1, nodes=counter)
    elif isinstance(value, list):
        if len(value) > _MAX_INVENTORY_RECORDS:
            raise ValueError("Windows inventory JSON exceeds the record limit")
        for item in value:
            _validate_json_shape(item, depth=depth + 1, nodes=counter)


def _json_object(output: str) -> dict[str, object]:
    document = parse_json_document(output, max_chars=8 * 1024 * 1024)
    if not isinstance(document, dict):
        raise ValueError("Windows inventory response must be an object")
    _validate_json_shape(document)
    return document


def _json_records(output: str) -> list[dict[str, object]]:
    document = parse_json_document(output, max_chars=8 * 1024 * 1024)
    if document is None:
        document = []
    elif isinstance(document, dict):
        document = [document]
    if not isinstance(document, list) or any(not isinstance(item, dict) for item in document):
        raise ValueError("Windows inventory response must be an array of objects")
    _validate_json_shape(document)
    return document


_OS_INFO_SCRIPT = (
    "$o=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop;"
    "$c=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue;"
    "$p=Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue;"
    "$boot=$null;if($null -ne $o.LastBootUpTime){"
    "$boot=$o.LastBootUpTime.ToUniversalTime().ToString('o')};"
    "$up=$null;if($null -ne $o.LastBootUpTime){"
    "$up=[math]::Max(0,[int64]((Get-Date)-$o.LastBootUpTime).TotalSeconds)};"
    "$tz=$null;try{$tz=(Get-TimeZone -ErrorAction Stop).Id}catch{};"
    "$installed=$null;if($null -ne $o.InstallDate){"
    "$installed=$o.InstallDate.ToUniversalTime().ToString('o')};"
    "[ordered]@{Name=$o.Caption;Version=$o.Version;Build=$o.BuildNumber;"
    "Architecture=$o.OSArchitecture;Hostname=$o.CSName;MachineId=$p.UUID;"
    "BootTime=$boot;UptimeSeconds=$up;Timezone=$tz;Manufacturer=$c.Manufacturer;"
    "Model=$c.Model;InstalledAt=$installed;Domain=$c.Domain;"
    "PartOfDomain=[bool]$c.PartOfDomain} | ConvertTo-Json -Compress -Depth 4"
)

_HARDWARE_SCRIPT = (
    "$c=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop;"
    "$cpus=@(Get-CimInstance Win32_Processor -ErrorAction Stop | "
    "Select-Object -First 256 | ForEach-Object {[ordered]@{Vendor=$_.Manufacturer;"
    "Model=$_.Name;PhysicalCores=$_.NumberOfCores;"
    "LogicalProcessors=$_.NumberOfLogicalProcessors;Architecture=$_.AddressWidth}});"
    "$disks=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' "
    "-ErrorAction Stop | Select-Object -First 256 | ForEach-Object {"
    "[ordered]@{Name=$_.DeviceID;MountPoint=$_.DeviceID;CapacityBytes=$_.Size;"
    "FreeBytes=$_.FreeSpace;DiskType=$_.FileSystem;SerialNumber=$_.VolumeSerialNumber}});"
    "$gpus=@(Get-CimInstance Win32_VideoController -ErrorAction Stop | "
    "Select-Object -First 32 | ForEach-Object {[ordered]@{Vendor=$_.AdapterCompatibility;"
    "Model=$_.Name;MemoryBytes=$_.AdapterRAM}});"
    "$board=Get-CimInstance Win32_BaseBoard -ErrorAction Stop | "
    "Select-Object -First 1;"
    "$bios=Get-CimInstance Win32_BIOS -ErrorAction Stop | "
    "Select-Object -First 1;"
    "$release=$null;if($null -ne $bios.ReleaseDate){"
    "$release=$bios.ReleaseDate.ToUniversalTime().ToString('o')};"
    "$boardText=(@($board.Manufacturer,$board.Product) | Where-Object {$_}) -join ' ';"
    "[ordered]@{MemoryBytes=$c.TotalPhysicalMemory;Manufacturer=$c.Manufacturer;"
    "DeviceModel=$c.Model;CPUs=$cpus;Disks=$disks;GPUs=$gpus;"
    "Motherboard=$boardText.Trim();"
    "BiosUefi=$bios.Name;FirmwareVersion=$bios.SMBIOSBIOSVersion;"
    "FirmwareReleaseDate=$release} | "
    "ConvertTo-Json -Compress -Depth 6"
)

_SOFTWARE_SCRIPT = (
    "$paths=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
    "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
    "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
    "$items=@(Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | "
    "Where-Object {$null -ne $_.DisplayName -and [string]$_.DisplayName -ne ''} | "
    "Sort-Object DisplayName,DisplayVersion,Publisher,InstallLocation -Unique | "
    "Select-Object -First 20000 | ForEach-Object {"
    "$arch=$null;if([string]$_.PSPath -match 'WOW6432Node'){$arch='x86'};"
    "elseif([string]$_.PSPath -match '^Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE')"
    "{$arch='x64'};"
    "$packageId=$null;if([string]$_.PSChildName -match '^\\{[0-9A-Fa-f-]{36}\\}$')"
    "{$packageId=[string]$_.PSChildName};"
    "[ordered]@{Name=$_.DisplayName;Version=$_.DisplayVersion;Vendor=$_.Publisher;"
    "InstallationPath=$_.InstallLocation;InstallationDate=$_.InstallDate;"
    "Architecture=$arch;PackageManager='windows_registry';Source='native';"
    "PackageId=$packageId}});"
    "ConvertTo-Json -InputObject $items -Compress -Depth 4"
)

_PROCESSES_SCRIPT = (
    "$owners=@{};try{Get-Process -IncludeUserName -ErrorAction Stop | "
    "Select-Object -First 20000 | ForEach-Object {$owners[[int]$_.Id]=$_.UserName}}catch{};"
    "$items=@(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object -First 20000 | "
    "ForEach-Object {$started=$null;if($null -ne $_.CreationDate){"
    "$started=$_.CreationDate.ToUniversalTime().ToString('o')};"
    "[ordered]@{Pid=$_.ProcessId;ParentPid=$_.ParentProcessId;Name=$_.Name;"
    "ExecutablePath=$_.ExecutablePath;User=$owners[[int]$_.ProcessId];StartTime=$started;"
    "MemoryBytes=$_.WorkingSetSize}});"
    "ConvertTo-Json -InputObject $items -Compress -Depth 4"
)

_SERVICES_SCRIPT = (
    "$items=@(Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object -First 20000 | "
    "ForEach-Object {[ordered]@{Name=$_.Name;DisplayName=$_.DisplayName;State=$_.State;"
    "StartupType=$_.StartMode;ExecutablePath=$_.PathName;ServiceAccount=$_.StartName}});"
    "ConvertTo-Json -InputObject $items -Compress -Depth 4"
)

_USERS_SCRIPT = (
    "$groups=@{};$admins=@{};Get-LocalGroupMember -SID 'S-1-5-32-544' "
    "-ErrorAction Stop | ForEach-Object {$admins[[string]$_.SID]=$true};"
    "try{Get-LocalGroup -ErrorAction Stop | ForEach-Object {$group=$_.Name;"
    "try{Get-LocalGroupMember -Group $group -ErrorAction Stop | ForEach-Object {"
    "$sid=[string]$_.SID;if(-not $groups.ContainsKey($sid)){$groups[$sid]=@()};"
    "$groups[$sid]+=,$group}}catch{}}}catch{};"
    "$items=@(Get-LocalUser -ErrorAction Stop | Select-Object -First 20000 | "
    "ForEach-Object {$sid=[string]$_.SID;$last=$null;if($null -ne $_.LastLogon){"
    "$last=$_.LastLogon.ToUniversalTime().ToString('o')};"
    "$expires=$null;if($null -ne $_.PasswordExpires){"
    "$expires=$_.PasswordExpires.ToUniversalTime().ToString('o')};$memberOf=@($groups[$sid]);"
    "[ordered]@{Name=$_.Name;SID=$sid;Enabled=[bool]$_.Enabled;Groups=$memberOf;"
    "IsAdministrator=[bool]$admins[$sid];"
    "IsGuest=[bool]($sid -match '-501$');LastLogon=$last;"
    "PasswordRequired=[bool]$_.PasswordRequired;PasswordExpires=$expires;"
    "UserMayChangePassword=[bool]$_.UserMayChangePassword}});"
    "ConvertTo-Json -InputObject $items -Compress -Depth 5"
)

_NETWORK_INTERFACES_SCRIPT = (
    "$configs=@{};Get-NetIPConfiguration -All -ErrorAction Stop | "
    "ForEach-Object {$configs[[int]$_.InterfaceIndex]=$_};"
    "$ipif=@{};Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop | "
    "ForEach-Object {$ipif[[int]$_.InterfaceIndex]=$_};"
    "$cim=@{};Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' "
    "-ErrorAction Stop | ForEach-Object {$cim[[int]$_.InterfaceIndex]=$_};"
    "$routes=@{};Get-NetRoute -ErrorAction Stop | Where-Object {"
    "$_.DestinationPrefix -in @('0.0.0.0/0','::/0')} | ForEach-Object {"
    "$i=[int]$_.InterfaceIndex;if(-not $routes.ContainsKey($i)){$routes[$i]=@()};"
    "$routes[$i]+=,$_.NextHop};"
    "$items=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object -First 4096 | "
    "ForEach-Object {$i=[int]$_.InterfaceIndex;$cfg=$configs[$i];$v4=$ipif[$i];"
    "$legacy=$cim[$i];$addresses=@();foreach($a in @($cfg.IPv4Address)+"
    "@($cfg.IPv6Address)){if($null -ne $a){$addresses+=,[ordered]@{"
    "Address=$a.IPAddress;PrefixLength=$a.PrefixLength}}};"
    "$gateways=@(@($cfg.IPv4DefaultGateway)+@($cfg.IPv6DefaultGateway) | "
    "ForEach-Object {$_.NextHop})+@($routes[$i]);"
    "$dns=@($cfg.DNSServer.ServerAddresses);$obtained=$null;$expires=$null;"
    "$dhcp=$null;if($null -ne $v4){$dhcp=($v4.Dhcp -eq 'Enabled')};"
    "if($null -ne $legacy.DHCPLeaseObtained){"
    "$obtained=$legacy.DHCPLeaseObtained.ToUniversalTime().ToString('o')};"
    "if($null -ne $legacy.DHCPLeaseExpires){"
    "$expires=$legacy.DHCPLeaseExpires.ToUniversalTime().ToString('o')};"
    "[ordered]@{Name=$_.Name;Description=$_.InterfaceDescription;"
    "MacAddress=$_.MacAddress;Addresses=$addresses;Gateways=@($gateways | "
    "Where-Object {$_} | Select-Object -Unique);DnsServers=@($dns | "
    "Where-Object {$_} | Select-Object -Unique);DhcpEnabled=$dhcp;"
    "DhcpServer=$legacy.DHCPServer;DhcpLeaseObtained=$obtained;"
    "DhcpLeaseExpires=$expires;IsUp=($_.Status -eq 'Up')}});"
    "ConvertTo-Json -InputObject $items -Compress -Depth 6"
)

_LISTENING_PORTS_SCRIPT = (
    "$names=@{};Get-Process -ErrorAction SilentlyContinue | ForEach-Object {"
    "$names[[int]$_.Id]=$_.ProcessName};"
    "$items=@();$items+=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | "
    "Select-Object -First 20000 | ForEach-Object {$p=$names[[int]$_.OwningProcess];"
    "[ordered]@{Protocol='TCP';Address=$_.LocalAddress;Port=$_.LocalPort;"
    "Pid=$_.OwningProcess;Process=$p}});"
    "$items+=@(Get-NetUDPEndpoint -ErrorAction Stop | Select-Object -First 20000 | "
    "ForEach-Object {$p=$names[[int]$_.OwningProcess];"
    "[ordered]@{Protocol='UDP';Address=$_.LocalAddress;Port=$_.LocalPort;"
    "Pid=$_.OwningProcess;Process=$p}});"
    "$items=@($items | Select-Object -First 20000);"
    "ConvertTo-Json -InputObject $items -Compress -Depth 4"
)

_BROWSER_EXTENSIONS_SCRIPT = (
    "$items=@();$profiles=@(Get-CimInstance Win32_UserProfile -ErrorAction Stop | "
    "Where-Object {-not $_.Special -and $_.LocalPath} | Select-Object -First 512);"
    "$browsers=@(@{Name='Chrome';Relative='AppData\\Local\\Google\\Chrome\\User Data'},"
    "@{Name='Edge';Relative='AppData\\Local\\Microsoft\\Edge\\User Data'},"
    "@{Name='Brave';Relative='AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data'});"
    "foreach($profile in $profiles){foreach($browser in $browsers){"
    "$root=Join-Path $profile.LocalPath $browser.Relative;"
    "if(-not (Test-Path -LiteralPath $root)){continue};"
    "foreach($browserProfile in @(Get-ChildItem -LiteralPath $root -Directory "
    "-ErrorAction SilentlyContinue | Where-Object {$_.Name -eq 'Default' -or "
    "$_.Name -like 'Profile *'} | Select-Object -First 256)){"
    "$extensionRoot=Join-Path $browserProfile.FullName 'Extensions';"
    "if(-not (Test-Path -LiteralPath $extensionRoot)){continue};"
    "foreach($extension in @(Get-ChildItem -LiteralPath $extensionRoot -Directory "
    "-ErrorAction SilentlyContinue | Select-Object -First 4096)){"
    "$version=Get-ChildItem -LiteralPath $extension.FullName -Directory "
    "-ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | "
    "Select-Object -First 1;if($null -eq $version){continue};"
    "$manifestPath=Join-Path $version.FullName 'manifest.json';"
    "$manifestFile=Get-Item -LiteralPath $manifestPath -ErrorAction SilentlyContinue;"
    "if($null -eq $manifestFile -or $manifestFile.Length -gt 2097152){continue};"
    "try{$manifest=Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | "
    "ConvertFrom-Json -ErrorAction Stop}catch{continue};"
    "$permissions=@(@($manifest.permissions)+@($manifest.host_permissions) | "
    "Where-Object {$_ -is [string]} | Select-Object -First 512 -Unique);"
    "$items+=,[ordered]@{Browser=$browser.Name;ExtensionId=$extension.Name;"
    "Name=[string]$manifest.name;Version=[string]$manifest.version;Enabled=$null;"
    "Permissions=$permissions;Profile=$browserProfile.Name};"
    "if($items.Count -ge 20000){break}}}};"
    "$firefoxRoot=Join-Path $profile.LocalPath 'AppData\\Roaming\\Mozilla\\Firefox\\Profiles';"
    "if(Test-Path -LiteralPath $firefoxRoot){foreach($firefoxProfile in @(" 
    "Get-ChildItem -LiteralPath $firefoxRoot -Directory -ErrorAction SilentlyContinue | "
    "Select-Object -First 256)){"
    "$extensionsPath=Join-Path $firefoxProfile.FullName 'extensions.json';"
    "$extensionsFile=Get-Item -LiteralPath $extensionsPath -ErrorAction SilentlyContinue;"
    "if($null -eq $extensionsFile -or $extensionsFile.Length -gt 10485760){continue};"
    "try{$document=Get-Content -LiteralPath $extensionsPath -Raw -ErrorAction Stop | "
    "ConvertFrom-Json -ErrorAction Stop}catch{continue};foreach($addon in @($document.addons) | "
    "Select-Object -First 4096){if(-not $addon.id){continue};"
    "$permissions=@($addon.userPermissions.permissions | Where-Object {$_ -is [string]} | "
    "Select-Object -First 512 -Unique);$items+=,[ordered]@{Browser='Firefox';"
    "ExtensionId=[string]$addon.id;Name=[string]$addon.defaultLocale.name;"
    "Version=[string]$addon.version;Enabled=[bool]$addon.active;Permissions=$permissions;"
    "Profile=$firefoxProfile.Name};if($items.Count -ge 20000){break}}}}};"
    "$items=@($items | Select-Object -First 20000);"
    "ConvertTo-Json -InputObject $items -Compress -Depth 6"
)

_CERTIFICATES_SCRIPT = (
    "$items=@();$stores=@('Cert:\\LocalMachine\\Root','Cert:\\LocalMachine\\CA',"
    "'Cert:\\LocalMachine\\My');$now=Get-Date;foreach($store in $stores){"
    "foreach($certificate in @(Get-ChildItem -Path $store -ErrorAction SilentlyContinue | "
    "Select-Object -First 10000)){$keySize=$null;"
    "try{$keySize=$certificate.PublicKey.Key.KeySize}catch{};"
    "$before=$null;if($null -ne $certificate.NotBefore){"
    "$before=$certificate.NotBefore.ToUniversalTime().ToString('o')};"
    "$after=$null;if($null -ne $certificate.NotAfter){"
    "$after=$certificate.NotAfter.ToUniversalTime().ToString('o')};"
    "$items+=,[ordered]@{Store=$store;Subject=$certificate.Subject;Issuer=$certificate.Issuer;"
    "Thumbprint=$certificate.Thumbprint;SerialNumber=$certificate.SerialNumber;"
    "NotBefore=$before;NotAfter=$after;SignatureAlgorithm=$certificate.SignatureAlgorithm.FriendlyName;"
    "PublicKeyAlgorithm=$certificate.PublicKey.Oid.FriendlyName;KeySize=$keySize;"
    "HasPrivateKey=[bool]$certificate.HasPrivateKey;"
    "SelfSigned=([string]$certificate.Subject -eq [string]$certificate.Issuer);"
    "Expired=($certificate.NotAfter -lt $now)};if($items.Count -ge 20000){break}}};"
    "$items=@($items | Select-Object -First 20000);"
    "ConvertTo-Json -InputObject $items -Compress -Depth 4"
)


def _firewall_profiles(output: str) -> dict[str, dict[str, bool | str]]:
    profiles: dict[str, dict[str, bool | str]] = {}
    current = "unknown"
    for line in output.splitlines()[:1000]:
        stripped = line.strip()
        profile_match = re.match(r"^(Domain|Private|Public) Profile Settings", stripped, re.I)
        if profile_match:
            current = profile_match.group(1).casefold()
            profiles.setdefault(current, {})
            continue
        state_match = re.match(r"^State\s+(ON|OFF)$", stripped, re.I)
        if state_match:
            profiles.setdefault(current, {})["enabled"] = state_match.group(1).upper() == "ON"
    if not profiles:
        raise ValueError("Windows firewall output did not contain profile state")
    return profiles


def _powershell(script: str) -> tuple[str, ...]:
    # ``script`` values are module constants, never derived from scan requests.
    encoding_setup = (
        "$utf8NoBom=[System.Text.UTF8Encoding]::new($false);"
        "[Console]::OutputEncoding=$utf8NoBom;$OutputEncoding=$utf8NoBom;"
    )
    return (*_POWERSHELL_PREFIX, f"{encoding_setup}{script}")


class WindowsCollector(NativeCollector):
    platform_name = "windows"

    @classmethod
    def default_runner(
        cls,
        *,
        timeout_seconds: float = 60.0,
        max_output_bytes: int = 8 * 1024 * 1024,
    ) -> SafeSubprocessRunner:
        return SafeSubprocessRunner(
            ("powershell.exe", "netsh.exe", "reg.exe", "schtasks.exe"),
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def inventory_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        """Return dependency-free Windows inventory collected through native APIs."""

        return (
            NativeCommand(
                "os_info",
                "powershell.exe",
                _powershell(_OS_INFO_SCRIPT),
                _json_object,
            ),
            NativeCommand(
                "hardware",
                "powershell.exe",
                _powershell(_HARDWARE_SCRIPT),
                _json_object,
                timeout_seconds=120,
            ),
            NativeCommand(
                "software",
                "powershell.exe",
                _powershell(_SOFTWARE_SCRIPT),
                _json_records,
                timeout_seconds=120,
            ),
            NativeCommand(
                "processes",
                "powershell.exe",
                _powershell(_PROCESSES_SCRIPT),
                _json_records,
                timeout_seconds=120,
            ),
            NativeCommand(
                "services",
                "powershell.exe",
                _powershell(_SERVICES_SCRIPT),
                _json_records,
                timeout_seconds=120,
            ),
            NativeCommand(
                "users",
                "powershell.exe",
                _powershell(_USERS_SCRIPT),
                _json_records,
                timeout_seconds=120,
            ),
            NativeCommand(
                "network_interfaces",
                "powershell.exe",
                _powershell(_NETWORK_INTERFACES_SCRIPT),
                _json_records,
                timeout_seconds=120,
            ),
            NativeCommand(
                "listening_ports",
                "powershell.exe",
                _powershell(_LISTENING_PORTS_SCRIPT),
                _json_records,
                timeout_seconds=120,
            ),
            NativeCommand(
                "browser_extensions",
                "powershell.exe",
                _powershell(_BROWSER_EXTENSIONS_SCRIPT),
                _json_records,
                timeout_seconds=120,
            ),
            NativeCommand(
                "certificates",
                "powershell.exe",
                _powershell(_CERTIFICATES_SCRIPT),
                _json_records,
                timeout_seconds=120,
            ),
        )

    def posture_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        return (
            (
                NativeCommand(
                    "firewall",
                    "powershell.exe",
                    _powershell(
                        "$items=@(Get-NetFirewallProfile -ErrorAction Stop | "
                        "ForEach-Object {[ordered]@{Name=[string]$_.Name;"
                        "Enabled=[bool]$_.Enabled;"
                        "DefaultInboundAction=[string]$_.DefaultInboundAction;"
                        "DefaultOutboundAction=[string]$_.DefaultOutboundAction;"
                        "NotifyOnListen=[bool]$_.NotifyOnListen;"
                        "LogAllowed=[bool]$_.LogAllowed;LogBlocked=[bool]$_.LogBlocked;"
                        "LogFile=[string]$_.LogFileName}});"
                        "ConvertTo-Json -InputObject $items -Compress -Depth 4"
                    ),
                    _json_records,
                ),
                NativeCommand(
                    "firewall",
                    "netsh.exe",
                    ("advfirewall", "show", "allprofiles", "state"),
                    _firewall_profiles,
                ),
            ),
            NativeCommand(
                "antivirus",
                "powershell.exe",
                _powershell(
                    "$defender=$null;try{$defender=Get-MpComputerStatus -ErrorAction Stop | "
                    "Select-Object AntivirusEnabled,AntispywareEnabled,"
                    "RealTimeProtectionEnabled,AntivirusSignatureVersion,"
                    "AntivirusSignatureLastUpdated,AntivirusSignatureAge}catch{};"
                    "$products=@();try{$products=@(Get-CimInstance -Namespace "
                    "root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | "
                    "Select-Object -First 64 | ForEach-Object {[ordered]@{"
                    "Name=$_.displayName;ProductState=$_.productState;"
                    "PathToSignedProductExe=$_.pathToSignedProductExe}})}catch{};"
                    "[ordered]@{Defender=$defender;RegisteredProducts=$products} | "
                    "ConvertTo-Json -Compress -Depth 5"
                ),
                json_value,
            ),
            NativeCommand(
                "disk_encryption",
                "powershell.exe",
                _powershell(
                    "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,"
                    "ProtectionStatus,EncryptionMethod,EncryptionPercentage | "
                    "ConvertTo-Json -Compress"
                ),
                json_value,
            ),
            NativeCommand(
                "secure_boot",
                "powershell.exe",
                _powershell("Confirm-SecureBootUEFI | ConvertTo-Json -Compress"),
                json_value,
            ),
            NativeCommand(
                "tpm",
                "powershell.exe",
                _powershell(
                    "Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,"
                    "ManufacturerIdTxt,ManufacturerVersion | ConvertTo-Json -Compress"
                ),
                json_value,
            ),
            NativeCommand(
                "uac",
                "reg.exe",
                (
                    "query",
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    "/v",
                    "EnableLUA",
                ),
                registry_values,
            ),
            NativeCommand(
                "remote_desktop",
                "reg.exe",
                (
                    "query",
                    r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                    "/v",
                    "fDenyTSConnections",
                ),
                registry_values,
            ),
            NativeCommand(
                "automatic_updates",
                "reg.exe",
                (
                    "query",
                    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
                ),
                registry_values,
                allowed_returncodes=frozenset({0, 1}),
            ),
            NativeCommand(
                "local_security_controls",
                "powershell.exe",
                _powershell(
                    '$g=Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" '
                    "-ErrorAction SilentlyContinue | Where-Object {$_.SID -match '-501$'};"
                    "$guest=$null;if($null -ne $g){$guest=-not [bool]$g.Disabled};"
                    "$p=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\"
                    "CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue;"
                    "$d=Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' "
                    "-ErrorAction SilentlyContinue;"
                    "$lock=$null;if($null -ne $p.InactivityTimeoutSecs){"
                    "$lock=[int]$p.InactivityTimeoutSecs -gt 0}elseif("
                    "$null -ne $d.ScreenSaveActive -and $null -ne $d.ScreenSaverIsSecure){"
                    "$lock=($d.ScreenSaveActive -eq '1' -and "
                    "$d.ScreenSaverIsSecure -eq '1')};"
                    "$n=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Policies\\LAPS' "
                    "-ErrorAction SilentlyContinue;"
                    "$l=Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\"
                    "AdmPwd' -ErrorAction SilentlyContinue;"
                    "$laps=(($null -ne $n.BackupDirectory -and [int]$n.BackupDirectory -gt 0) "
                    "-or ($null -ne $l.AdmPwdEnabled -and [int]$l.AdmPwdEnabled -eq 1));"
                    "$audit=$null;try{$audit=[bool](Get-WinEvent -ListLog Security "
                    "-ErrorAction Stop).IsEnabled}catch{};"
                    "[ordered]@{GuestAccountEnabled=$guest;LockScreenEnabled=$lock;"
                    "AuditLoggingEnabled=$audit;LocalAdminPasswordManaged=$laps} | "
                    "ConvertTo-Json -Compress"
                ),
                json_value,
            ),
            NativeCommand(
                "local_users",
                "powershell.exe",
                _powershell(
                    "$a=@{};try{Get-LocalGroupMember -SID 'S-1-5-32-544' "
                    "-ErrorAction Stop | ForEach-Object {$a[$_.SID.Value]=$true}}catch{};"
                    "Get-LocalUser -ErrorAction Stop | ForEach-Object {"
                    "[ordered]@{Name=$_.Name;SID=$_.SID.Value;Enabled=[bool]$_.Enabled;"
                    "LastLogon=$_.LastLogon;IsAdministrator=[bool]$a[$_.SID.Value]}} | "
                    "ConvertTo-Json -Compress"
                ),
                json_value,
            ),
        )

    def patch_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        return (
            NativeCommand(
                "installed_updates",
                "powershell.exe",
                _powershell(
                    "Get-HotFix | Select-Object HotFixID,InstalledOn | ConvertTo-Json -Compress"
                ),
                hotfix_json,
                timeout_seconds=120,
            ),
            NativeCommand(
                "pending_reboot",
                "powershell.exe",
                _powershell(
                    "[bool](Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                    "Component Based Servicing\\RebootPending') | ConvertTo-Json -Compress"
                ),
                json_value,
            ),
            NativeCommand(
                "pending_updates",
                "powershell.exe",
                _powershell(
                    "$s=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher();"
                    "$s.Online=$false;$r=$s.Search('IsInstalled=0 and IsHidden=0');"
                    "$ids=@('0FA1201D-4330-4FA8-8AE9-B877473B6441',"
                    "'E6CF1350-C01B-414D-A61F-263D14D133B4');"
                    "$updates=@($r.Updates | Select-Object -First 10000 | ForEach-Object {"
                    "$u=$_;$categoryIds=@($u.Categories | ForEach-Object {$_.CategoryID});"
                    "$categoryNames=@($u.Categories | ForEach-Object {$_.Name});"
                    "$security=[bool](@($categoryIds | Where-Object {$ids -contains $_}).Count);"
                    "$changed=$null;if($null -ne $u.LastDeploymentChangeTime){"
                    "$changed=$u.LastDeploymentChangeTime.ToUniversalTime().ToString('o')};"
                    "[ordered]@{UpdateId=[string]$u.Identity.UpdateID;"
                    "Revision=[int]$u.Identity.RevisionNumber;Title=[string]$u.Title;"
                    "Description=[string]$u.Description;KbArticleIds=@($u.KBArticleIDs);"
                    "Categories=$categoryNames;SecurityRelated=$security;"
                    "MsrcSeverity=[string]$u.MsrcSeverity;RebootRequired=[bool]$u.RebootRequired;"
                    "Mandatory=[bool]$u.IsMandatory;AutoSelected=[bool]$u.AutoSelectOnWebSites;"
                    "LastDeploymentChangeTime=$changed}});"
                    "$sec=@($updates | Where-Object SecurityRelated);"
                    "[ordered]@{Count=$updates.Count;SecurityCount=$sec.Count;"
                    "RebootRequired=[bool]($updates | Where-Object RebootRequired);"
                    "CatalogMode='cached-offline';Updates=$updates} | "
                    "ConvertTo-Json -Compress -Depth 7"
                ),
                json_value,
                timeout_seconds=120,
            ),
        )

    def persistence_checks(self) -> Iterable[NativeCommand | tuple[NativeCommand, ...]]:
        return (
            NativeCommand(
                "machine_run_items",
                "reg.exe",
                ("query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                registry_startup,
                allowed_returncodes=frozenset({0, 1}),
            ),
            NativeCommand(
                "user_run_items",
                "reg.exe",
                ("query", r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                registry_startup,
                allowed_returncodes=frozenset({0, 1}),
            ),
            NativeCommand(
                "scheduled_tasks",
                "schtasks.exe",
                ("/Query", "/FO", "CSV", "/NH"),
                csv_rows,
                timeout_seconds=120,
            ),
        )

    def filesystem_checks(self, category: str) -> tuple[NativeCheckResult, ...]:
        if category != "persistence":
            return ()
        directories: list[Path] = []
        program_data = os.environ.get("PROGRAMDATA")
        app_data = os.environ.get("APPDATA")
        suffix = Path("Microsoft/Windows/Start Menu/Programs/Startup")
        if program_data:
            directories.append(Path(program_data) / suffix)
        if app_data:
            directories.append(Path(app_data) / suffix)
        if not directories:
            return ()
        return (
            self.collect_directory_metadata(
                name="startup_folders",
                category=category,
                directories=directories,
                deadline_at=self.deadline_at,
            ),
        )
