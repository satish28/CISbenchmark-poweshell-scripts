# Windows 11 Security Audit Test Cases
## CIS Benchmark & Privilege Escalation Checks (Non-Admin Context)

**Scope**: Low-privilege user enumeration aligned with CIS Microsoft Windows 11 Benchmark v3.0 and common privilege escalation vectors.

**Constraints**: No admin access, Sophos EDR present (avoid noisy techniques).

---

## 1. User & Credential Enumeration

### TC-1.1: Current User Context
```powershell
# Check current user privileges and group membership
whoami /all
whoami /priv
whoami /groups
```
**What to look for**: SeDebugPrivilege, SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege enabled — any of these can lead to privilege escalation.

### TC-1.2: Local Users Enumeration
```powershell
# List local users (works without admin)
Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon
net user
```
**CIS Alignment**: 1.1.x — Ensure proper account configurations.

### TC-1.3: Local Groups & Membership
```powershell
# Check group memberships
Get-LocalGroup | ForEach-Object { 
    Write-Host "`n=== $($_.Name) ===" -ForegroundColor Cyan
    Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue 
}
net localgroup administrators
net localgroup "Remote Desktop Users"
net localgroup "Backup Operators"
```
**Privesc relevance**: Backup Operators, Remote Desktop Users, Hyper-V Administrators can be abused.

### TC-1.4: Credential Manager Secrets
```powershell
# List stored credentials (user can see their own)
cmdkey /list
```
**What to look for**: Stored domain credentials, RDP credentials, generic credentials.

---

## 2. Service Misconfigurations
-
### TC-2.1: Unquoted Service Paths
```powershell
# Find unquoted service paths (classic privesc)
Get-CimInstance -ClassName Win32_Service | Where-Object {
    $_.PathName -notmatch '^"' -and 
    $_.PathName -match '\s' -and 
    $_.PathName -notmatch '^C:\\Windows\\system32'
} | Select-Object Name, StartMode, State, PathName
```
**Privesc**: If path is `C:\Program Files\Vulnerable App\service.exe`, attacker can place `C:\Program.exe`.

### TC-2.2: Service Binary Permissions
```powershell
# Check write permissions on service binaries
$services = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.PathName }
foreach ($svc in $services) {
    $path = ($svc.PathName -replace '"', '').Split(' ')[0]
    if (Test-Path $path) {
        $acl = Get-Acl $path -ErrorAction SilentlyContinue
        $writeAccess = $acl.Access | Where-Object {
            $_.FileSystemRights -match 'Write|FullControl|Modify' -and
            $_.IdentityReference -match 'Users|Everyone|Authenticated Users|BUILTIN\\Users'
        }
        if ($writeAccess) {
            Write-Host "[VULN] $($svc.Name): $path" -ForegroundColor Red
            $writeAccess | Format-Table IdentityReference, FileSystemRights
        }
    }
}
```

### TC-2.3: Service Registry Permissions
```powershell
# Check if current user can modify service registry keys
$services = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue
foreach ($svc in $services) {
    try {
        $acl = Get-Acl $svc.PSPath -ErrorAction SilentlyContinue
        $writeAccess = $acl.Access | Where-Object {
            $_.RegistryRights -match 'FullControl|SetValue|WriteKey' -and
            $_.IdentityReference -match 'Users|Everyone|Authenticated Users'
        }
        if ($writeAccess) {
            Write-Host "[VULN] Service registry: $($svc.Name)" -ForegroundColor Red
        }
    } catch {}
}
```

---

## 3. Scheduled Tasks Analysis

### TC-3.1: User-Writable Scheduled Task Binaries
```powershell
# List scheduled tasks and check binary permissions
Get-ScheduledTask | ForEach-Object {
    $actions = $_.Actions
    foreach ($action in $actions) {
        if ($action.Execute) {
            $path = $action.Execute -replace '"', ''
            if (Test-Path $path) {
                $acl = Get-Acl $path -ErrorAction SilentlyContinue
                $writeAccess = $acl.Access | Where-Object {
                    $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                    $_.IdentityReference -match 'Users|Everyone|Authenticated'
                }
                if ($writeAccess) {
                    Write-Host "[VULN] Task: $($_.TaskName) -> $path" -ForegroundColor Red
                }
            }
        }
    }
}
```

### TC-3.2: Scheduled Tasks Running as SYSTEM
```powershell
# Find tasks running as SYSTEM that we might be able to abuse
Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq 'SYSTEM' } |
    Select-Object TaskName, TaskPath, @{N='Actions';E={$_.Actions.Execute -join '; '}}
```

---

## 4. File System & Directory Permissions

### TC-4.1: World-Writable Directories in PATH
```powershell
# Check for writable directories in system PATH
$pathDirs = $env:PATH -split ';'
foreach ($dir in $pathDirs) {
    if (Test-Path $dir) {
        $acl = Get-Acl $dir -ErrorAction SilentlyContinue
        $writeAccess = $acl.Access | Where-Object {
            $_.FileSystemRights -match 'Write|FullControl|Modify|CreateFiles' -and
            $_.IdentityReference -match 'Users|Everyone|Authenticated Users'
        }
        if ($writeAccess) {
            Write-Host "[VULN] Writable PATH dir: $dir" -ForegroundColor Red
            $writeAccess | Select-Object IdentityReference, FileSystemRights
        }
    }
}
```
**Privesc**: DLL hijacking / binary planting in PATH directories.

### TC-4.2: Program Files Permissions
```powershell
# Check for writable locations in Program Files
$locations = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:ProgramData")
foreach ($loc in $locations) {
    Get-ChildItem $loc -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
        $writeAccess = $acl.Access | Where-Object {
            $_.FileSystemRights -match 'Write|FullControl|Modify' -and
            $_.IdentityReference -match 'Users|Everyone|Authenticated Users|BUILTIN\\Users'
        }
        if ($writeAccess) {
            Write-Host "[VULN] Writable: $($_.FullName)" -ForegroundColor Yellow
        }
    }
}
```

### TC-4.3: AlwaysInstallElevated Check
```powershell
# Check for AlwaysInstallElevated (critical privesc)
$hkcu = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
$hklm = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue

if ($hkcu.AlwaysInstallElevated -eq 1 -and $hklm.AlwaysInstallElevated -eq 1) {
    Write-Host "[CRITICAL] AlwaysInstallElevated is ENABLED!" -ForegroundColor Red
}
```
**CIS**: 18.9.59.1 — Ensure 'Always install with elevated privileges' is set to 'Disabled'.

---

## 5. Registry Security Settings

### TC-5.1: AutoLogon Credentials
```powershell
# Check for stored AutoLogon credentials
$autoLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
if ($autoLogon.DefaultPassword) {
    Write-Host "[CRITICAL] AutoLogon password found: $($autoLogon.DefaultUserName)" -ForegroundColor Red
}
if ($autoLogon.AutoAdminLogon -eq 1) {
    Write-Host "[WARN] AutoAdminLogon enabled" -ForegroundColor Yellow
}
```

### TC-5.2: LSA Protection Settings
```powershell
# Check LSA protection (CIS 18.4.x)
$lsaSettings = @{
    "RunAsPPL" = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    "DisableRestrictedAdmin" = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    "DisableRestrictedAdminOutboundCreds" = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
}

Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue |
    Select-Object RunAsPPL, LimitBlankPasswordUse, RestrictAnonymous, RestrictAnonymousSAM
```
**CIS**: 2.3.10.x — Network access restrictions.

### TC-5.3: UAC Configuration
```powershell
# Check UAC settings (CIS 2.3.17.x)
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Get-ItemProperty -Path $uacPath -ErrorAction SilentlyContinue | Select-Object `
    EnableLUA,
    ConsentPromptBehaviorAdmin,
    ConsentPromptBehaviorUser,
    EnableInstallerDetection,
    EnableSecureUIAPaths,
    EnableVirtualization,
    FilterAdministratorToken
```
**CIS Requirements**:
- EnableLUA = 1
- ConsentPromptBehaviorAdmin = 2 (Prompt on secure desktop)
- FilterAdministratorToken = 1

### TC-5.4: Windows Defender Settings
```powershell
# Check Defender configuration
Get-MpPreference | Select-Object `
    DisableRealtimeMonitoring,
    DisableBehaviorMonitoring,
    DisableScriptScanning,
    DisableIOAVProtection,
    ExclusionPath,
    ExclusionExtension,
    ExclusionProcess
```
**What to look for**: Any DisableX = True, or overly broad exclusions.

---

## 6. Network Configuration

### TC-6.1: Network Shares
```powershell
# List network shares
Get-SmbShare | Select-Object Name, Path, Description
net share
```

### TC-6.2: Open Ports & Listening Services
```powershell
# List listening ports and associated processes
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, @{
    N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}
} | Sort-Object LocalPort
```

### TC-6.3: Firewall Configuration
```powershell
# Check firewall status
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# List inbound allow rules
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
    Select-Object DisplayName, Profile, @{N='LocalPort';E={
        ($_ | Get-NetFirewallPortFilter).LocalPort
    }} | Where-Object { $_.LocalPort }
```
**CIS**: 9.x — Windows Defender Firewall settings.

### TC-6.4: SMB Configuration
```powershell
# Check SMB configuration
Get-SmbServerConfiguration | Select-Object `
    EnableSMB1Protocol,
    EnableSMB2Protocol,
    RequireSecuritySignature,
    EnableSecuritySignature,
    EncryptData
```
**CIS**: 18.4.14.x — SMBv1 should be disabled, signing should be required.

---

## 7. Password & Authentication Policy

### TC-7.1: Local Security Policy (Limited View)
```powershell
# Export local security policy
secedit /export /cfg "$env:TEMP\secpol.cfg" 2>$null
if (Test-Path "$env:TEMP\secpol.cfg") {
    Get-Content "$env:TEMP\secpol.cfg" | Select-String -Pattern "^(Minimum|Maximum|Password|Lockout)"
    Remove-Item "$env:TEMP\secpol.cfg" -Force
}
```

### TC-7.2: Password Policy via Net Accounts
```powershell
net accounts
```
**CIS Alignment**:
- 1.1.1: Minimum password age >= 1
- 1.1.2: Maximum password age <= 365
- 1.1.3: Minimum password length >= 14
- 1.1.4: Password complexity enabled
- 1.2.1: Account lockout duration >= 15
- 1.2.2: Account lockout threshold <= 5

---

## 8. Installed Software & Patches

### TC-8.1: Installed Software Enumeration
```powershell
# List installed software
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                 "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Where-Object { $_.DisplayName } |
    Sort-Object DisplayName
```

### TC-8.2: Installed Hotfixes
```powershell
# Check installed patches
Get-HotFix | Select-Object HotFixID, Description, InstalledOn | Sort-Object InstalledOn -Descending
wmic qfe list brief
```
**What to look for**: Missing recent patches, especially security updates.

### TC-8.3: PowerShell Constrained Language Mode
```powershell
# Check PowerShell language mode
$ExecutionContext.SessionState.LanguageMode
```
**CIS**: ConstrainedLanguage mode should be enabled for non-admin users.

---

## 9. Audit & Logging Configuration

### TC-9.1: Audit Policy
```powershell
# Check audit policy settings
auditpol /get /category:* 2>$null
```
**CIS 17.x**: Various audit categories should be configured for Success and Failure.

### TC-9.2: Event Log Configuration
```powershell
# Check event log sizes and retention
Get-WinEvent -ListLog Security, Application, System, "Windows PowerShell" |
    Select-Object LogName, MaximumSizeInBytes, @{N='MaxSizeMB';E={$_.MaximumSizeInBytes/1MB}}, RecordCount, IsEnabled
```
**CIS**: 18.9.27.x — Event log sizes should be >= 32768 KB.

---

## 10. BitLocker & Encryption

### TC-10.1: BitLocker Status
```powershell
# Check BitLocker status (may fail without admin, but try)
Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod
manage-bde -status 2>$null
```
**CIS**: 18.9.12.x — BitLocker should be enabled on OS volumes.

---

## 11. Browser & Application Security

### TC-11.1: Browser Extensions
```powershell
# Chrome extensions
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" -ErrorAction SilentlyContinue |
    Select-Object Name, LastWriteTime

# Edge extensions
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" -ErrorAction SilentlyContinue |
    Select-Object Name, LastWriteTime
```

### TC-11.2: Office Macro Settings
```powershell
# Check Office macro security
$officePaths = @(
    "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security"
)
foreach ($path in $officePaths) {
    if (Test-Path $path) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | Select-Object VBAWarnings, BlockContentExecutionFromInternet
    }
}
```

---

## 12. Startup & Persistence Locations

### TC-12.1: Run Keys
```powershell
# Check persistence locations
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Write-Host "`n=== $key ===" -ForegroundColor Cyan
        Get-ItemProperty $key -ErrorAction SilentlyContinue
    }
}
```

### TC-12.2: Startup Folders
```powershell
# Check startup folders
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($path in $startupPaths) {
    if (Test-Path $path) {
        Write-Host "`n=== $path ===" -ForegroundColor Cyan
        Get-ChildItem $path -ErrorAction SilentlyContinue
    }
}
```

---

## 13. Sensitive File Discovery

### TC-13.1: Sensitive Files in User Profile
```powershell
# Search for potentially sensitive files
$sensitivePatterns = @("*password*", "*credential*", "*secret*", "*.kdbx", "*.key", "*.pem", "*.pfx", "id_rsa*", "*.ppk")
foreach ($pattern in $sensitivePatterns) {
    Get-ChildItem -Path $env:USERPROFILE -Recurse -Filter $pattern -ErrorAction SilentlyContinue |
        Select-Object FullName, LastWriteTime
}
```

### TC-13.2: Unattended Installation Files
```powershell
# Check for unattend.xml and sysprep files
$unattendPaths = @(
    "C:\unattend.xml",
    "C:\Windows\Panther\Unattend.xml",
    "C:\Windows\Panther\unattend.xml",
    "C:\Windows\system32\sysprep\unattend.xml",
    "C:\Windows\system32\sysprep.inf"
)

foreach ($path in $unattendPaths) {
    if (Test-Path $path) {
        Write-Host "[FOUND] $path" -ForegroundColor Yellow
    }
}
```

---

## 14. Windows Features & Optional Components

### TC-14.1: Dangerous Features
```powershell
# Check for dangerous optional features
Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -match 'SMB1|Telnet|TFTP|PowerShellV2' } |
    Select-Object FeatureName, State
```
**CIS**: PowerShell v2, SMBv1, Telnet Client should be disabled.

---

## 15. EDR/AV Evasion Indicators (Defensive Check)

### TC-15.1: AMSI Status
```powershell
# Check AMSI configuration
$amsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI"
if (Test-Path $amsiPath) {
    Get-ItemProperty $amsiPath -ErrorAction SilentlyContinue
}

# Check if AMSI is being bypassed in current session
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') 2>$null
```

### TC-15.2: Security Product Enumeration
```powershell
# List security products
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
    Select-Object displayName, productState, pathToSignedProductExe
```

---

## Severity Classification

| Severity | Description |
|----------|-------------|
| CRITICAL | Direct path to SYSTEM/Admin (AlwaysInstallElevated, AutoLogon creds, writable service binaries) |
| HIGH | Likely privesc with effort (unquoted paths, writable scheduled tasks, dangerous privileges) |
| MEDIUM | Policy violations, misconfigurations that increase attack surface |
| LOW | Informational findings, defense-in-depth recommendations |

---

## Notes on Sophos EDR

- Avoid `Invoke-Expression`, `IEX`, or `DownloadString` patterns
- Don't use reflective loading or in-memory execution
- Stick to native PowerShell cmdlets and WMI/CIM queries
- Run checks incrementally rather than as a single large script
- If a check triggers, wait before continuing

