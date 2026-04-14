<#
.SYNOPSIS
    CIS-Audit.ps1 — Non-Privileged Windows CIS Benchmark Auditor

.DESCRIPTION
    Audits a Windows workstation/server against CIS Benchmark controls using
    ONLY standard-user (non-admin) PowerShell access. Generates an HTML report
    with PASS/FAIL/INFO results, remediation guidance, and an executive summary.

    This script checks ~70 controls across 9 security domains that are
    readable without elevation. Controls requiring admin access are flagged
    as SKIPPED with an explanation.

    AUTHORISED USE ONLY. Run this script only against systems you own or have
    explicit written authorisation to audit.

.PARAMETER OutputPath
    Path for the HTML report file (default: CIS_Audit_Report.html in current directory)

.PARAMETER JsonOutput
    Also export results as JSON (default: false)

.PARAMETER Verbose
    Show detailed progress during the audit

.EXAMPLE
    .\CIS-Audit.ps1
    .\CIS-Audit.ps1 -OutputPath "C:\Audits\report.html" -JsonOutput
    .\CIS-Audit.ps1 -Verbose

.NOTES
    Author  : SS
    Version : 1.0
    Date    : 2026-04-14
    Requires: PowerShell 5.1+ (built into Windows 10/11/Server 2016+)
    Privileges: Standard user (no admin/elevation required)
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\CIS_Audit_Report.html",
    [switch]$JsonOutput,
    [string]$JsonPath = ".\CIS_Audit_Results.json"
)

# ============================================================
# DISCLAIMER
# ============================================================
Write-Host @"
============================================================
  CIS Benchmark Auditor — Non-Privileged Edition
  AUTHORISED USE ONLY
============================================================
"@ -ForegroundColor Cyan

# ============================================================
# GLOBAL STATE
# ============================================================

# All audit results are collected here. Each result is a hashtable with:
#   Domain   : Security domain (e.g., "Account Policy", "Network")
#   ID       : CIS control reference number
#   Check    : Short description of what's being checked
#   Status   : PASS, FAIL, INFO, SKIPPED, or ERROR
#   Finding  : What was found (the actual value/state)
#   Expected : What the CIS benchmark expects
#   Remediation : How to fix it (if FAIL)
$global:Results = @()

# Counters for the summary
$global:PassCount  = 0
$global:FailCount  = 0
$global:InfoCount  = 0
$global:SkipCount  = 0
$global:ErrorCount = 0

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Add-Result {
    <#
    .SYNOPSIS
        Record a single audit check result.

    .DESCRIPTION
        Every check in this script calls Add-Result to log its finding.
        This centralises result collection and drives the final report.

    .PARAMETER Domain
        Security domain grouping (e.g., "Account Policy", "Network Security")

    .PARAMETER ID
        CIS control ID or custom reference (e.g., "1.1.1", "NET-01")

    .PARAMETER Check
        Human-readable description of what was checked

    .PARAMETER Status
        One of: PASS, FAIL, INFO, SKIPPED, ERROR

    .PARAMETER Finding
        What was actually found on the system

    .PARAMETER Expected
        What the CIS benchmark requires (for comparison)

    .PARAMETER Remediation
        How to fix the issue (shown only for FAIL results)
    #>
    param(
        [string]$Domain,
        [string]$ID,
        [string]$Check,
        [ValidateSet("PASS","FAIL","INFO","SKIPPED","ERROR")]
        [string]$Status,
        [string]$Finding,
        [string]$Expected = "",
        [string]$Remediation = ""
    )

    $global:Results += [PSCustomObject]@{
        Domain      = $Domain
        ID          = $ID
        Check       = $Check
        Status      = $Status
        Finding     = $Finding
        Expected    = $Expected
        Remediation = $Remediation
    }

    # Update counters
    switch ($Status) {
        "PASS"    { $global:PassCount++ }
        "FAIL"    { $global:FailCount++ }
        "INFO"    { $global:InfoCount++ }
        "SKIPPED" { $global:SkipCount++ }
        "ERROR"   { $global:ErrorCount++ }
    }

    # Verbose console output with colour coding
    $colour = switch ($Status) {
        "PASS"    { "Green" }
        "FAIL"    { "Red" }
        "INFO"    { "Yellow" }
        "SKIPPED" { "DarkGray" }
        "ERROR"   { "Magenta" }
    }
    Write-Host "  [$Status] " -ForegroundColor $colour -NoNewline
    Write-Host "$ID - $Check"
}


function Safe-RegQuery {
    <#
    .SYNOPSIS
        Safely read a registry value without admin privileges.

    .DESCRIPTION
        Many CIS controls check registry keys. Some keys are readable
        by standard users (HKLM\SOFTWARE, most HKCU), some are not
        (HKLM\SECURITY, HKLM\SAM). This wrapper returns $null
        instead of throwing an error when access is denied.

    .PARAMETER Path
        Full registry path (e.g., "HKLM:\SOFTWARE\Policies\...")

    .PARAMETER Name
        Value name within the key

    .RETURNS
        The registry value data, or $null if inaccessible.
    #>
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $val.$Name
    }
    catch {
        return $null
    }
}


function Test-CommandExists {
    <#
    .SYNOPSIS
        Check if a PowerShell command/cmdlet is available.

    .DESCRIPTION
        Some checks use cmdlets that may not exist on all Windows editions
        (e.g., Get-BitLockerVolume requires specific features). This avoids
        errors from calling non-existent commands.
    #>
    param([string]$Command)
    return [bool](Get-Command -Name $Command -ErrorAction SilentlyContinue)
}


# ============================================================
# SYSTEM INFORMATION COLLECTION
# ============================================================

function Collect-SystemInfo {
    <#
    .SYNOPSIS
        Gather baseline system information for the report header.

    .DESCRIPTION
        Collects hostname, OS version, domain membership, current user,
        and privilege level. All of this is readable by standard users
        via WMI/CIM and environment variables.
    #>
    Write-Host "`n[*] Collecting system information..." -ForegroundColor Cyan

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem

    $global:SysInfo = [PSCustomObject]@{
        Hostname     = $env:COMPUTERNAME
        OSName       = $os.Caption
        OSVersion    = $os.Version
        OSBuild      = $os.BuildNumber
        Architecture = $os.OSArchitecture
        Domain       = $cs.Domain
        DomainJoined = $cs.PartOfDomain
        CurrentUser  = "$env:USERDOMAIN\$env:USERNAME"
        IsAdmin      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        AuditDate    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShell   = $PSVersionTable.PSVersion.ToString()
    }

    Write-Host "  Hostname    : $($global:SysInfo.Hostname)"
    Write-Host "  OS          : $($global:SysInfo.OSName) ($($global:SysInfo.OSVersion))"
    Write-Host "  User        : $($global:SysInfo.CurrentUser)"
    Write-Host "  Admin       : $($global:SysInfo.IsAdmin)"
    Write-Host "  Domain      : $($global:SysInfo.Domain) (Joined: $($global:SysInfo.DomainJoined))"
}


# ============================================================
# DOMAIN 1: PASSWORD AND ACCOUNT POLICY
# ============================================================

function Audit-AccountPolicy {
    <#
    .SYNOPSIS
        Check password policy, lockout policy, and account settings.

    .DESCRIPTION
        Uses 'net accounts' which is readable by standard users.
        This command returns the local password policy (length, age,
        lockout threshold). On domain-joined machines, the effective
        policy may come from Group Policy — 'net accounts' shows the
        local policy which may differ from the applied GPO.

        CIS References:
          1.1.x — Password Policy
          1.2.x — Account Lockout Policy
    #>
    Write-Host "`n[*] Auditing Account Policy..." -ForegroundColor Cyan

    # 'net accounts' outputs the local security policy in plain text.
    # We parse each line to extract the values.
    $netAccounts = net accounts 2>&1

    # --- Parse password minimum length ---
    # CIS 1.1.4: Minimum password length >= 14 characters
    $minLength = ($netAccounts | Select-String "Minimum password length" | ForEach-Object {
        if ($_ -match "(\d+)") { [int]$Matches[1] } else { $null }
    })

    if ($null -ne $minLength) {
        $status = if ($minLength -ge 14) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Account Policy" -ID "1.1.4" `
            -Check "Minimum password length" `
            -Status $status `
            -Finding "Minimum length: $minLength characters" `
            -Expected ">= 14 characters (CIS)" `
            -Remediation "Set via: Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Minimum password length = 14"
    }

    # --- Parse maximum password age ---
    # CIS 1.1.2: Maximum password age <= 365 days (and > 0)
    $maxAge = ($netAccounts | Select-String "Maximum password age" | ForEach-Object {
        if ($_ -match "(\d+)") { [int]$Matches[1] } else { $null }
    })

    if ($null -ne $maxAge) {
        $status = if ($maxAge -le 365 -and $maxAge -gt 0) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Account Policy" -ID "1.1.2" `
            -Check "Maximum password age" `
            -Status $status `
            -Finding "Max age: $maxAge days" `
            -Expected "<= 365 days and > 0 (CIS)" `
            -Remediation "Set via GPO: Password Policy > Maximum password age = 365 or less"
    }

    # --- Parse minimum password age ---
    # CIS 1.1.3: Minimum password age >= 1 day (prevents rapid cycling)
    $minAge = ($netAccounts | Select-String "Minimum password age" | ForEach-Object {
        if ($_ -match "(\d+)") { [int]$Matches[1] } else { $null }
    })

    if ($null -ne $minAge) {
        $status = if ($minAge -ge 1) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Account Policy" -ID "1.1.3" `
            -Check "Minimum password age" `
            -Status $status `
            -Finding "Min age: $minAge day(s)" `
            -Expected ">= 1 day (CIS)" `
            -Remediation "Set via GPO: Password Policy > Minimum password age = 1"
    }

    # --- Parse password history ---
    # CIS 1.1.1: Password history >= 24 (remember this many passwords)
    $history = ($netAccounts | Select-String "password history" | ForEach-Object {
        if ($_ -match "(\d+)") { [int]$Matches[1] } else { $null }
    })

    if ($null -ne $history) {
        $status = if ($history -ge 24) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Account Policy" -ID "1.1.1" `
            -Check "Enforce password history" `
            -Status $status `
            -Finding "History depth: $history passwords" `
            -Expected ">= 24 passwords remembered (CIS)" `
            -Remediation "Set via GPO: Password Policy > Enforce password history = 24"
    }

    # --- Parse lockout threshold ---
    # CIS 1.2.1: Account lockout threshold <= 5 invalid attempts (and > 0)
    $lockoutThreshold = ($netAccounts | Select-String "Lockout threshold" | ForEach-Object {
        if ($_ -match "(\d+)") { [int]$Matches[1] }
        elseif ($_ -match "Never") { 0 }
        else { $null }
    })

    if ($null -ne $lockoutThreshold) {
        $status = if ($lockoutThreshold -ge 1 -and $lockoutThreshold -le 5) { "PASS" } else { "FAIL" }
        $finding = if ($lockoutThreshold -eq 0) { "Never (disabled)" } else { "$lockoutThreshold attempts" }
        Add-Result -Domain "Account Policy" -ID "1.2.1" `
            -Check "Account lockout threshold" `
            -Status $status `
            -Finding "Lockout after: $finding" `
            -Expected "1-5 invalid attempts (CIS)" `
            -Remediation "Set via GPO: Account Lockout Policy > Account lockout threshold = 5"
    }

    # --- Parse lockout duration ---
    # CIS 1.2.2: Account lockout duration >= 15 minutes
    $lockoutDuration = ($netAccounts | Select-String "Lockout duration" | ForEach-Object {
        if ($_ -match "(\d+)") { [int]$Matches[1] } else { $null }
    })

    if ($null -ne $lockoutDuration) {
        $status = if ($lockoutDuration -ge 15) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Account Policy" -ID "1.2.2" `
            -Check "Account lockout duration" `
            -Status $status `
            -Finding "Lockout duration: $lockoutDuration minutes" `
            -Expected ">= 15 minutes (CIS)" `
            -Remediation "Set via GPO: Account Lockout Policy > Account lockout duration = 15"
    }
}


# ============================================================
# DOMAIN 2: WINDOWS UPDATE AND PATCHING
# ============================================================

function Audit-WindowsUpdate {
    <#
    .SYNOPSIS
        Check Windows Update configuration and patch status.

    .DESCRIPTION
        Examines registry keys under HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
        and the Windows Update AU (Automatic Updates) subkey. These are readable by
        standard users. Also checks when the last update was installed.

        CIS References:
          18.9.x — Windows Update settings
    #>
    Write-Host "`n[*] Auditing Windows Update..." -ForegroundColor Cyan

    # --- Check if auto-update is enabled ---
    # CIS 18.9.101.2: Configure Automatic Updates = Enabled
    # Registry: AUOptions value under the AU subkey
    #   2 = Notify for download and notify for install
    #   3 = Auto download and notify for install
    #   4 = Auto download and schedule the install (recommended)
    #   5 = Allow local admin to choose (not recommended by CIS)
    $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $auOptions = Safe-RegQuery -Path $auPath -Name "AUOptions"

    if ($null -ne $auOptions) {
        $desc = switch ([int]$auOptions) {
            2 { "Notify for download and install" }
            3 { "Auto download, notify for install" }
            4 { "Auto download and schedule install" }
            5 { "Allow local admin to choose" }
            default { "Unknown ($auOptions)" }
        }
        $status = if ([int]$auOptions -eq 4) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Windows Update" -ID "18.9.101.2" `
            -Check "Automatic Updates configuration" `
            -Status $status `
            -Finding "AUOptions = $auOptions ($desc)" `
            -Expected "4 (Auto download and schedule install)" `
            -Remediation "Set via GPO: Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates = 4"
    } else {
        # If no policy key exists, check if Windows Update service is running
        # (which implies default auto-update behaviour)
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        $serviceStatus = if ($wuService) { $wuService.Status } else { "Not found" }
        Add-Result -Domain "Windows Update" -ID "18.9.101.2" `
            -Check "Automatic Updates configuration" `
            -Status "INFO" `
            -Finding "No GPO configured. Windows Update service: $serviceStatus. Using default settings." `
            -Expected "Explicit GPO configuration recommended"
    }

    # --- Check last update installation date ---
    # Not a specific CIS control, but critical for patch compliance.
    # Queries the Win32_QuickFixEngineering class which lists installed updates.
    try {
        $lastHotfix = Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop |
            Sort-Object InstalledOn -Descending |
            Select-Object -First 1

        if ($lastHotfix -and $lastHotfix.InstalledOn) {
            $daysSince = (New-TimeSpan -Start $lastHotfix.InstalledOn -End (Get-Date)).Days
            $status = if ($daysSince -le 30) { "PASS" } elseif ($daysSince -le 60) { "INFO" } else { "FAIL" }
            Add-Result -Domain "Windows Update" -ID "PATCH-01" `
                -Check "Last patch installation age" `
                -Status $status `
                -Finding "Last update: $($lastHotfix.HotFixID) installed $($lastHotfix.InstalledOn.ToString('yyyy-MM-dd')) ($daysSince days ago)" `
                -Expected "Patches installed within last 30 days" `
                -Remediation "Run Windows Update or WSUS client to install pending patches"
        }
    } catch {
        Add-Result -Domain "Windows Update" -ID "PATCH-01" `
            -Check "Last patch installation age" -Status "ERROR" `
            -Finding "Could not query patch history: $($_.Exception.Message)" -Expected "N/A"
    }

    # --- Check if WSUS is configured (enterprise environments) ---
    $wsusServer = Safe-RegQuery -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer"
    if ($wsusServer) {
        Add-Result -Domain "Windows Update" -ID "PATCH-02" `
            -Check "WSUS server configured" `
            -Status "INFO" `
            -Finding "WSUS URL: $wsusServer" `
            -Expected "N/A — informational"
    }
}


# ============================================================
# DOMAIN 3: WINDOWS FIREWALL
# ============================================================

function Audit-Firewall {
    <#
    .SYNOPSIS
        Check Windows Firewall status for all profiles.

    .DESCRIPTION
        Queries the firewall registry keys and netsh command to determine
        if the firewall is enabled for Domain, Private, and Public profiles.
        Standard users can read firewall state but cannot change rules.

        CIS References:
          9.1.x — Domain Profile
          9.2.x — Private Profile
          9.3.x — Public Profile
    #>
    Write-Host "`n[*] Auditing Windows Firewall..." -ForegroundColor Cyan

    # Query firewall state using netsh (works without admin)
    $fwProfiles = @("domainprofile", "privateprofile", "publicprofile")
    $cisIds     = @("9.1.1", "9.2.1", "9.3.1")
    $profileNames = @("Domain", "Private", "Public")

    for ($i = 0; $i -lt $fwProfiles.Count; $i++) {
        try {
            $fwState = netsh advfirewall show $fwProfiles[$i] state 2>&1
            $enabled = $fwState -match "ON"

            Add-Result -Domain "Windows Firewall" -ID $cisIds[$i] `
                -Check "Firewall enabled — $($profileNames[$i]) profile" `
                -Status $(if ($enabled) { "PASS" } else { "FAIL" }) `
                -Finding "Firewall state: $(if ($enabled) { 'ON' } else { 'OFF' })" `
                -Expected "ON (CIS)" `
                -Remediation "Enable via: netsh advfirewall set $($fwProfiles[$i]) state on (requires admin)"
        } catch {
            Add-Result -Domain "Windows Firewall" -ID $cisIds[$i] `
                -Check "Firewall enabled — $($profileNames[$i]) profile" `
                -Status "ERROR" -Finding "Could not query firewall state" -Expected "ON"
        }
    }

    # --- Check default inbound action ---
    # CIS 9.x.2: Inbound connections = Block (default deny)
    foreach ($i in 0..2) {
        try {
            $fwPolicy = netsh advfirewall show $fwProfiles[$i] 2>&1
            $inbound = $fwPolicy | Select-String "Firewall Policy" | Select-Object -First 1
            $isBlock = $inbound -match "BlockInbound"

            Add-Result -Domain "Windows Firewall" -ID "$($cisIds[$i] -replace '\.1$', '.2')" `
                -Check "Default inbound action — $($profileNames[$i]) profile" `
                -Status $(if ($isBlock) { "PASS" } else { "FAIL" }) `
                -Finding "Inbound policy: $($inbound -replace '.*Policy\s+', '')" `
                -Expected "BlockInbound (default deny)" `
                -Remediation "Set via GPO: Windows Firewall > $($profileNames[$i]) Profile > Inbound connections = Block"
        } catch {
            Add-Result -Domain "Windows Firewall" -ID "$($cisIds[$i] -replace '\.1$', '.2')" `
                -Check "Default inbound action — $($profileNames[$i]) profile" `
                -Status "ERROR" -Finding "Could not query" -Expected "BlockInbound"
        }
    }
}


# ============================================================
# DOMAIN 4: AUDIT / LOGGING POLICY
# ============================================================

function Audit-LoggingPolicy {
    <#
    .SYNOPSIS
        Check Windows event logging and audit policy configuration.

    .DESCRIPTION
        Queries the 'auditpol' command for the current audit policy settings.
        Standard users can READ audit policy on most Windows editions.
        Also checks event log size and retention settings via registry.

        CIS References:
          17.x — Advanced Audit Policy Configuration
          18.9.26.x — Event Log settings
    #>
    Write-Host "`n[*] Auditing Logging Policy..." -ForegroundColor Cyan

    # --- Query audit policy using auditpol ---
    # auditpol /get /category:* returns all audit categories and their settings.
    # Standard users can typically read this on workstations.
    try {
        $auditPol = auditpol /get /category:* 2>&1

        # Define CIS-required audit categories and expected settings
        # Format: [Category substring to match], [CIS ID], [Expected setting]
        $requiredAudits = @(
            @("Credential Validation",     "17.1.1", "Success and Failure"),
            @("Security Group Management", "17.2.5", "Success"),
            @("User Account Management",   "17.2.6", "Success and Failure"),
            @("Process Creation",          "17.3.1", "Success"),
            @("Logoff",                    "17.5.2", "Success"),
            @("Logon",                     "17.5.3", "Success and Failure"),
            @("Special Logon",             "17.5.6", "Success"),
            @("Audit Policy Change",       "17.7.1", "Success"),
            @("Authentication Policy",     "17.7.2", "Success"),
            @("Sensitive Privilege Use",    "17.8.1", "Success and Failure"),
            @("Security State Change",     "17.9.1", "Success"),
            @("System Integrity",          "17.9.4", "Success and Failure")
        )

        foreach ($audit in $requiredAudits) {
            $categoryName = $audit[0]
            $cisId        = $audit[1]
            $expected     = $audit[2]

            # Find the line matching this audit category
            $line = $auditPol | Select-String $categoryName | Select-Object -First 1

            if ($line) {
                $lineText = $line.ToString().Trim()
                # The setting is the last column (Success, Failure, Success and Failure, No Auditing)
                $setting = ($lineText -split '\s{2,}')[-1]

                # Check if the actual setting meets the expected level
                $pass = $false
                if ($expected -eq "Success and Failure") {
                    $pass = $setting -match "Success and Failure"
                } elseif ($expected -eq "Success") {
                    $pass = $setting -match "Success"
                } elseif ($expected -eq "Failure") {
                    $pass = $setting -match "Failure"
                }

                Add-Result -Domain "Audit Policy" -ID $cisId `
                    -Check "Audit: $categoryName" `
                    -Status $(if ($pass) { "PASS" } else { "FAIL" }) `
                    -Finding "Current: $setting" `
                    -Expected $expected `
                    -Remediation "Set via GPO: Advanced Audit Policy > $categoryName = $expected"
            } else {
                Add-Result -Domain "Audit Policy" -ID $cisId `
                    -Check "Audit: $categoryName" -Status "SKIPPED" `
                    -Finding "Could not find category in auditpol output (may require admin)" -Expected $expected
            }
        }
    } catch {
        Add-Result -Domain "Audit Policy" -ID "17.x" `
            -Check "Audit policy query" -Status "SKIPPED" `
            -Finding "auditpol requires elevated privileges on this system: $($_.Exception.Message)" `
            -Expected "N/A"
    }

    # --- Check event log maximum sizes ---
    # CIS 18.9.26.x: Minimum log sizes (in KB)
    $logSizes = @(
        @("Application", "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application", "MaxSize", 32768, "18.9.26.1.1"),
        @("Security",    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security",    "MaxSize", 196608, "18.9.26.2.1"),
        @("System",      "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System",      "MaxSize", 32768, "18.9.26.4.1")
    )

    foreach ($log in $logSizes) {
        $logName   = $log[0]
        $regPath   = $log[1]
        $regName   = $log[2]
        $minSizeKB = $log[3]
        $cisId     = $log[4]

        $currentSize = Safe-RegQuery -Path $regPath -Name $regName

        if ($null -ne $currentSize) {
            $status = if ([int]$currentSize -ge $minSizeKB) { "PASS" } else { "FAIL" }
            Add-Result -Domain "Audit Policy" -ID $cisId `
                -Check "$logName log maximum size" `
                -Status $status `
                -Finding "Max size: $([math]::Round($currentSize/1024, 1)) MB ($currentSize KB)" `
                -Expected ">= $([math]::Round($minSizeKB/1024, 1)) MB ($minSizeKB KB)" `
                -Remediation "Set via GPO: Event Log Service > $logName > Maximum Log Size = $minSizeKB KB"
        } else {
            # If GPO key doesn't exist, check the actual log configuration
            try {
                $logConfig = Get-WinEvent -ListLog $logName -ErrorAction Stop
                $actualKB = [math]::Round($logConfig.MaximumSizeInBytes / 1024)
                $status = if ($actualKB -ge $minSizeKB) { "PASS" } else { "FAIL" }
                Add-Result -Domain "Audit Policy" -ID $cisId `
                    -Check "$logName log maximum size" `
                    -Status $status `
                    -Finding "Max size: $([math]::Round($actualKB/1024, 1)) MB ($actualKB KB) (no GPO — local config)" `
                    -Expected ">= $([math]::Round($minSizeKB/1024, 1)) MB ($minSizeKB KB)" `
                    -Remediation "Set via GPO or locally via Event Viewer > Log Properties > Maximum log size"
            } catch {
                Add-Result -Domain "Audit Policy" -ID $cisId `
                    -Check "$logName log maximum size" -Status "INFO" `
                    -Finding "Could not determine log size" -Expected ">= $minSizeKB KB"
            }
        }
    }
}


# ============================================================
# DOMAIN 5: NETWORK SECURITY
# ============================================================

function Audit-NetworkSecurity {
    <#
    .SYNOPSIS
        Check network security settings: SMB, RDP, IPv6, and services.

    .DESCRIPTION
        Examines registry keys and service states for network security
        hardening. These checks cover protocol-level security settings
        that are readable by standard users.

        CIS References:
          2.3.x — Security Options (LAN Manager, SMB)
          18.4.x — Network settings
    #>
    Write-Host "`n[*] Auditing Network Security..." -ForegroundColor Cyan

    # --- SMBv1 Protocol ---
    # CIS 18.3.3: SMB v1 should be DISABLED (vulnerable to EternalBlue/WannaCry)
    $smb1Client = Safe-RegQuery -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start"
    if ($null -ne $smb1Client) {
        # Start = 4 means disabled, anything else means enabled
        $status = if ([int]$smb1Client -eq 4) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Network Security" -ID "18.3.3" `
            -Check "SMBv1 client driver disabled" `
            -Status $status `
            -Finding "mrxsmb10 Start = $smb1Client (4=Disabled)" `
            -Expected "4 (Disabled)" `
            -Remediation "Disable via: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol (requires admin)"
    }

    $smb1Server = Safe-RegQuery -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1"
    if ($null -ne $smb1Server) {
        $status = if ([int]$smb1Server -eq 0) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Network Security" -ID "18.3.3b" `
            -Check "SMBv1 server disabled" `
            -Status $status `
            -Finding "LanmanServer SMB1 = $smb1Server (0=Disabled)" `
            -Expected "0 (Disabled)" `
            -Remediation "Disable via GPO or PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol `$false"
    }

    # --- SMB Signing ---
    # CIS 2.3.8.1/2.3.8.2: SMB client and server signing should be required
    $smbClientSign = Safe-RegQuery -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature"
    if ($null -ne $smbClientSign) {
        $status = if ([int]$smbClientSign -eq 1) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Network Security" -ID "2.3.8.1" `
            -Check "SMB client signing required" `
            -Status $status `
            -Finding "RequireSecuritySignature = $smbClientSign" `
            -Expected "1 (Enabled)" `
            -Remediation "Set via GPO: Security Options > Microsoft network client: Digitally sign communications (always) = Enabled"
    }

    $smbServerSign = Safe-RegQuery -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature"
    if ($null -ne $smbServerSign) {
        $status = if ([int]$smbServerSign -eq 1) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Network Security" -ID "2.3.8.2" `
            -Check "SMB server signing required" `
            -Status $status `
            -Finding "RequireSecuritySignature = $smbServerSign" `
            -Expected "1 (Enabled)" `
            -Remediation "Set via GPO: Security Options > Microsoft network server: Digitally sign communications (always) = Enabled"
    }

    # --- RDP Security ---
    # CIS 18.9.65.3.9.1: Set RDP encryption level to High
    $rdpEncryption = Safe-RegQuery -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel"
    if ($null -ne $rdpEncryption) {
        $status = if ([int]$rdpEncryption -ge 3) { "PASS" } else { "FAIL" }
        $level = switch ([int]$rdpEncryption) { 1 {"Low"} 2 {"Client Compatible"} 3 {"High"} 4 {"FIPS"} default {"Unknown"} }
        Add-Result -Domain "Network Security" -ID "18.9.65.3.9.1" `
            -Check "RDP minimum encryption level" `
            -Status $status `
            -Finding "MinEncryptionLevel = $rdpEncryption ($level)" `
            -Expected ">= 3 (High)" `
            -Remediation "Set via GPO: Remote Desktop Session Host > Security > Set client connection encryption level = High"
    }

    # CIS 18.9.65.3.9.2: Require NLA for RDP
    $rdpNLA = Safe-RegQuery -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication"
    if ($null -ne $rdpNLA) {
        $status = if ([int]$rdpNLA -eq 1) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Network Security" -ID "18.9.65.3.9.2" `
            -Check "RDP Network Level Authentication (NLA) required" `
            -Status $status `
            -Finding "UserAuthentication = $rdpNLA" `
            -Expected "1 (Enabled)" `
            -Remediation "Set via GPO: Remote Desktop Session Host > Security > Require user authentication for remote connections by using NLA = Enabled"
    } else {
        # Check the non-policy registry path
        $rdpNLA2 = Safe-RegQuery -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"
        if ($null -ne $rdpNLA2) {
            $status = if ([int]$rdpNLA2 -eq 1) { "PASS" } else { "FAIL" }
            Add-Result -Domain "Network Security" -ID "18.9.65.3.9.2" `
                -Check "RDP Network Level Authentication (NLA)" `
                -Status $status `
                -Finding "UserAuthentication = $rdpNLA2 (local setting, no GPO)" `
                -Expected "1 (Enabled)"
        }
    }

    # --- Check for listening services (informational) ---
    # List open TCP ports to identify unnecessary network exposure
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Select-Object LocalAddress, LocalPort, OwningProcess |
            Sort-Object LocalPort -Unique

        $listenerCount = $listeners.Count
        $knownRisky = $listeners | Where-Object { $_.LocalPort -in @(21, 23, 69, 135, 445, 1433, 3389, 5985, 5986) }

        Add-Result -Domain "Network Security" -ID "NET-01" `
            -Check "Total listening TCP ports" `
            -Status "INFO" `
            -Finding "$listenerCount ports listening. Risky ports detected: $($knownRisky.Count)" `
            -Expected "Minimise listening services"

        if ($knownRisky) {
            foreach ($port in $knownRisky) {
                $procName = try { (Get-Process -Id $port.OwningProcess -ErrorAction Stop).ProcessName } catch { "Unknown" }
                $portDesc = switch ($port.LocalPort) {
                    21 {"FTP"} 23 {"Telnet"} 69 {"TFTP"} 135 {"RPC"}
                    445 {"SMB"} 1433 {"MSSQL"} 3389 {"RDP"} 5985 {"WinRM-HTTP"} 5986 {"WinRM-HTTPS"}
                }
                Add-Result -Domain "Network Security" -ID "NET-02" `
                    -Check "Risky port open: $($port.LocalPort) ($portDesc)" `
                    -Status "INFO" `
                    -Finding "Port $($port.LocalPort) ($portDesc) listening — Process: $procName (PID $($port.OwningProcess))" `
                    -Expected "Disable if not required"
            }
        }
    } catch {
        Add-Result -Domain "Network Security" -ID "NET-01" `
            -Check "Listening TCP ports" -Status "SKIPPED" `
            -Finding "Get-NetTCPConnection not available: $($_.Exception.Message)" -Expected "N/A"
    }
}


# ============================================================
# DOMAIN 6: USER RIGHTS AND LOCAL ACCOUNTS
# ============================================================

function Audit-UserAccounts {
    <#
    .SYNOPSIS
        Check local user accounts, guest account, and auto-logon.

    .DESCRIPTION
        Enumerates local accounts, checks for the guest account state,
        default Administrator account rename, and auto-logon credentials.
        These are readable by standard users via WMI and registry.

        CIS References:
          2.3.1.x — Accounts settings
          2.3.7.x — Interactive logon
    #>
    Write-Host "`n[*] Auditing User Accounts..." -ForegroundColor Cyan

    # --- Guest account disabled ---
    # CIS 2.3.1.2: Guest account must be disabled
    try {
        $guest = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE 'S-1-5-%-501'" -ErrorAction Stop
        if ($guest) {
            $status = if ($guest.Disabled) { "PASS" } else { "FAIL" }
            Add-Result -Domain "User Accounts" -ID "2.3.1.2" `
                -Check "Guest account disabled" `
                -Status $status `
                -Finding "Guest account '$($guest.Name)': Disabled=$($guest.Disabled)" `
                -Expected "Disabled = True" `
                -Remediation "Disable via: net user Guest /active:no (requires admin)"
        }
    } catch {
        Add-Result -Domain "User Accounts" -ID "2.3.1.2" `
            -Check "Guest account disabled" -Status "ERROR" `
            -Finding "Could not query: $($_.Exception.Message)" -Expected "Disabled"
    }

    # --- Administrator account renamed ---
    # CIS 2.3.1.5: Rename the built-in Administrator account
    try {
        $admin = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE 'S-1-5-%-500'" -ErrorAction Stop
        if ($admin) {
            $status = if ($admin.Name -ne "Administrator") { "PASS" } else { "FAIL" }
            Add-Result -Domain "User Accounts" -ID "2.3.1.5" `
                -Check "Built-in Administrator account renamed" `
                -Status $status `
                -Finding "Admin account name: '$($admin.Name)'" `
                -Expected "Not 'Administrator' (renamed)" `
                -Remediation "Rename via GPO: Security Options > Accounts: Rename administrator account"
        }
    } catch {
        Add-Result -Domain "User Accounts" -ID "2.3.1.5" -Check "Administrator renamed" `
            -Status "ERROR" -Finding "Could not query" -Expected "Renamed"
    }

    # --- Auto-logon credentials in registry ---
    # CIS 2.3.7.4: Do not store auto-logon credentials (password in cleartext in registry!)
    $autoLogon = Safe-RegQuery -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon"
    $autoPassword = Safe-RegQuery -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword"

    $autoEnabled = ($autoLogon -eq "1")
    $passStored = ($null -ne $autoPassword -and $autoPassword -ne "")

    if ($autoEnabled -or $passStored) {
        Add-Result -Domain "User Accounts" -ID "2.3.7.4" `
            -Check "Auto-logon disabled (no stored credentials)" `
            -Status "FAIL" `
            -Finding "AutoAdminLogon=$autoLogon, DefaultPassword=$(if($passStored){'PRESENT (cleartext!)'}else{'Not set'})" `
            -Expected "AutoAdminLogon=0, no DefaultPassword" `
            -Remediation "Remove via: reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v DefaultPassword /f"
    } else {
        Add-Result -Domain "User Accounts" -ID "2.3.7.4" `
            -Check "Auto-logon disabled (no stored credentials)" `
            -Status "PASS" `
            -Finding "AutoAdminLogon=$autoLogon, no stored password" `
            -Expected "No auto-logon credentials"
    }

    # --- Enumerate all local accounts (informational) ---
    try {
        $localAccounts = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop
        foreach ($acct in $localAccounts) {
            $flags = @()
            if ($acct.Disabled) { $flags += "Disabled" }
            if ($acct.Lockout) { $flags += "Locked" }
            if ($acct.PasswordRequired -eq $false) { $flags += "NO PASSWORD REQUIRED" }
            if ($acct.PasswordChangeable -eq $false) { $flags += "Cannot change password" }

            $statusStr = if ($flags.Count -gt 0) { $flags -join ", " } else { "Active, password required" }
            $severity = if ($acct.PasswordRequired -eq $false -and -not $acct.Disabled) { "FAIL" } else { "INFO" }

            Add-Result -Domain "User Accounts" -ID "ACCT-01" `
                -Check "Local account: $($acct.Name)" `
                -Status $severity `
                -Finding "SID: $($acct.SID) | Status: $statusStr" `
                -Expected "All accounts should require passwords"
        }
    } catch {}
}


# ============================================================
# DOMAIN 7: SECURITY FEATURES
# ============================================================

function Audit-SecurityFeatures {
    <#
    .SYNOPSIS
        Check Windows security features: UAC, BitLocker, Defender, DEP, ASLR.

    .DESCRIPTION
        Verifies that key security features are enabled and properly configured.
        Standard users can read most of these settings via registry and WMI.

        CIS References:
          2.3.17.x — UAC
          18.9.x  — Security features
    #>
    Write-Host "`n[*] Auditing Security Features..." -ForegroundColor Cyan

    # --- UAC Enabled ---
    # CIS 2.3.17.1: UAC must be enabled
    $uacEnabled = Safe-RegQuery -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
    if ($null -ne $uacEnabled) {
        $status = if ([int]$uacEnabled -eq 1) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Security Features" -ID "2.3.17.1" `
            -Check "User Account Control (UAC) enabled" `
            -Status $status `
            -Finding "EnableLUA = $uacEnabled" `
            -Expected "1 (Enabled)" `
            -Remediation "Set via GPO: Security Options > User Account Control: Run all administrators in Admin Approval Mode = Enabled"
    }

    # --- UAC: Prompt behaviour for admins ---
    # CIS 2.3.17.2: Prompt for consent on the secure desktop
    $uacPrompt = Safe-RegQuery -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"
    if ($null -ne $uacPrompt) {
        $desc = switch ([int]$uacPrompt) {
            0 {"Elevate without prompting"} 1 {"Prompt for credentials on secure desktop"}
            2 {"Prompt for consent on secure desktop"} 3 {"Prompt for credentials"}
            4 {"Prompt for consent"} 5 {"Prompt for consent for non-Windows binaries"}
        }
        $status = if ([int]$uacPrompt -le 2 -and [int]$uacPrompt -ge 1) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Security Features" -ID "2.3.17.2" `
            -Check "UAC admin prompt behaviour" `
            -Status $status `
            -Finding "ConsentPromptBehaviorAdmin = $uacPrompt ($desc)" `
            -Expected "1 or 2 (Prompt on secure desktop)" `
            -Remediation "Set via GPO: Security Options > UAC: Behavior of the elevation prompt for administrators"
    }

    # --- Windows Defender / Antivirus ---
    # Check if real-time protection is enabled
    $defenderDisabled = Safe-RegQuery -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware"
    if ($null -ne $defenderDisabled) {
        $status = if ([int]$defenderDisabled -eq 0) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Security Features" -ID "18.9.47.1" `
            -Check "Windows Defender not disabled by policy" `
            -Status $status `
            -Finding "DisableAntiSpyware = $defenderDisabled (0=Defender active)" `
            -Expected "0 (Not disabled)" `
            -Remediation "Remove GPO disabling Defender, or set DisableAntiSpyware = 0"
    }

    # Check Defender real-time monitoring
    $rtpDisabled = Safe-RegQuery -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring"
    if ($null -ne $rtpDisabled) {
        $status = if ([int]$rtpDisabled -eq 0) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Security Features" -ID "18.9.47.9.1" `
            -Check "Defender real-time protection enabled" `
            -Status $status `
            -Finding "DisableRealtimeMonitoring = $rtpDisabled" `
            -Expected "0 (Real-time protection ON)" `
            -Remediation "Enable via Windows Security > Virus & threat protection > Real-time protection = ON"
    }

    # --- DEP (Data Execution Prevention) ---
    # CIS 18.3.1: DEP should be enabled (OptIn at minimum, OptOut or AlwaysOn preferred)
    try {
        $dep = Get-CimInstance -ClassName Win32_OperatingSystem -Property DataExecutionPrevention_SupportPolicy
        $depPolicy = $dep.DataExecutionPrevention_SupportPolicy
        $depDesc = switch ($depPolicy) {
            0 {"AlwaysOff"} 1 {"AlwaysOn"} 2 {"OptIn (default)"} 3 {"OptOut"}
        }
        $status = if ($depPolicy -ge 1) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Security Features" -ID "18.3.1" `
            -Check "Data Execution Prevention (DEP)" `
            -Status $status `
            -Finding "DEP policy: $depPolicy ($depDesc)" `
            -Expected ">= 1 (AlwaysOn, OptIn, or OptOut)" `
            -Remediation "Set via: bcdedit /set nx OptOut (requires admin)"
    } catch {}

    # --- Secure Boot ---
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        Add-Result -Domain "Security Features" -ID "SEC-01" `
            -Check "UEFI Secure Boot enabled" `
            -Status $(if ($secureBoot) { "PASS" } else { "FAIL" }) `
            -Finding "Secure Boot: $secureBoot" `
            -Expected "True" `
            -Remediation "Enable in BIOS/UEFI firmware settings"
    } catch {
        Add-Result -Domain "Security Features" -ID "SEC-01" `
            -Check "UEFI Secure Boot" -Status "INFO" `
            -Finding "Could not determine (may not be UEFI or requires admin)" -Expected "Enabled"
    }

    # --- PowerShell Script Execution Policy ---
    $execPolicy = Get-ExecutionPolicy
    $status = if ($execPolicy -in @("Restricted", "AllSigned", "RemoteSigned")) { "PASS" } else { "FAIL" }
    Add-Result -Domain "Security Features" -ID "18.9.100.1" `
        -Check "PowerShell execution policy" `
        -Status $status `
        -Finding "Execution policy: $execPolicy" `
        -Expected "Restricted, AllSigned, or RemoteSigned" `
        -Remediation "Set via GPO: Turn on Script Execution = Allow only signed scripts"

    # --- PowerShell Script Block Logging ---
    $scriptBlockLog = Safe-RegQuery -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging"
    if ($null -ne $scriptBlockLog) {
        $status = if ([int]$scriptBlockLog -eq 1) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Security Features" -ID "18.9.100.2" `
            -Check "PowerShell Script Block Logging" `
            -Status $status `
            -Finding "EnableScriptBlockLogging = $scriptBlockLog" `
            -Expected "1 (Enabled)" `
            -Remediation "Set via GPO: Administrative Templates > PowerShell > Turn on PowerShell Script Block Logging = Enabled"
    }
}


# ============================================================
# DOMAIN 8: CREDENTIAL PROTECTION
# ============================================================

function Audit-CredentialProtection {
    <#
    .SYNOPSIS
        Check credential storage and protection settings.

    .DESCRIPTION
        Examines LAN Manager authentication level, credential caching,
        WDigest plaintext credential storage, and LSASS protection.

        CIS References:
          2.3.11.x — Network security (LAN Manager)
          18.3.x   — Credential protection
    #>
    Write-Host "`n[*] Auditing Credential Protection..." -ForegroundColor Cyan

    # --- LAN Manager Authentication Level ---
    # CIS 2.3.11.7: LmCompatibilityLevel should be 5 (Send NTLMv2 response only. Refuse LM & NTLM)
    $lmLevel = Safe-RegQuery -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"
    if ($null -ne $lmLevel) {
        $desc = switch ([int]$lmLevel) {
            0 {"Send LM & NTLM"} 1 {"Send LM & NTLM, use NTLMv2 if negotiated"}
            2 {"Send NTLM only"} 3 {"Send NTLMv2 only"} 4 {"Send NTLMv2, refuse LM"}
            5 {"Send NTLMv2, refuse LM & NTLM"}
        }
        $status = if ([int]$lmLevel -ge 5) { "PASS" } elseif ([int]$lmLevel -ge 3) { "INFO" } else { "FAIL" }
        Add-Result -Domain "Credential Protection" -ID "2.3.11.7" `
            -Check "LAN Manager authentication level" `
            -Status $status `
            -Finding "LmCompatibilityLevel = $lmLevel ($desc)" `
            -Expected "5 (Send NTLMv2 response only, refuse LM & NTLM)" `
            -Remediation "Set via GPO: Security Options > Network security: LAN Manager authentication level = Send NTLMv2 response only"
    }

    # --- WDigest Authentication (plaintext password in memory) ---
    # CIS 18.3.7: WDigest must be disabled (prevents Mimikatz-style attacks)
    $wdigest = Safe-RegQuery -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential"
    if ($null -ne $wdigest) {
        $status = if ([int]$wdigest -eq 0) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Credential Protection" -ID "18.3.7" `
            -Check "WDigest authentication disabled" `
            -Status $status `
            -Finding "UseLogonCredential = $wdigest (0=disabled, no plaintext creds in LSASS)" `
            -Expected "0 (Disabled)" `
            -Remediation "Set via registry: HKLM\SYSTEM\...\WDigest\UseLogonCredential = 0"
    } else {
        # On Windows 8.1+/Server 2012 R2+, WDigest is disabled by default when key is absent
        Add-Result -Domain "Credential Protection" -ID "18.3.7" `
            -Check "WDigest authentication disabled" `
            -Status "PASS" `
            -Finding "UseLogonCredential key not set (WDigest disabled by default on modern Windows)" `
            -Expected "Absent or 0"
    }

    # --- Cached Logon Credentials ---
    # CIS 2.3.6.1: CachedLogonsCount should be <= 4 (or 0 for high-security)
    $cachedLogons = Safe-RegQuery -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount"
    if ($null -ne $cachedLogons) {
        $count = [int]$cachedLogons
        $status = if ($count -le 4) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Credential Protection" -ID "2.3.6.1" `
            -Check "Cached logon credentials count" `
            -Status $status `
            -Finding "CachedLogonsCount = $count" `
            -Expected "<= 4 (CIS), 0 for high-security environments" `
            -Remediation "Set via GPO: Security Options > Interactive logon: Number of previous logons to cache = 4"
    }

    # --- LSASS Protection (RunAsPPL) ---
    $lsassPPL = Safe-RegQuery -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
    if ($null -ne $lsassPPL) {
        $status = if ([int]$lsassPPL -eq 1) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Credential Protection" -ID "18.3.5" `
            -Check "LSASS runs as Protected Process Light (PPL)" `
            -Status $status `
            -Finding "RunAsPPL = $lsassPPL" `
            -Expected "1 (Protected)" `
            -Remediation "Set via registry: HKLM\SYSTEM\...\Lsa\RunAsPPL = 1 (requires reboot)"
    }

    # --- Credential Guard ---
    $credGuard = Safe-RegQuery -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity"
    if ($null -ne $credGuard) {
        $status = if ([int]$credGuard -eq 1) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Credential Protection" -ID "18.3.6" `
            -Check "Virtualization Based Security (Credential Guard)" `
            -Status $status `
            -Finding "EnableVirtualizationBasedSecurity = $credGuard" `
            -Expected "1 (Enabled)" `
            -Remediation "Enable via GPO: Device Guard > Turn On Virtualization Based Security = Enabled"
    }
}


# ============================================================
# DOMAIN 9: MISCELLANEOUS HARDENING
# ============================================================

function Audit-MiscHardening {
    <#
    .SYNOPSIS
        Additional hardening checks: screen lock, remote assistance, autorun, etc.

    .DESCRIPTION
        Covers miscellaneous CIS controls that don't fit neatly into the
        other domains but are important for workstation hardening.
    #>
    Write-Host "`n[*] Auditing Miscellaneous Hardening..." -ForegroundColor Cyan

    # --- Screen saver / lock timeout ---
    # CIS 2.3.7.3: Machine inactivity timeout <= 900 seconds (15 min)
    $lockTimeout = Safe-RegQuery -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs"
    if ($null -ne $lockTimeout) {
        $status = if ([int]$lockTimeout -le 900 -and [int]$lockTimeout -gt 0) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Misc Hardening" -ID "2.3.7.3" `
            -Check "Machine inactivity lock timeout" `
            -Status $status `
            -Finding "InactivityTimeoutSecs = $lockTimeout seconds ($([math]::Round($lockTimeout/60, 1)) min)" `
            -Expected "<= 900 seconds (15 minutes)" `
            -Remediation "Set via GPO: Security Options > Interactive logon: Machine inactivity limit = 900"
    }

    # Also check the user-level screensaver settings
    $ssActive = Safe-RegQuery -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive"
    $ssSecure = Safe-RegQuery -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure"
    $ssTimeout = Safe-RegQuery -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut"

    if ($null -ne $ssActive) {
        $isActive = $ssActive -eq "1"
        $isSecure = $ssSecure -eq "1"
        $timeout = if ($ssTimeout) { [int]$ssTimeout } else { 0 }

        $status = if ($isActive -and $isSecure -and $timeout -le 900 -and $timeout -gt 0) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Misc Hardening" -ID "LOCK-01" `
            -Check "Screen saver with password lock" `
            -Status $status `
            -Finding "Active=$ssActive, Secure=$ssSecure, Timeout=${timeout}s ($([math]::Round($timeout/60,1)) min)" `
            -Expected "Active, password-protected, <= 900 seconds"
    }

    # --- AutoRun/AutoPlay ---
    # CIS 18.9.8.3: Disable AutoRun for all drives
    $autorun = Safe-RegQuery -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun"
    if ($null -ne $autorun) {
        $status = if ([int]$autorun -eq 255) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Misc Hardening" -ID "18.9.8.3" `
            -Check "AutoRun disabled for all drives" `
            -Status $status `
            -Finding "NoDriveTypeAutoRun = $autorun (255 = all drives)" `
            -Expected "255 (Disabled for all drive types)" `
            -Remediation "Set via GPO: Administrative Templates > Windows Components > AutoPlay Policies > Turn off Autoplay = All drives"
    }

    # --- Remote Assistance ---
    # CIS 18.8.36.1: Disable solicited Remote Assistance
    $remoteAssist = Safe-RegQuery -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp"
    if ($null -ne $remoteAssist) {
        $status = if ([int]$remoteAssist -eq 0) { "PASS" } else { "FAIL" }
        Add-Result -Domain "Misc Hardening" -ID "18.8.36.1" `
            -Check "Solicited Remote Assistance disabled" `
            -Status $status `
            -Finding "fAllowToGetHelp = $remoteAssist" `
            -Expected "0 (Disabled)" `
            -Remediation "Set via GPO: System > Remote Assistance > Configure Solicited Remote Assistance = Disabled"
    }

    # --- Windows Script Host ---
    $wsh = Safe-RegQuery -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled"
    if ($null -ne $wsh) {
        $status = if ([int]$wsh -eq 0) { "PASS" } else { "INFO" }
        Add-Result -Domain "Misc Hardening" -ID "MISC-01" `
            -Check "Windows Script Host" `
            -Status $status `
            -Finding "WSH Enabled = $wsh (0=Disabled)" `
            -Expected "0 (Disabled) to prevent .vbs/.js execution" `
            -Remediation "Disable via: HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled = 0"
    }

    # --- Check installed software for known vulnerable applications ---
    try {
        $installedApps = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher |
            Sort-Object DisplayName

        $appCount = $installedApps.Count
        Add-Result -Domain "Misc Hardening" -ID "MISC-02" `
            -Check "Installed software inventory" `
            -Status "INFO" `
            -Finding "$appCount applications installed (review for unnecessary software)" `
            -Expected "Minimal software footprint"
    } catch {}
}


# ============================================================
# HTML REPORT GENERATOR
# ============================================================

function Generate-HTMLReport {
    <#
    .SYNOPSIS
        Generate a professional HTML audit report from collected results.

    .DESCRIPTION
        Creates a self-contained HTML file with:
          - Executive summary (pass/fail/skip counts, pie chart)
          - System information
          - Detailed findings grouped by domain
          - Colour-coded status badges
          - Remediation guidance for all FAIL items
          - Timestamp and auditor information
    #>
    Write-Host "`n[*] Generating HTML report..." -ForegroundColor Cyan

    $total = $global:Results.Count
    $passRate = if ($total -gt 0) { [math]::Round(($global:PassCount / $total) * 100, 1) } else { 0 }

    # Group results by domain for the detailed section
    $grouped = $global:Results | Group-Object -Property Domain

    # Build the HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CIS Benchmark Audit Report - $($global:SysInfo.Hostname)</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: 'Segoe UI', Tahoma, sans-serif; background:#f5f5f5; color:#333; line-height:1.6; }
  .container { max-width:1100px; margin:0 auto; padding:20px; }
  .header { background:linear-gradient(135deg, #1a237e, #283593); color:#fff; padding:30px; border-radius:8px; margin-bottom:24px; }
  .header h1 { font-size:24px; margin-bottom:8px; }
  .header p { opacity:0.85; font-size:14px; }
  .summary { display:grid; grid-template-columns:repeat(auto-fit, minmax(140px,1fr)); gap:16px; margin-bottom:24px; }
  .stat-card { background:#fff; padding:20px; border-radius:8px; text-align:center; box-shadow:0 1px 3px rgba(0,0,0,0.1); }
  .stat-card .number { font-size:32px; font-weight:700; }
  .stat-card .label { font-size:12px; text-transform:uppercase; color:#666; margin-top:4px; }
  .pass .number { color:#2e7d32; }
  .fail .number { color:#c62828; }
  .info .number { color:#f57f17; }
  .skip .number { color:#78909c; }
  .error .number { color:#6a1b9a; }
  .rate .number { color:#1565c0; }
  .sysinfo { background:#fff; padding:20px; border-radius:8px; margin-bottom:24px; box-shadow:0 1px 3px rgba(0,0,0,0.1); }
  .sysinfo h2 { font-size:18px; margin-bottom:12px; color:#1a237e; }
  .sysinfo table { width:100%; border-collapse:collapse; }
  .sysinfo td { padding:6px 12px; border-bottom:1px solid #eee; font-size:14px; }
  .sysinfo td:first-child { font-weight:600; width:180px; color:#555; }
  .domain { background:#fff; border-radius:8px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.1); overflow:hidden; }
  .domain-header { padding:16px 20px; background:#e8eaf6; font-size:16px; font-weight:600; color:#1a237e; cursor:pointer; }
  .domain-header:hover { background:#c5cae9; }
  .domain-body { padding:0; }
  table.results { width:100%; border-collapse:collapse; font-size:13px; }
  table.results th { background:#f5f5f5; padding:10px 12px; text-align:left; font-weight:600; color:#555; border-bottom:2px solid #ddd; }
  table.results td { padding:10px 12px; border-bottom:1px solid #eee; vertical-align:top; }
  table.results tr:hover { background:#fafafa; }
  .badge { display:inline-block; padding:2px 10px; border-radius:12px; font-size:11px; font-weight:600; color:#fff; }
  .badge-pass { background:#2e7d32; }
  .badge-fail { background:#c62828; }
  .badge-info { background:#f57f17; color:#333; }
  .badge-skipped { background:#78909c; }
  .badge-error { background:#6a1b9a; }
  .remediation { background:#fff3e0; padding:8px 12px; border-radius:4px; font-size:12px; margin-top:6px; border-left:3px solid #f57f17; }
  .footer { text-align:center; padding:20px; color:#999; font-size:12px; }
  .disclaimer { background:#ffebee; padding:16px; border-radius:8px; margin-bottom:24px; border-left:4px solid #c62828; font-size:13px; }
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>CIS Benchmark Audit Report</h1>
  <p>Host: $($global:SysInfo.Hostname) | Date: $($global:SysInfo.AuditDate) | Auditor: $($global:SysInfo.CurrentUser)</p>
  <p>OS: $($global:SysInfo.OSName) ($($global:SysInfo.OSVersion)) | Privilege: $(if($global:SysInfo.IsAdmin){'Administrator'}else{'Standard User (non-admin)'})</p>
</div>

<div class="disclaimer">
  <strong>Disclaimer:</strong> This audit was performed with standard user (non-admin) privileges. Some CIS controls require elevated access and are marked SKIPPED. A complete CIS benchmark audit requires a separate admin-privileged pass.
</div>

<div class="summary">
  <div class="stat-card rate"><div class="number">${passRate}%</div><div class="label">Pass Rate</div></div>
  <div class="stat-card pass"><div class="number">$($global:PassCount)</div><div class="label">Passed</div></div>
  <div class="stat-card fail"><div class="number">$($global:FailCount)</div><div class="label">Failed</div></div>
  <div class="stat-card info"><div class="number">$($global:InfoCount)</div><div class="label">Info</div></div>
  <div class="stat-card skip"><div class="number">$($global:SkipCount)</div><div class="label">Skipped</div></div>
  <div class="stat-card error"><div class="number">$($global:ErrorCount)</div><div class="label">Errors</div></div>
</div>

<div class="sysinfo">
  <h2>System Information</h2>
  <table>
    <tr><td>Hostname</td><td>$($global:SysInfo.Hostname)</td></tr>
    <tr><td>Operating System</td><td>$($global:SysInfo.OSName)</td></tr>
    <tr><td>Version / Build</td><td>$($global:SysInfo.OSVersion) (Build $($global:SysInfo.OSBuild))</td></tr>
    <tr><td>Architecture</td><td>$($global:SysInfo.Architecture)</td></tr>
    <tr><td>Domain</td><td>$($global:SysInfo.Domain) (Joined: $($global:SysInfo.DomainJoined))</td></tr>
    <tr><td>Current User</td><td>$($global:SysInfo.CurrentUser)</td></tr>
    <tr><td>Admin Privileges</td><td>$($global:SysInfo.IsAdmin)</td></tr>
    <tr><td>PowerShell Version</td><td>$($global:SysInfo.PowerShell)</td></tr>
    <tr><td>Audit Date</td><td>$($global:SysInfo.AuditDate)</td></tr>
  </table>
</div>

"@

    # Detailed findings by domain
    foreach ($group in $grouped) {
        $domainPass = ($group.Group | Where-Object Status -eq "PASS").Count
        $domainFail = ($group.Group | Where-Object Status -eq "FAIL").Count
        $domainTotal = $group.Group.Count

        $html += @"
<div class="domain">
  <div class="domain-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
    $($group.Name) ($domainTotal checks: $domainPass passed, $domainFail failed)
  </div>
  <div class="domain-body">
    <table class="results">
      <tr><th style="width:60px">Status</th><th style="width:70px">ID</th><th style="width:240px">Check</th><th>Finding</th><th style="width:200px">Expected</th></tr>
"@

        foreach ($result in $group.Group) {
            $badgeClass = switch ($result.Status) {
                "PASS"    { "badge-pass" }
                "FAIL"    { "badge-fail" }
                "INFO"    { "badge-info" }
                "SKIPPED" { "badge-skipped" }
                "ERROR"   { "badge-error" }
            }

            $remediationHtml = ""
            if ($result.Status -eq "FAIL" -and $result.Remediation) {
                $remediationHtml = "<div class='remediation'><strong>Remediation:</strong> $($result.Remediation)</div>"
            }

            # Escape HTML characters in findings
            $findingSafe = [System.Web.HttpUtility]::HtmlEncode($result.Finding)
            $expectedSafe = [System.Web.HttpUtility]::HtmlEncode($result.Expected)

            $html += @"
      <tr>
        <td><span class="badge $badgeClass">$($result.Status)</span></td>
        <td>$($result.ID)</td>
        <td>$($result.Check)</td>
        <td>${findingSafe}${remediationHtml}</td>
        <td>$expectedSafe</td>
      </tr>
"@
        }

        $html += @"
    </table>
  </div>
</div>
"@
    }

    $html += @"
<div class="footer">
  Generated by CIS-Audit.ps1 (Non-Privileged Edition) | $($global:SysInfo.AuditDate)
</div>

</div>
</body>
</html>
"@

    # Write the HTML file
    # Load System.Web for HtmlEncode
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "  HTML report saved to: $OutputPath" -ForegroundColor Green
}


# ============================================================
# JSON EXPORT
# ============================================================

function Export-JsonResults {
    <#
    .SYNOPSIS
        Export audit results as JSON for programmatic processing.

    .DESCRIPTION
        Creates a JSON file with all results, system info, and summary stats.
        Useful for importing into SIEM, ticketing systems, or dashboards.
    #>
    Write-Host "  JSON results saved to: $JsonPath" -ForegroundColor Green

    $export = @{
        SystemInfo = $global:SysInfo
        Summary = @{
            Total    = $global:Results.Count
            Pass     = $global:PassCount
            Fail     = $global:FailCount
            Info     = $global:InfoCount
            Skipped  = $global:SkipCount
            Error    = $global:ErrorCount
            PassRate = if ($global:Results.Count -gt 0) { [math]::Round(($global:PassCount / $global:Results.Count) * 100, 1) } else { 0 }
        }
        Results = $global:Results
    }

    $export | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonPath -Encoding UTF8
}


# ============================================================
# MAIN EXECUTION
# ============================================================

Write-Host "`nStarting audit at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')..." -ForegroundColor Cyan
$startTime = Get-Date

# Collect system information
Collect-SystemInfo

# Run all audit domains
Audit-AccountPolicy        # Domain 1: Password & lockout policy
Audit-WindowsUpdate        # Domain 2: Patching & update config
Audit-Firewall             # Domain 3: Windows Firewall profiles
Audit-LoggingPolicy        # Domain 4: Audit policy & log sizes
Audit-NetworkSecurity      # Domain 5: SMB, RDP, listening ports
Audit-UserAccounts         # Domain 6: Local accounts, guest, auto-logon
Audit-SecurityFeatures     # Domain 7: UAC, Defender, DEP, Secure Boot
Audit-CredentialProtection # Domain 8: LM auth, WDigest, LSASS, Credential Guard
Audit-MiscHardening        # Domain 9: Screen lock, autorun, remote assistance

# Generate reports
Generate-HTMLReport

if ($JsonOutput) {
    Export-JsonResults
}

# Print summary
$elapsed = (Get-Date) - $startTime
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Total checks : $($global:Results.Count)"
Write-Host "  Passed       : $($global:PassCount)" -ForegroundColor Green
Write-Host "  Failed       : $($global:FailCount)" -ForegroundColor Red
Write-Host "  Info         : $($global:InfoCount)" -ForegroundColor Yellow
Write-Host "  Skipped      : $($global:SkipCount)" -ForegroundColor DarkGray
Write-Host "  Errors       : $($global:ErrorCount)" -ForegroundColor Magenta
Write-Host "  Pass rate    : $(if($global:Results.Count -gt 0){[math]::Round(($global:PassCount/$global:Results.Count)*100,1)}else{0})%"
Write-Host "  Duration     : $([math]::Round($elapsed.TotalSeconds, 1))s"
Write-Host "  Report       : $OutputPath"
if ($JsonOutput) { Write-Host "  JSON         : $JsonPath" }
Write-Host "============================================================`n" -ForegroundColor Cyan
