<#
.SYNOPSIS
    CIS-Audit.ps1 - Non-Privileged Windows CIS Benchmark Auditor

.DESCRIPTION
    Audits a Windows workstation/server against CIS Benchmark controls using
    ONLY standard-user (non-admin) PowerShell access. Generates an HTML report
    with PASS/FAIL/INFO results, remediation guidance, and an executive summary.

    This script checks ~130+ controls across 24 security domains that are
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
    Version : 2.0
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
  CIS Benchmark Auditor - Non-Privileged Edition
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
        IsAdmin      = $false
        AuditDate    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShell   = $PSVersionTable.PSVersion.ToString()
    }

    # Check admin status separately - the double type-cast syntax
    # [WindowsPrincipal][WindowsIdentity] can cause parse errors
    # in constrained environments, so we use New-Object instead
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $global:SysInfo.IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        $global:SysInfo.IsAdmin = $false
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
        policy may come from Group Policy - 'net accounts' shows the
        local policy which may differ from the applied GPO.

        CIS References:
          1.1.x - Password Policy
          1.2.x - Account Lockout Policy
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
          18.9.x - Windows Update settings
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
            -Expected "N/A - informational"
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
          9.1.x - Domain Profile
          9.2.x - Private Profile
          9.3.x - Public Profile
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
                -Check "Firewall enabled - $($profileNames[$i]) profile" `
                -Status $(if ($enabled) { "PASS" } else { "FAIL" }) `
                -Finding "Firewall state: $(if ($enabled) { 'ON' } else { 'OFF' })" `
                -Expected "ON (CIS)" `
                -Remediation "Enable via: netsh advfirewall set $($fwProfiles[$i]) state on (requires admin)"
        } catch {
            Add-Result -Domain "Windows Firewall" -ID $cisIds[$i] `
                -Check "Firewall enabled - $($profileNames[$i]) profile" `
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
                -Check "Default inbound action - $($profileNames[$i]) profile" `
                -Status $(if ($isBlock) { "PASS" } else { "FAIL" }) `
                -Finding "Inbound policy: $($inbound -replace '.*Policy\s+', '')" `
                -Expected "BlockInbound (default deny)" `
                -Remediation "Set via GPO: Windows Firewall > $($profileNames[$i]) Profile > Inbound connections = Block"
        } catch {
            Add-Result -Domain "Windows Firewall" -ID "$($cisIds[$i] -replace '\.1$', '.2')" `
                -Check "Default inbound action - $($profileNames[$i]) profile" `
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
          17.x - Advanced Audit Policy Configuration
          18.9.26.x - Event Log settings
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
                    -Finding "Max size: $([math]::Round($actualKB/1024, 1)) MB ($actualKB KB) (no GPO - local config)" `
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
          2.3.x - Security Options (LAN Manager, SMB)
          18.4.x - Network settings
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
                    -Finding "Port $($port.LocalPort) ($portDesc) listening - Process: $procName (PID $($port.OwningProcess))" `
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
          2.3.1.x - Accounts settings
          2.3.7.x - Interactive logon
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
          2.3.17.x - UAC
          18.9.x  - Security features
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
          2.3.11.x - Network security (LAN Manager)
          18.3.x   - Credential protection
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
# ============================================================
# DOMAIN 10: PERSISTENCE MECHANISMS - Scheduled Tasks
# ============================================================

function Audit-ScheduledTasks {
    <#
    .SYNOPSIS
        Audit scheduled tasks for suspicious or misconfigured entries.

    .DESCRIPTION
        Scheduled tasks are one of the most common persistence mechanisms
        used by attackers (MITRE ATT&CK T1053.005). Standard users can
        enumerate all scheduled tasks using schtasks.exe.

        We flag:
          - Tasks running as SYSTEM or high-privilege accounts
          - Tasks executing from user-writable directories (e.g., Temp, Downloads)
          - Tasks with actions pointing to non-existent binaries
          - Tasks running scripts (.ps1, .bat, .cmd, .vbs, .js)
          - Hidden tasks (tasks in paths not starting with \Microsoft)
    #>
    Write-Host "`n[*] Auditing Scheduled Tasks..." -ForegroundColor Cyan

    try {
        # Get all scheduled tasks as CSV for reliable parsing
        $tasks = schtasks /query /fo CSV /v 2>&1 | ConvertFrom-Csv -ErrorAction Stop

        $totalTasks = $tasks.Count
        $suspiciousCount = 0

        # Directories that standard users can write to - tasks running
        # executables from here are privilege escalation risks
        $writablePaths = @(
            $env:TEMP, $env:TMP, "$env:USERPROFILE\Downloads",
            "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents",
            "$env:APPDATA", "$env:LOCALAPPDATA\Temp",
            "C:\Users\Public"
        )

        # Script extensions that indicate potentially suspicious task actions
        $scriptExtensions = @(".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta")

        foreach ($task in $tasks) {
            $taskName = $task.TaskName
            $taskAction = $task."Task To Run"
            $runAs = $task."Run As User"
            $status = $task.Status

            # Skip empty or header rows
            if (-not $taskName -or $taskName -eq "TaskName") { continue }

            # --- Check 1: Non-Microsoft tasks (potential persistence) ---
            # Tasks not under \Microsoft\ are custom-created and worth reviewing
            $isCustom = $taskName -notmatch "^\\Microsoft\\"
            if (-not $isCustom) { continue }  # Skip built-in Microsoft tasks for brevity

            $findings = @()

            # --- Check 2: Running as SYSTEM or high-privilege account ---
            if ($runAs -match "SYSTEM|LOCAL SERVICE|NETWORK SERVICE|Administrator") {
                $findings += "Runs as $runAs (high privilege)"
            }

            # --- Check 3: Action points to writable directory ---
            foreach ($wPath in $writablePaths) {
                if ($taskAction -and $wPath -and $taskAction -like "*$wPath*") {
                    $findings += "Executes from user-writable path: $wPath"
                    break
                }
            }

            # --- Check 4: Action is a script file ---
            foreach ($ext in $scriptExtensions) {
                if ($taskAction -and $taskAction -like "*$ext*") {
                    $findings += "Executes script ($ext)"
                    break
                }
            }

            # --- Check 5: Action binary doesn't exist ---
            if ($taskAction -and $taskAction -ne "COM handler") {
                # Extract the executable path (first token, strip quotes)
                $exePath = ($taskAction -split '\s+')[0] -replace '"', ''
                if ($exePath -and $exePath -ne "COM" -and -not (Test-Path $exePath -ErrorAction SilentlyContinue)) {
                    # Only flag if it looks like a real path
                    if ($exePath -match '^[A-Z]:\\' -or $exePath -match '^\\\\') {
                        $findings += "Binary not found: $exePath"
                    }
                }
            }

            if ($findings.Count -gt 0) {
                $suspiciousCount++
                Add-Result -Domain "Scheduled Tasks" -ID "PERSIST-01" `
                    -Check "Suspicious task: $taskName" `
                    -Status "FAIL" `
                    -Finding "Action: $taskAction | RunAs: $runAs | Issues: $($findings -join '; ')" `
                    -Expected "Tasks should run with least privilege from protected directories" `
                    -Remediation "Review task legitimacy. Remove if unauthorised. If legitimate, move binary to a protected directory and reduce privilege."
            }
        }

        Add-Result -Domain "Scheduled Tasks" -ID "PERSIST-02" `
            -Check "Scheduled tasks summary" `
            -Status $(if ($suspiciousCount -eq 0) { "PASS" } else { "INFO" }) `
            -Finding "$totalTasks total tasks, $suspiciousCount custom tasks with findings" `
            -Expected "No suspicious scheduled tasks"

    } catch {
        Add-Result -Domain "Scheduled Tasks" -ID "PERSIST-01" `
            -Check "Scheduled tasks audit" -Status "ERROR" `
            -Finding "Could not enumerate tasks: $($_.Exception.Message)" -Expected "N/A"
    }
}


# ============================================================
# DOMAIN 11: PERSISTENCE MECHANISMS - Startup & Run Keys
# ============================================================

function Audit-StartupPersistence {
    <#
    .SYNOPSIS
        Audit registry Run keys, Startup folders, and other auto-start locations.

    .DESCRIPTION
        Checks all common auto-start extensibility points (ASEPs) that are
        readable by standard users. These are the locations malware and
        attackers use to survive reboots (MITRE ATT&CK T1547.001).

        Registry locations checked:
          - HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
          - HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
          - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
          - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
          - HKLM:\SOFTWARE\WOW6432Node\...\Run (32-bit on 64-bit)

        Filesystem locations:
          - %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup (user)
          - C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup (all users)
    #>
    Write-Host "`n[*] Auditing Startup Persistence..." -ForegroundColor Cyan

    # --- Registry Run keys ---
    $runKeys = @(
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (WOW64)")
    )

    $totalEntries = 0
    $suspiciousEntries = 0

    foreach ($keyInfo in $runKeys) {
        $keyPath = $keyInfo[0]
        $keyLabel = $keyInfo[1]

        try {
            $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }

            # Iterate over each value (each is a startup entry)
            $props.PSObject.Properties | Where-Object {
                $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSProvider","PSDrive")
            } | ForEach-Object {
                $totalEntries++
                $entryName = $_.Name
                $entryValue = $_.Value
                $issues = @()

                # Check if the path contains user-writable directories
                if ($entryValue -match '(?i)(\\Temp\\|\\Downloads\\|\\AppData\\Local\\Temp|\\Users\\Public)') {
                    $issues += "Executes from writable location"
                }

                # Check for script execution
                if ($entryValue -match '(?i)\.(ps1|bat|cmd|vbs|js|wsf|hta)') {
                    $issues += "Runs a script file"
                }

                # Check for encoded/obfuscated PowerShell
                if ($entryValue -match '(?i)(powershell.*-enc|powershell.*-e\s|cmd.*\/c.*powershell)') {
                    $issues += "SUSPICIOUS: Encoded/obfuscated PowerShell"
                }

                # Check if binary exists
                $binaryPath = ($entryValue -replace '"', '' -split '\s+')[0]
                if ($binaryPath -match '^[A-Z]:\\' -and -not (Test-Path $binaryPath -ErrorAction SilentlyContinue)) {
                    $issues += "Binary not found on disk"
                }

                $severity = if ($issues.Count -gt 0) { $suspiciousEntries++; "FAIL" } else { "INFO" }

                Add-Result -Domain "Startup Persistence" -ID "PERSIST-10" `
                    -Check "$keyLabel`: $entryName" `
                    -Status $severity `
                    -Finding "Value: $entryValue$(if($issues){' | Issues: ' + ($issues -join '; ')})" `
                    -Expected "Only legitimate, signed applications from protected directories" `
                    -Remediation "Verify this entry is legitimate. Remove if unauthorised: Remove-ItemProperty -Path '$keyPath' -Name '$entryName'"
            }
        } catch {
            # Access denied or key doesn't exist - expected for some HKLM paths
        }
    }

    # --- Startup folders ---
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            $items = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if ($item.Name -eq "desktop.ini") { continue }
                $totalEntries++
                $ext = $item.Extension.ToLower()
                $isScript = $ext -in @(".bat", ".cmd", ".vbs", ".js", ".ps1", ".wsf", ".hta", ".lnk")

                Add-Result -Domain "Startup Persistence" -ID "PERSIST-11" `
                    -Check "Startup folder: $($item.Name)" `
                    -Status $(if ($isScript) { $suspiciousEntries++; "FAIL" } else { "INFO" }) `
                    -Finding "Path: $($item.FullName) | Size: $($item.Length) bytes | Modified: $($item.LastWriteTime)" `
                    -Expected "Only verified startup items" `
                    -Remediation "Verify legitimacy. Remove if unauthorised."
            }
        }
    }

    Add-Result -Domain "Startup Persistence" -ID "PERSIST-12" `
        -Check "Startup persistence summary" `
        -Status $(if ($suspiciousEntries -eq 0) { "PASS" } else { "INFO" }) `
        -Finding "$totalEntries total startup entries, $suspiciousEntries with findings" `
        -Expected "No suspicious startup entries"
}


# ============================================================
# DOMAIN 12: TLS / SSL AND CIPHER CONFIGURATION
# ============================================================

function Audit-TLSConfiguration {
    <#
    .SYNOPSIS
        Audit TLS/SSL protocol versions and cipher suite configuration.

    .DESCRIPTION
        The Schannel registry keys control which TLS/SSL versions and ciphers
        are enabled system-wide. Weak protocols (SSL 2.0/3.0, TLS 1.0/1.1)
        should be disabled. These registry keys are readable by standard users.

        CIS References:
          18.4.x - TLS/SSL settings
    #>
    Write-Host "`n[*] Auditing TLS/SSL Configuration..." -ForegroundColor Cyan

    $schannelBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    # Protocols that should be DISABLED (insecure)
    $deprecatedProtocols = @(
        @("SSL 2.0", "TLS-01"),
        @("SSL 3.0", "TLS-02"),
        @("TLS 1.0", "TLS-03"),
        @("TLS 1.1", "TLS-04")
    )

    foreach ($proto in $deprecatedProtocols) {
        $protoName = $proto[0]
        $checkId = $proto[1]

        # Check both Client and Server sub-keys
        foreach ($side in @("Client", "Server")) {
            $regPath = "$schannelBase\$protoName\$side"
            $enabled = Safe-RegQuery -Path $regPath -Name "Enabled"
            $disabledByDefault = Safe-RegQuery -Path $regPath -Name "DisabledByDefault"

            if ($null -ne $enabled) {
                $isDisabled = ([int]$enabled -eq 0)
                $status = if ($isDisabled) { "PASS" } else { "FAIL" }
                Add-Result -Domain "TLS Configuration" -ID "$checkId" `
                    -Check "$protoName $side disabled" `
                    -Status $status `
                    -Finding "Enabled=$enabled, DisabledByDefault=$disabledByDefault" `
                    -Expected "Enabled=0, DisabledByDefault=1" `
                    -Remediation "Disable via registry: $regPath\Enabled = 0, DisabledByDefault = 1"
            } elseif ($null -ne $disabledByDefault -and [int]$disabledByDefault -eq 1) {
                Add-Result -Domain "TLS Configuration" -ID "$checkId" `
                    -Check "$protoName $side disabled" `
                    -Status "PASS" `
                    -Finding "No Enabled key, DisabledByDefault=1" `
                    -Expected "Disabled"
            } else {
                # Key doesn't exist - check if protocol is disabled by default in this OS
                Add-Result -Domain "TLS Configuration" -ID "$checkId" `
                    -Check "$protoName $side disabled" `
                    -Status "INFO" `
                    -Finding "No explicit registry configuration (OS default applies)" `
                    -Expected "Explicitly disabled recommended"
            }
        }
    }

    # Protocols that should be ENABLED
    foreach ($goodProto in @("TLS 1.2", "TLS 1.3")) {
        foreach ($side in @("Client", "Server")) {
            $regPath = "$schannelBase\$goodProto\$side"
            $enabled = Safe-RegQuery -Path $regPath -Name "Enabled"
            $disabledByDefault = Safe-RegQuery -Path $regPath -Name "DisabledByDefault"

            if ($null -ne $enabled -and [int]$enabled -eq 0) {
                Add-Result -Domain "TLS Configuration" -ID "TLS-05" `
                    -Check "$goodProto $side enabled" `
                    -Status "FAIL" `
                    -Finding "Enabled=0 ($goodProto is explicitly disabled!)" `
                    -Expected "Enabled=1 or key absent (default enabled)" `
                    -Remediation "Enable via registry: $regPath\Enabled = 1"
            } elseif ($null -ne $disabledByDefault -and [int]$disabledByDefault -eq 1) {
                Add-Result -Domain "TLS Configuration" -ID "TLS-05" `
                    -Check "$goodProto $side enabled" `
                    -Status "FAIL" `
                    -Finding "DisabledByDefault=1 ($goodProto disabled by default)" `
                    -Expected "DisabledByDefault=0" `
                    -Remediation "Set DisabledByDefault=0 at $regPath"
            } else {
                Add-Result -Domain "TLS Configuration" -ID "TLS-05" `
                    -Check "$goodProto $side enabled" `
                    -Status "PASS" `
                    -Finding "Enabled (explicit or OS default)"  `
                    -Expected "Enabled"
            }
        }
    }

    # --- Check for weak ciphers ---
    $weakCiphers = @("RC4", "DES", "NULL", "EXPORT", "MD5")
    $cipherBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"

    foreach ($cipher in $weakCiphers) {
        try {
            $cipherKeys = Get-ChildItem -Path $cipherBase -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match $cipher }
            foreach ($ck in $cipherKeys) {
                $cEnabled = Safe-RegQuery -Path $ck.PSPath -Name "Enabled"
                if ($null -ne $cEnabled -and [int]$cEnabled -ne 0) {
                    Add-Result -Domain "TLS Configuration" -ID "TLS-06" `
                        -Check "Weak cipher enabled: $($ck.PSChildName)" `
                        -Status "FAIL" `
                        -Finding "Enabled=$cEnabled" `
                        -Expected "0 (Disabled)" `
                        -Remediation "Disable via registry under SCHANNEL\Ciphers"
                }
            }
        } catch {}
    }
}


# ============================================================
# DOMAIN 13: NETWORK SHARES AND MAPPINGS
# ============================================================

function Audit-NetworkShares {
    <#
    .SYNOPSIS
        Audit network shares and mapped drives.

    .DESCRIPTION
        Enumerates local shares via 'net share' and mapped network drives.
        Checks for overly permissive shares, administrative shares, and
        shares pointing to sensitive locations.
    #>
    Write-Host "`n[*] Auditing Network Shares..." -ForegroundColor Cyan

    # --- Local shares ---
    try {
        $shares = Get-CimInstance -ClassName Win32_Share -ErrorAction Stop

        foreach ($share in $shares) {
            $shareName = $share.Name
            $sharePath = $share.Path
            $shareType = $share.Type

            # Type 0 = Disk, 1 = Print, 2 = Device, 2147483648 = Admin hidden
            $isAdmin = ($shareType -ge 2147483648) -or ($shareName -match '\$$')
            $isSensitive = $sharePath -match '(?i)(\\Windows|\\System32|\\Users\\|C:\\$)'

            $issues = @()
            if ($isAdmin -and $shareName -notin @("IPC$")) {
                $issues += "Administrative/hidden share exposed"
            }
            if ($isSensitive) {
                $issues += "Points to sensitive directory"
            }

            # Check share permissions (accessible to standard users via WMI)
            try {
                $security = Get-CimInstance -ClassName Win32_LogicalShareSecuritySetting -Filter "Name='$shareName'" -ErrorAction Stop
                $descriptor = $security | Invoke-CimMethod -MethodName GetSecurityDescriptor -ErrorAction Stop
                $dacl = $descriptor.Descriptor.DACL

                foreach ($ace in $dacl) {
                    $trusteeName = $ace.Trustee.Name
                    $accessMask = $ace.AccessMask
                    # 2032127 = Full Control, 1245631 = Change, 1179817 = Read
                    if ($trusteeName -eq "Everyone" -and $accessMask -ge 1245631) {
                        $issues += "Everyone has Change or Full Control"
                    }
                }
            } catch {}

            $severity = if ($issues.Count -gt 0) { "FAIL" } else { "INFO" }
            Add-Result -Domain "Network Shares" -ID "SHARE-01" `
                -Check "Share: $shareName" `
                -Status $severity `
                -Finding "Path: $sharePath | Type: $shareType$(if($isAdmin){' (Admin)'})" + $(if($issues){" | Issues: $($issues -join '; ')"}) `
                -Expected "Minimal shares with restrictive permissions" `
                -Remediation "Remove unnecessary shares: net share $shareName /delete. Restrict permissions."
        }
    } catch {
        Add-Result -Domain "Network Shares" -ID "SHARE-01" -Check "Share enumeration" `
            -Status "ERROR" -Finding "Could not enumerate: $($_.Exception.Message)" -Expected "N/A"
    }

    # --- Mapped network drives ---
    try {
        $mappedDrives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayRoot -and $_.DisplayRoot -match '^\\\\' }

        foreach ($drive in $mappedDrives) {
            Add-Result -Domain "Network Shares" -ID "SHARE-02" `
                -Check "Mapped drive: $($drive.Name):" `
                -Status "INFO" `
                -Finding "Maps to: $($drive.DisplayRoot)" `
                -Expected "Review for necessity and credential exposure"
        }
    } catch {}
}


# ============================================================
# DOMAIN 14: CREDENTIAL FILES ON DISK
# ============================================================

function Audit-CredentialFiles {
    <#
    .SYNOPSIS
        Scan for plaintext credentials and sensitive files on disk.

    .DESCRIPTION
        Searches common locations where credentials are accidentally
        stored in plaintext. This is a key finding in penetration tests
        and CIS hardening reviews.

        Locations scanned:
          - PowerShell console history (ConsoleHost_history.txt)
          - .rdp files with saved passwords
          - SSH private keys (~/.ssh/)
          - Git credentials (~/.git-credentials)
          - AWS/Azure/GCP credential files
          - unattend.xml from Windows installs
          - web.config files with connection strings
          - KeePass/password manager databases (informational)
    #>
    Write-Host "`n[*] Auditing Credential Files on Disk..." -ForegroundColor Cyan

    $userProfile = $env:USERPROFILE
    $sensitiveFiles = @()

    # --- PowerShell history ---
    # ConsoleHost_history.txt records every command typed in PowerShell.
    # May contain passwords passed as arguments, API keys, etc.
    $psHistoryPath = "$userProfile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHistoryPath) {
        $histSize = (Get-Item $psHistoryPath).Length
        $histLines = (Get-Content $psHistoryPath -ErrorAction SilentlyContinue | Measure-Object).Count

        # Scan for credential patterns in history
        $credPatterns = Get-Content $psHistoryPath -ErrorAction SilentlyContinue |
            Select-String -Pattern '(?i)(password|passwd|secret|token|apikey|api_key|credential|connectionstring)' -AllMatches

        $status = if ($credPatterns.Count -gt 0) { "FAIL" } else { "INFO" }
        Add-Result -Domain "Credential Files" -ID "CRED-01" `
            -Check "PowerShell history file" `
            -Status $status `
            -Finding "Path: $psHistoryPath | Size: $([math]::Round($histSize/1024,1)) KB | Lines: $histLines | Credential patterns found: $($credPatterns.Count)" `
            -Expected "No credential patterns in command history" `
            -Remediation "Clear history: Remove-Item '$psHistoryPath'. Disable: Set-PSReadlineOption -HistorySaveStyle SaveNothing"
    }

    # --- SSH private keys ---
    $sshDir = "$userProfile\.ssh"
    if (Test-Path $sshDir) {
        $sshFiles = Get-ChildItem -Path $sshDir -File -ErrorAction SilentlyContinue
        foreach ($sshFile in $sshFiles) {
            if ($sshFile.Name -match '^id_' -and $sshFile.Name -notmatch '\.pub$') {
                # Check if the key is encrypted (look for "ENCRYPTED" in the file header)
                $header = Get-Content $sshFile.FullName -First 3 -ErrorAction SilentlyContinue | Out-String
                $isEncrypted = $header -match "ENCRYPTED"

                Add-Result -Domain "Credential Files" -ID "CRED-02" `
                    -Check "SSH private key: $($sshFile.Name)" `
                    -Status $(if ($isEncrypted) { "INFO" } else { "FAIL" }) `
                    -Finding "Path: $($sshFile.FullName) | Encrypted: $isEncrypted" `
                    -Expected "Private keys should be passphrase-protected" `
                    -Remediation "Add passphrase: ssh-keygen -p -f '$($sshFile.FullName)'"
            }
        }
    }

    # --- Git credentials ---
    $gitCred = "$userProfile\.git-credentials"
    if (Test-Path $gitCred) {
        Add-Result -Domain "Credential Files" -ID "CRED-03" `
            -Check "Git credentials file (.git-credentials)" `
            -Status "FAIL" `
            -Finding "Plaintext credential store found: $gitCred" `
            -Expected "Use Git Credential Manager (encrypted) instead of .git-credentials" `
            -Remediation "Switch to GCM: git config --global credential.helper manager. Delete .git-credentials."
    }

    # --- RDP files with saved passwords ---
    $rdpFiles = Get-ChildItem -Path $userProfile -Recurse -Filter "*.rdp" -ErrorAction SilentlyContinue -Depth 3
    foreach ($rdp in $rdpFiles) {
        $content = Get-Content $rdp.FullName -ErrorAction SilentlyContinue | Out-String
        $hasPassword = $content -match "password 51:"  # RDP encrypted password field

        if ($hasPassword) {
            Add-Result -Domain "Credential Files" -ID "CRED-04" `
                -Check "RDP file with saved password: $($rdp.Name)" `
                -Status "FAIL" `
                -Finding "Path: $($rdp.FullName) - contains saved (encrypted) password" `
                -Expected "RDP files should not store credentials" `
                -Remediation "Remove saved password from the .rdp file or delete the file"
        }
    }

    # --- Cloud credential files ---
    $cloudCreds = @(
        @("$userProfile\.aws\credentials", "AWS credentials", "CRED-05"),
        @("$userProfile\.azure\accessTokens.json", "Azure access tokens", "CRED-06"),
        @("$userProfile\.config\gcloud\credentials.db", "GCP credentials", "CRED-07"),
        @("$userProfile\.config\gcloud\application_default_credentials.json", "GCP ADC", "CRED-08")
    )

    foreach ($cc in $cloudCreds) {
        if (Test-Path $cc[0]) {
            Add-Result -Domain "Credential Files" -ID $cc[2] `
                -Check "Cloud credential file: $($cc[1])" `
                -Status "INFO" `
                -Finding "Found: $($cc[0])" `
                -Expected "Review access scope and rotation schedule"
        }
    }

    # --- unattend.xml (Windows install file with potential passwords) ---
    $unattendPaths = @(
        "C:\unattend.xml", "C:\Windows\Panther\unattend.xml",
        "C:\Windows\Panther\Unattend\unattend.xml", "C:\Windows\system32\sysprep\unattend.xml"
    )
    foreach ($ua in $unattendPaths) {
        if (Test-Path $ua) {
            $content = Get-Content $ua -ErrorAction SilentlyContinue | Out-String
            $hasPassword = $content -match '(?i)<Password>|<AdministratorPassword>'

            Add-Result -Domain "Credential Files" -ID "CRED-09" `
                -Check "Unattend.xml found" `
                -Status $(if ($hasPassword) { "FAIL" } else { "INFO" }) `
                -Finding "Path: $ua | Contains password tags: $hasPassword" `
                -Expected "unattend.xml should be removed after Windows installation" `
                -Remediation "Delete the file: Remove-Item '$ua' (requires admin for system paths)"
        }
    }

    # --- KeePass databases (informational - not a vulnerability, but maps the cred surface) ---
    $kdbx = Get-ChildItem -Path $userProfile -Recurse -Filter "*.kdbx" -ErrorAction SilentlyContinue -Depth 4
    foreach ($db in $kdbx) {
        Add-Result -Domain "Credential Files" -ID "CRED-10" `
            -Check "KeePass database: $($db.Name)" `
            -Status "INFO" `
            -Finding "Path: $($db.FullName) | Modified: $($db.LastWriteTime)" `
            -Expected "Informational - ensure master password is strong"
    }
}


# ============================================================
# DOMAIN 15: WI-FI PROFILES
# ============================================================

function Audit-WiFiProfiles {
    <#
    .SYNOPSIS
        Audit saved Wi-Fi profiles for weak security configurations.

    .DESCRIPTION
        Uses netsh to enumerate saved wireless profiles and checks for:
          - Open (no security) networks
          - WEP-secured networks (trivially crackable)
          - WPA (v1) networks (deprecated)
          - Networks configured to connect automatically
    #>
    Write-Host "`n[*] Auditing Wi-Fi Profiles..." -ForegroundColor Cyan

    try {
        $profiles = netsh wlan show profiles 2>&1
        if ($profiles -match "is not running") {
            Add-Result -Domain "Wi-Fi Security" -ID "WIFI-01" -Check "Wi-Fi service" `
                -Status "INFO" -Finding "WLAN AutoConfig service not running (no Wi-Fi)" -Expected "N/A"
            return
        }

        $profileNames = ($profiles | Select-String "All User Profile\s+:\s+(.+)" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })

        if (-not $profileNames -or $profileNames.Count -eq 0) {
            Add-Result -Domain "Wi-Fi Security" -ID "WIFI-01" -Check "Wi-Fi profiles" `
                -Status "INFO" -Finding "No saved Wi-Fi profiles found" -Expected "N/A"
            return
        }

        foreach ($name in $profileNames) {
            $detail = netsh wlan show profile name="$name" 2>&1 | Out-String

            # Extract security type
            $authMatch = [regex]::Match($detail, 'Authentication\s+:\s+(.+)')
            $authType = if ($authMatch.Success) { $authMatch.Groups[1].Value.Trim() } else { "Unknown" }

            $cipherMatch = [regex]::Match($detail, 'Cipher\s+:\s+(.+)')
            $cipherType = if ($cipherMatch.Success) { $cipherMatch.Groups[1].Value.Trim() } else { "Unknown" }

            $autoConnect = $detail -match "Connection mode\s+:\s+Connect automatically"

            $issues = @()
            if ($authType -match "(?i)Open") { $issues += "OPEN network (no encryption)" }
            if ($authType -match "(?i)WEP") { $issues += "WEP (trivially crackable)" }
            if ($authType -match "(?i)^WPA[^2]" -and $authType -notmatch "WPA2|WPA3") { $issues += "WPA v1 (deprecated)" }
            if ($autoConnect) { $issues += "Auto-connect enabled" }

            $status = if ($issues | Where-Object { $_ -match "OPEN|WEP" }) { "FAIL" }
                      elseif ($issues.Count -gt 0) { "INFO" }
                      else { "PASS" }

            Add-Result -Domain "Wi-Fi Security" -ID "WIFI-02" `
                -Check "Wi-Fi profile: $name" `
                -Status $status `
                -Finding "Auth: $authType | Cipher: $cipherType | Auto: $autoConnect$(if($issues){' | Issues: ' + ($issues -join '; ')})" `
                -Expected "WPA2/WPA3 with AES, no auto-connect to untrusted networks" `
                -Remediation "Remove weak profiles: netsh wlan delete profile name=`"$name`". Disable auto-connect for non-trusted networks."
        }
    } catch {
        Add-Result -Domain "Wi-Fi Security" -ID "WIFI-01" -Check "Wi-Fi audit" `
            -Status "ERROR" -Finding "Error: $($_.Exception.Message)" -Expected "N/A"
    }
}


# ============================================================
# DOMAIN 16: BROWSER SECURITY
# ============================================================

function Audit-BrowserSecurity {
    <#
    .SYNOPSIS
        Audit browser extensions and security settings.

    .DESCRIPTION
        Checks Chrome and Edge extension manifests for excessive permissions.
        Extensions with broad permissions (<all_urls>, tabs, webRequest,
        cookies) can intercept all browsing activity and credentials.
    #>
    Write-Host "`n[*] Auditing Browser Security..." -ForegroundColor Cyan

    $browsers = @(
        @("Chrome", "$env:LOCALAPPDATA\Google\Chrome\User Data"),
        @("Edge", "$env:LOCALAPPDATA\Microsoft\Edge\User Data")
    )

    # Permissions that indicate excessive access
    $riskyPerms = @("<all_urls>", "*://*/*", "tabs", "webRequest", "webRequestBlocking",
                     "cookies", "clipboardRead", "nativeMessaging", "debugger", "proxy",
                     "management", "downloads", "history", "passwords")

    foreach ($browser in $browsers) {
        $browserName = $browser[0]
        $browserPath = $browser[1]

        if (-not (Test-Path $browserPath)) { continue }

        # Find all profile directories (Default, Profile 1, etc.)
        $profiles = Get-ChildItem -Path $browserPath -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile" }

        foreach ($profile in $profiles) {
            $extPath = Join-Path $profile.FullName "Extensions"
            if (-not (Test-Path $extPath)) { continue }

            $extensions = Get-ChildItem -Path $extPath -Directory -ErrorAction SilentlyContinue

            foreach ($ext in $extensions) {
                # Find the latest version directory
                $versionDir = Get-ChildItem -Path $ext.FullName -Directory -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending | Select-Object -First 1

                if (-not $versionDir) { continue }

                $manifestPath = Join-Path $versionDir.FullName "manifest.json"
                if (-not (Test-Path $manifestPath)) { continue }

                try {
                    $manifest = Get-Content $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json

                    $extName = $manifest.name
                    # Skip Chrome/Edge internal extensions
                    if ($extName -match '^__MSG_' -or $extName -match '^Chrome |^Microsoft ') {
                        $extName = if ($manifest.short_name) { $manifest.short_name } else { $ext.Name }
                    }

                    # Collect all permissions
                    $allPerms = @()
                    if ($manifest.permissions) { $allPerms += $manifest.permissions }
                    if ($manifest.optional_permissions) { $allPerms += $manifest.optional_permissions }
                    if ($manifest.host_permissions) { $allPerms += $manifest.host_permissions }

                    # Check for risky permissions
                    $foundRisky = $allPerms | Where-Object { $_ -in $riskyPerms -or $_ -match '^\*://' -or $_ -match '<all_urls>' }

                    if ($foundRisky -and $foundRisky.Count -gt 0) {
                        Add-Result -Domain "Browser Security" -ID "BROWSER-01" `
                            -Check "$browserName extension: $extName ($($profile.Name))" `
                            -Status "INFO" `
                            -Finding "Risky permissions: $($foundRisky -join ', ')" `
                            -Expected "Extensions should use minimal permissions" `
                            -Remediation "Review extension necessity. Remove via browser settings if not needed."
                    }
                } catch {}
            }
        }
    }
}


# ============================================================
# DOMAIN 17: OFFICE MACRO SETTINGS
# ============================================================

function Audit-OfficeMacros {
    <#
    .SYNOPSIS
        Audit Microsoft Office macro security settings.

    .DESCRIPTION
        Checks the registry keys that control macro execution in Office
        applications. Permissive macro settings are a primary vector for
        phishing and malware delivery.

        VBA macro settings (values):
          1 = Enable all macros (DANGEROUS)
          2 = Disable with notification (default)
          3 = Disable except digitally signed
          4 = Disable all without notification (most secure)
    #>
    Write-Host "`n[*] Auditing Office Macro Settings..." -ForegroundColor Cyan

    $officeApps = @("Word", "Excel", "PowerPoint", "Outlook", "Access")

    # Check both Office 16.0 (2016/2019/365) and 15.0 (2013)
    $officeVersions = @("16.0", "15.0")

    foreach ($ver in $officeVersions) {
        foreach ($app in $officeApps) {
            $regPath = "HKCU:\SOFTWARE\Microsoft\Office\$ver\$app\Security"
            $vbaWarnings = Safe-RegQuery -Path $regPath -Name "VBAWarnings"

            if ($null -ne $vbaWarnings) {
                $desc = switch ([int]$vbaWarnings) {
                    1 { "Enable all macros (DANGEROUS)" }
                    2 { "Disable with notification (default)" }
                    3 { "Disable except digitally signed" }
                    4 { "Disable all without notification" }
                    default { "Unknown ($vbaWarnings)" }
                }

                $status = switch ([int]$vbaWarnings) {
                    1 { "FAIL" }
                    2 { "INFO" }
                    3 { "PASS" }
                    4 { "PASS" }
                    default { "INFO" }
                }

                Add-Result -Domain "Office Macros" -ID "OFFICE-01" `
                    -Check "Office $ver $app macro setting" `
                    -Status $status `
                    -Finding "VBAWarnings = $vbaWarnings ($desc)" `
                    -Expected "3 (Signed only) or 4 (All disabled)" `
                    -Remediation "Set via GPO: Office > $app > Security > Macro Settings = Disable except digitally signed"
            }

            # Check if the VBA trust access to the object model is enabled
            $trustVBA = Safe-RegQuery -Path $regPath -Name "AccessVBOM"
            if ($null -ne $trustVBA -and [int]$trustVBA -eq 1) {
                Add-Result -Domain "Office Macros" -ID "OFFICE-02" `
                    -Check "Office $ver $app VBA object model access" `
                    -Status "FAIL" `
                    -Finding "AccessVBOM = 1 (Trust access to VBA project object model)" `
                    -Expected "0 (Disabled)" `
                    -Remediation "Disable via GPO or registry"
            }
        }
    }
}


# ============================================================
# DOMAIN 18: CERTIFICATE STORE
# ============================================================

function Audit-CertificateStore {
    <#
    .SYNOPSIS
        Review the certificate store for expired, weak, or suspicious certificates.

    .DESCRIPTION
        Checks both the user certificate store (always accessible) and
        readable portions of the machine store. Flags expired certs,
        weak key algorithms, and untrusted root CAs.
    #>
    Write-Host "`n[*] Auditing Certificate Store..." -ForegroundColor Cyan

    $stores = @(
        @("Cert:\CurrentUser\Root", "User Trusted Root CAs"),
        @("Cert:\CurrentUser\My", "User Personal Certificates"),
        @("Cert:\LocalMachine\Root", "Machine Trusted Root CAs"),
        @("Cert:\LocalMachine\My", "Machine Personal Certificates")
    )

    foreach ($storeInfo in $stores) {
        $storePath = $storeInfo[0]
        $storeLabel = $storeInfo[1]

        try {
            $certs = Get-ChildItem -Path $storePath -ErrorAction Stop

            foreach ($cert in $certs) {
                $issues = @()

                # Check expiry
                if ($cert.NotAfter -lt (Get-Date)) {
                    $issues += "EXPIRED ($($cert.NotAfter.ToString('yyyy-MM-dd')))"
                }

                # Check key size (RSA < 2048 is weak)
                if ($cert.PublicKey.Key) {
                    try {
                        $keySize = $cert.PublicKey.Key.KeySize
                        if ($keySize -lt 2048) {
                            $issues += "Weak key size ($keySize bits)"
                        }
                    } catch {}
                }

                # Check signature algorithm (SHA1 is deprecated)
                if ($cert.SignatureAlgorithm.FriendlyName -match "sha1") {
                    $issues += "SHA-1 signature (deprecated)"
                }

                if ($issues.Count -gt 0) {
                    Add-Result -Domain "Certificate Store" -ID "CERT-01" `
                        -Check "Certificate: $($cert.Subject | Select-Object -First 1)" `
                        -Status "FAIL" `
                        -Finding "Store: $storeLabel | Thumbprint: $($cert.Thumbprint) | Issues: $($issues -join '; ')" `
                        -Expected "Valid, non-expired, SHA-256+, RSA 2048+ keys" `
                        -Remediation "Remove expired/weak certificates from the store"
                }
            }
        } catch {
            # LocalMachine stores may not be fully readable
        }
    }
}


# ============================================================
# DOMAIN 19: WRITABLE PATH DIRECTORIES
# ============================================================

function Audit-WritablePaths {
    <#
    .SYNOPSIS
        Check if any directories in the system PATH are writable by the current user.

    .DESCRIPTION
        If a directory in PATH is writable, an attacker can place a malicious
        DLL or executable there to hijack legitimate program execution.
        This is a classic privilege escalation vector (DLL search order hijacking).
    #>
    Write-Host "`n[*] Auditing Writable PATH Directories..." -ForegroundColor Cyan

    $pathDirs = $env:PATH -split ';' | Where-Object { $_ -and $_.Trim() }
    $writableCount = 0

    foreach ($dir in $pathDirs) {
        $dir = $dir.Trim()
        if (-not (Test-Path $dir -PathType Container)) {
            Add-Result -Domain "Writable Paths" -ID "PATH-01" `
                -Check "PATH directory missing: $dir" `
                -Status "INFO" `
                -Finding "Directory does not exist" `
                -Expected "All PATH directories should exist"
            continue
        }

        # Test writability by attempting to get ACL and check for write access
        try {
            $acl = Get-Acl -Path $dir -ErrorAction Stop
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $userSids = @($currentUser.User.Value) + ($currentUser.Groups | ForEach-Object { $_.Value })

            $isWritable = $false
            foreach ($ace in $acl.Access) {
                $aceSid = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { "" }
                if ($aceSid -in $userSids -or $ace.IdentityReference.Value -match "Everyone|BUILTIN\\Users|Authenticated Users") {
                    $rights = $ace.FileSystemRights.ToString()
                    if ($rights -match "Write|Modify|FullControl|CreateFiles") {
                        $isWritable = $true
                        break
                    }
                }
            }

            if ($isWritable) {
                $writableCount++
                Add-Result -Domain "Writable Paths" -ID "PATH-02" `
                    -Check "Writable PATH directory: $dir" `
                    -Status "FAIL" `
                    -Finding "Current user has write access to PATH directory: $dir" `
                    -Expected "PATH directories should not be writable by standard users" `
                    -Remediation "Remove write permissions or remove the directory from PATH"
            }
        } catch {}
    }

    if ($writableCount -eq 0) {
        Add-Result -Domain "Writable Paths" -ID "PATH-02" `
            -Check "PATH directory write access" `
            -Status "PASS" `
            -Finding "No writable PATH directories found for current user ($($pathDirs.Count) dirs checked)" `
            -Expected "No writable PATH directories"
    }
}


# ============================================================
# DOMAIN 20: UNQUOTED SERVICE PATHS
# ============================================================

function Audit-UnquotedServicePaths {
    <#
    .SYNOPSIS
        Find Windows services with unquoted executable paths containing spaces.

    .DESCRIPTION
        If a service path like C:\Program Files\My App\service.exe is not
        quoted, Windows will try to execute:
          1. C:\Program.exe
          2. C:\Program Files\My.exe
          3. C:\Program Files\My App\service.exe

        An attacker who can write to C:\ or C:\Program Files\ can place a
        malicious binary that gets executed with the service's privileges
        (often SYSTEM). This is MITRE ATT&CK T1574.009.
    #>
    Write-Host "`n[*] Auditing Unquoted Service Paths..." -ForegroundColor Cyan

    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s' }

        $unquotedCount = 0

        foreach ($svc in $services) {
            $pathName = $svc.PathName

            # Skip svchost and system services (their paths are resolved differently)
            if ($pathName -match '(?i)svchost\.exe|\\system32\\' -and $pathName -notmatch 'Program Files') { continue }

            # Extract the executable path (before any arguments)
            # Look for .exe and take everything before it plus the extension
            if ($pathName -match '^(.+?\.exe)') {
                $exePath = $Matches[1]
                if ($exePath -match '\s' -and $exePath -notmatch '^"') {
                    $unquotedCount++
                    Add-Result -Domain "Unquoted Service Paths" -ID "UNQUOTE-01" `
                        -Check "Unquoted service: $($svc.Name)" `
                        -Status "FAIL" `
                        -Finding "Service: $($svc.DisplayName) | StartMode: $($svc.StartMode) | RunAs: $($svc.StartName) | Path: $pathName" `
                        -Expected "Service paths with spaces must be quoted" `
                        -Remediation "Fix: sc.exe config `"$($svc.Name)`" binPath= `"$pathName`" (requires admin)"
                }
            }
        }

        if ($unquotedCount -eq 0) {
            Add-Result -Domain "Unquoted Service Paths" -ID "UNQUOTE-01" `
                -Check "Unquoted service path check" `
                -Status "PASS" `
                -Finding "No unquoted service paths with spaces found" `
                -Expected "All service paths properly quoted"
        }
    } catch {
        Add-Result -Domain "Unquoted Service Paths" -ID "UNQUOTE-01" -Check "Service path audit" `
            -Status "ERROR" -Finding "Could not enumerate: $($_.Exception.Message)" -Expected "N/A"
    }
}


# ============================================================
# DOMAIN 21: INSTALLED SERVICES STATE
# ============================================================

function Audit-InstalledServices {
    <#
    .SYNOPSIS
        Audit running and auto-start services for unnecessary or risky services.

    .DESCRIPTION
        Services that start automatically but aren't needed increase the
        attack surface. Services running as SYSTEM with high exposure
        (listening on network) are particularly risky.
    #>
    Write-Host "`n[*] Auditing Installed Services..." -ForegroundColor Cyan

    # Services that CIS recommends disabling if not needed
    $riskyServices = @{
        "RemoteRegistry"  = "Remote Registry (allows remote registry editing)"
        "TermService"     = "Remote Desktop Services"
        "WinRM"           = "Windows Remote Management"
        "SNMP"            = "SNMP Service (community strings often weak)"
        "TlntSvr"         = "Telnet Server (cleartext protocol)"
        "FTPSVC"          = "FTP Server"
        "W3SVC"           = "IIS Web Server"
        "SSDPSRV"         = "SSDP Discovery (UPnP)"
        "upnphost"        = "UPnP Device Host"
        "lmhosts"         = "TCP/IP NetBIOS Helper"
        "WerSvc"          = "Windows Error Reporting"
        "Fax"             = "Fax Service"
        "XblGameSave"     = "Xbox services (unnecessary on workstations)"
        "XblAuthManager"  = "Xbox Auth"
    }

    foreach ($svcName in $riskyServices.Keys) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            $startType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue).StartMode
            $isRunning = $svc.Status -eq "Running"

            if ($isRunning -or $startType -eq "Auto") {
                Add-Result -Domain "Services" -ID "SVC-01" `
                    -Check "Risky service: $svcName" `
                    -Status "FAIL" `
                    -Finding "$($riskyServices[$svcName]) | Status: $($svc.Status) | StartType: $startType" `
                    -Expected "Disabled or Manual start (if not required)" `
                    -Remediation "Disable: Set-Service -Name $svcName -StartupType Disabled (requires admin)"
            }
        }
    }
}


# ============================================================
# DOMAIN 22: ENVIRONMENT VARIABLES
# ============================================================

function Audit-EnvironmentVariables {
    <#
    .SYNOPSIS
        Audit environment variables for credential leakage and misconfigurations.

    .DESCRIPTION
        Developers sometimes store API keys, tokens, and passwords as
        environment variables. Also checks proxy settings that might
        indicate traffic interception.
    #>
    Write-Host "`n[*] Auditing Environment Variables..." -ForegroundColor Cyan

    # Patterns that suggest credential storage
    $credPatterns = @("KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL",
                      "API_KEY", "APIKEY", "AUTH", "PRIVATE", "ACCESS_KEY")

    $allVars = [Environment]::GetEnvironmentVariables("User")
    $machineVars = [Environment]::GetEnvironmentVariables("Machine")

    foreach ($scope in @(@($allVars, "User"), @($machineVars, "Machine"))) {
        $vars = $scope[0]
        $scopeName = $scope[1]

        foreach ($key in $vars.Keys) {
            $value = $vars[$key]
            $upperKey = $key.ToUpper()

            # Check if variable name matches credential patterns
            $matchedPattern = $credPatterns | Where-Object { $upperKey -match $_ }

            if ($matchedPattern -and $value -and $value.Length -gt 3) {
                # Mask the value for the report (show first 4 chars only)
                $maskedValue = $value.Substring(0, [Math]::Min(4, $value.Length)) + "****"

                Add-Result -Domain "Environment Variables" -ID "ENV-01" `
                    -Check "Potential credential in env var: $key ($scopeName)" `
                    -Status "FAIL" `
                    -Finding "Variable '$key' matches pattern '$matchedPattern' | Value: $maskedValue" `
                    -Expected "Credentials should not be stored as environment variables" `
                    -Remediation "Move credential to a secrets manager or encrypted config file. Remove from env."
            }
        }
    }

    # --- Check proxy settings ---
    $httpProxy = $allVars["HTTP_PROXY"]
    $httpsProxy = $allVars["HTTPS_PROXY"]
    $noProxy = $allVars["NO_PROXY"]

    if ($httpProxy -or $httpsProxy) {
        $hasCredInProxy = ($httpProxy + $httpsProxy) -match '://[^:]+:[^@]+@'

        Add-Result -Domain "Environment Variables" -ID "ENV-02" `
            -Check "Proxy configuration in environment" `
            -Status $(if ($hasCredInProxy) { "FAIL" } else { "INFO" }) `
            -Finding "HTTP_PROXY=$httpProxy | HTTPS_PROXY=$httpsProxy$(if($hasCredInProxy){' | WARNING: Credentials embedded in proxy URL!'})" `
            -Expected "No credentials in proxy URLs" `
            -Remediation "Remove credentials from proxy URLs. Use authenticated proxy with credential manager."
    }

    # Check IE/System proxy
    $ieProxy = Safe-RegQuery -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyServer"
    $ieProxyEnabled = Safe-RegQuery -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable"

    if ($ieProxy -and $ieProxyEnabled -eq 1) {
        Add-Result -Domain "Environment Variables" -ID "ENV-03" `
            -Check "System proxy configured" `
            -Status "INFO" `
            -Finding "Proxy: $ieProxy (enabled)" `
            -Expected "Verify proxy is legitimate and managed"
    }
}


# ============================================================
# DOMAIN 23: DNS CLIENT CONFIGURATION
# ============================================================

function Audit-DNSConfiguration {
    <#
    .SYNOPSIS
        Audit DNS client settings for potential misconfiguration or hijacking.

    .DESCRIPTION
        Checks configured DNS servers across all network adapters, DNS suffix
        search lists, and DNS-over-HTTPS configuration. A malicious DNS server
        can redirect all traffic.
    #>
    Write-Host "`n[*] Auditing DNS Configuration..." -ForegroundColor Cyan

    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop

        # Well-known public DNS servers (for comparison)
        $knownDNS = @{
            "8.8.8.8"       = "Google Public DNS"
            "8.8.4.4"       = "Google Public DNS"
            "1.1.1.1"       = "Cloudflare DNS"
            "1.0.0.1"       = "Cloudflare DNS"
            "9.9.9.9"       = "Quad9 DNS"
            "149.112.112.112" = "Quad9 DNS"
            "208.67.222.222"  = "OpenDNS"
            "208.67.220.220"  = "OpenDNS"
        }

        foreach ($adapter in $adapters) {
            $adapterName = $adapter.Description
            $dnsServers = $adapter.DNSServerSearchOrder

            if ($dnsServers) {
                $dnsInfo = @()
                $hasUnknown = $false

                foreach ($dns in $dnsServers) {
                    if ($knownDNS.ContainsKey($dns)) {
                        $dnsInfo += "$dns ($($knownDNS[$dns]))"
                    } elseif ($dns -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') {
                        $dnsInfo += "$dns (Private/internal)"
                    } else {
                        $dnsInfo += "$dns (UNKNOWN PUBLIC DNS)"
                        $hasUnknown = $true
                    }
                }

                Add-Result -Domain "DNS Configuration" -ID "DNS-01" `
                    -Check "DNS servers: $adapterName" `
                    -Status $(if ($hasUnknown) { "INFO" } else { "PASS" }) `
                    -Finding "DNS: $($dnsInfo -join ', ')" `
                    -Expected "Known legitimate DNS servers" `
                    -Remediation "Verify unknown DNS servers are legitimate. Could indicate DNS hijacking."
            }

            # Check DNS suffix search list
            $suffixList = $adapter.DNSDomainSuffixSearchOrder
            if ($suffixList -and $suffixList.Count -gt 0) {
                Add-Result -Domain "DNS Configuration" -ID "DNS-02" `
                    -Check "DNS suffix search list: $adapterName" `
                    -Status "INFO" `
                    -Finding "Suffixes: $($suffixList -join ', ')" `
                    -Expected "Review for legitimacy - malicious suffixes can redirect queries"
            }
        }
    } catch {
        Add-Result -Domain "DNS Configuration" -ID "DNS-01" -Check "DNS audit" `
            -Status "ERROR" -Finding "Could not query: $($_.Exception.Message)" -Expected "N/A"
    }

    # --- DNS-over-HTTPS status ---
    $dohEnabled = Safe-RegQuery -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh"
    if ($null -ne $dohEnabled) {
        $desc = switch ([int]$dohEnabled) { 0 {"Disabled"} 1 {"Automatic"} 2 {"Enabled"} }
        Add-Result -Domain "DNS Configuration" -ID "DNS-03" `
            -Check "DNS-over-HTTPS (DoH)" `
            -Status "INFO" `
            -Finding "EnableAutoDoh = $dohEnabled ($desc)" `
            -Expected "Enabled for privacy (2) unless organisational policy requires plaintext DNS inspection"
    }
}


# ============================================================
# DOMAIN 24: INSTALLED SOFTWARE DEEP SCAN
# ============================================================

function Audit-InstalledSoftwareDeep {
    <#
    .SYNOPSIS
        Deep scan of installed software for known-vulnerable or end-of-life applications.

    .DESCRIPTION
        Goes beyond the basic inventory in Domain 9. Checks for:
          - End-of-life (EOL) software versions (Java 8, Python 2, etc.)
          - Known-vulnerable application categories (Flash, Silverlight, old browsers)
          - Multiple Java/Python/Node versions (update confusion)
          - Remote access tools (TeamViewer, AnyDesk - legitimate but risky)
    #>
    Write-Host "`n[*] Auditing Installed Software (Deep)..." -ForegroundColor Cyan

    try {
        $apps = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

        # Known EOL / vulnerable software patterns
        $eolPatterns = @(
            @("Adobe Flash Player",     "EOL since 2020, known attack vector"),
            @("Microsoft Silverlight",  "EOL, no security updates"),
            @("Java [678]\.",           "Legacy Java version, should be updated or removed"),
            @("Python 2\.",             "EOL since 2020"),
            @("Internet Explorer",       "EOL, use Edge"),
            @("Adobe Reader [0-9]\.",   "Legacy Adobe Reader, update to current DC version"),
            @("WinRAR [0-4]\.",         "Older WinRAR with known CVEs")
        )

        # Remote access tools (not necessarily bad, but should be documented)
        $remoteAccessTools = @("TeamViewer", "AnyDesk", "LogMeIn", "Splashtop",
                               "VNC", "RealVNC", "TightVNC", "UltraVNC",
                               "ConnectWise", "RemotePC", "Parsec")

        foreach ($app in $apps) {
            $appName = $app.DisplayName
            $appVersion = $app.DisplayVersion

            # Check against EOL patterns
            foreach ($pattern in $eolPatterns) {
                if ($appName -match $pattern[0]) {
                    Add-Result -Domain "Software Audit" -ID "SW-01" `
                        -Check "EOL/vulnerable software: $appName" `
                        -Status "FAIL" `
                        -Finding "$appName $appVersion - $($pattern[1])" `
                        -Expected "Remove or update to supported version" `
                        -Remediation "Uninstall via Control Panel or winget uninstall"
                }
            }

            # Check for remote access tools
            foreach ($rat in $remoteAccessTools) {
                if ($appName -match $rat) {
                    Add-Result -Domain "Software Audit" -ID "SW-02" `
                        -Check "Remote access tool: $appName" `
                        -Status "INFO" `
                        -Finding "$appName $appVersion (Publisher: $($app.Publisher))" `
                        -Expected "Remote access tools should be authorised and monitored" `
                        -Remediation "Verify this is an authorised tool. Remove if not approved."
                }
            }
        }
    } catch {}
}


# ============================================================
# MAIN EXECUTION
# ============================================================

Write-Host "`nStarting audit at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')..." -ForegroundColor Cyan
$startTime = Get-Date

# Collect system information
Collect-SystemInfo

# --- Original CIS Benchmark Domains (1-9) ---
Audit-AccountPolicy             # Domain 1:  Password & lockout policy
Audit-WindowsUpdate             # Domain 2:  Patching & update config
Audit-Firewall                  # Domain 3:  Windows Firewall profiles
Audit-LoggingPolicy             # Domain 4:  Audit policy & log sizes
Audit-NetworkSecurity           # Domain 5:  SMB, RDP, listening ports
Audit-UserAccounts              # Domain 6:  Local accounts, guest, auto-logon
Audit-SecurityFeatures          # Domain 7:  UAC, Defender, DEP, Secure Boot
Audit-CredentialProtection      # Domain 8:  LM auth, WDigest, LSASS, Credential Guard
Audit-MiscHardening             # Domain 9:  Screen lock, autorun, remote assistance

# --- Expanded Security Domains (10-24) ---
Audit-ScheduledTasks            # Domain 10: Scheduled task persistence
Audit-StartupPersistence        # Domain 11: Run keys, startup folders
Audit-TLSConfiguration          # Domain 12: TLS/SSL protocols & ciphers
Audit-NetworkShares             # Domain 13: Shares & mapped drives
Audit-CredentialFiles           # Domain 14: Plaintext creds on disk
Audit-WiFiProfiles              # Domain 15: Wi-Fi security settings
Audit-BrowserSecurity           # Domain 16: Browser extensions & permissions
Audit-OfficeMacros              # Domain 17: Office macro settings
Audit-CertificateStore          # Domain 18: Cert store review
Audit-WritablePaths             # Domain 19: Writable PATH directories
Audit-UnquotedServicePaths      # Domain 20: Unquoted service path hijacking
Audit-InstalledServices         # Domain 21: Risky services running
Audit-EnvironmentVariables      # Domain 22: Credential leakage in env vars
Audit-DNSConfiguration          # Domain 23: DNS servers & DoH
Audit-InstalledSoftwareDeep     # Domain 24: EOL/vulnerable software scan

# Generate reports
Generate-HTMLReport

if ($JsonOutput) {
    Export-JsonResults
}

# Print summary
$elapsed = (Get-Date) - $startTime
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  AUDIT COMPLETE (v2.0 - Expanded)" -ForegroundColor Cyan
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
