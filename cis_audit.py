#!/usr/bin/env python3
"""
cis_audit.py - Non-Privileged Windows CIS Benchmark Auditor (Pure Python)
Author : SS
Purpose: Audit a Windows workstation/server against CIS Benchmark controls
         using ONLY standard-user access and Python standard library.
         Generates an HTML report with PASS/FAIL/INFO results.
Usage  : python cis_audit.py
         python cis_audit.py --output C:\\Audits\\report.html --json

AUTHORISED USE ONLY. Run this tool only against systems you own or have
explicit written authorisation to audit.
"""

import argparse
import ctypes
import datetime
import html
import json
import os
import platform
import re
import subprocess
import sys

# winreg is Windows-only; we import it conditionally so the script
# can at least be syntax-checked on non-Windows systems
try:
    import winreg
except ImportError:
    winreg = None


# ============================================================
# GLOBAL STATE
# ============================================================

results = []       # List of result dicts
pass_count = 0
fail_count = 0
info_count = 0
skip_count = 0
error_count = 0
sys_info = {}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def add_result(domain, check_id, check, status, finding, expected="", remediation=""):
    """
    Record a single audit check result.

    Every check in this script calls add_result() to log its finding.
    This centralises result collection and drives the final report.

    Args:
        domain:      Security domain grouping (e.g., "Account Policy")
        check_id:    CIS control ID or custom reference (e.g., "1.1.4")
        check:       Human-readable description of what was checked
        status:      One of: PASS, FAIL, INFO, SKIPPED, ERROR
        finding:     What was actually found on the system
        expected:    What the CIS benchmark requires
        remediation: How to fix the issue (shown for FAIL results)
    """
    global pass_count, fail_count, info_count, skip_count, error_count

    results.append({
        "domain": domain,
        "id": check_id,
        "check": check,
        "status": status,
        "finding": finding,
        "expected": expected,
        "remediation": remediation,
    })

    counts = {"PASS": "pass_count", "FAIL": "fail_count", "INFO": "info_count",
              "SKIPPED": "skip_count", "ERROR": "error_count"}
    if status in counts:
        globals()[counts[status]] += 1

    # Console output with colour coding via ANSI (Win10+ supports this)
    colours = {"PASS": "\033[92m", "FAIL": "\033[91m", "INFO": "\033[93m",
               "SKIPPED": "\033[90m", "ERROR": "\033[95m"}
    reset = "\033[0m"
    colour = colours.get(status, "")
    print(f"  {colour}[{status:>7}]{reset} {check_id} - {check}")


def run_cmd(command, shell=True):
    """
    Run a shell command and return its stdout as a string.

    Uses subprocess.run with shell=True for commands like 'net accounts'
    that are CMD built-ins. Captures both stdout and stderr.
    Returns empty string on failure instead of raising.

    Args:
        command: The command string to execute.
        shell:   Whether to run through the system shell (default True).

    Returns:
        stdout as a stripped string, or empty string on error.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=shell,
            timeout=30,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return ""


def reg_query(hive, path, name):
    """
    Read a registry value using the winreg module.

    This is the primary way we read system configuration without admin.
    Many HKLM keys under SOFTWARE and SYSTEM are readable by standard users.
    Keys under SECURITY and SAM are not.

    Args:
        hive: Registry hive constant (e.g., winreg.HKEY_LOCAL_MACHINE)
        path: Subkey path (e.g., "SOFTWARE\\Policies\\Microsoft\\...")
        name: Value name within the key

    Returns:
        The value data (str, int, etc.) or None if inaccessible.
    """
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except (OSError, FileNotFoundError, PermissionError):
        return None


def reg_enum_values(hive, path):
    """
    Enumerate all values under a registry key.

    Returns a list of (name, data, type) tuples for each value.
    Returns empty list if the key doesn't exist or is inaccessible.
    """
    if winreg is None:
        return []
    try:
        values = []
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, data, vtype = winreg.EnumValue(key, i)
                    values.append((name, data, vtype))
                    i += 1
                except OSError:
                    break
        return values
    except (OSError, FileNotFoundError, PermissionError):
        return []


def reg_enum_subkeys(hive, path):
    """
    Enumerate all subkeys under a registry key.

    Returns a list of subkey name strings.
    """
    if winreg is None:
        return []
    try:
        subkeys = []
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
        return subkeys
    except (OSError, FileNotFoundError, PermissionError):
        return []


def parse_net_accounts():
    """
    Parse 'net accounts' output into a dict of policy settings.

    'net accounts' is readable by standard users and returns the local
    password policy, lockout policy, and related settings. Each line
    is in the format "Setting name                  value".

    Returns:
        Dict mapping setting names to their values (as strings).
    """
    output = run_cmd("net accounts")
    policies = {}
    for line in output.splitlines():
        if ":" in line:
            # Split on the LAST colon-space to handle names with colons
            parts = line.split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                val = parts[1].strip()
                policies[key] = val
    return policies


# ============================================================
# SYSTEM INFORMATION
# ============================================================

def collect_system_info():
    """Gather baseline system information for the report header."""
    global sys_info

    print("\n[*] Collecting system information...")

    # Check if running as admin
    is_admin = False
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError):
        pass

    sys_info = {
        "hostname": os.environ.get("COMPUTERNAME", platform.node()),
        "os_name": platform.platform(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "domain": os.environ.get("USERDOMAIN", ""),
        "current_user": f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}",
        "is_admin": is_admin,
        "audit_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "python_version": platform.python_version(),
    }

    for k, v in sys_info.items():
        print(f"  {k:>16}: {v}")


# ============================================================
# DOMAIN 1: ACCOUNT POLICY
# ============================================================

def audit_account_policy():
    """
    Check password policy, lockout policy via 'net accounts'.

    CIS References: 1.1.x (Password Policy), 1.2.x (Account Lockout)
    """
    print("\n[*] Auditing Account Policy...")
    policies = parse_net_accounts()

    # --- Password minimum length ---
    # CIS 1.1.4: >= 14 characters
    val = policies.get("Minimum password length")
    if val is not None:
        try:
            length = int(val)
            add_result("Account Policy", "1.1.4", "Minimum password length",
                       "PASS" if length >= 14 else "FAIL",
                       f"Minimum length: {length} characters", ">= 14 characters",
                       "GPO: Password Policy > Minimum password length = 14")
        except ValueError:
            pass

    # --- Maximum password age ---
    # CIS 1.1.2: <= 365 days and > 0
    val = policies.get("Maximum password age (days)")
    if val is not None:
        try:
            days = int(val)
            ok = 0 < days <= 365
            add_result("Account Policy", "1.1.2", "Maximum password age",
                       "PASS" if ok else "FAIL",
                       f"Max age: {days} days", "<= 365 days and > 0",
                       "GPO: Password Policy > Maximum password age = 365 or less")
        except ValueError:
            pass

    # --- Minimum password age ---
    # CIS 1.1.3: >= 1 day
    val = policies.get("Minimum password age (days)")
    if val is not None:
        try:
            days = int(val)
            add_result("Account Policy", "1.1.3", "Minimum password age",
                       "PASS" if days >= 1 else "FAIL",
                       f"Min age: {days} day(s)", ">= 1 day",
                       "GPO: Password Policy > Minimum password age = 1")
        except ValueError:
            pass

    # --- Password history ---
    # CIS 1.1.1: >= 24
    val = policies.get("Length of password history maintained")
    if val is not None:
        try:
            history = int(val)
            add_result("Account Policy", "1.1.1", "Enforce password history",
                       "PASS" if history >= 24 else "FAIL",
                       f"History: {history} passwords", ">= 24 passwords",
                       "GPO: Password Policy > Enforce password history = 24")
        except ValueError:
            pass

    # --- Lockout threshold ---
    # CIS 1.2.1: 1-5 attempts
    val = policies.get("Lockout threshold")
    if val is not None:
        try:
            if val.lower() == "never":
                threshold = 0
            else:
                threshold = int(val)
            ok = 1 <= threshold <= 5
            finding = "Never (disabled)" if threshold == 0 else f"{threshold} attempts"
            add_result("Account Policy", "1.2.1", "Account lockout threshold",
                       "PASS" if ok else "FAIL",
                       f"Lockout after: {finding}", "1-5 invalid attempts",
                       "GPO: Account Lockout Policy > Lockout threshold = 5")
        except ValueError:
            pass

    # --- Lockout duration ---
    # CIS 1.2.2: >= 15 minutes
    val = policies.get("Lockout duration (minutes)")
    if val is not None:
        try:
            mins = int(val)
            add_result("Account Policy", "1.2.2", "Account lockout duration",
                       "PASS" if mins >= 15 else "FAIL",
                       f"Lockout duration: {mins} minutes", ">= 15 minutes",
                       "GPO: Account Lockout Policy > Lockout duration = 15")
        except ValueError:
            pass


# ============================================================
# DOMAIN 2: WINDOWS UPDATE
# ============================================================

def audit_windows_update():
    """
    Check Windows Update configuration and patch status.
    CIS References: 18.9.x
    """
    print("\n[*] Auditing Windows Update...")

    HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else None

    # --- Auto-update configuration ---
    au_options = reg_query(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions")
    if au_options is not None:
        desc = {2: "Notify for download and install", 3: "Auto download, notify for install",
                4: "Auto download and schedule install", 5: "Allow local admin to choose"}.get(au_options, f"Unknown ({au_options})")
        add_result("Windows Update", "18.9.101.2", "Automatic Updates configuration",
                   "PASS" if au_options == 4 else "FAIL",
                   f"AUOptions = {au_options} ({desc})", "4 (Auto download and schedule install)",
                   "GPO: Windows Update > Configure Automatic Updates = 4")
    else:
        add_result("Windows Update", "18.9.101.2", "Automatic Updates configuration",
                   "INFO", "No GPO configured (using default settings)",
                   "Explicit GPO configuration recommended")

    # --- Last patch date ---
    # Query via wmic (available to standard users)
    output = run_cmd("wmic qfe get InstalledOn /format:list")
    dates = []
    for line in output.splitlines():
        m = re.search(r"InstalledOn=(\d+/\d+/\d+)", line)
        if m:
            try:
                dates.append(datetime.datetime.strptime(m.group(1), "%m/%d/%Y"))
            except ValueError:
                pass

    if dates:
        latest = max(dates)
        days_ago = (datetime.datetime.now() - latest).days
        status = "PASS" if days_ago <= 30 else ("INFO" if days_ago <= 60 else "FAIL")
        add_result("Windows Update", "PATCH-01", "Last patch installation age",
                   status,
                   f"Last update: {latest.strftime('%Y-%m-%d')} ({days_ago} days ago)",
                   "Patches within last 30 days",
                   "Run Windows Update to install pending patches")

    # --- WSUS server ---
    wsus = reg_query(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "WUServer")
    if wsus:
        add_result("Windows Update", "PATCH-02", "WSUS server configured",
                   "INFO", f"WSUS URL: {wsus}", "Informational")


# ============================================================
# DOMAIN 3: WINDOWS FIREWALL
# ============================================================

def audit_firewall():
    """
    Check Windows Firewall status for all profiles.
    CIS References: 9.1.x, 9.2.x, 9.3.x
    """
    print("\n[*] Auditing Windows Firewall...")

    profiles = [
        ("domainprofile",  "Domain",  "9.1.1"),
        ("privateprofile", "Private", "9.2.1"),
        ("publicprofile",  "Public",  "9.3.1"),
    ]

    for profile_key, profile_name, cis_id in profiles:
        output = run_cmd(f"netsh advfirewall show {profile_key} state")
        enabled = "ON" in output.upper()

        add_result("Windows Firewall", cis_id,
                   f"Firewall enabled - {profile_name} profile",
                   "PASS" if enabled else "FAIL",
                   f"Firewall state: {'ON' if enabled else 'OFF'}", "ON",
                   f"Enable: netsh advfirewall set {profile_key} state on")

        # Default inbound action
        policy_output = run_cmd(f"netsh advfirewall show {profile_key}")
        block = "BlockInbound" in policy_output
        inbound_id = cis_id.replace(".1", ".2")

        add_result("Windows Firewall", inbound_id,
                   f"Default inbound block - {profile_name} profile",
                   "PASS" if block else "FAIL",
                   f"Inbound policy: {'BlockInbound' if block else 'AllowInbound'}",
                   "BlockInbound (default deny)",
                   f"GPO: Firewall > {profile_name} > Inbound connections = Block")


# ============================================================
# DOMAIN 4: AUDIT / LOGGING POLICY
# ============================================================

def audit_logging_policy():
    """
    Check audit policy and event log sizes.
    CIS References: 17.x, 18.9.26.x
    """
    print("\n[*] Auditing Logging Policy...")

    HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else None

    # --- Audit policy via auditpol ---
    output = run_cmd("auditpol /get /category:*")
    if output:
        required = [
            ("Credential Validation",     "17.1.1", "Success and Failure"),
            ("Security Group Management", "17.2.5", "Success"),
            ("User Account Management",   "17.2.6", "Success and Failure"),
            ("Process Creation",          "17.3.1", "Success"),
            ("Logon",                     "17.5.3", "Success and Failure"),
            ("Special Logon",             "17.5.6", "Success"),
            ("Audit Policy Change",       "17.7.1", "Success"),
            ("Sensitive Privilege Use",   "17.8.1", "Success and Failure"),
            ("Security State Change",     "17.9.1", "Success"),
            ("System Integrity",          "17.9.4", "Success and Failure"),
        ]

        for category, cis_id, expected in required:
            # Find the line for this category
            for line in output.splitlines():
                if category.lower() in line.lower():
                    # The setting is the rightmost column after whitespace
                    parts = re.split(r"\s{2,}", line.strip())
                    setting = parts[-1] if parts else "Unknown"

                    if expected == "Success and Failure":
                        ok = "success and failure" in setting.lower()
                    elif expected == "Success":
                        ok = "success" in setting.lower()
                    else:
                        ok = expected.lower() in setting.lower()

                    add_result("Audit Policy", cis_id, f"Audit: {category}",
                               "PASS" if ok else "FAIL",
                               f"Current: {setting}", expected,
                               f"GPO: Advanced Audit Policy > {category} = {expected}")
                    break
    else:
        add_result("Audit Policy", "17.x", "Audit policy query",
                   "SKIPPED", "auditpol may require elevation on this system", "N/A")

    # --- Event log max sizes ---
    log_checks = [
        ("Application", r"SOFTWARE\Policies\Microsoft\Windows\EventLog\Application", 32768, "18.9.26.1.1"),
        ("Security",    r"SOFTWARE\Policies\Microsoft\Windows\EventLog\Security",    196608, "18.9.26.2.1"),
        ("System",      r"SOFTWARE\Policies\Microsoft\Windows\EventLog\System",      32768, "18.9.26.4.1"),
    ]

    for log_name, reg_path, min_kb, cis_id in log_checks:
        size = reg_query(HKLM, reg_path, "MaxSize")
        if size is not None:
            ok = int(size) >= min_kb
            add_result("Audit Policy", cis_id, f"{log_name} log maximum size",
                       "PASS" if ok else "FAIL",
                       f"Max size: {int(size)//1024} MB ({size} KB)",
                       f">= {min_kb//1024} MB ({min_kb} KB)",
                       f"GPO: Event Log > {log_name} > Maximum Log Size = {min_kb} KB")
        else:
            add_result("Audit Policy", cis_id, f"{log_name} log maximum size",
                       "INFO", "No GPO configured (using local defaults)",
                       f">= {min_kb//1024} MB")


# ============================================================
# DOMAIN 5: NETWORK SECURITY
# ============================================================

def audit_network_security():
    """
    Check SMB, RDP, and listening ports.
    CIS References: 2.3.x, 18.3.x, 18.9.x
    """
    print("\n[*] Auditing Network Security...")

    HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else None

    # --- SMBv1 ---
    # CIS 18.3.3: SMBv1 should be disabled
    smb1 = reg_query(HKLM, r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start")
    if smb1 is not None:
        add_result("Network Security", "18.3.3", "SMBv1 client driver disabled",
                   "PASS" if smb1 == 4 else "FAIL",
                   f"mrxsmb10 Start = {smb1} (4=Disabled)", "4 (Disabled)",
                   "Disable: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")

    smb1_srv = reg_query(HKLM, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
    if smb1_srv is not None:
        add_result("Network Security", "18.3.3b", "SMBv1 server disabled",
                   "PASS" if smb1_srv == 0 else "FAIL",
                   f"SMB1 = {smb1_srv} (0=Disabled)", "0 (Disabled)",
                   "Disable: Set-SmbServerConfiguration -EnableSMB1Protocol $false")

    # --- SMB Signing ---
    for label, path, cis_id in [
        ("SMB client signing", r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "2.3.8.1"),
        ("SMB server signing", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "2.3.8.2"),
    ]:
        val = reg_query(HKLM, path, "RequireSecuritySignature")
        if val is not None:
            add_result("Network Security", cis_id, f"{label} required",
                       "PASS" if val == 1 else "FAIL",
                       f"RequireSecuritySignature = {val}", "1 (Enabled)",
                       f"GPO: Security Options > {label} = Enabled")

    # --- RDP NLA ---
    nla = reg_query(HKLM, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication")
    if nla is not None:
        add_result("Network Security", "18.9.65.3.9.2", "RDP Network Level Authentication (NLA)",
                   "PASS" if nla == 1 else "FAIL",
                   f"UserAuthentication = {nla}", "1 (Enabled)",
                   "GPO: Remote Desktop > Require NLA = Enabled")

    # --- Listening ports ---
    output = run_cmd("netstat -ano -p TCP")
    risky_ports = {21: "FTP", 23: "Telnet", 69: "TFTP", 135: "RPC",
                   445: "SMB", 1433: "MSSQL", 3389: "RDP", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS"}
    listeners = set()
    for line in output.splitlines():
        if "LISTENING" in line:
            parts = line.split()
            if len(parts) >= 2:
                addr = parts[1]
                port_str = addr.rsplit(":", 1)[-1]
                try:
                    port = int(port_str)
                    listeners.add(port)
                except ValueError:
                    pass

    add_result("Network Security", "NET-01", "Total listening TCP ports",
               "INFO", f"{len(listeners)} unique ports listening", "Minimise listening services")

    for port in sorted(listeners):
        if port in risky_ports:
            add_result("Network Security", "NET-02", f"Risky port open: {port} ({risky_ports[port]})",
                       "INFO", f"Port {port} ({risky_ports[port]}) listening",
                       "Disable if not required")


# ============================================================
# DOMAIN 6: USER ACCOUNTS
# ============================================================

def audit_user_accounts():
    """
    Check local accounts, guest status, auto-logon.
    CIS References: 2.3.1.x, 2.3.7.x
    """
    print("\n[*] Auditing User Accounts...")

    HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else None

    # --- Guest account ---
    output = run_cmd("net user Guest")
    if output:
        active = "Account active" in output
        is_active = "Yes" in output.split("Account active")[-1].split("\n")[0] if active else False
        add_result("User Accounts", "2.3.1.2", "Guest account disabled",
                   "PASS" if not is_active else "FAIL",
                   f"Guest account active: {is_active}", "Disabled (active=No)",
                   "Disable: net user Guest /active:no")

    # --- Administrator renamed ---
    output = run_cmd('wmic useraccount where "SID like \'S-1-5-%-500\'" get Name /value')
    if output:
        m = re.search(r"Name=(.+)", output)
        if m:
            admin_name = m.group(1).strip()
            add_result("User Accounts", "2.3.1.5", "Built-in Administrator renamed",
                       "PASS" if admin_name.lower() != "administrator" else "FAIL",
                       f"Admin account name: '{admin_name}'", "Not 'Administrator'",
                       "GPO: Security Options > Rename administrator account")

    # --- Auto-logon ---
    auto_logon = reg_query(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon")
    auto_pass = reg_query(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword")

    auto_on = auto_logon == "1" or auto_logon == 1
    pass_stored = auto_pass is not None and auto_pass != ""

    if auto_on or pass_stored:
        add_result("User Accounts", "2.3.7.4", "Auto-logon disabled",
                   "FAIL",
                   f"AutoAdminLogon={auto_logon}, DefaultPassword={'PRESENT (cleartext!)' if pass_stored else 'Not set'}",
                   "AutoAdminLogon=0, no DefaultPassword",
                   "Remove: reg delete HKLM\\...\\Winlogon /v DefaultPassword /f")
    else:
        add_result("User Accounts", "2.3.7.4", "Auto-logon disabled",
                   "PASS", f"AutoAdminLogon={auto_logon}, no stored password",
                   "No auto-logon credentials")

    # --- Enumerate local accounts ---
    output = run_cmd('wmic useraccount where "LocalAccount=True" get Name,Disabled,PasswordRequired /format:list')
    if output:
        # Parse blocks separated by blank lines
        blocks = output.split("\n\n")
        for block in blocks:
            lines = {l.split("=")[0].strip(): l.split("=")[1].strip()
                     for l in block.strip().splitlines() if "=" in l}
            if "Name" in lines:
                name = lines["Name"]
                disabled = lines.get("Disabled", "").upper() == "TRUE"
                pw_req = lines.get("PasswordRequired", "").upper() == "TRUE"

                if not pw_req and not disabled:
                    add_result("User Accounts", "ACCT-01",
                               f"Local account: {name}",
                               "FAIL",
                               f"Active account with no password required!",
                               "All accounts should require passwords")
                else:
                    status_str = []
                    if disabled:
                        status_str.append("Disabled")
                    if not pw_req:
                        status_str.append("No password required")
                    add_result("User Accounts", "ACCT-01",
                               f"Local account: {name}", "INFO",
                               f"Status: {', '.join(status_str) if status_str else 'Active, password required'}",
                               "Password required")


# ============================================================
# DOMAIN 7: SECURITY FEATURES
# ============================================================

def audit_security_features():
    """
    Check UAC, Defender, DEP, PowerShell settings.
    CIS References: 2.3.17.x, 18.9.x
    """
    print("\n[*] Auditing Security Features...")

    HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else None

    # --- UAC ---
    uac = reg_query(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    if uac is not None:
        add_result("Security Features", "2.3.17.1", "User Account Control (UAC) enabled",
                   "PASS" if uac == 1 else "FAIL",
                   f"EnableLUA = {uac}", "1 (Enabled)",
                   "GPO: Security Options > UAC: Admin Approval Mode = Enabled")

    # --- UAC prompt behaviour ---
    uac_prompt = reg_query(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin")
    if uac_prompt is not None:
        desc = {0: "Elevate without prompting", 1: "Prompt for credentials on secure desktop",
                2: "Prompt for consent on secure desktop", 3: "Prompt for credentials",
                4: "Prompt for consent", 5: "Prompt for non-Windows binaries"}.get(uac_prompt, f"Unknown ({uac_prompt})")
        add_result("Security Features", "2.3.17.2", "UAC admin prompt behaviour",
                   "PASS" if uac_prompt in (1, 2) else "FAIL",
                   f"ConsentPromptBehaviorAdmin = {uac_prompt} ({desc})",
                   "1 or 2 (Prompt on secure desktop)",
                   "GPO: Security Options > UAC: Behavior of elevation prompt")

    # --- Windows Defender ---
    defender_off = reg_query(HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware")
    if defender_off is not None:
        add_result("Security Features", "18.9.47.1", "Windows Defender not disabled",
                   "PASS" if defender_off == 0 else "FAIL",
                   f"DisableAntiSpyware = {defender_off}", "0 (Defender active)",
                   "Remove GPO disabling Defender")

    rtp_off = reg_query(HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring")
    if rtp_off is not None:
        add_result("Security Features", "18.9.47.9.1", "Defender real-time protection",
                   "PASS" if rtp_off == 0 else "FAIL",
                   f"DisableRealtimeMonitoring = {rtp_off}", "0 (Enabled)",
                   "Enable via Windows Security settings")

    # --- PowerShell Execution Policy ---
    output = run_cmd("powershell -NoProfile -Command \"Get-ExecutionPolicy\"")
    if output:
        policy = output.strip()
        ok = policy.lower() in ("restricted", "allsigned", "remotesigned")
        add_result("Security Features", "18.9.100.1", "PowerShell execution policy",
                   "PASS" if ok else "FAIL",
                   f"Execution policy: {policy}",
                   "Restricted, AllSigned, or RemoteSigned",
                   "GPO: Turn on Script Execution = Allow only signed scripts")

    # --- Script Block Logging ---
    sbl = reg_query(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging")
    if sbl is not None:
        add_result("Security Features", "18.9.100.2", "PowerShell Script Block Logging",
                   "PASS" if sbl == 1 else "FAIL",
                   f"EnableScriptBlockLogging = {sbl}", "1 (Enabled)",
                   "GPO: PowerShell > Script Block Logging = Enabled")


# ============================================================
# DOMAIN 8: CREDENTIAL PROTECTION
# ============================================================

def audit_credential_protection():
    """
    Check LM auth, WDigest, LSASS, Credential Guard.
    CIS References: 2.3.11.x, 18.3.x
    """
    print("\n[*] Auditing Credential Protection...")

    HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else None

    # --- LAN Manager auth level ---
    lm = reg_query(HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel")
    if lm is not None:
        desc = {0: "Send LM & NTLM", 1: "Send LM & NTLM, use NTLMv2 if negotiated",
                2: "Send NTLM only", 3: "Send NTLMv2 only",
                4: "Send NTLMv2, refuse LM", 5: "Send NTLMv2, refuse LM & NTLM"}.get(lm, f"Unknown ({lm})")
        status = "PASS" if lm >= 5 else ("INFO" if lm >= 3 else "FAIL")
        add_result("Credential Protection", "2.3.11.7", "LAN Manager authentication level",
                   status, f"LmCompatibilityLevel = {lm} ({desc})",
                   "5 (NTLMv2 only, refuse LM & NTLM)",
                   "GPO: Security Options > LAN Manager authentication level")

    # --- WDigest ---
    wdigest = reg_query(HKLM, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential")
    if wdigest is not None:
        add_result("Credential Protection", "18.3.7", "WDigest authentication disabled",
                   "PASS" if wdigest == 0 else "FAIL",
                   f"UseLogonCredential = {wdigest}", "0 (Disabled)",
                   "Registry: WDigest\\UseLogonCredential = 0")
    else:
        add_result("Credential Protection", "18.3.7", "WDigest authentication disabled",
                   "PASS", "Key not set (WDigest disabled by default on modern Windows)", "Absent or 0")

    # --- Cached logons ---
    cached = reg_query(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount")
    if cached is not None:
        try:
            count = int(cached)
            add_result("Credential Protection", "2.3.6.1", "Cached logon credentials",
                       "PASS" if count <= 4 else "FAIL",
                       f"CachedLogonsCount = {count}", "<= 4",
                       "GPO: Interactive logon: Number of previous logons to cache")
        except ValueError:
            pass

    # --- LSASS PPL ---
    ppl = reg_query(HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
    if ppl is not None:
        add_result("Credential Protection", "18.3.5", "LSASS Protected Process Light",
                   "PASS" if ppl == 1 else "FAIL",
                   f"RunAsPPL = {ppl}", "1 (Protected)",
                   "Registry: Lsa\\RunAsPPL = 1")

    # --- Credential Guard ---
    cg = reg_query(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "EnableVirtualizationBasedSecurity")
    if cg is not None:
        add_result("Credential Protection", "18.3.6", "Virtualization Based Security",
                   "PASS" if cg == 1 else "FAIL",
                   f"EnableVirtualizationBasedSecurity = {cg}", "1 (Enabled)",
                   "GPO: Device Guard > Turn On VBS = Enabled")


# ============================================================
# DOMAIN 9: MISCELLANEOUS HARDENING
# ============================================================

def audit_misc_hardening():
    """
    Screen lock, autorun, remote assistance, etc.
    """
    print("\n[*] Auditing Miscellaneous Hardening...")

    HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else None
    HKCU = winreg.HKEY_CURRENT_USER if winreg else None

    # --- Screen lock timeout ---
    timeout = reg_query(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs")
    if timeout is not None:
        add_result("Misc Hardening", "2.3.7.3", "Machine inactivity lock timeout",
                   "PASS" if 0 < timeout <= 900 else "FAIL",
                   f"InactivityTimeoutSecs = {timeout}s ({timeout//60} min)",
                   "<= 900 seconds (15 minutes)",
                   "GPO: Interactive logon: Machine inactivity limit = 900")

    # --- Screensaver ---
    ss_active = reg_query(HKCU, r"Control Panel\Desktop", "ScreenSaveActive")
    ss_secure = reg_query(HKCU, r"Control Panel\Desktop", "ScreenSaverIsSecure")
    ss_timeout = reg_query(HKCU, r"Control Panel\Desktop", "ScreenSaveTimeOut")

    if ss_active is not None:
        active = ss_active == "1"
        secure = ss_secure == "1"
        to = int(ss_timeout) if ss_timeout else 0
        ok = active and secure and 0 < to <= 900

        add_result("Misc Hardening", "LOCK-01", "Screen saver with password lock",
                   "PASS" if ok else "FAIL",
                   f"Active={ss_active}, Secure={ss_secure}, Timeout={to}s",
                   "Active, password-protected, <= 900s")

    # --- AutoRun ---
    autorun = reg_query(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun")
    if autorun is not None:
        add_result("Misc Hardening", "18.9.8.3", "AutoRun disabled for all drives",
                   "PASS" if autorun == 255 else "FAIL",
                   f"NoDriveTypeAutoRun = {autorun} (255=all drives)", "255",
                   "GPO: AutoPlay Policies > Turn off Autoplay = All drives")

    # --- Remote Assistance ---
    ra = reg_query(HKLM, r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fAllowToGetHelp")
    if ra is not None:
        add_result("Misc Hardening", "18.8.36.1", "Remote Assistance disabled",
                   "PASS" if ra == 0 else "FAIL",
                   f"fAllowToGetHelp = {ra}", "0 (Disabled)",
                   "GPO: System > Remote Assistance > Solicited = Disabled")


# ============================================================
# DOMAIN 10: PERSISTENCE - SCHEDULED TASKS
# ============================================================

def audit_scheduled_tasks():
    """
    Audit scheduled tasks for suspicious entries.
    MITRE ATT&CK T1053.005
    """
    print("\n[*] Auditing Scheduled Tasks...")

    output = run_cmd('schtasks /query /fo CSV /v')
    if not output:
        add_result("Scheduled Tasks", "PERSIST-01", "Scheduled tasks audit",
                   "SKIPPED", "Could not enumerate tasks", "N/A")
        return

    # Parse CSV - first line is header
    lines = output.splitlines()
    if len(lines) < 2:
        return

    headers = [h.strip('"') for h in lines[0].split('","')]
    suspicious = 0
    total = 0

    # Map header names to indices
    idx = {}
    for i, h in enumerate(headers):
        idx[h] = i

    task_name_i = idx.get("TaskName", 0)
    action_i = idx.get("Task To Run", 8)
    runas_i = idx.get("Run As User", -1)

    writable = [os.environ.get("TEMP", ""), os.environ.get("TMP", ""),
                os.path.expanduser("~\\Downloads"), os.path.expanduser("~\\Desktop"),
                "C:\\Users\\Public"]
    script_ext = (".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta")

    for line in lines[1:]:
        fields = [f.strip('"') for f in line.split('","')]
        if len(fields) <= max(task_name_i, action_i):
            continue

        task_name = fields[task_name_i]
        action = fields[action_i] if action_i < len(fields) else ""
        runas = fields[runas_i] if runas_i >= 0 and runas_i < len(fields) else ""

        # Skip Microsoft built-in tasks
        if task_name.startswith("\\Microsoft\\"):
            continue

        total += 1
        issues = []

        if re.search(r"SYSTEM|LOCAL SERVICE|NETWORK SERVICE|Administrator", runas, re.I):
            issues.append(f"Runs as {runas}")

        for wp in writable:
            if wp and action and wp.lower() in action.lower():
                issues.append("Runs from writable path")
                break

        for ext in script_ext:
            if action and ext in action.lower():
                issues.append(f"Executes script ({ext})")
                break

        if issues:
            suspicious += 1
            add_result("Scheduled Tasks", "PERSIST-01",
                       f"Suspicious task: {task_name}", "FAIL",
                       f"Action: {action[:120]} | RunAs: {runas} | {'; '.join(issues)}",
                       "Tasks should run with least privilege",
                       "Review task legitimacy. Remove if unauthorised.")

    add_result("Scheduled Tasks", "PERSIST-02", "Scheduled tasks summary",
               "PASS" if suspicious == 0 else "INFO",
               f"{total} custom tasks scanned, {suspicious} with findings",
               "No suspicious tasks")


# ============================================================
# DOMAIN 11: PERSISTENCE - STARTUP / RUN KEYS
# ============================================================

def audit_startup_persistence():
    """
    Audit Run keys and Startup folders.
    MITRE ATT&CK T1547.001
    """
    print("\n[*] Auditing Startup Persistence...")

    HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else None
    HKCU = winreg.HKEY_CURRENT_USER if winreg else None

    run_keys = [
        (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    ]

    total = 0
    suspect = 0

    for hive, path, label in run_keys:
        if hive is None:
            continue
        values = reg_enum_values(hive, path)
        for name, data, vtype in values:
            total += 1
            issues = []
            data_str = str(data)

            if re.search(r"(?i)(\\Temp\\|\\Downloads\\|\\AppData\\Local\\Temp|\\Users\\Public)", data_str):
                issues.append("Runs from writable location")
            if re.search(r"(?i)(powershell.*-enc|powershell.*-e\s|cmd.*/c.*powershell)", data_str):
                issues.append("SUSPICIOUS: Encoded PowerShell")
            if re.search(r"(?i)\.(ps1|bat|cmd|vbs|js|wsf|hta)", data_str):
                issues.append("Runs a script file")

            severity = "FAIL" if issues else "INFO"
            if issues:
                suspect += 1

            add_result("Startup Persistence", "PERSIST-10",
                       f"{label}: {name}", severity,
                       f"Value: {data_str[:150]}{'...' if len(data_str)>150 else ''}"
                       + (f" | {'; '.join(issues)}" if issues else ""),
                       "Only legitimate apps from protected directories",
                       f"Verify legitimacy. Remove if unauthorised.")

    # --- Startup folders ---
    startup_dirs = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    ]
    for sd in startup_dirs:
        if os.path.isdir(sd):
            for item in os.listdir(sd):
                if item.lower() == "desktop.ini":
                    continue
                total += 1
                fpath = os.path.join(sd, item)
                ext = os.path.splitext(item)[1].lower()
                is_script = ext in (".bat", ".cmd", ".vbs", ".js", ".ps1", ".wsf", ".hta", ".lnk")
                if is_script:
                    suspect += 1

                add_result("Startup Persistence", "PERSIST-11",
                           f"Startup folder: {item}",
                           "FAIL" if is_script else "INFO",
                           f"Path: {fpath}", "Only verified startup items")

    add_result("Startup Persistence", "PERSIST-12", "Startup persistence summary",
               "PASS" if suspect == 0 else "INFO",
               f"{total} entries, {suspect} with findings", "No suspicious entries")


# ============================================================
# DOMAIN 12: TLS / SSL CONFIGURATION
# ============================================================

def audit_tls_config():
    """
    Check TLS/SSL protocol versions via Schannel registry.
    """
    print("\n[*] Auditing TLS/SSL Configuration...")

    HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else None
    base = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    # Protocols that should be DISABLED
    deprecated = [("SSL 2.0", "TLS-01"), ("SSL 3.0", "TLS-02"),
                  ("TLS 1.0", "TLS-03"), ("TLS 1.1", "TLS-04")]

    for proto_name, cis_id in deprecated:
        for side in ("Client", "Server"):
            path = f"{base}\\{proto_name}\\{side}"
            enabled = reg_query(HKLM, path, "Enabled")
            dbd = reg_query(HKLM, path, "DisabledByDefault")

            if enabled is not None:
                ok = enabled == 0
                add_result("TLS Configuration", cis_id,
                           f"{proto_name} {side} disabled",
                           "PASS" if ok else "FAIL",
                           f"Enabled={enabled}, DisabledByDefault={dbd}",
                           "Enabled=0", f"Set {path}\\Enabled = 0")
            elif dbd is not None and dbd == 1:
                add_result("TLS Configuration", cis_id,
                           f"{proto_name} {side} disabled",
                           "PASS", f"DisabledByDefault=1", "Disabled")
            else:
                add_result("TLS Configuration", cis_id,
                           f"{proto_name} {side} disabled",
                           "INFO", "No explicit config (OS default)", "Explicitly disabled recommended")

    # Protocols that should be ENABLED
    for proto_name in ("TLS 1.2", "TLS 1.3"):
        for side in ("Client", "Server"):
            path = f"{base}\\{proto_name}\\{side}"
            enabled = reg_query(HKLM, path, "Enabled")
            dbd = reg_query(HKLM, path, "DisabledByDefault")

            if enabled is not None and enabled == 0:
                add_result("TLS Configuration", "TLS-05",
                           f"{proto_name} {side} enabled", "FAIL",
                           f"Explicitly disabled!", "Enabled or absent",
                           f"Set {path}\\Enabled = 1")
            elif dbd is not None and dbd == 1:
                add_result("TLS Configuration", "TLS-05",
                           f"{proto_name} {side} enabled", "FAIL",
                           "DisabledByDefault=1", "DisabledByDefault=0")
            else:
                add_result("TLS Configuration", "TLS-05",
                           f"{proto_name} {side} enabled", "PASS",
                           "Enabled (explicit or default)", "Enabled")


# ============================================================
# DOMAIN 13: CREDENTIAL FILES ON DISK
# ============================================================

def audit_credential_files():
    """
    Scan for plaintext credentials and sensitive files.
    """
    print("\n[*] Auditing Credential Files...")

    home = os.path.expanduser("~")

    # --- PowerShell history ---
    ps_hist = os.path.join(home, "AppData", "Roaming", "Microsoft", "Windows",
                           "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
    if os.path.isfile(ps_hist):
        try:
            size = os.path.getsize(ps_hist)
            with open(ps_hist, "r", errors="replace") as f:
                content = f.read()
            cred_hits = len(re.findall(r"(?i)(password|passwd|secret|token|apikey|api_key|credential)", content))
            add_result("Credential Files", "CRED-01", "PowerShell history file",
                       "FAIL" if cred_hits > 0 else "INFO",
                       f"Size: {size//1024} KB | Credential patterns: {cred_hits}",
                       "No credential patterns in history",
                       "Clear: Remove-Item; Disable: Set-PSReadlineOption -HistorySaveStyle SaveNothing")
        except OSError:
            pass

    # --- SSH private keys ---
    ssh_dir = os.path.join(home, ".ssh")
    if os.path.isdir(ssh_dir):
        for item in os.listdir(ssh_dir):
            if item.startswith("id_") and not item.endswith(".pub"):
                fpath = os.path.join(ssh_dir, item)
                try:
                    with open(fpath, "r", errors="replace") as f:
                        header = f.read(200)
                    encrypted = "ENCRYPTED" in header
                    add_result("Credential Files", "CRED-02",
                               f"SSH private key: {item}",
                               "INFO" if encrypted else "FAIL",
                               f"Encrypted: {encrypted}",
                               "Passphrase-protected",
                               f"Add passphrase: ssh-keygen -p -f {fpath}")
                except OSError:
                    pass

    # --- Git credentials ---
    git_cred = os.path.join(home, ".git-credentials")
    if os.path.isfile(git_cred):
        add_result("Credential Files", "CRED-03", "Git credentials file",
                   "FAIL", f"Plaintext cred store: {git_cred}",
                   "Use Git Credential Manager instead",
                   "Switch to GCM: git config --global credential.helper manager")

    # --- Cloud credential files ---
    cloud_files = [
        (os.path.join(home, ".aws", "credentials"), "AWS credentials", "CRED-05"),
        (os.path.join(home, ".azure", "accessTokens.json"), "Azure tokens", "CRED-06"),
    ]
    for fpath, desc, cid in cloud_files:
        if os.path.isfile(fpath):
            add_result("Credential Files", cid, f"Cloud creds: {desc}",
                       "INFO", f"Found: {fpath}", "Review access scope and rotation")

    # --- unattend.xml ---
    for ua in [r"C:\unattend.xml", r"C:\Windows\Panther\unattend.xml",
               r"C:\Windows\Panther\Unattend\unattend.xml"]:
        if os.path.isfile(ua):
            try:
                with open(ua, "r", errors="replace") as f:
                    content = f.read()
                has_pw = bool(re.search(r"(?i)<Password>|<AdministratorPassword>", content))
                add_result("Credential Files", "CRED-09", "unattend.xml found",
                           "FAIL" if has_pw else "INFO",
                           f"Path: {ua} | Password tags: {has_pw}",
                           "Remove after installation")
            except OSError:
                pass


# ============================================================
# DOMAIN 14: UNQUOTED SERVICE PATHS
# ============================================================

def audit_unquoted_service_paths():
    """
    Find services with unquoted paths containing spaces.
    MITRE ATT&CK T1574.009
    """
    print("\n[*] Auditing Unquoted Service Paths...")

    output = run_cmd('wmic service get Name,PathName,StartMode,StartName /format:csv')
    if not output:
        add_result("Unquoted Service Paths", "UNQUOTE-01", "Service path audit",
                   "SKIPPED", "Could not enumerate services", "N/A")
        return

    unquoted = 0
    for line in output.splitlines():
        if not line.strip() or "PathName" in line or "Node" in line:
            continue
        parts = line.split(",")
        if len(parts) < 4:
            continue

        # CSV format: Node,Name,PathName,StartMode,StartName
        svc_name = parts[1].strip()
        path_name = parts[2].strip()
        start_mode = parts[3].strip() if len(parts) > 3 else ""
        start_name = parts[4].strip() if len(parts) > 4 else ""

        if not path_name or path_name.startswith('"'):
            continue

        # Extract the exe path (before arguments)
        m = re.match(r'^(.+?\.exe)', path_name, re.I)
        if m:
            exe_path = m.group(1)
            if " " in exe_path and not exe_path.startswith('"'):
                # Skip svchost and system32 paths
                if re.search(r"(?i)svchost\.exe|\\system32\\", exe_path) and "Program Files" not in exe_path:
                    continue
                unquoted += 1
                add_result("Unquoted Service Paths", "UNQUOTE-01",
                           f"Unquoted: {svc_name}", "FAIL",
                           f"Path: {path_name[:120]} | StartMode: {start_mode} | RunAs: {start_name}",
                           "Paths with spaces must be quoted",
                           f'Fix: sc.exe config "{svc_name}" binPath= "\\"{path_name}\\""')

    if unquoted == 0:
        add_result("Unquoted Service Paths", "UNQUOTE-01", "Unquoted service path check",
                   "PASS", "No unquoted paths with spaces found", "All paths quoted")


# ============================================================
# DOMAIN 15: ENVIRONMENT VARIABLES
# ============================================================

def audit_environment_variables():
    """
    Check environment variables for credential leakage.
    """
    print("\n[*] Auditing Environment Variables...")

    cred_patterns = ["KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD",
                     "CREDENTIAL", "API_KEY", "APIKEY", "AUTH", "PRIVATE"]

    for key, value in os.environ.items():
        upper = key.upper()
        matched = [p for p in cred_patterns if p in upper]

        # Skip common false positives
        if key.upper() in ("PATH", "PATHEXT", "PSMODULEPATH", "PUBLIC",
                           "AUTHTYPE", "KEYS", "PRIVATEPROFILE"):
            continue

        if matched and value and len(value) > 3:
            masked = value[:4] + "****"
            add_result("Environment Variables", "ENV-01",
                       f"Potential credential: {key}", "FAIL",
                       f"Matches pattern: {matched[0]} | Value: {masked}",
                       "Credentials should not be in env vars",
                       "Move to secrets manager. Remove from environment.")

    # --- Proxy with credentials ---
    for proxy_var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        proxy = os.environ.get(proxy_var, "")
        if proxy and re.search(r"://[^:]+:[^@]+@", proxy):
            add_result("Environment Variables", "ENV-02",
                       f"Credentials in {proxy_var}", "FAIL",
                       f"Proxy URL contains embedded credentials",
                       "No credentials in proxy URLs",
                       "Use authenticated proxy with credential manager")


# ============================================================
# DOMAIN 16: OFFICE MACRO SETTINGS
# ============================================================

def audit_office_macros():
    """
    Check Microsoft Office macro security settings.
    """
    print("\n[*] Auditing Office Macro Settings...")

    HKCU = winreg.HKEY_CURRENT_USER if winreg else None
    if HKCU is None:
        return

    apps = ["Word", "Excel", "PowerPoint", "Outlook"]
    versions = ["16.0", "15.0"]

    for ver in versions:
        for app in apps:
            path = f"SOFTWARE\\Microsoft\\Office\\{ver}\\{app}\\Security"
            vba = reg_query(HKCU, path, "VBAWarnings")
            if vba is not None:
                desc = {1: "Enable all macros (DANGEROUS)", 2: "Disable with notification",
                        3: "Disable except signed", 4: "Disable all"}.get(vba, f"Unknown ({vba})")
                status = "FAIL" if vba == 1 else ("PASS" if vba in (3, 4) else "INFO")
                add_result("Office Macros", "OFFICE-01",
                           f"Office {ver} {app} macros", status,
                           f"VBAWarnings = {vba} ({desc})",
                           "3 (Signed only) or 4 (All disabled)",
                           f"GPO: Office > {app} > Macro Settings")


# ============================================================
# DOMAIN 17: INSTALLED SERVICES
# ============================================================

def audit_services():
    """Check for risky services that should be disabled."""
    print("\n[*] Auditing Installed Services...")

    risky = {
        "RemoteRegistry": "Remote Registry editing",
        "TlntSvr": "Telnet Server (cleartext)",
        "SNMP": "SNMP (weak community strings)",
        "FTPSVC": "FTP Server",
        "W3SVC": "IIS Web Server",
        "SSDPSRV": "SSDP Discovery (UPnP)",
        "upnphost": "UPnP Device Host",
    }

    output = run_cmd('sc query type= service state= all')
    running_services = set()
    current_name = ""
    for line in output.splitlines():
        if "SERVICE_NAME:" in line:
            current_name = line.split(":", 1)[1].strip()
        if "RUNNING" in line and current_name:
            running_services.add(current_name.lower())

    for svc_name, desc in risky.items():
        if svc_name.lower() in running_services:
            add_result("Services", "SVC-01", f"Risky service running: {svc_name}",
                       "FAIL", f"{desc} - RUNNING",
                       "Disabled or stopped if not required",
                       f"Disable: sc config {svc_name} start=disabled")


# ============================================================
# DOMAIN 18: SOFTWARE AUDIT
# ============================================================

def audit_installed_software():
    """Check for EOL/vulnerable software and remote access tools."""
    print("\n[*] Auditing Installed Software...")

    HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else None
    if HKLM is None:
        return

    apps = []
    for path in [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                 r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]:
        for subkey_name in reg_enum_subkeys(HKLM, path):
            name = reg_query(HKLM, f"{path}\\{subkey_name}", "DisplayName")
            version = reg_query(HKLM, f"{path}\\{subkey_name}", "DisplayVersion")
            if name:
                apps.append((name, version or ""))

    eol_patterns = [
        (r"Adobe Flash Player", "EOL since 2020"),
        (r"Microsoft Silverlight", "EOL, no updates"),
        (r"Java [678]\.", "Legacy Java version"),
        (r"Python 2\.", "EOL since 2020"),
    ]

    remote_tools = ["TeamViewer", "AnyDesk", "LogMeIn", "VNC",
                    "RealVNC", "TightVNC", "ConnectWise", "Splashtop"]

    for name, version in apps:
        for pattern, reason in eol_patterns:
            if re.search(pattern, name, re.I):
                add_result("Software Audit", "SW-01",
                           f"EOL software: {name}", "FAIL",
                           f"{name} {version} - {reason}",
                           "Remove or update", "Uninstall via Control Panel")

        for tool in remote_tools:
            if tool.lower() in name.lower():
                add_result("Software Audit", "SW-02",
                           f"Remote access: {name}", "INFO",
                           f"{name} {version}",
                           "Should be authorised and monitored")


# ============================================================
# HTML REPORT GENERATOR
# ============================================================

def generate_html_report(output_path):
    """Generate a self-contained HTML audit report."""
    print("\n[*] Generating HTML report...")

    total = len(results)
    pass_rate = round((pass_count / total) * 100, 1) if total > 0 else 0

    # Group results by domain
    domains = {}
    for r in results:
        domains.setdefault(r["domain"], []).append(r)

    # Build HTML
    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CIS Audit Report - {html.escape(sys_info.get('hostname', ''))}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Tahoma,sans-serif;background:#f5f5f5;color:#333;line-height:1.6}}
.c{{max-width:1100px;margin:0 auto;padding:20px}}
.hdr{{background:linear-gradient(135deg,#1a237e,#283593);color:#fff;padding:30px;border-radius:8px;margin-bottom:24px}}
.hdr h1{{font-size:24px;margin-bottom:8px}}.hdr p{{opacity:.85;font-size:14px}}
.sum{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:16px;margin-bottom:24px}}
.sc{{background:#fff;padding:20px;border-radius:8px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.sc .n{{font-size:32px;font-weight:700}}.sc .l{{font-size:12px;text-transform:uppercase;color:#666;margin-top:4px}}
.p .n{{color:#2e7d32}}.f .n{{color:#c62828}}.i .n{{color:#f57f17}}.s .n{{color:#78909c}}.e .n{{color:#6a1b9a}}.r .n{{color:#1565c0}}
.si{{background:#fff;padding:20px;border-radius:8px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.si h2{{font-size:18px;margin-bottom:12px;color:#1a237e}}.si table{{width:100%;border-collapse:collapse}}
.si td{{padding:6px 12px;border-bottom:1px solid #eee;font-size:14px}}.si td:first-child{{font-weight:600;width:180px;color:#555}}
.dom{{background:#fff;border-radius:8px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.1);overflow:hidden}}
.dh{{padding:16px 20px;background:#e8eaf6;font-size:16px;font-weight:600;color:#1a237e;cursor:pointer}}
.dh:hover{{background:#c5cae9}}
table.res{{width:100%;border-collapse:collapse;font-size:13px}}
table.res th{{background:#f5f5f5;padding:10px 12px;text-align:left;font-weight:600;color:#555;border-bottom:2px solid #ddd}}
table.res td{{padding:10px 12px;border-bottom:1px solid #eee;vertical-align:top}}
table.res tr:hover{{background:#fafafa}}
.b{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600;color:#fff}}
.b-p{{background:#2e7d32}}.b-f{{background:#c62828}}.b-i{{background:#f57f17;color:#333}}.b-s{{background:#78909c}}.b-e{{background:#6a1b9a}}
.rem{{background:#fff3e0;padding:8px 12px;border-radius:4px;font-size:12px;margin-top:6px;border-left:3px solid #f57f17}}
.dis{{background:#ffebee;padding:16px;border-radius:8px;margin-bottom:24px;border-left:4px solid #c62828;font-size:13px}}
.ft{{text-align:center;padding:20px;color:#999;font-size:12px}}
</style>
</head>
<body>
<div class="c">
<div class="hdr">
<h1>CIS Benchmark Audit Report</h1>
<p>Host: {html.escape(sys_info.get('hostname',''))} | Date: {html.escape(sys_info.get('audit_date',''))} | User: {html.escape(sys_info.get('current_user',''))}</p>
<p>OS: {html.escape(sys_info.get('os_name',''))} | Privilege: {'Administrator' if sys_info.get('is_admin') else 'Standard User (non-admin)'}</p>
</div>
<div class="dis"><strong>Disclaimer:</strong> This audit was performed with standard user (non-admin) privileges. Some controls may be marked SKIPPED.</div>
<div class="sum">
<div class="sc r"><div class="n">{pass_rate}%</div><div class="l">Pass Rate</div></div>
<div class="sc p"><div class="n">{pass_count}</div><div class="l">Passed</div></div>
<div class="sc f"><div class="n">{fail_count}</div><div class="l">Failed</div></div>
<div class="sc i"><div class="n">{info_count}</div><div class="l">Info</div></div>
<div class="sc s"><div class="n">{skip_count}</div><div class="l">Skipped</div></div>
<div class="sc e"><div class="n">{error_count}</div><div class="l">Errors</div></div>
</div>
<div class="si"><h2>System Information</h2><table>"""

    for k, v in sys_info.items():
        report += f"<tr><td>{html.escape(k)}</td><td>{html.escape(str(v))}</td></tr>"

    report += "</table></div>"

    # Domain sections
    for domain_name, domain_results in domains.items():
        d_pass = sum(1 for r in domain_results if r["status"] == "PASS")
        d_fail = sum(1 for r in domain_results if r["status"] == "FAIL")
        d_total = len(domain_results)

        report += f"""<div class="dom">
<div class="dh" onclick="var b=this.nextElementSibling;b.style.display=b.style.display==='none'?'block':'none'">
{html.escape(domain_name)} ({d_total} checks: {d_pass} passed, {d_fail} failed)</div>
<div><table class="res">
<tr><th style="width:60px">Status</th><th style="width:70px">ID</th><th style="width:220px">Check</th><th>Finding</th><th style="width:180px">Expected</th></tr>"""

        for r in domain_results:
            badge = {"PASS": "b-p", "FAIL": "b-f", "INFO": "b-i", "SKIPPED": "b-s", "ERROR": "b-e"}.get(r["status"], "b-i")
            rem_html = ""
            if r["status"] == "FAIL" and r["remediation"]:
                rem_html = f'<div class="rem"><strong>Fix:</strong> {html.escape(r["remediation"])}</div>'

            report += f"""<tr>
<td><span class="b {badge}">{r['status']}</span></td>
<td>{html.escape(r['id'])}</td>
<td>{html.escape(r['check'])}</td>
<td>{html.escape(r['finding'])}{rem_html}</td>
<td>{html.escape(r['expected'])}</td></tr>"""

        report += "</table></div></div>"

    report += f"""<div class="ft">Generated by cis_audit.py (Pure Python Edition) | {html.escape(sys_info.get('audit_date',''))}</div>
</div></body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"  HTML report saved to: {output_path}")


def export_json(json_path):
    """Export results as JSON."""
    export = {
        "system_info": sys_info,
        "summary": {
            "total": len(results), "pass": pass_count, "fail": fail_count,
            "info": info_count, "skipped": skip_count, "error": error_count,
            "pass_rate": round((pass_count / len(results)) * 100, 1) if results else 0,
        },
        "results": results,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2, default=str)
    print(f"  JSON results saved to: {json_path}")


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Non-Privileged Windows CIS Benchmark Auditor (Pure Python)")
    parser.add_argument("--output", "-o", default="CIS_Audit_Report.html",
                        help="HTML report output path (default: CIS_Audit_Report.html)")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Also export results as JSON")
    parser.add_argument("--json-path", default="CIS_Audit_Results.json",
                        help="JSON output path (default: CIS_Audit_Results.json)")
    args = parser.parse_args()

    # Check we're on Windows
    if sys.platform != "win32":
        print("ERROR: This script must be run on Windows.")
        sys.exit(1)

    print("=" * 60)
    print("  CIS Benchmark Auditor - Pure Python Edition")
    print("  AUTHORISED USE ONLY")
    print("=" * 60)

    start = datetime.datetime.now()

    # Collect system info
    collect_system_info()

    # Run all audit domains
    audit_account_policy()          # Domain 1
    audit_windows_update()          # Domain 2
    audit_firewall()                # Domain 3
    audit_logging_policy()          # Domain 4
    audit_network_security()        # Domain 5
    audit_user_accounts()           # Domain 6
    audit_security_features()       # Domain 7
    audit_credential_protection()   # Domain 8
    audit_misc_hardening()          # Domain 9
    audit_scheduled_tasks()         # Domain 10
    audit_startup_persistence()     # Domain 11
    audit_tls_config()              # Domain 12
    audit_credential_files()        # Domain 13
    audit_unquoted_service_paths()  # Domain 14
    audit_environment_variables()   # Domain 15
    audit_office_macros()           # Domain 16
    audit_services()                # Domain 17
    audit_installed_software()      # Domain 18

    # Generate reports
    generate_html_report(args.output)
    if args.json:
        export_json(args.json_path)

    elapsed = (datetime.datetime.now() - start).total_seconds()

    print(f"\n{'='*60}")
    print(f"  AUDIT COMPLETE")
    print(f"{'='*60}")
    print(f"  Total checks : {len(results)}")
    print(f"  \033[92mPassed       : {pass_count}\033[0m")
    print(f"  \033[91mFailed       : {fail_count}\033[0m")
    print(f"  \033[93mInfo         : {info_count}\033[0m")
    print(f"  \033[90mSkipped      : {skip_count}\033[0m")
    print(f"  \033[95mErrors       : {error_count}\033[0m")
    total = len(results)
    rate = round((pass_count / total) * 100, 1) if total > 0 else 0
    print(f"  Pass rate    : {rate}%")
    print(f"  Duration     : {elapsed:.1f}s")
    print(f"  Report       : {args.output}")
    if args.json:
        print(f"  JSON         : {args.json_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
