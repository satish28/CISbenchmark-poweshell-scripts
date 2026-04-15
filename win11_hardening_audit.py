#!/usr/bin/env python3
"""
win11_hardening_audit.py - Windows 11 Enterprise Hardening Auditor
Author : SS
Purpose: Audit a Windows 11 Enterprise (10.0.26200) workstation against
         CIS Benchmarks, Microsoft Security Baselines, and DISA STIGs
         using ONLY standard-user (non-admin) access and Python stdlib.
Usage  : python win11_hardening_audit.py
         python win11_hardening_audit.py --output C:\\Audits\\report.html --json

Target : Windows 11 Enterprise 24H2 (Build 26200)
Priv   : Standard user (no elevation required)
Deps   : Python 3.6+ stdlib only (no pip installs)

AUTHORISED USE ONLY. Run this tool only against systems you own or have
explicit written authorisation to audit.
"""

# --- stdlib imports ---
import argparse
import ctypes
import datetime
import html as html_mod
import json
import os
import platform
import re
import subprocess
import sys
import time

try:
    import winreg
except ImportError:
    winreg = None

# ============================================================
# GLOBAL STATE
# ============================================================

results = []
counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0, "SKIP": 0, "ERROR": 0}
sysinfo = {}

# ============================================================
# HELPERS
# ============================================================

def add(domain, cid, check, status, finding, expected="", fix=""):
    """Record a single audit result."""
    results.append({
        "domain": domain, "id": cid, "check": check, "status": status,
        "finding": finding, "expected": expected, "remediation": fix,
    })
    counts[status] = counts.get(status, 0) + 1
    c = {"PASS":"\033[92m","FAIL":"\033[91m","WARN":"\033[93m",
         "INFO":"\033[96m","SKIP":"\033[90m","ERROR":"\033[95m"}.get(status,"")
    print(f"  {c}[{status:>5}]\033[0m {cid} - {check}")


def cmd(command, timeout=30):
    """Run a shell command, return stdout string. Empty on failure."""
    try:
        r = subprocess.run(command, capture_output=True, text=True,
                           shell=True, timeout=timeout, errors="replace")
        return r.stdout.strip()
    except Exception:
        return ""


def reg(hive, path, name):
    """Read a registry value. Returns None if inaccessible."""
    if not winreg:
        return None
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as k:
            v, _ = winreg.QueryValueEx(k, name)
            return v
    except (OSError, FileNotFoundError, PermissionError):
        return None


def reg_values(hive, path):
    """Enumerate all values under a key. Returns list of (name, data, type)."""
    if not winreg:
        return []
    try:
        vals = []
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    vals.append(winreg.EnumValue(k, i))
                    i += 1
                except OSError:
                    break
        return vals
    except (OSError, FileNotFoundError, PermissionError):
        return []


def reg_subkeys(hive, path):
    """Enumerate subkey names under a key."""
    if not winreg:
        return []
    try:
        keys = []
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    keys.append(winreg.EnumKey(k, i))
                    i += 1
                except OSError:
                    break
        return keys
    except (OSError, FileNotFoundError, PermissionError):
        return []


HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else None
HKCU = winreg.HKEY_CURRENT_USER if winreg else None

# ============================================================
# SYSTEM INFORMATION
# ============================================================

def collect_sysinfo():
    """Gather system identification for the report header."""
    global sysinfo
    print("\n[*] Collecting system information...")

    is_admin = False
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        pass

    build = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber") or ""
    ubr = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR") or ""
    display_ver = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion") or ""
    edition = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID") or ""
    product = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName") or platform.platform()

    sysinfo = {
        "hostname": os.environ.get("COMPUTERNAME", platform.node()),
        "product": product,
        "edition": edition,
        "display_version": display_ver,
        "build": f"{build}.{ubr}" if ubr else build,
        "architecture": platform.machine(),
        "domain": os.environ.get("USERDOMAIN", ""),
        "domain_joined": os.environ.get("USERDNSDOMAIN", "N/A"),
        "current_user": f"{os.environ.get('USERDOMAIN','')}\\{os.environ.get('USERNAME','')}",
        "is_admin": is_admin,
        "audit_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "python": platform.python_version(),
        "target_build": "26200 (24H2)",
    }

    for k, v in sysinfo.items():
        print(f"  {k:>18}: {v}")

    # Validate target build
    if build and build != "26200":
        print(f"\n  WARNING: This script targets build 26200 (24H2). Detected build: {build}")
        print(f"  Some checks may not be applicable to your build.\n")


# ============================================================
# DOMAIN 1: ACCOUNT POLICY (CIS 1.x)
# ============================================================

def audit_account_policy():
    print("\n[*] Domain 1: Account Policy...")
    out = cmd("net accounts")
    if not out:
        add("Account Policy", "1.x", "net accounts", "SKIP", "Could not query", "N/A")
        return

    def extract(pattern):
        for line in out.splitlines():
            if pattern.lower() in line.lower():
                m = re.search(r"(\d+)", line)
                if m:
                    return int(m.group(1))
                if "never" in line.lower():
                    return 0
        return None

    # CIS 1.1.1: Password history >= 24
    v = extract("password history")
    if v is not None:
        add("Account Policy", "1.1.1", "Password history depth",
            "PASS" if v >= 24 else "FAIL", f"{v} passwords remembered",
            ">= 24", "GPO: Password Policy > Enforce password history = 24")

    # CIS 1.1.2: Max password age <= 365 and > 0
    v = extract("maximum password age")
    if v is not None:
        add("Account Policy", "1.1.2", "Maximum password age",
            "PASS" if 0 < v <= 365 else "FAIL", f"{v} days",
            "<= 365 and > 0", "GPO: Password Policy > Maximum password age")

    # CIS 1.1.3: Min password age >= 1
    v = extract("minimum password age")
    if v is not None:
        add("Account Policy", "1.1.3", "Minimum password age",
            "PASS" if v >= 1 else "FAIL", f"{v} day(s)",
            ">= 1", "GPO: Password Policy > Minimum password age = 1")

    # CIS 1.1.4: Min password length >= 14
    v = extract("minimum password length")
    if v is not None:
        add("Account Policy", "1.1.4", "Minimum password length",
            "PASS" if v >= 14 else "FAIL", f"{v} characters",
            ">= 14", "GPO: Password Policy > Minimum password length = 14")

    # CIS 1.2.1: Lockout threshold 1-5
    v = extract("lockout threshold")
    if v is not None:
        ok = 1 <= v <= 5
        add("Account Policy", "1.2.1", "Account lockout threshold",
            "PASS" if ok else "FAIL",
            f"{v} attempts" if v else "Never (disabled)",
            "1-5 attempts", "GPO: Account Lockout Policy > Threshold = 5")

    # CIS 1.2.2: Lockout duration >= 15
    v = extract("lockout duration")
    if v is not None:
        add("Account Policy", "1.2.2", "Account lockout duration",
            "PASS" if v >= 15 else "FAIL", f"{v} minutes",
            ">= 15 minutes", "GPO: Account Lockout Policy > Duration = 15")

    # CIS 1.2.3: Reset lockout counter >= 15
    v = extract("lockout observation")
    if v is not None:
        add("Account Policy", "1.2.3", "Lockout counter reset",
            "PASS" if v >= 15 else "FAIL", f"{v} minutes",
            ">= 15 minutes", "GPO: Account Lockout Policy > Reset counter = 15")


# ============================================================
# DOMAIN 2: LOCAL POLICIES - SECURITY OPTIONS (CIS 2.3.x)
# ============================================================

def audit_security_options():
    print("\n[*] Domain 2: Security Options...")

    checks = [
        # (CIS ID, Check name, reg path, reg name, pass_fn, expected, remediation)
        ("2.3.1.2", "Guest account disabled",
         r"SAM\SAM\Domains\Account\Users\000001F5", "F",
         None, "Guest account disabled",  # Special - checked via net user
         "net user Guest /active:no"),

        ("2.3.1.5", "Administrator account renamed",
         None, None, None, "Not 'Administrator'",
         "GPO: Security Options > Rename administrator account"),

        ("2.3.7.1", "Interactive logon: Do not display last username",
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DontDisplayLastUserName",
         lambda v: v == 1, "1 (Enabled)",
         "GPO: Security Options > Do not display last user name = Enabled"),

        ("2.3.7.3", "Machine inactivity lock timeout",
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs",
         lambda v: 0 < v <= 900, "<= 900 seconds (15 min)",
         "GPO: Security Options > Machine inactivity limit = 900"),

        ("2.3.8.1", "SMB client signing required",
         r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature",
         lambda v: v == 1, "1 (Required)",
         "GPO: Security Options > Microsoft network client: Digitally sign communications (always)"),

        ("2.3.8.2", "SMB server signing required",
         r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature",
         lambda v: v == 1, "1 (Required)",
         "GPO: Security Options > Microsoft network server: Digitally sign communications (always)"),

        ("2.3.10.1", "Network access: Do not allow anonymous enum of SAM accounts",
         r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM",
         lambda v: v == 1, "1 (Enabled)",
         "GPO: Security Options > Network access: Do not allow anonymous enumeration of SAM accounts"),

        ("2.3.10.2", "Network access: Do not allow anonymous enum of SAM accounts and shares",
         r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous",
         lambda v: v == 1, "1 (Enabled)",
         "GPO: Security Options > Do not allow anonymous enumeration of SAM accounts and shares"),

        ("2.3.11.7", "LAN Manager authentication level",
         r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel",
         lambda v: v >= 5, "5 (NTLMv2 only, refuse LM & NTLM)",
         "GPO: Security Options > Network security: LAN Manager authentication level"),

        ("2.3.11.10", "LDAP client signing",
         r"SYSTEM\CurrentControlSet\Control\Lsa", "LDAPClientIntegrity",
         lambda v: v >= 1, ">= 1 (Negotiate or Require signing)",
         "GPO: Security Options > Network security: LDAP client signing requirements"),

        ("2.3.17.1", "UAC: Admin Approval Mode enabled",
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA",
         lambda v: v == 1, "1 (Enabled)",
         "GPO: Security Options > UAC: Run all administrators in Admin Approval Mode"),

        ("2.3.17.2", "UAC: Admin prompt behaviour",
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin",
         lambda v: v in (1, 2), "1 or 2 (Prompt on secure desktop)",
         "GPO: Security Options > UAC: Behavior of the elevation prompt for administrators"),

        ("2.3.17.3", "UAC: Standard user prompt behaviour",
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorUser",
         lambda v: v == 0, "0 (Automatically deny elevation)",
         "GPO: Security Options > UAC: Behavior of the elevation prompt for standard users"),

        ("2.3.17.4", "UAC: Detect application installations",
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableInstallerDetection",
         lambda v: v == 1, "1 (Enabled)",
         "GPO: Security Options > UAC: Detect application installations and prompt for elevation"),

        ("2.3.17.6", "UAC: Virtualize file and registry writes",
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableVirtualization",
         lambda v: v == 1, "1 (Enabled)",
         "GPO: Security Options > UAC: Virtualize file and registry write failures"),
    ]

    # Special: Guest account
    out = cmd("net user Guest")
    if out:
        active = bool(re.search(r"Account active\s+Yes", out, re.I))
        add("Security Options", "2.3.1.2", "Guest account disabled",
            "PASS" if not active else "FAIL",
            f"Guest active: {active}", "Disabled (active=No)",
            "net user Guest /active:no")

    # Special: Admin renamed
    out = cmd('wmic useraccount where "SID like \'S-1-5-%-500\'" get Name /value')
    if out:
        m = re.search(r"Name=(.+)", out)
        if m:
            name = m.group(1).strip()
            add("Security Options", "2.3.1.5", "Administrator account renamed",
                "PASS" if name.lower() != "administrator" else "FAIL",
                f"Admin name: '{name}'", "Not 'Administrator'",
                "GPO: Security Options > Rename administrator account")

    # Registry-based checks
    for cid, check_name, path, name, pass_fn, expected, fix in checks:
        if path is None:
            continue  # handled above
        v = reg(HKLM, path, name)
        if v is not None:
            ok = pass_fn(v) if pass_fn else False
            desc_map = {
                "LmCompatibilityLevel": {0:"Send LM & NTLM",1:"Send LM & NTLM, negotiate NTLMv2",
                    2:"Send NTLM only",3:"Send NTLMv2 only",4:"NTLMv2, refuse LM",5:"NTLMv2, refuse LM & NTLM"},
                "ConsentPromptBehaviorAdmin": {0:"Elevate without prompting",1:"Prompt creds on secure desktop",
                    2:"Prompt consent on secure desktop",3:"Prompt creds",4:"Prompt consent",5:"Prompt for non-Windows"},
            }
            desc = desc_map.get(name, {}).get(v, "")
            finding = f"{name} = {v}" + (f" ({desc})" if desc else "")
            add("Security Options", cid, check_name, "PASS" if ok else "FAIL",
                finding, expected, fix)
        else:
            add("Security Options", cid, check_name, "INFO",
                f"{name}: Not configured (key absent)", expected, fix)


# ============================================================
# DOMAIN 3: WINDOWS FIREWALL (CIS 9.x)
# ============================================================

def audit_firewall():
    print("\n[*] Domain 3: Windows Firewall...")
    profiles = [("domainprofile","Domain","9.1"),("privateprofile","Private","9.2"),("publicprofile","Public","9.3")]

    for key, name, cis in profiles:
        out = cmd(f"netsh advfirewall show {key}")
        if not out:
            add("Firewall", f"{cis}.1", f"Firewall state - {name}", "SKIP",
                "Could not query", "ON")
            continue

        # State
        on = bool(re.search(r"State\s+ON", out, re.I))
        add("Firewall", f"{cis}.1", f"Firewall enabled - {name}",
            "PASS" if on else "FAIL", f"State: {'ON' if on else 'OFF'}", "ON",
            f"netsh advfirewall set {key} state on")

        # Inbound default
        block_in = "blockinbound" in out.lower()
        add("Firewall", f"{cis}.2", f"Inbound default block - {name}",
            "PASS" if block_in else "FAIL",
            f"{'BlockInbound' if block_in else 'AllowInbound'}",
            "BlockInbound", f"GPO: Firewall > {name} > Inbound = Block")

        # Log dropped packets
        log_drop = bool(re.search(r"LogDroppedConnections\s+Enable", out, re.I))
        add("Firewall", f"{cis}.7", f"Log dropped connections - {name}",
            "PASS" if log_drop else "WARN",
            f"LogDroppedConnections: {'Enabled' if log_drop else 'Disabled'}",
            "Enabled", f"GPO: Firewall > {name} > Logging > Log dropped packets")


# ============================================================
# DOMAIN 4: AUDIT POLICY (CIS 17.x)
# ============================================================

def audit_audit_policy():
    print("\n[*] Domain 4: Audit Policy...")
    out = cmd("auditpol /get /category:*")
    if not out:
        add("Audit Policy", "17.x", "Audit policy query", "SKIP",
            "auditpol may require elevation", "N/A")
        return

    required = [
        ("Credential Validation",       "17.1.1",  "Success and Failure"),
        ("Application Group Management","17.2.1",  "Success and Failure"),
        ("Security Group Management",   "17.2.5",  "Success"),
        ("User Account Management",     "17.2.6",  "Success and Failure"),
        ("Process Creation",            "17.3.1",  "Success"),
        ("Account Lockout",             "17.5.1",  "Failure"),
        ("Group Membership",            "17.5.2",  "Success"),
        ("Logon",                       "17.5.3",  "Success and Failure"),
        ("Logoff",                      "17.5.2b", "Success"),
        ("Other Logon/Logoff",          "17.5.4",  "Success and Failure"),
        ("Special Logon",               "17.5.6",  "Success"),
        ("Detailed File Share",         "17.6.1",  "Failure"),
        ("File Share",                  "17.6.2",  "Success and Failure"),
        ("Other Object Access",         "17.6.3",  "Success and Failure"),
        ("Removable Storage",           "17.6.4",  "Success and Failure"),
        ("Audit Policy Change",         "17.7.1",  "Success"),
        ("Authentication Policy",       "17.7.2",  "Success"),
        ("MPSSVC Rule-Level",           "17.7.3",  "Success and Failure"),
        ("Sensitive Privilege Use",     "17.8.1",  "Success and Failure"),
        ("IPsec Driver",               "17.9.2",  "Success and Failure"),
        ("Other System Events",         "17.9.3",  "Success and Failure"),
        ("Security State Change",       "17.9.1",  "Success"),
        ("Security System Extension",   "17.9.4",  "Success"),
        ("System Integrity",            "17.9.5",  "Success and Failure"),
    ]

    for cat, cid, expected in required:
        found = False
        for line in out.splitlines():
            if cat.lower() in line.lower():
                parts = re.split(r"\s{2,}", line.strip())
                setting = parts[-1] if parts else "Unknown"
                if expected == "Success and Failure":
                    ok = "success and failure" in setting.lower()
                elif expected == "Success":
                    ok = "success" in setting.lower()
                elif expected == "Failure":
                    ok = "failure" in setting.lower()
                else:
                    ok = expected.lower() in setting.lower()
                add("Audit Policy", cid, f"Audit: {cat}",
                    "PASS" if ok else "FAIL", f"Current: {setting}", expected,
                    f"GPO: Advanced Audit Policy > {cat} = {expected}")
                found = True
                break
        if not found:
            add("Audit Policy", cid, f"Audit: {cat}", "SKIP",
                "Category not found in auditpol output", expected)


# ============================================================
# DOMAIN 5: WINDOWS 11 SECURITY FEATURES (CIS 18.x + MS Baseline)
# ============================================================

def audit_win11_features():
    print("\n[*] Domain 5: Windows 11 Security Features...")

    # --- Credential Guard / VBS ---
    vbs = reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "EnableVirtualizationBasedSecurity")
    if vbs is not None:
        add("Win11 Security", "18.8.5.1", "Virtualization Based Security (VBS)",
            "PASS" if vbs == 1 else "FAIL", f"EnableVBS = {vbs}", "1 (Enabled)",
            "GPO: Device Guard > Turn On VBS = Enabled")
    else:
        # Check runtime status via msinfo32 alternative
        out = cmd('powershell -NoProfile -Command "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue).VirtualizationBasedSecurityStatus"')
        if out:
            status_map = {"0": "Not running", "1": "Reboot required", "2": "Running"}
            add("Win11 Security", "18.8.5.1", "VBS runtime status",
                "PASS" if out.strip() == "2" else "WARN",
                f"VBS status: {status_map.get(out.strip(), out.strip())}", "Running (2)")

    # --- HVCI (Hypervisor-enforced Code Integrity) ---
    hvci = reg(HKLM, r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled")
    if hvci is not None:
        add("Win11 Security", "18.8.5.2", "HVCI (Memory Integrity)",
            "PASS" if hvci == 1 else "FAIL", f"HVCI Enabled = {hvci}", "1 (Enabled)",
            "Settings > Device security > Core isolation > Memory integrity = On")

    # --- Credential Guard ---
    cg = reg(HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags")
    if cg is not None:
        desc = {0: "Disabled", 1: "Enabled with UEFI lock", 2: "Enabled without lock"}.get(cg, str(cg))
        add("Win11 Security", "18.8.5.3", "Credential Guard",
            "PASS" if cg >= 1 else "FAIL", f"LsaCfgFlags = {cg} ({desc})",
            ">= 1 (Enabled)", "GPO: Device Guard > Credential Guard = Enabled with UEFI lock")

    # --- LSASS PPL ---
    ppl = reg(HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
    if ppl is not None:
        add("Win11 Security", "18.4.1", "LSASS Protected Process Light",
            "PASS" if ppl in (1, 2) else "FAIL", f"RunAsPPL = {ppl}",
            "1 or 2 (Protected)", "Registry: Lsa\\RunAsPPL = 2")
    else:
        add("Win11 Security", "18.4.1", "LSASS PPL", "WARN",
            "RunAsPPL not configured (Win11 24H2 enables by default)", "Enabled by default on 24H2")

    # --- Windows Defender / AV ---
    av_off = reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware")
    if av_off is not None:
        add("Win11 Security", "18.9.47.1", "Defender not disabled by policy",
            "PASS" if av_off == 0 else "FAIL", f"DisableAntiSpyware = {av_off}",
            "0 (Not disabled)", "Remove GPO disabling Defender")

    rtp = reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring")
    if rtp is not None:
        add("Win11 Security", "18.9.47.9.1", "Defender real-time protection",
            "PASS" if rtp == 0 else "FAIL", f"DisableRealtimeMonitoring = {rtp}",
            "0 (Active)", "Enable via Windows Security > Virus & threat protection")

    # --- Tamper Protection ---
    tamper = reg(HKLM, r"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection")
    if tamper is not None:
        add("Win11 Security", "18.9.47.15", "Defender Tamper Protection",
            "PASS" if tamper == 5 else "WARN", f"TamperProtection = {tamper} (5=On)",
            "5 (On)", "Settings > Windows Security > Virus & threat > Tamper Protection")

    # --- Cloud-delivered protection ---
    cloud = reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SpynetReporting")
    if cloud is not None:
        add("Win11 Security", "18.9.47.4.1", "Defender cloud protection",
            "PASS" if cloud >= 1 else "FAIL", f"SpynetReporting = {cloud}",
            ">= 1 (Basic or Advanced)", "GPO: Defender > MAPS > Join Microsoft MAPS")

    # --- Attack Surface Reduction rules ---
    asr_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
    asr_rules = reg_values(HKLM, asr_path)
    if asr_rules:
        enabled_count = sum(1 for _, v, _ in asr_rules if v in (1, 6))  # 1=Block, 6=Warn
        add("Win11 Security", "18.9.47.5.1", "Attack Surface Reduction rules",
            "PASS" if enabled_count >= 5 else "WARN",
            f"{enabled_count}/{len(asr_rules)} ASR rules in Block or Warn mode",
            ">= 5 rules active", "GPO: Defender > Exploit Guard > ASR > Configure ASR rules")
    else:
        add("Win11 Security", "18.9.47.5.1", "ASR rules", "WARN",
            "No ASR policy keys found", "ASR rules should be configured")

    # --- Exploit Protection (DEP, ASLR, SEHOP, CFG) ---
    dep = None
    try:
        dep_info = cmd('powershell -NoProfile -Command "(Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy"')
        if dep_info:
            dep = int(dep_info.strip())
    except Exception:
        pass
    if dep is not None:
        desc = {0:"AlwaysOff",1:"AlwaysOn",2:"OptIn",3:"OptOut"}.get(dep, str(dep))
        add("Win11 Security", "18.4.2", "Data Execution Prevention (DEP)",
            "PASS" if dep >= 1 else "FAIL", f"DEP policy: {dep} ({desc})",
            ">= 1 (Not AlwaysOff)", "bcdedit /set nx OptOut")

    # --- Secure Boot ---
    try:
        sb = cmd('powershell -NoProfile -Command "Confirm-SecureBootUEFI"')
        if sb:
            add("Win11 Security", "SEC-01", "UEFI Secure Boot",
                "PASS" if "true" in sb.lower() else "FAIL",
                f"SecureBoot: {sb.strip()}", "True", "Enable in BIOS/UEFI settings")
    except Exception:
        pass

    # --- BitLocker (query status without admin) ---
    bl = cmd("manage-bde -status C: 2>&1")
    if bl and "Protection On" in bl:
        add("Win11 Security", "SEC-02", "BitLocker on C: drive",
            "PASS", "Protection On", "Protection On")
    elif bl and "Protection Off" in bl:
        add("Win11 Security", "SEC-02", "BitLocker on C: drive",
            "FAIL", "Protection Off", "Protection On",
            "Enable via: Control Panel > BitLocker Drive Encryption")
    elif bl and "Access is denied" not in bl:
        add("Win11 Security", "SEC-02", "BitLocker on C: drive",
            "INFO", f"Status unclear: {bl[:100]}", "Protection On")

    # --- PowerShell Constrained Language Mode ---
    ps_lang = cmd('powershell -NoProfile -Command "$ExecutionContext.SessionState.LanguageMode"')
    if ps_lang:
        add("Win11 Security", "PS-01", "PowerShell Language Mode",
            "PASS" if "constrained" in ps_lang.lower() else "INFO",
            f"LanguageMode: {ps_lang.strip()}", "ConstrainedLanguage (if WDAC enforced)")

    # --- PowerShell Script Block Logging ---
    sbl = reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging")
    if sbl is not None:
        add("Win11 Security", "18.9.100.1", "PowerShell Script Block Logging",
            "PASS" if sbl == 1 else "FAIL", f"EnableScriptBlockLogging = {sbl}",
            "1 (Enabled)", "GPO: PowerShell > Script Block Logging = Enabled")

    # --- PowerShell Transcription ---
    trans = reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting")
    if trans is not None:
        add("Win11 Security", "18.9.100.2", "PowerShell Transcription",
            "PASS" if trans == 1 else "WARN", f"EnableTranscripting = {trans}",
            "1 (Enabled)", "GPO: PowerShell > Turn on Transcription = Enabled")

    # --- PowerShell Execution Policy ---
    ep = cmd('powershell -NoProfile -Command "Get-ExecutionPolicy"')
    if ep:
        ok = ep.strip().lower() in ("restricted", "allsigned", "remotesigned")
        add("Win11 Security", "18.9.100.3", "PowerShell execution policy",
            "PASS" if ok else "FAIL", f"ExecutionPolicy: {ep.strip()}",
            "Restricted, AllSigned, or RemoteSigned")


# ============================================================
# DOMAIN 6: NETWORK SECURITY (CIS 18.x + hardening)
# ============================================================

def audit_network():
    print("\n[*] Domain 6: Network Security...")

    # --- SMBv1 ---
    smb1 = reg(HKLM, r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start")
    if smb1 is not None:
        add("Network", "18.3.3", "SMBv1 client disabled",
            "PASS" if smb1 == 4 else "FAIL", f"mrxsmb10 Start = {smb1} (4=Disabled)",
            "4 (Disabled)", "Disable-WindowsOptionalFeature -FeatureName SMB1Protocol")

    smb1s = reg(HKLM, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
    if smb1s is not None:
        add("Network", "18.3.3b", "SMBv1 server disabled",
            "PASS" if smb1s == 0 else "FAIL", f"SMB1 = {smb1s} (0=Off)", "0")

    # --- RDP NLA ---
    nla = reg(HKLM, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication")
    if nla is not None:
        add("Network", "18.9.65.3.9.2", "RDP Network Level Authentication",
            "PASS" if nla == 1 else "FAIL", f"NLA = {nla}", "1 (Required)")

    # --- RDP encryption ---
    rdp_enc = reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "MinEncryptionLevel")
    if rdp_enc is not None:
        desc = {1:"Low",2:"Client Compatible",3:"High",4:"FIPS"}.get(rdp_enc, str(rdp_enc))
        add("Network", "18.9.65.3.9.1", "RDP encryption level",
            "PASS" if rdp_enc >= 3 else "FAIL", f"Level = {rdp_enc} ({desc})", ">= 3 (High)")

    # --- WinRM ---
    winrm_basic = reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client", "AllowBasic")
    if winrm_basic is not None:
        add("Network", "18.9.102.1.1", "WinRM client: Allow Basic auth",
            "PASS" if winrm_basic == 0 else "FAIL",
            f"AllowBasic = {winrm_basic}", "0 (Disabled)")

    winrm_unenc = reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client", "AllowUnencryptedTraffic")
    if winrm_unenc is not None:
        add("Network", "18.9.102.1.2", "WinRM client: Allow unencrypted traffic",
            "PASS" if winrm_unenc == 0 else "FAIL",
            f"AllowUnencryptedTraffic = {winrm_unenc}", "0 (Disabled)")

    # --- NetBIOS over TCP/IP ---
    # Enumerate adapters and check NetbiosOptions
    adapters = reg_subkeys(HKLM, r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces")
    for adapter in adapters[:3]:  # Check first 3 to avoid noise
        nb = reg(HKLM, rf"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\{adapter}", "NetbiosOptions")
        if nb is not None:
            desc = {0:"Default (DHCP)",1:"Enabled",2:"Disabled"}.get(nb, str(nb))
            add("Network", "NET-NB", f"NetBIOS over TCP/IP ({adapter[:20]}...)",
                "PASS" if nb == 2 else "WARN", f"NetbiosOptions = {nb} ({desc})",
                "2 (Disabled)", "Adapter > IPv4 > Advanced > WINS > Disable NetBIOS")
            break  # Only report first for brevity

    # --- LLMNR ---
    llmnr = reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast")
    if llmnr is not None:
        add("Network", "18.5.4.1", "LLMNR disabled",
            "PASS" if llmnr == 0 else "FAIL", f"EnableMulticast = {llmnr}",
            "0 (Disabled)", "GPO: DNS Client > Turn off multicast name resolution")

    # --- mDNS ---
    mdns = reg(HKLM, r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "EnableMDNS")
    if mdns is not None:
        add("Network", "NET-MDNS", "mDNS disabled",
            "PASS" if mdns == 0 else "WARN", f"EnableMDNS = {mdns}",
            "0 (Disabled)", "Registry: Dnscache\\Parameters\\EnableMDNS = 0")

    # --- Listening ports ---
    out = cmd("netstat -ano -p TCP")
    risky = {21:"FTP",23:"Telnet",69:"TFTP",135:"RPC",445:"SMB",
             1433:"MSSQL",3389:"RDP",5985:"WinRM-HTTP",5986:"WinRM-HTTPS"}
    ports = set()
    for line in out.splitlines():
        if "LISTENING" in line:
            m = re.search(r":(\d+)\s", line)
            if m:
                ports.add(int(m.group(1)))

    add("Network", "NET-01", "Listening TCP ports", "INFO",
        f"{len(ports)} ports listening", "Minimise attack surface")
    for p in sorted(ports):
        if p in risky:
            add("Network", "NET-02", f"Risky port: {p} ({risky[p]})",
                "WARN", f"Port {p} ({risky[p]}) listening", "Disable if not required")


# ============================================================
# DOMAIN 7: TLS / SSL CONFIGURATION
# ============================================================

def audit_tls():
    print("\n[*] Domain 7: TLS/SSL Configuration...")
    base = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    for proto, cid in [("SSL 2.0","TLS-01"),("SSL 3.0","TLS-02"),("TLS 1.0","TLS-03"),("TLS 1.1","TLS-04")]:
        for side in ("Client", "Server"):
            en = reg(HKLM, rf"{base}\{proto}\{side}", "Enabled")
            dbd = reg(HKLM, rf"{base}\{proto}\{side}", "DisabledByDefault")
            if en is not None:
                add("TLS Config", cid, f"{proto} {side} disabled",
                    "PASS" if en == 0 else "FAIL",
                    f"Enabled={en}, DisabledByDefault={dbd}", "Enabled=0",
                    f"Registry: SCHANNEL\\Protocols\\{proto}\\{side}\\Enabled = 0")
            elif dbd is not None and dbd == 1:
                add("TLS Config", cid, f"{proto} {side} disabled",
                    "PASS", "DisabledByDefault=1", "Disabled")
            else:
                add("TLS Config", cid, f"{proto} {side} disabled",
                    "INFO", "No explicit config (OS default)", "Explicitly disable recommended")

    for proto in ("TLS 1.2", "TLS 1.3"):
        for side in ("Client", "Server"):
            en = reg(HKLM, rf"{base}\{proto}\{side}", "Enabled")
            dbd = reg(HKLM, rf"{base}\{proto}\{side}", "DisabledByDefault")
            if en is not None and en == 0:
                add("TLS Config", "TLS-05", f"{proto} {side} enabled",
                    "FAIL", "Explicitly disabled!", "Enabled or absent")
            elif dbd is not None and dbd == 1:
                add("TLS Config", "TLS-05", f"{proto} {side} enabled",
                    "FAIL", "DisabledByDefault=1", "DisabledByDefault=0")
            else:
                add("TLS Config", "TLS-05", f"{proto} {side} enabled",
                    "PASS", "Enabled (explicit or default)", "Enabled")


# ============================================================
# DOMAIN 8: CREDENTIAL PROTECTION
# ============================================================

def audit_credentials():
    print("\n[*] Domain 8: Credential Protection...")

    # WDigest
    wd = reg(HKLM, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential")
    if wd is not None:
        add("Credentials", "18.3.7", "WDigest disabled",
            "PASS" if wd == 0 else "FAIL", f"UseLogonCredential = {wd}",
            "0 (No plaintext creds in LSASS)", "Registry: WDigest\\UseLogonCredential = 0")
    else:
        add("Credentials", "18.3.7", "WDigest disabled",
            "PASS", "Key absent (disabled by default on Win11)", "Absent or 0")

    # Cached logons
    cl = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount")
    if cl is not None:
        try:
            n = int(cl)
            add("Credentials", "2.3.6.1", "Cached logon count",
                "PASS" if n <= 4 else "FAIL", f"CachedLogonsCount = {n}",
                "<= 4", "GPO: Interactive logon: cached logons = 4")
        except ValueError:
            pass

    # Auto-logon
    al = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon")
    ap = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword")
    auto = (al in ("1", 1))
    pw = (ap is not None and ap != "")
    if auto or pw:
        add("Credentials", "2.3.7.4", "Auto-logon disabled",
            "FAIL", f"AutoAdminLogon={al}, DefaultPassword={'PRESENT!' if pw else 'absent'}",
            "No auto-logon", "Remove DefaultPassword from Winlogon registry")
    else:
        add("Credentials", "2.3.7.4", "Auto-logon disabled",
            "PASS", "No auto-logon configured", "No auto-logon")

    # --- Credential files on disk ---
    home = os.path.expanduser("~")

    # PowerShell history
    ps_hist = os.path.join(home, "AppData", "Roaming", "Microsoft", "Windows",
                           "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
    if os.path.isfile(ps_hist):
        try:
            sz = os.path.getsize(ps_hist)
            with open(ps_hist, "r", errors="replace") as f:
                content = f.read()
            hits = len(re.findall(r"(?i)(password|secret|token|apikey|credential|connectionstring)", content))
            add("Credentials", "CRED-01", "PowerShell history",
                "FAIL" if hits > 0 else "INFO",
                f"Size: {sz//1024}KB, credential patterns: {hits}",
                "No credential patterns",
                "Remove-Item ConsoleHost_history.txt; Set-PSReadlineOption -HistorySaveStyle SaveNothing")
        except OSError:
            pass

    # SSH keys
    ssh_dir = os.path.join(home, ".ssh")
    if os.path.isdir(ssh_dir):
        for item in os.listdir(ssh_dir):
            if item.startswith("id_") and not item.endswith(".pub"):
                fpath = os.path.join(ssh_dir, item)
                try:
                    with open(fpath, "r", errors="replace") as f:
                        hdr = f.read(200)
                    enc = "ENCRYPTED" in hdr
                    add("Credentials", "CRED-02", f"SSH key: {item}",
                        "INFO" if enc else "FAIL",
                        f"Encrypted: {enc}", "Passphrase protected",
                        f"ssh-keygen -p -f {fpath}")
                except OSError:
                    pass

    # Git credentials
    if os.path.isfile(os.path.join(home, ".git-credentials")):
        add("Credentials", "CRED-03", "Git credentials file",
            "FAIL", "Plaintext .git-credentials found",
            "Use Git Credential Manager", "git config --global credential.helper manager")

    # Cloud creds
    for fpath, desc, cid in [
        (os.path.join(home, ".aws", "credentials"), "AWS creds", "CRED-04"),
        (os.path.join(home, ".azure", "accessTokens.json"), "Azure tokens", "CRED-05"),
    ]:
        if os.path.isfile(fpath):
            add("Credentials", cid, f"Cloud: {desc}", "INFO",
                f"Found: {fpath}", "Review rotation schedule")


# ============================================================
# DOMAIN 9: PERSISTENCE & STARTUP
# ============================================================

def audit_persistence():
    print("\n[*] Domain 9: Persistence & Startup...")

    # --- Run keys ---
    run_keys = [
        (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    ]
    total = 0
    suspect = 0
    for hive, path, label in run_keys:
        if not hive:
            continue
        for name, data, _ in reg_values(hive, path):
            total += 1
            d = str(data)
            issues = []
            if re.search(r"(?i)(\\Temp\\|\\Downloads\\|\\AppData\\Local\\Temp|\\Users\\Public)", d):
                issues.append("Writable location")
            if re.search(r"(?i)(powershell.*-enc|powershell.*-e\s|cmd.*/c.*powershell)", d):
                issues.append("Encoded PowerShell")
            if re.search(r"(?i)\.(ps1|bat|cmd|vbs|js|wsf|hta)", d):
                issues.append("Script execution")
            if issues:
                suspect += 1
                add("Persistence", "PERSIST-01", f"{label}: {name}", "FAIL",
                    f"{d[:120]} | {'; '.join(issues)}", "Legitimate apps from protected dirs")

    # --- Scheduled tasks ---
    out = cmd("schtasks /query /fo CSV /v")
    if out:
        task_count = 0
        task_suspect = 0
        for line in out.splitlines()[1:]:
            fields = [f.strip('"') for f in line.split('","')]
            if len(fields) < 9:
                continue
            tname = fields[0] if fields else ""
            action = fields[8] if len(fields) > 8 else ""
            runas = fields[-1] if fields else ""
            if tname.startswith("\\Microsoft\\"):
                continue
            task_count += 1
            issues = []
            if re.search(r"(?i)SYSTEM|Administrator", runas):
                issues.append(f"Runs as {runas}")
            if re.search(r"(?i)\.(ps1|bat|cmd|vbs|js)", action):
                issues.append("Script execution")
            if issues:
                task_suspect += 1
                add("Persistence", "PERSIST-02", f"Task: {tname[:60]}", "WARN",
                    f"Action: {action[:80]} | {'; '.join(issues)}",
                    "Least privilege, protected dirs")

        add("Persistence", "PERSIST-03", "Persistence summary", 
            "PASS" if (suspect + task_suspect) == 0 else "INFO",
            f"Run keys: {total} ({suspect} suspicious), Tasks: {task_count} custom ({task_suspect} flagged)",
            "No suspicious persistence")


# ============================================================
# DOMAIN 10: WINDOWS UPDATE & PATCHING
# ============================================================

def audit_patching():
    print("\n[*] Domain 10: Windows Update & Patching...")

    # AU config
    au = reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions")
    if au is not None:
        desc = {2:"Notify",3:"Auto download, notify",4:"Auto download and schedule",5:"Admin chooses"}.get(au, str(au))
        add("Patching", "18.9.101.2", "Auto-update configuration",
            "PASS" if au == 4 else "FAIL", f"AUOptions = {au} ({desc})",
            "4 (Auto download and schedule)")

    # Last patch date
    out = cmd("wmic qfe get InstalledOn /format:list")
    dates = []
    for line in out.splitlines():
        m = re.search(r"InstalledOn=(\d+/\d+/\d+)", line)
        if m:
            try:
                dates.append(datetime.datetime.strptime(m.group(1), "%m/%d/%Y"))
            except ValueError:
                pass
    if dates:
        latest = max(dates)
        days = (datetime.datetime.now() - latest).days
        add("Patching", "PATCH-01", "Last patch age",
            "PASS" if days <= 30 else ("WARN" if days <= 60 else "FAIL"),
            f"Last update: {latest.strftime('%Y-%m-%d')} ({days} days ago)",
            "<= 30 days", "Run Windows Update")


# ============================================================
# DOMAIN 11: MISC HARDENING
# ============================================================

def audit_misc():
    print("\n[*] Domain 11: Miscellaneous Hardening...")

    # AutoRun
    ar = reg(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun")
    if ar is not None:
        add("Misc", "18.9.8.3", "AutoRun disabled",
            "PASS" if ar == 255 else "FAIL", f"NoDriveTypeAutoRun = {ar}",
            "255 (All drives)", "GPO: AutoPlay > Turn off Autoplay = All drives")

    # Remote Assistance
    ra = reg(HKLM, r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fAllowToGetHelp")
    if ra is not None:
        add("Misc", "18.8.36.1", "Remote Assistance disabled",
            "PASS" if ra == 0 else "FAIL", f"fAllowToGetHelp = {ra}",
            "0 (Disabled)")

    # Screensaver
    ss_a = reg(HKCU, r"Control Panel\Desktop", "ScreenSaveActive")
    ss_s = reg(HKCU, r"Control Panel\Desktop", "ScreenSaverIsSecure")
    ss_t = reg(HKCU, r"Control Panel\Desktop", "ScreenSaveTimeOut")
    if ss_a is not None:
        active = ss_a == "1"
        secure = ss_s == "1"
        to = int(ss_t) if ss_t else 0
        ok = active and secure and 0 < to <= 900
        add("Misc", "LOCK-01", "Screensaver password lock",
            "PASS" if ok else "FAIL",
            f"Active={ss_a}, Secure={ss_s}, Timeout={to}s",
            "Active, password-protected, <= 900s")

    # Office macros
    for ver in ("16.0", "15.0"):
        for app in ("Word", "Excel", "PowerPoint", "Outlook"):
            vba = reg(HKCU, rf"SOFTWARE\Microsoft\Office\{ver}\{app}\Security", "VBAWarnings")
            if vba is not None:
                desc = {1:"Enable all (DANGEROUS)",2:"Disable w/ notification",3:"Signed only",4:"Disable all"}.get(vba, str(vba))
                add("Misc", "OFFICE-01", f"Office {ver} {app} macros",
                    "FAIL" if vba == 1 else ("PASS" if vba in (3,4) else "INFO"),
                    f"VBAWarnings = {vba} ({desc})", "3 (Signed only) or 4 (Disable all)")

    # Unquoted service paths
    out = cmd("wmic service get Name,PathName,StartName /format:csv")
    unquoted = 0
    if out:
        for line in out.splitlines():
            parts = line.split(",")
            if len(parts) < 3:
                continue
            sname, spath = parts[1].strip(), parts[2].strip()
            if not spath or spath.startswith('"'):
                continue
            m = re.match(r"^(.+?\.exe)", spath, re.I)
            if m:
                exe = m.group(1)
                if " " in exe and not exe.startswith('"'):
                    if re.search(r"(?i)svchost|\\system32\\", exe) and "Program Files" not in exe:
                        continue
                    unquoted += 1
                    if unquoted <= 5:  # Limit output
                        add("Misc", "UNQUOTE-01", f"Unquoted: {sname}",
                            "FAIL", f"Path: {spath[:100]}", "Quoted paths")

    if unquoted == 0:
        add("Misc", "UNQUOTE-01", "Unquoted service paths", "PASS",
            "No unquoted paths with spaces", "All paths quoted")
    elif unquoted > 5:
        add("Misc", "UNQUOTE-01", f"...and {unquoted-5} more unquoted paths",
            "FAIL", f"Total: {unquoted} unquoted service paths", "All paths quoted")

    # Environment variable credential leakage
    cred_pats = ["KEY","SECRET","TOKEN","PASSWORD","PASSWD","CREDENTIAL","APIKEY"]
    skip_vars = {"PATH","PATHEXT","PSMODULEPATH","PUBLIC","AUTHTYPE","KEYS"}
    for k, v in os.environ.items():
        if k.upper() in skip_vars:
            continue
        matched = [p for p in cred_pats if p in k.upper()]
        if matched and v and len(v) > 3:
            add("Misc", "ENV-01", f"Credential in env: {k}", "FAIL",
                f"Matches: {matched[0]} | Value: {v[:4]}****",
                "Not in env vars", "Move to secrets manager")

    # Writable PATH dirs
    writable_count = 0
    for d in os.environ.get("PATH", "").split(";"):
        d = d.strip()
        if not d or not os.path.isdir(d):
            continue
        # Simple write test: try to create a temp file
        test_file = os.path.join(d, f".audit_write_test_{os.getpid()}.tmp")
        try:
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
            writable_count += 1
            if writable_count <= 3:
                add("Misc", "PATH-01", f"Writable PATH dir: {d}", "FAIL",
                    f"Current user can write to PATH directory", "Not writable by standard users")
        except (OSError, PermissionError):
            pass
    if writable_count == 0:
        add("Misc", "PATH-01", "Writable PATH directories", "PASS",
            "No writable PATH dirs found", "No writable PATH dirs")


# ============================================================
# DOMAIN 12: SERVICES
# ============================================================

def audit_services():
    print("\n[*] Domain 12: Services...")
    risky = {
        "RemoteRegistry":"Remote Registry editing",
        "TlntSvr":"Telnet Server",
        "SNMP":"SNMP Service",
        "FTPSVC":"FTP Server",
        "W3SVC":"IIS Web Server",
        "SSDPSRV":"SSDP Discovery (UPnP)",
        "upnphost":"UPnP Device Host",
        "WMSvc":"Web Management Service",
        "WMPNetworkSvc":"WMP Network Sharing",
        "XblGameSave":"Xbox Game Save",
        "XblAuthManager":"Xbox Auth",
    }
    out = cmd("sc query type= service state= all")
    running = set()
    cur = ""
    for line in out.splitlines():
        if "SERVICE_NAME:" in line:
            cur = line.split(":", 1)[1].strip()
        if "RUNNING" in line and cur:
            running.add(cur.lower())
    for svc, desc in risky.items():
        if svc.lower() in running:
            add("Services", "SVC-01", f"Risky service: {svc}",
                "FAIL", f"{desc} - RUNNING", "Disabled",
                f"sc config {svc} start=disabled (requires admin)")


# ============================================================
# DOMAIN 13: INSTALLED SOFTWARE
# ============================================================

def audit_software():
    print("\n[*] Domain 13: Software Audit...")

    apps = []
    for base in [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                 r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]:
        for sk in reg_subkeys(HKLM, base):
            name = reg(HKLM, rf"{base}\{sk}", "DisplayName")
            ver = reg(HKLM, rf"{base}\{sk}", "DisplayVersion")
            if name:
                apps.append((name, ver or ""))

    eol = [
        (r"Adobe Flash Player", "EOL since 2020"),
        (r"Microsoft Silverlight", "EOL"),
        (r"Java [678]\.", "Legacy Java"),
        (r"Python 2\.", "EOL since 2020"),
        (r"WinRAR [0-4]\.", "Older WinRAR with known CVEs"),
        (r"7-Zip\s+1[0-8]\.", "Older 7-Zip with known CVEs"),
    ]
    remote = ["TeamViewer","AnyDesk","LogMeIn","VNC","RealVNC","ConnectWise","Splashtop","Parsec"]

    for name, ver in apps:
        for pat, reason in eol:
            if re.search(pat, name, re.I):
                add("Software", "SW-01", f"EOL: {name}", "FAIL",
                    f"{name} {ver} - {reason}", "Remove or update")
        for tool in remote:
            if tool.lower() in name.lower():
                add("Software", "SW-02", f"Remote access: {name}", "INFO",
                    f"{name} {ver}", "Authorised tools only")


# ============================================================
# HTML REPORT
# ============================================================

def gen_html(path):
    print("\n[*] Generating HTML report...")
    total = len(results)
    pass_rate = round((counts["PASS"] / total) * 100, 1) if total else 0

    doms = {}
    for r in results:
        doms.setdefault(r["domain"], []).append(r)

    h = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Win11 Hardening Audit - {html_mod.escape(sysinfo.get('hostname',''))}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f8f9fa;color:#1a1a1a;line-height:1.6}}
.w{{max-width:1100px;margin:0 auto;padding:20px}}
.hdr{{background:linear-gradient(135deg,#0c2461,#1e3799);color:#fff;padding:32px;border-radius:10px;margin-bottom:24px}}
.hdr h1{{font-size:22px;margin-bottom:6px}}.hdr p{{opacity:.85;font-size:13px}}
.dis{{background:#fff3cd;padding:14px 18px;border-radius:8px;margin-bottom:20px;border-left:4px solid #ffc107;font-size:13px;color:#664d03}}
.sum{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:24px}}
.sc{{background:#fff;padding:16px;border-radius:8px;text-align:center;border:1px solid #e9ecef}}
.sc .n{{font-size:28px;font-weight:600}}.sc .l{{font-size:11px;text-transform:uppercase;color:#6c757d;margin-top:2px;letter-spacing:.5px}}
.p .n{{color:#198754}}.f .n{{color:#dc3545}}.wa .n{{color:#fd7e14}}.i .n{{color:#0dcaf0}}.s .n{{color:#6c757d}}.r .n{{color:#0d6efd}}
.si{{background:#fff;padding:18px;border-radius:8px;margin-bottom:20px;border:1px solid #e9ecef}}
.si h2{{font-size:16px;margin-bottom:10px;color:#0c2461}}.si table{{width:100%;border-collapse:collapse}}
.si td{{padding:5px 10px;border-bottom:1px solid #f1f3f5;font-size:13px}}.si td:first-child{{font-weight:600;width:170px;color:#495057}}
.dm{{background:#fff;border-radius:8px;margin-bottom:14px;border:1px solid #e9ecef;overflow:hidden}}
.dh{{padding:14px 18px;cursor:pointer;display:flex;justify-content:space-between;align-items:center}}
.dh:hover{{background:#f8f9fa}}.dh h3{{font-size:14px;font-weight:600;color:#0c2461}}
.dh span{{font-size:12px;color:#6c757d}}
table.t{{width:100%;border-collapse:collapse;font-size:12px}}
table.t th{{background:#f8f9fa;padding:8px 10px;text-align:left;font-weight:600;color:#495057;border-bottom:2px solid #dee2e6}}
table.t td{{padding:8px 10px;border-bottom:1px solid #f1f3f5;vertical-align:top}}
table.t tr:hover{{background:#f8f9fa}}
.b{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600;color:#fff;letter-spacing:.3px}}
.b-p{{background:#198754}}.b-f{{background:#dc3545}}.b-w{{background:#fd7e14}}.b-i{{background:#0dcaf0;color:#000}}.b-s{{background:#6c757d}}.b-e{{background:#6f42c1}}
.rx{{background:#fff3cd;padding:6px 10px;border-radius:4px;font-size:11px;margin-top:4px;border-left:3px solid #ffc107;color:#664d03}}
.ft{{text-align:center;padding:16px;color:#adb5bd;font-size:11px}}
</style></head><body>
<div class="w">
<div class="hdr"><h1>Windows 11 Enterprise Hardening Audit</h1>
<p>Host: {html_mod.escape(sysinfo.get('hostname',''))} | Build: {html_mod.escape(sysinfo.get('build',''))} ({html_mod.escape(sysinfo.get('display_version',''))}) | {html_mod.escape(sysinfo.get('edition',''))}</p>
<p>User: {html_mod.escape(sysinfo.get('current_user',''))} | Privilege: {'Administrator' if sysinfo.get('is_admin') else 'Standard User'} | {html_mod.escape(sysinfo.get('audit_date',''))}</p></div>
<div class="dis"><strong>Note:</strong> This audit was executed with standard user (non-admin) privileges targeting Windows 11 Enterprise Build 26200 (24H2). Some checks may be marked SKIP where elevation is required.</div>
<div class="sum">
<div class="sc r"><div class="n">{pass_rate}%</div><div class="l">Pass Rate</div></div>
<div class="sc p"><div class="n">{counts['PASS']}</div><div class="l">Passed</div></div>
<div class="sc f"><div class="n">{counts['FAIL']}</div><div class="l">Failed</div></div>
<div class="sc wa"><div class="n">{counts['WARN']}</div><div class="l">Warnings</div></div>
<div class="sc i"><div class="n">{counts['INFO']}</div><div class="l">Info</div></div>
<div class="sc s"><div class="n">{counts['SKIP']}</div><div class="l">Skipped</div></div>
</div>
<div class="si"><h2>System Information</h2><table>"""
    for k, v in sysinfo.items():
        h += f"<tr><td>{html_mod.escape(str(k))}</td><td>{html_mod.escape(str(v))}</td></tr>"
    h += "</table></div>"

    for dname, dres in doms.items():
        dp = sum(1 for r in dres if r["status"]=="PASS")
        df = sum(1 for r in dres if r["status"]=="FAIL")
        dw = sum(1 for r in dres if r["status"]=="WARN")
        h += f"""<div class="dm"><div class="dh" onclick="var b=this.nextElementSibling;b.style.display=b.style.display==='none'?'block':'none'">
<h3>{html_mod.escape(dname)}</h3><span>{len(dres)} checks: {dp}P {df}F {dw}W</span></div>
<div><table class="t"><tr><th style="width:50px">Status</th><th style="width:70px">ID</th><th style="width:200px">Check</th><th>Finding</th><th style="width:170px">Expected</th></tr>"""
        for r in dres:
            bc = {"PASS":"b-p","FAIL":"b-f","WARN":"b-w","INFO":"b-i","SKIP":"b-s","ERROR":"b-e"}.get(r["status"],"b-i")
            rx = ""
            if r["status"] == "FAIL" and r["remediation"]:
                rx = f'<div class="rx">{html_mod.escape(r["remediation"])}</div>'
            h += f"""<tr><td><span class="b {bc}">{r['status']}</span></td><td>{html_mod.escape(r['id'])}</td>
<td>{html_mod.escape(r['check'])}</td><td>{html_mod.escape(r['finding'])}{rx}</td>
<td>{html_mod.escape(r['expected'])}</td></tr>"""
        h += "</table></div></div>"

    h += f'<div class="ft">win11_hardening_audit.py | {html_mod.escape(sysinfo.get("audit_date",""))}</div></div></body></html>'

    with open(path, "w", encoding="utf-8") as f:
        f.write(h)
    print(f"  HTML report: {path}")


def gen_json(path):
    out = {"system_info": sysinfo, "summary": counts, "results": results}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, default=str)
    print(f"  JSON report: {path}")


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Windows 11 Enterprise Hardening Auditor (stdlib, no admin)")
    parser.add_argument("--output", "-o", default="Win11_Hardening_Report.html", help="HTML report path")
    parser.add_argument("--json", "-j", action="store_true", help="Also export JSON")
    parser.add_argument("--json-path", default="Win11_Hardening_Results.json")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("ERROR: This script must run on Windows.")
        sys.exit(1)

    print("=" * 62)
    print("  Windows 11 Enterprise Hardening Auditor")
    print("  Target: Build 26200 (24H2) | Privilege: Standard User")
    print("  AUTHORISED USE ONLY")
    print("=" * 62)

    t0 = time.time()
    collect_sysinfo()

    audit_account_policy()      # 1
    audit_security_options()    # 2
    audit_firewall()            # 3
    audit_audit_policy()        # 4
    audit_win11_features()      # 5
    audit_network()             # 6
    audit_tls()                 # 7
    audit_credentials()         # 8
    audit_persistence()         # 9
    audit_patching()            # 10
    audit_misc()                # 11
    audit_services()            # 12
    audit_software()            # 13

    gen_html(args.output)
    if args.json:
        gen_json(args.json_path)

    elapsed = time.time() - t0
    total = len(results)
    pr = round((counts["PASS"]/total)*100, 1) if total else 0

    print(f"\n{'='*62}")
    print(f"  AUDIT COMPLETE - {sysinfo.get('hostname','')}")
    print(f"{'='*62}")
    print(f"  Total   : {total}")
    print(f"  \033[92mPassed  : {counts['PASS']}\033[0m")
    print(f"  \033[91mFailed  : {counts['FAIL']}\033[0m")
    print(f"  \033[93mWarnings: {counts['WARN']}\033[0m")
    print(f"  \033[96mInfo    : {counts['INFO']}\033[0m")
    print(f"  \033[90mSkipped : {counts['SKIP']}\033[0m")
    print(f"  Rate    : {pr}%")
    print(f"  Time    : {elapsed:.1f}s")
    print(f"  Report  : {args.output}")
    if args.json:
        print(f"  JSON    : {args.json_path}")
    print(f"{'='*62}\n")


if __name__ == "__main__":
    main()
