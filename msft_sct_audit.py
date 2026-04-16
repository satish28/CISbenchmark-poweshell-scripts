#!/usr/bin/env python3
"""
msft_sct_audit.py - Microsoft Security Compliance Toolkit Baseline Auditor
Author : SS
Purpose: Audit a Windows 11 Enterprise PC against the Microsoft Security
         Compliance Toolkit (SCT) recommended baseline settings for Windows 11
         24H2/25H2. Checks registry values, audit policy, account policy,
         and security options that the SCT GPO backup would configure.
Usage  : python msft_sct_audit.py
         python msft_sct_audit.py -o C:/Audits/sct_report.html --json

Target : Windows 11 Enterprise 24H2+ (Build 26100/26200+)
Source : Microsoft Security Compliance Toolkit 1.0 - Windows 11 v24H2/v25H2
         Security Baseline package (MS-Security-Baseline-Windows-11-v24H2)
Priv   : Standard user (no elevation required)
Deps   : Python 3.6+ stdlib only

AUTHORISED USE ONLY. Run this tool only against systems you own or have
explicit written authorisation to audit.
"""

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
# GLOBALS
# ============================================================

results = []
counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0, "SKIP": 0}
sysinfo = {}

HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else None
HKCU = winreg.HKEY_CURRENT_USER if winreg else None

# ============================================================
# HELPERS
# ============================================================

def add(domain, ref, check, status, finding, expected="", fix=""):
    results.append({"domain": domain, "ref": ref, "check": check,
                     "status": status, "finding": finding,
                     "expected": expected, "remediation": fix})
    counts[status] = counts.get(status, 0) + 1
    c = {"PASS":"\033[92m","FAIL":"\033[91m","WARN":"\033[93m",
         "INFO":"\033[96m","SKIP":"\033[90m"}.get(status, "")
    print(f"  {c}[{status:>4}]\033[0m {ref} {check}")


def cmd(command, timeout=30):
    try:
        r = subprocess.run(command, capture_output=True, text=True,
                           shell=True, timeout=timeout, errors="replace")
        return r.stdout.strip()
    except Exception:
        return ""


def reg(hive, path, name):
    if not winreg:
        return None
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as k:
            v, _ = winreg.QueryValueEx(k, name)
            return v
    except (OSError, FileNotFoundError, PermissionError):
        return None


def reg_values(hive, path):
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


def check_reg(domain, ref, check, hive, path, name, pass_fn, expected, fix=""):
    """
    Core registry check function used by all baseline controls.
    Reads a registry value and evaluates it against the SCT baseline.

    Args:
        domain:   Baseline category (e.g., "Security Options")
        ref:      SCT reference ID
        check:    Description of the control
        hive:     Registry hive (HKLM or HKCU)
        path:     Registry key path
        name:     Value name
        pass_fn:  Lambda(value) -> bool that returns True if compliant
        expected: String describing the expected (compliant) value
        fix:      Remediation guidance
    """
    v = reg(hive, path, name)
    if v is not None:
        ok = False
        try:
            ok = pass_fn(v)
        except Exception:
            pass
        add(domain, ref, check, "PASS" if ok else "FAIL",
            f"{name} = {v}", expected, fix)
    else:
        add(domain, ref, check, "INFO",
            f"{name}: Not configured (key absent)", expected, fix)


# ============================================================
# SYSTEM INFO
# ============================================================

def collect_sysinfo():
    global sysinfo
    print("\n[*] Collecting system information...")

    is_admin = False
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        pass

    build = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber") or ""
    ubr = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR") or ""
    dv = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion") or ""
    ed = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID") or ""
    pn = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName") or platform.platform()

    sysinfo = {
        "hostname": os.environ.get("COMPUTERNAME", platform.node()),
        "product": pn, "edition": ed, "display_version": dv,
        "build": f"{build}.{ubr}" if ubr else build,
        "architecture": platform.machine(),
        "domain": os.environ.get("USERDOMAIN", ""),
        "user": f"{os.environ.get('USERDOMAIN','')}\\{os.environ.get('USERNAME','')}",
        "is_admin": is_admin,
        "baseline": "Microsoft SCT - Windows 11 v24H2/v25H2 Security Baseline",
        "audit_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "python": platform.python_version(),
    }
    for k, v in sysinfo.items():
        print(f"  {k:>18}: {v}")


# ============================================================
# 1. ACCOUNT POLICY (Password Policy + Account Lockout)
# SCT baseline: GptTmpl.inf [System Access] section
# ============================================================

def audit_account_policy():
    """
    Maps to the SCT security template [System Access] settings.
    These are the password and lockout policies that the baseline
    GPO configures via the security template (.inf file).
    """
    print("\n[*] SCT Baseline: Account Policy (Password + Lockout)...")
    out = cmd("net accounts")
    if not out:
        add("Account Policy", "AcctPol", "net accounts query", "SKIP",
            "Could not query", "N/A")
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

    # SCT: PasswordHistorySize = 24
    v = extract("password history")
    if v is not None:
        add("Account Policy", "PwdHist", "Enforce password history",
            "PASS" if v >= 24 else "FAIL", f"{v} passwords", "24",
            "GPO: Password Policy > Enforce password history = 24")

    # SCT: MaximumPasswordAge = 365
    v = extract("maximum password age")
    if v is not None:
        add("Account Policy", "MaxPwdAge", "Maximum password age",
            "PASS" if 0 < v <= 365 else "FAIL", f"{v} days", "<= 365, > 0",
            "GPO: Password Policy > Maximum password age = 365")

    # SCT: MinimumPasswordAge = 1
    v = extract("minimum password age")
    if v is not None:
        add("Account Policy", "MinPwdAge", "Minimum password age",
            "PASS" if v >= 1 else "FAIL", f"{v} day(s)", ">= 1",
            "GPO: Password Policy > Minimum password age = 1")

    # SCT: MinimumPasswordLength = 14
    v = extract("minimum password length")
    if v is not None:
        add("Account Policy", "MinPwdLen", "Minimum password length",
            "PASS" if v >= 14 else "FAIL", f"{v} chars", ">= 14",
            "GPO: Password Policy > Minimum password length = 14")

    # SCT: LockoutBadCount = 5
    v = extract("lockout threshold")
    if v is not None:
        add("Account Policy", "LockThresh", "Account lockout threshold",
            "PASS" if 1 <= v <= 5 else "FAIL",
            f"{v} attempts" if v else "Never", "1-5 (SCT: 5)",
            "GPO: Account Lockout > Threshold = 5")

    # SCT: LockoutDuration = 15
    v = extract("lockout duration")
    if v is not None:
        add("Account Policy", "LockDur", "Account lockout duration",
            "PASS" if v >= 15 else "FAIL", f"{v} min", ">= 15",
            "GPO: Account Lockout > Duration = 15")

    # SCT: ResetLockoutCount = 15
    v = extract("lockout observation")
    if v is not None:
        add("Account Policy", "LockReset", "Lockout counter reset",
            "PASS" if v >= 15 else "FAIL", f"{v} min", ">= 15",
            "GPO: Account Lockout > Reset counter = 15")


# ============================================================
# 2. SECURITY OPTIONS
# SCT baseline: Registry.pol + GptTmpl.inf [Registry Values]
# These map to HKLM\SOFTWARE\...\Policies\System and related
# ============================================================

def audit_security_options():
    """
    Maps to the SCT GPO 'MSFT Windows 11 - Computer' registry values.
    Each check_reg call corresponds to a specific registry.pol entry
    from the SCT baseline GPO backup.
    """
    print("\n[*] SCT Baseline: Security Options...")

    SYS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
    LMWS = r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    LMSV = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

    # --- UAC Settings ---
    # SCT: EnableLUA = 1 (Admin Approval Mode)
    check_reg("Security Options", "UAC-01", "UAC: Admin Approval Mode enabled",
              HKLM, SYS, "EnableLUA", lambda v: v == 1, "1 (Enabled)",
              "GPO: Security Options > Run all admins in Admin Approval Mode")

    # SCT 24H2 NEW: FilterAdministratorToken = 1
    check_reg("Security Options", "UAC-02", "UAC: Filter administrator token",
              HKLM, SYS, "FilterAdministratorToken", lambda v: v == 1, "1 (Enabled)",
              "GPO: Security Options > Admin Approval Mode for built-in Admin")

    # SCT: ConsentPromptBehaviorAdmin = 2 (Prompt consent on secure desktop)
    check_reg("Security Options", "UAC-03", "UAC: Admin prompt behaviour",
              HKLM, SYS, "ConsentPromptBehaviorAdmin", lambda v: v == 2,
              "2 (Prompt consent on secure desktop)",
              "GPO: Security Options > Elevation prompt for administrators")

    # SCT: ConsentPromptBehaviorUser = 0 (Auto deny)
    check_reg("Security Options", "UAC-04", "UAC: Standard user prompt behaviour",
              HKLM, SYS, "ConsentPromptBehaviorUser", lambda v: v == 0,
              "0 (Automatically deny)",
              "GPO: Security Options > Elevation prompt for standard users")

    # SCT: EnableInstallerDetection = 1
    check_reg("Security Options", "UAC-05", "UAC: Detect application installations",
              HKLM, SYS, "EnableInstallerDetection", lambda v: v == 1, "1",
              "GPO: Security Options > Detect app installations")

    # SCT: PromptOnSecureDesktop = 1
    check_reg("Security Options", "UAC-06", "UAC: Switch to secure desktop",
              HKLM, SYS, "PromptOnSecureDesktop", lambda v: v == 1, "1",
              "GPO: Security Options > Switch to secure desktop when prompting")

    # SCT: EnableVirtualization = 1
    check_reg("Security Options", "UAC-07", "UAC: Virtualise file/registry writes",
              HKLM, SYS, "EnableVirtualization", lambda v: v == 1, "1",
              "GPO: Security Options > Virtualise file and registry write failures")

    # SCT 24H2 NEW: Enhanced Privilege Protection Mode
    # TypeOfAdminApprovalMode = 2 (Admin Approval Mode with enhanced privilege protection)
    check_reg("Security Options", "UAC-08", "UAC: Enhanced Privilege Protection Mode",
              HKLM, SYS, "TypeOfAdminApprovalMode", lambda v: v == 2,
              "2 (Enhanced privilege protection) [24H2 NEW]",
              "GPO: Security Options > Configure type of Admin Approval Mode")

    # --- LAN Manager / NTLM ---
    # SCT: LmCompatibilityLevel = 5
    check_reg("Security Options", "LM-01", "LAN Manager authentication level",
              HKLM, LSA, "LmCompatibilityLevel", lambda v: v >= 5,
              "5 (NTLMv2 only, refuse LM & NTLM)",
              "GPO: Security Options > Network security: LAN Manager auth level")

    # SCT: NoLMHash = 1
    check_reg("Security Options", "LM-02", "Do not store LAN Manager hash",
              HKLM, LSA, "NoLMHash", lambda v: v == 1, "1",
              "GPO: Security Options > Do not store LAN Manager hash value")

    # SCT: RestrictAnonymousSAM = 1
    check_reg("Security Options", "ANON-01", "Restrict anonymous SAM enum",
              HKLM, LSA, "RestrictAnonymousSAM", lambda v: v == 1, "1",
              "GPO: Security Options > Do not allow anonymous enum of SAM accounts")

    # SCT: RestrictAnonymous = 1
    check_reg("Security Options", "ANON-02", "Restrict anonymous SAM + shares",
              HKLM, LSA, "RestrictAnonymous", lambda v: v == 1, "1",
              "GPO: Security Options > Do not allow anonymous enum of SAM accounts and shares")

    # SCT: EveryoneIncludesAnonymous = 0
    check_reg("Security Options", "ANON-03", "Everyone does not include anonymous",
              HKLM, LSA, "EveryoneIncludesAnonymous", lambda v: v == 0, "0",
              "GPO: Security Options > Let Everyone apply to anonymous users = Disabled")

    # SCT: ForceGuest = 0 (Classic security model)
    check_reg("Security Options", "NET-01", "Network access: Sharing security model",
              HKLM, LSA, "ForceGuest", lambda v: v == 0,
              "0 (Classic - users authenticate as themselves)",
              "GPO: Security Options > Network access: Sharing and security model")

    # --- SMB Signing ---
    # SCT: RequireSecuritySignature = 1 (Client)
    check_reg("Security Options", "SMB-01", "SMB client: Signing required",
              HKLM, LMWS, "RequireSecuritySignature", lambda v: v == 1, "1",
              "GPO: Security Options > Microsoft network client: Digitally sign (always)")

    # SCT: EnableSecuritySignature = 1 (Client)
    check_reg("Security Options", "SMB-02", "SMB client: Signing enabled",
              HKLM, LMWS, "EnableSecuritySignature", lambda v: v == 1, "1",
              "GPO: Security Options > Microsoft network client: Digitally sign (if server agrees)")

    # SCT: RequireSecuritySignature = 1 (Server)
    check_reg("Security Options", "SMB-03", "SMB server: Signing required",
              HKLM, LMSV, "RequireSecuritySignature", lambda v: v == 1, "1",
              "GPO: Security Options > Microsoft network server: Digitally sign (always)")

    # SCT: EnableSecuritySignature = 1 (Server)
    check_reg("Security Options", "SMB-04", "SMB server: Signing enabled",
              HKLM, LMSV, "EnableSecuritySignature", lambda v: v == 1, "1",
              "GPO: Security Options > Microsoft network server: Digitally sign (if client agrees)")

    # --- Interactive Logon ---
    # SCT: DontDisplayLastUserName = 1
    check_reg("Security Options", "LOGON-01", "Do not display last signed-in user",
              HKLM, SYS, "DontDisplayLastUserName", lambda v: v == 1, "1",
              "GPO: Security Options > Interactive logon: Do not display last user name")

    # SCT: InactivityTimeoutSecs = 900
    check_reg("Security Options", "LOGON-02", "Machine inactivity limit",
              HKLM, SYS, "InactivityTimeoutSecs", lambda v: 0 < v <= 900,
              "<= 900 (15 min)",
              "GPO: Security Options > Interactive logon: Machine inactivity limit")

    # --- LDAP ---
    # SCT: LDAPClientIntegrity = 1
    check_reg("Security Options", "LDAP-01", "LDAP client signing requirements",
              HKLM, LSA, "LDAPClientIntegrity", lambda v: v >= 1,
              ">= 1 (Negotiate signing)",
              "GPO: Security Options > Network security: LDAP client signing")

    # --- Network security ---
    # SCT: NTLMMinClientSec = 537395200 (Require NTLMv2 + 128-bit)
    check_reg("Security Options", "NTLM-01", "NTLM minimum client session security",
              HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NTLMMinClientSec",
              lambda v: v == 537395200, "537395200 (NTLMv2 + 128-bit encryption)",
              "GPO: Security Options > NTLM: Minimum session security for clients")

    # SCT: NTLMMinServerSec = 537395200
    check_reg("Security Options", "NTLM-02", "NTLM minimum server session security",
              HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NTLMMinServerSec",
              lambda v: v == 537395200, "537395200 (NTLMv2 + 128-bit encryption)",
              "GPO: Security Options > NTLM: Minimum session security for servers")


# ============================================================
# 3. MS SECURITY GUIDE (Custom ADMX settings from SCT)
# ============================================================

def audit_ms_security_guide():
    """
    The SCT ships a custom ADMX 'MSSecurityGuide.admx' with settings
    not available in the default Windows templates. These write to
    specific registry paths.
    """
    print("\n[*] SCT Baseline: MS Security Guide (Custom ADMX)...")

    # SCT: SMB v1 client driver = 4 (Disabled)
    check_reg("MS Security Guide", "MSSG-01", "SMBv1 client driver disabled",
              HKLM, r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start",
              lambda v: v == 4, "4 (Disabled)",
              "GPO: MS Security Guide > Configure SMB v1 client driver = Disable driver")

    # SCT: SMBv1 server = 0 (Disabled)
    check_reg("MS Security Guide", "MSSG-02", "SMBv1 server disabled",
              HKLM, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1",
              lambda v: v == 0, "0 (Disabled)",
              "GPO: MS Security Guide > Configure SMB v1 server = Disabled")

    # SCT: Structured Exception Handling Overwrite Protection (SEHOP) = 1
    check_reg("MS Security Guide", "MSSG-03", "SEHOP enabled",
              HKLM, r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
              "DisableExceptionChainValidation", lambda v: v == 0,
              "0 (SEHOP enabled - validation NOT disabled)",
              "GPO: MS Security Guide > Enable SEHOP")

    # SCT: WDigest UseLogonCredential = 0
    # Note: 25H2 baseline removes this as deprecated, but 24H2 still includes it
    check_reg("MS Security Guide", "MSSG-04", "WDigest plaintext credentials disabled",
              HKLM, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
              "UseLogonCredential", lambda v: v == 0,
              "0 (No plaintext creds in LSASS memory)",
              "Registry: WDigest\\UseLogonCredential = 0")

    # SCT: Apply UAC restrictions to local accounts on network logons = 1
    check_reg("MS Security Guide", "MSSG-05", "UAC restrictions on local network logons",
              HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
              "LocalAccountTokenFilterPolicy", lambda v: v == 0,
              "0 (UAC restrictions apply to local accounts)",
              "GPO: MS Security Guide > Apply UAC restrictions to local accounts")

    # SCT: NetBT NodeType = 2 (P-node - only point-to-point, no broadcast)
    check_reg("MS Security Guide", "MSSG-06", "NetBIOS node type (P-node)",
              HKLM, r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "NodeType",
              lambda v: v == 2, "2 (P-node - no broadcast)",
              "GPO: MS Security Guide > Configure NetBIOS node type")


# ============================================================
# 4. MSS (LEGACY) SETTINGS
# ============================================================

def audit_mss_legacy():
    """
    MSS (Legacy) settings from the custom ADMX included in the SCT.
    These are older settings from the Microsoft Solutions for Security
    guides that are still recommended.
    """
    print("\n[*] SCT Baseline: MSS (Legacy) Settings...")

    TCP = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

    # SCT: DisableIPSourceRouting = 2 (Highest protection)
    check_reg("MSS Legacy", "MSS-01", "IP source routing protection",
              HKLM, TCP, "DisableIPSourceRouting", lambda v: v == 2,
              "2 (Highest protection - drop all)",
              "GPO: MSS (Legacy) > IP source routing protection level")

    # SCT: DisableIPSourceRoutingIPv6 = 2
    check_reg("MSS Legacy", "MSS-02", "IPv6 source routing protection",
              HKLM, r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
              "DisableIPSourceRouting", lambda v: v == 2,
              "2 (Highest protection)",
              "GPO: MSS (Legacy) > IPv6 source routing protection")

    # SCT: EnableICMPRedirect = 0
    check_reg("MSS Legacy", "MSS-03", "ICMP redirects disabled",
              HKLM, TCP, "EnableICMPRedirect", lambda v: v == 0,
              "0 (Disabled)", "GPO: MSS (Legacy) > Allow ICMP redirects = Disabled")

    # SCT: NoNameReleaseOnDemand = 1
    check_reg("MSS Legacy", "MSS-04", "NetBIOS name release on demand disabled",
              HKLM, r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
              "NoNameReleaseOnDemand", lambda v: v == 1, "1",
              "GPO: MSS (Legacy) > Allow the computer to ignore NetBIOS name release requests")


# ============================================================
# 5. WINDOWS DEFENDER ANTIVIRUS
# SCT baseline: Administrative Templates\Windows Defender
# ============================================================

def audit_defender():
    """
    Maps to the SCT GPO Windows Defender Antivirus settings.
    The 24H2 baseline adds new settings for scan scheduling on VDI
    and updated cloud protection levels.
    """
    print("\n[*] SCT Baseline: Windows Defender Antivirus...")

    DEF = r"SOFTWARE\Policies\Microsoft\Windows Defender"

    # SCT: DisableAntiSpyware = 0
    check_reg("Defender", "DEF-01", "Defender not disabled by policy",
              HKLM, DEF, "DisableAntiSpyware", lambda v: v == 0,
              "0 (Defender active)", "GPO: Defender > Turn off Microsoft Defender = Disabled")

    # SCT: PUAProtection = 1
    check_reg("Defender", "DEF-02", "PUA (Potentially Unwanted App) protection",
              HKLM, DEF, "PUAProtection", lambda v: v == 1,
              "1 (PUA protection enabled)",
              "GPO: Defender > Configure detection for PUA = Enabled")

    # Real-Time Protection
    RTP = rf"{DEF}\Real-Time Protection"
    check_reg("Defender", "DEF-03", "Real-time protection enabled",
              HKLM, RTP, "DisableRealtimeMonitoring", lambda v: v == 0,
              "0 (Real-time ON)", "GPO: Defender > Real-Time Protection > Turn off = Disabled")

    check_reg("Defender", "DEF-04", "Behaviour monitoring enabled",
              HKLM, RTP, "DisableBehaviorMonitoring", lambda v: v == 0,
              "0 (Behaviour monitoring ON)",
              "GPO: Defender > Real-Time Protection > Turn off behavior monitoring = Disabled")

    check_reg("Defender", "DEF-05", "Scan all downloaded files and attachments",
              HKLM, RTP, "DisableIOAVProtection", lambda v: v == 0,
              "0 (IOAV ON)", "GPO: Defender > Real-Time Protection > Scan downloads = Not disabled")

    check_reg("Defender", "DEF-06", "Script scanning enabled",
              HKLM, RTP, "DisableScriptScanning", lambda v: v == 0,
              "0 (Script scanning ON)",
              "GPO: Defender > Real-Time Protection > Turn off script scanning = Disabled")

    # Cloud-delivered protection (MAPS)
    MAPS = rf"{DEF}\Spynet"
    check_reg("Defender", "DEF-07", "Cloud-delivered protection (MAPS)",
              HKLM, MAPS, "SpynetReporting", lambda v: v >= 2,
              "2 (Advanced MAPS membership)",
              "GPO: Defender > MAPS > Join Microsoft MAPS = Advanced")

    check_reg("Defender", "DEF-08", "Send file samples for analysis",
              HKLM, MAPS, "SubmitSamplesConsent", lambda v: v == 1,
              "1 (Send safe samples automatically)",
              "GPO: Defender > MAPS > Send file samples = Send safe samples")

    # SCT: Cloud block level = 2 (High)
    check_reg("Defender", "DEF-09", "Cloud protection level",
              HKLM, rf"{DEF}\MpEngine", "MpCloudBlockLevel", lambda v: v >= 2,
              ">= 2 (High)",
              "GPO: Defender > MpEngine > Cloud protection level = High")

    # SCT: Extended cloud check timeout = 50 seconds
    check_reg("Defender", "DEF-10", "Extended cloud check timeout",
              HKLM, rf"{DEF}\MpEngine", "MpBafsExtendedTimeout", lambda v: v >= 50,
              ">= 50 seconds",
              "GPO: Defender > MpEngine > Extended cloud check = 50")

    # Tamper Protection (informational - not GPO-managed)
    tp = reg(HKLM, r"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection")
    if tp is not None:
        add("Defender", "DEF-11", "Tamper Protection",
            "PASS" if tp == 5 else "WARN",
            f"TamperProtection = {tp} (5=On)", "5 (On)",
            "Settings > Windows Security > Tamper Protection = On")

    # --- Attack Surface Reduction (ASR) Rules ---
    # SCT 24H2 baseline: multiple ASR rules in Block mode
    # SCT 25H2: adds PSExec/WMI rule (d1e49aac-...) in Audit mode (2)
    ASR_PATH = rf"{DEF}\Windows Defender Exploit Guard\ASR\Rules"

    # Expected ASR rules from the SCT baseline
    # GUID -> (description, expected_value, value_desc)
    sct_asr_rules = {
        "56a863a9-875e-4185-98a7-b882c64b5ce5": ("Block abuse of exploited vulnerable signed drivers", 1, "Block"),
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": ("Block Adobe Reader from creating child processes", 1, "Block"),
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a": ("Block all Office apps from creating child processes", 1, "Block"),
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": ("Block credential stealing from LSASS", 1, "Block"),
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": ("Block executable content from email and webmail", 1, "Block"),
        "01443614-cd74-433a-b99e-2ecdc07bfc25": ("Block executable files unless they meet criteria", 1, "Block"),
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc": ("Block execution of potentially obfuscated scripts", 1, "Block"),
        "d3e037e1-3eb8-44c8-a917-57927947596d": ("Block JavaScript/VBScript from launching downloaded content", 1, "Block"),
        "3b576869-a4ec-4529-8536-b80a7769e899": ("Block Office apps from creating executable content", 1, "Block"),
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": ("Block Office apps from injecting code into other processes", 1, "Block"),
        "26190899-1602-49e8-8b27-eb1d0a1ce869": ("Block Office communication app from creating child processes", 1, "Block"),
        "e6db77e5-3df2-4cf1-b95a-636979351e5b": ("Block persistence through WMI event subscription", 1, "Block"),
        "d1e49aac-8f56-4280-b9ba-993a6d77406c": ("Block process creations from PSExec and WMI [25H2]", 2, "Audit"),
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": ("Block untrusted/unsigned processes from USB", 1, "Block"),
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": ("Block Win32 API calls from Office macros", 1, "Block"),
        "c1db55ab-c21a-4637-bb3f-a12568109d35": ("Use advanced protection against ransomware", 1, "Block"),
    }

    asr_vals = reg_values(HKLM, ASR_PATH)
    asr_dict = {n.lower(): v for n, v, _ in asr_vals}

    configured = 0
    compliant = 0
    for guid, (desc, exp_val, exp_desc) in sct_asr_rules.items():
        current = asr_dict.get(guid.lower())
        if current is not None:
            configured += 1
            ok = (current == exp_val)
            if ok:
                compliant += 1
            mode = {0:"Disabled",1:"Block",2:"Audit",6:"Warn"}.get(current, str(current))
            add("Defender ASR", f"ASR-{guid[:8]}", f"ASR: {desc}",
                "PASS" if ok else "FAIL",
                f"Mode = {current} ({mode})", f"{exp_val} ({exp_desc})",
                f"GPO: Defender > Exploit Guard > ASR > Rule {guid}")
        else:
            add("Defender ASR", f"ASR-{guid[:8]}", f"ASR: {desc}",
                "FAIL", "Not configured", f"{exp_val} ({exp_desc})",
                f"GPO: Defender > Exploit Guard > ASR > Rule {guid}")

    add("Defender ASR", "ASR-SUM", "ASR rules summary",
        "PASS" if compliant >= 14 else ("WARN" if configured >= 10 else "FAIL"),
        f"{compliant}/{len(sct_asr_rules)} compliant, {configured} configured",
        f">= 14 of {len(sct_asr_rules)} rules compliant")


# ============================================================
# 6. CREDENTIAL PROTECTION
# ============================================================

def audit_credential_protection():
    """
    SCT baseline settings for credential protection including
    Credential Guard, LSASS PPL, and VBS.
    """
    print("\n[*] SCT Baseline: Credential Protection / Device Guard...")

    # SCT: VBS enabled = 1
    check_reg("Credential Protection", "VBS-01", "Virtualization Based Security",
              HKLM, r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
              "EnableVirtualizationBasedSecurity", lambda v: v == 1, "1 (Enabled)",
              "GPO: Device Guard > Turn On VBS = Enabled")

    # SCT: RequirePlatformSecurityFeatures = 3 (Secure Boot + DMA Protection)
    check_reg("Credential Protection", "VBS-02", "VBS platform security features",
              HKLM, r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
              "RequirePlatformSecurityFeatures", lambda v: v == 3,
              "3 (Secure Boot + DMA Protection)",
              "GPO: Device Guard > Select Platform Security Level")

    # SCT: LsaCfgFlags = 1 (Credential Guard with UEFI lock)
    check_reg("Credential Protection", "CG-01", "Credential Guard",
              HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags",
              lambda v: v >= 1,
              ">= 1 (Enabled with UEFI lock)",
              "GPO: Device Guard > Credential Guard Configuration")

    # SCT: HVCI = 1
    check_reg("Credential Protection", "HVCI-01", "HVCI (Memory Integrity)",
              HKLM, r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
              "Enabled", lambda v: v == 1, "1 (Enabled)",
              "Settings > Device security > Core isolation > Memory integrity")

    # SCT: LSASS RunAsPPL = 2 (PPL on 24H2+)
    check_reg("Credential Protection", "LSASS-01", "LSASS Protected Process Light",
              HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL",
              lambda v: v in (1, 2), "1 or 2 (Protected)",
              "Registry: HKLM\\...\\Lsa\\RunAsPPL = 2")

    # SCT: CachedLogonsCount = 4
    v = reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount")
    if v is not None:
        try:
            n = int(v)
            add("Credential Protection", "CACHE-01", "Cached logon credentials",
                "PASS" if n <= 4 else "FAIL", f"CachedLogonsCount = {n}",
                "<= 4", "GPO: Interactive logon: Number of previous logons to cache")
        except ValueError:
            pass


# ============================================================
# 7. AUDIT POLICY
# SCT baseline: Audit.csv in GPO backup
# ============================================================

def audit_audit_policy():
    """
    Maps to the SCT baseline Audit.csv which specifies the
    Advanced Audit Policy Configuration settings. These are the
    exact settings from the Windows 11 24H2/25H2 Intune baseline.
    """
    print("\n[*] SCT Baseline: Advanced Audit Policy...")

    out = cmd("auditpol /get /category:*")
    if not out:
        add("Audit Policy", "AUDIT", "Audit policy query", "SKIP",
            "auditpol may require elevation", "N/A")
        return

    # SCT 24H2/25H2 baseline audit settings
    # (Category substring, SCT reference, Expected setting)
    sct_audit = [
        ("Credential Validation",           "AUD-01", "Success and Failure"),
        ("Application Group Management",    "AUD-02", "Success and Failure"),
        ("Security Group Management",       "AUD-03", "Success"),
        ("User Account Management",         "AUD-04", "Success and Failure"),
        ("PNP Activity",                    "AUD-05", "Success"),
        ("Process Creation",                "AUD-06", "Success"),
        ("Account Lockout",                 "AUD-07", "Failure"),
        ("Group Membership",                "AUD-08", "Success"),
        ("Logon",                           "AUD-09", "Success and Failure"),
        ("Other Logon/Logoff",              "AUD-10", "Success and Failure"),
        ("Special Logon",                   "AUD-11", "Success"),
        ("Detailed File Share",             "AUD-12", "Failure"),
        ("File Share",                      "AUD-13", "Success and Failure"),
        ("Other Object Access",             "AUD-14", "Success and Failure"),
        ("Removable Storage",               "AUD-15", "Success and Failure"),
        ("Audit Policy Change",             "AUD-16", "Success"),
        ("Authentication Policy",           "AUD-17", "Success"),
        ("MPSSVC Rule-Level",               "AUD-18", "Success and Failure"),
        ("Other Policy Change",             "AUD-19", "Failure"),
        ("Sensitive Privilege Use",         "AUD-20", "Success"),
        ("Other System Events",             "AUD-21", "Success and Failure"),
        ("Security State Change",           "AUD-22", "Success"),
        ("Security System Extension",       "AUD-23", "Success"),
        ("System Integrity",                "AUD-24", "Success and Failure"),
    ]

    for cat, ref, expected in sct_audit:
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
                add("Audit Policy", ref, f"Audit: {cat}",
                    "PASS" if ok else "FAIL", f"Current: {setting}", expected,
                    f"auditpol /set /subcategory:\"{cat}\" /success:enable /failure:enable")
                found = True
                break
        if not found:
            add("Audit Policy", ref, f"Audit: {cat}", "SKIP",
                "Not found in auditpol output", expected)

    # SCT 25H2 NEW: Include command line in process creation events
    check_reg("Audit Policy", "AUD-CMD", "Command line in process creation events",
              HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
              "ProcessCreationIncludeCmdLine_Enabled", lambda v: v == 1,
              "1 (Enabled) [25H2 NEW]",
              "GPO: System > Audit Process Creation > Include command line")


# ============================================================
# 8. WINDOWS FIREWALL
# SCT baseline: Registry.pol firewall settings
# ============================================================

def audit_firewall():
    print("\n[*] SCT Baseline: Windows Firewall...")
    for key, name, cis in [("domainprofile","Domain","FW-D"),
                            ("privateprofile","Private","FW-P"),
                            ("publicprofile","Public","FW-PU")]:
        out = cmd(f"netsh advfirewall show {key}")
        if not out:
            add("Firewall", cis, f"Firewall - {name}", "SKIP", "Could not query", "ON")
            continue
        on = bool(re.search(r"State\s+ON", out, re.I))
        add("Firewall", f"{cis}-1", f"Firewall enabled - {name}",
            "PASS" if on else "FAIL", f"{'ON' if on else 'OFF'}", "ON",
            f"netsh advfirewall set {key} state on")
        block = "blockinbound" in out.lower()
        add("Firewall", f"{cis}-2", f"Inbound default block - {name}",
            "PASS" if block else "FAIL",
            f"{'BlockInbound' if block else 'AllowInbound'}", "BlockInbound")
        log_drop = bool(re.search(r"LogDroppedConnections\s+Enable", out, re.I))
        add("Firewall", f"{cis}-3", f"Log dropped packets - {name}",
            "PASS" if log_drop else "WARN",
            f"{'Enabled' if log_drop else 'Disabled'}", "Enabled")


# ============================================================
# 9. ADMINISTRATIVE TEMPLATES (Registry.pol settings)
# ============================================================

def audit_admin_templates():
    """
    Maps to the bulk of the SCT GPO Registry.pol entries.
    These are Administrative Template settings that write to
    HKLM SOFTWARE Policies ... paths.
    """
    print("\n[*] SCT Baseline: Administrative Templates...")

    POL = r"SOFTWARE\Policies\Microsoft"

    # --- Remote Desktop ---
    TS = rf"{POL}\Windows NT\Terminal Services"

    check_reg("Admin Templates", "RDP-01", "RDP: Require NLA",
              HKLM, TS, "UserAuthentication", lambda v: v == 1, "1",
              "GPO: Remote Desktop > Require NLA")

    check_reg("Admin Templates", "RDP-02", "RDP: Encryption level = High",
              HKLM, TS, "MinEncryptionLevel", lambda v: v >= 3, ">= 3 (High)",
              "GPO: Remote Desktop > Set client encryption level = High")

    check_reg("Admin Templates", "RDP-03", "RDP: Always prompt for password",
              HKLM, TS, "fPromptForPassword", lambda v: v == 1, "1",
              "GPO: Remote Desktop > Always prompt for password")

    check_reg("Admin Templates", "RDP-04", "RDP: Do not allow drive redirection",
              HKLM, TS, "fDisableCdm", lambda v: v == 1, "1",
              "GPO: Remote Desktop > Do not allow drive redirection")

    # --- Remote Assistance ---
    check_reg("Admin Templates", "RA-01", "Solicited Remote Assistance disabled",
              HKLM, TS, "fAllowToGetHelp", lambda v: v == 0, "0 (Disabled)",
              "GPO: System > Remote Assistance > Configure Solicited = Disabled")

    # --- Windows Installer ---
    check_reg("Admin Templates", "MSI-01", "Always install with elevated privileges = Disabled",
              HKLM, rf"{POL}\Windows\Installer", "AlwaysInstallElevated",
              lambda v: v == 0, "0 (Disabled)",
              "GPO: Windows Installer > Always install elevated = Disabled")

    # --- WinRM ---
    WRM = rf"{POL}\Windows\WinRM"
    check_reg("Admin Templates", "WINRM-01", "WinRM client: No Basic auth",
              HKLM, rf"{WRM}\Client", "AllowBasic", lambda v: v == 0, "0",
              "GPO: WinRM Client > Allow Basic authentication = Disabled")

    check_reg("Admin Templates", "WINRM-02", "WinRM client: No unencrypted traffic",
              HKLM, rf"{WRM}\Client", "AllowUnencryptedTraffic", lambda v: v == 0, "0",
              "GPO: WinRM Client > Allow unencrypted traffic = Disabled")

    check_reg("Admin Templates", "WINRM-03", "WinRM service: No Basic auth",
              HKLM, rf"{WRM}\Service", "AllowBasic", lambda v: v == 0, "0",
              "GPO: WinRM Service > Allow Basic authentication = Disabled")

    check_reg("Admin Templates", "WINRM-04", "WinRM service: No unencrypted traffic",
              HKLM, rf"{WRM}\Service", "AllowUnencryptedTraffic", lambda v: v == 0, "0",
              "GPO: WinRM Service > Allow unencrypted traffic = Disabled")

    # --- AutoPlay ---
    check_reg("Admin Templates", "AUTO-01", "AutoPlay disabled for all drives",
              HKLM, rf"{POL}\Windows\CurrentVersion\Policies\Explorer",
              "NoDriveTypeAutoRun", lambda v: v == 255, "255 (All drives)",
              "GPO: Windows Components > AutoPlay > Turn off Autoplay = All drives")

    check_reg("Admin Templates", "AUTO-02", "AutoRun default behaviour = Do not execute",
              HKLM, rf"{POL}\Windows\Explorer", "NoAutorun", lambda v: v == 1, "1",
              "GPO: Windows Components > AutoPlay > Default behavior for AutoRun = Do not execute")

    # --- LLMNR disabled ---
    check_reg("Admin Templates", "DNS-01", "LLMNR disabled",
              HKLM, rf"{POL}\Windows NT\DNSClient", "EnableMulticast",
              lambda v: v == 0, "0 (Disabled)",
              "GPO: Network > DNS Client > Turn off multicast name resolution")

    # --- Mark of the Web (24H2 NEW) ---
    check_reg("Admin Templates", "MOTW-01",
              "MotW: Do not remove from insecure sources = Disabled [24H2 NEW]",
              HKLM, rf"{POL}\Windows\Explorer",
              "NoMarkOfTheWebOnZoneRedirection", lambda v: v == 0,
              "0 (Disabled - MotW IS applied when copying from insecure sources)",
              "GPO: File Explorer > Do not apply MotW to files from insecure sources = Disabled")

    # --- Sudo disabled (24H2 NEW) ---
    check_reg("Admin Templates", "SUDO-01", "Sudo command disabled [24H2 NEW]",
              HKLM, rf"{POL}\Windows\Sudo", "Enabled", lambda v: v == 0,
              "0 (Disabled)",
              "GPO: System > Configure the behavior of the sudo command = Disabled")

    # --- PowerShell ---
    PS = rf"{POL}\Windows\PowerShell"
    check_reg("Admin Templates", "PS-01", "PowerShell Script Block Logging",
              HKLM, rf"{PS}\ScriptBlockLogging", "EnableScriptBlockLogging",
              lambda v: v == 1, "1 (Enabled)",
              "GPO: PowerShell > Turn on Script Block Logging")

    check_reg("Admin Templates", "PS-02", "PowerShell Transcription",
              HKLM, rf"{PS}\Transcription", "EnableTranscripting",
              lambda v: v == 1, "1 (Enabled)",
              "GPO: PowerShell > Turn on PowerShell Transcription")

    # --- Event Log sizes ---
    EL = rf"{POL}\Windows\EventLog"
    for log, size, lid in [("Application",32768,"EL-01"),("Security",196608,"EL-02"),("System",32768,"EL-03")]:
        check_reg("Admin Templates", lid, f"{log} log max size",
                  HKLM, rf"{EL}\{log}", "MaxSize", lambda v, s=size: v >= s,
                  f">= {size//1024} MB ({size} KB)",
                  f"GPO: Event Log Service > {log} > Max log size = {size}")

    # --- Windows Update ---
    check_reg("Admin Templates", "WU-01", "Auto-update configuration",
              HKLM, rf"{POL}\Windows\WindowsUpdate\AU", "AUOptions",
              lambda v: v == 4, "4 (Auto download and schedule)",
              "GPO: Windows Update > Configure Automatic Updates = 4")

    # --- Network: Disable IPv6 Transition Technologies ---
    check_reg("Admin Templates", "NET-ISATAP", "ISATAP state disabled",
              HKLM, rf"{POL}\Windows\TCPIP\v6Transition", "ISATAP_State",
              lambda v: str(v).lower() == "disabled", "Disabled",
              "GPO: Network > TCPIP Settings > IPv6 Transition > ISATAP State = Disabled")

    # --- BitLocker (informational) ---
    bl = cmd("manage-bde -status C: 2>&1")
    if bl and "Protection On" in bl:
        add("Admin Templates", "BL-01", "BitLocker on C:", "PASS",
            "Protection On", "Protection On")
    elif bl and "Protection Off" in bl:
        add("Admin Templates", "BL-01", "BitLocker on C:", "FAIL",
            "Protection Off", "Protection On",
            "Enable via Control Panel > BitLocker")


# ============================================================
# 10. ADDITIONAL HARDENING (Patching, Services, Persistence)
# ============================================================

def audit_additional():
    """
    Additional checks that complement the SCT baseline but aren't
    directly in the GPO backup. These cover operational security
    that Microsoft recommends alongside the baseline.
    """
    print("\n[*] Additional: Patching, Services, Persistence...")

    # --- Last patch age ---
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
            f"Last update: {latest.strftime('%Y-%m-%d')} ({days}d ago)",
            "<= 30 days")

    # --- Risky services ---
    out = cmd("sc query type= service state= all")
    running = set()
    cur = ""
    for line in out.splitlines():
        if "SERVICE_NAME:" in line:
            cur = line.split(":", 1)[1].strip()
        if "RUNNING" in line and cur:
            running.add(cur.lower())

    risky = {"RemoteRegistry":"Remote Registry","TlntSvr":"Telnet",
             "FTPSVC":"FTP","SSDPSRV":"SSDP/UPnP","SNMP":"SNMP"}
    for svc, desc in risky.items():
        if svc.lower() in running:
            add("Services", "SVC", f"Risky service: {svc}",
                "FAIL", f"{desc} - RUNNING", "Disabled")

    # --- Credential files ---
    home = os.path.expanduser("~")
    ps_hist = os.path.join(home, "AppData", "Roaming", "Microsoft", "Windows",
                           "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
    if os.path.isfile(ps_hist):
        try:
            with open(ps_hist, "r", errors="replace") as f:
                content = f.read()
            hits = len(re.findall(r"(?i)(password|secret|token|apikey|credential)", content))
            add("Credentials", "CRED-01", "PowerShell history",
                "FAIL" if hits > 0 else "INFO",
                f"Size: {os.path.getsize(ps_hist)//1024}KB, credential patterns: {hits}",
                "No credential patterns")
        except OSError:
            pass

    if os.path.isfile(os.path.join(home, ".git-credentials")):
        add("Credentials", "CRED-02", "Git credentials file",
            "FAIL", "Plaintext .git-credentials found", "Use Git Credential Manager")

    # --- Unquoted service paths ---
    out = cmd("wmic service get Name,PathName /format:csv")
    unq = 0
    if out:
        for line in out.splitlines():
            parts = line.split(",")
            if len(parts) < 3:
                continue
            spath = parts[2].strip()
            if not spath or spath.startswith('"'):
                continue
            m = re.match(r"^(.+?\.exe)", spath, re.I)
            if m and " " in m.group(1) and not re.search(r"(?i)svchost|\\system32\\", m.group(1)):
                unq += 1
                if unq <= 3:
                    add("Services", "UNQUOTE", f"Unquoted: {parts[1].strip()[:40]}",
                        "FAIL", f"Path: {spath[:80]}", "Quoted paths")
    if unq == 0:
        add("Services", "UNQUOTE", "Unquoted service paths", "PASS",
            "None found", "All quoted")


# ============================================================
# HTML REPORT
# ============================================================

def gen_html(path):
    print("\n[*] Generating HTML report...")
    total = len(results)
    pr = round((counts["PASS"]/total)*100, 1) if total else 0
    doms = {}
    for r in results:
        doms.setdefault(r["domain"], []).append(r)

    h = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>SCT Baseline Audit - {html_mod.escape(sysinfo.get('hostname',''))}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f8f9fa;color:#1a1a1a;line-height:1.6}}
.w{{max-width:1140px;margin:0 auto;padding:20px}}
.hd{{background:linear-gradient(135deg,#0c2461,#1e3799);color:#fff;padding:30px;border-radius:10px;margin-bottom:20px}}
.hd h1{{font-size:20px;margin-bottom:4px}}.hd p{{opacity:.85;font-size:12px}}
.nt{{background:#e3f2fd;padding:12px 16px;border-radius:8px;margin-bottom:18px;border-left:4px solid #1565c0;font-size:12px;color:#0d47a1}}
.sm{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:20px}}
.sc{{background:#fff;padding:14px;border-radius:8px;text-align:center;border:1px solid #e9ecef}}
.sc .n{{font-size:26px;font-weight:600}}.sc .l{{font-size:10px;text-transform:uppercase;color:#6c757d;letter-spacing:.5px}}
.p .n{{color:#198754}}.f .n{{color:#dc3545}}.wa .n{{color:#fd7e14}}.i .n{{color:#0dcaf0}}.s .n{{color:#6c757d}}.r .n{{color:#0d6efd}}
.si{{background:#fff;padding:16px;border-radius:8px;margin-bottom:18px;border:1px solid #e9ecef}}
.si h2{{font-size:15px;margin-bottom:8px;color:#0c2461}}.si table{{width:100%;border-collapse:collapse}}
.si td{{padding:4px 8px;border-bottom:1px solid #f1f3f5;font-size:12px}}.si td:first-child{{font-weight:600;width:160px;color:#495057}}
.dm{{background:#fff;border-radius:8px;margin-bottom:12px;border:1px solid #e9ecef;overflow:hidden}}
.dh{{padding:12px 16px;cursor:pointer;display:flex;justify-content:space-between;align-items:center}}
.dh:hover{{background:#f8f9fa}}.dh h3{{font-size:13px;font-weight:600;color:#0c2461}}.dh span{{font-size:11px;color:#6c757d}}
table.t{{width:100%;border-collapse:collapse;font-size:11px}}
table.t th{{background:#f8f9fa;padding:6px 8px;text-align:left;font-weight:600;color:#495057;border-bottom:2px solid #dee2e6}}
table.t td{{padding:6px 8px;border-bottom:1px solid #f1f3f5;vertical-align:top}}
table.t tr:hover{{background:#fafbfc}}
.b{{display:inline-block;padding:1px 7px;border-radius:10px;font-size:9px;font-weight:600;color:#fff;letter-spacing:.3px}}
.b-p{{background:#198754}}.b-f{{background:#dc3545}}.b-w{{background:#fd7e14}}.b-i{{background:#0dcaf0;color:#000}}.b-s{{background:#6c757d}}
.rx{{background:#fff8e1;padding:4px 8px;border-radius:3px;font-size:10px;margin-top:3px;border-left:2px solid #ffc107;color:#664d03}}
.ft{{text-align:center;padding:14px;color:#adb5bd;font-size:10px}}
</style></head><body><div class="w">
<div class="hd"><h1>Microsoft Security Compliance Toolkit - Baseline Audit</h1>
<p>Host: {html_mod.escape(sysinfo.get('hostname',''))} | Build: {html_mod.escape(sysinfo.get('build',''))} ({html_mod.escape(sysinfo.get('display_version',''))}) | {html_mod.escape(sysinfo.get('edition',''))}</p>
<p>Baseline: {html_mod.escape(sysinfo.get('baseline',''))} | User: {html_mod.escape(sysinfo.get('user',''))} | {html_mod.escape(sysinfo.get('audit_date',''))}</p></div>
<div class="nt"><strong>Baseline source:</strong> Microsoft Security Compliance Toolkit 1.0 - Windows 11 v24H2/v25H2 Security Baseline package. This audit checks the registry values, audit policy, and security options that the SCT GPO backup would configure. Standard user access (no admin).</div>
<div class="sm">
<div class="sc r"><div class="n">{pr}%</div><div class="l">Compliance</div></div>
<div class="sc p"><div class="n">{counts['PASS']}</div><div class="l">Pass</div></div>
<div class="sc f"><div class="n">{counts['FAIL']}</div><div class="l">Fail</div></div>
<div class="sc wa"><div class="n">{counts['WARN']}</div><div class="l">Warn</div></div>
<div class="sc i"><div class="n">{counts['INFO']}</div><div class="l">Info</div></div>
<div class="sc s"><div class="n">{counts['SKIP']}</div><div class="l">Skip</div></div>
</div>
<div class="si"><h2>System Information</h2><table>"""

    for k, v in sysinfo.items():
        h += f"<tr><td>{html_mod.escape(str(k))}</td><td>{html_mod.escape(str(v))}</td></tr>"
    h += "</table></div>"

    for dname, dres in doms.items():
        dp = sum(1 for r in dres if r["status"]=="PASS")
        df = sum(1 for r in dres if r["status"]=="FAIL")
        h += f"""<div class="dm"><div class="dh" onclick="var b=this.nextElementSibling;b.style.display=b.style.display==='none'?'block':'none'">
<h3>{html_mod.escape(dname)}</h3><span>{len(dres)} checks: {dp}P {df}F</span></div>
<div><table class="t"><tr><th style="width:45px">Status</th><th style="width:65px">Ref</th><th style="width:200px">Control</th><th>Finding</th><th style="width:160px">SCT Expected</th></tr>"""
        for r in dres:
            bc = {"PASS":"b-p","FAIL":"b-f","WARN":"b-w","INFO":"b-i","SKIP":"b-s"}.get(r["status"],"b-i")
            rx = ""
            if r["status"] == "FAIL" and r["remediation"]:
                rx = f'<div class="rx">{html_mod.escape(r["remediation"])}</div>'
            h += f"""<tr><td><span class="b {bc}">{r['status']}</span></td><td>{html_mod.escape(r['ref'])}</td>
<td>{html_mod.escape(r['check'])}</td><td>{html_mod.escape(r['finding'])}{rx}</td>
<td>{html_mod.escape(r['expected'])}</td></tr>"""
        h += "</table></div></div>"

    h += f'<div class="ft">msft_sct_audit.py | Microsoft SCT Baseline | {html_mod.escape(sysinfo.get("audit_date",""))}</div></div></body></html>'

    with open(path, "w", encoding="utf-8") as f:
        f.write(h)
    print(f"  HTML report: {path}")


def gen_json(path):
    out = {"system_info": sysinfo, "baseline": "Microsoft SCT Windows 11 24H2/25H2",
           "summary": counts, "total": len(results),
           "compliance_pct": round((counts["PASS"]/len(results))*100, 1) if results else 0,
           "results": results}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, default=str)
    print(f"  JSON report: {path}")


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Microsoft Security Compliance Toolkit Baseline Auditor for Windows 11")
    parser.add_argument("-o", "--output", default="SCT_Baseline_Report.html",
                        help="HTML report path")
    parser.add_argument("--json", action="store_true", help="Also export JSON")
    parser.add_argument("--json-path", default="SCT_Baseline_Results.json")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("ERROR: This script must run on Windows.")
        sys.exit(1)

    print("=" * 64)
    print("  Microsoft Security Compliance Toolkit - Baseline Auditor")
    print("  Target: Windows 11 24H2/25H2 Security Baseline")
    print("  Privilege: Standard User (no admin required)")
    print("  AUTHORISED USE ONLY")
    print("=" * 64)

    t0 = time.time()
    collect_sysinfo()

    audit_account_policy()          # 1. Password + Lockout
    audit_security_options()        # 2. Security Options (UAC, SMB, NTLM, Logon)
    audit_ms_security_guide()       # 3. MS Security Guide custom ADMX
    audit_mss_legacy()              # 4. MSS (Legacy) settings
    audit_defender()                # 5. Windows Defender + ASR rules
    audit_credential_protection()   # 6. VBS, HVCI, Credential Guard, LSASS
    audit_audit_policy()            # 7. Advanced Audit Policy (24 subcategories)
    audit_firewall()                # 8. Windows Firewall
    audit_admin_templates()         # 9. Administrative Templates (RDP, WinRM, AutoPlay, PS, etc.)
    audit_additional()              # 10. Patching, Services, Credentials

    gen_html(args.output)
    if args.json:
        gen_json(args.json_path)

    elapsed = time.time() - t0
    total = len(results)
    pr = round((counts["PASS"]/total)*100, 1) if total else 0

    print(f"\n{'='*64}")
    print(f"  SCT BASELINE AUDIT COMPLETE")
    print(f"{'='*64}")
    print(f"  Total     : {total} controls checked")
    print(f"  \033[92mCompliant : {counts['PASS']}\033[0m")
    print(f"  \033[91mNon-compl : {counts['FAIL']}\033[0m")
    print(f"  \033[93mWarnings  : {counts['WARN']}\033[0m")
    print(f"  \033[96mInfo      : {counts['INFO']}\033[0m")
    print(f"  \033[90mSkipped   : {counts['SKIP']}\033[0m")
    print(f"  Compliance: {pr}%")
    print(f"  Duration  : {elapsed:.1f}s")
    print(f"  Report    : {args.output}")
    if args.json:
        print(f"  JSON      : {args.json_path}")
    print(f"{'='*64}\n")


if __name__ == "__main__":
    main()
