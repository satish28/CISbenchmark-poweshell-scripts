#!/usr/bin/env python3
"""
win11_azuread_audit.py — Windows 11 Azure AD Security Auditor
Author : ss
Purpose: Non-admin security audit for Azure AD-joined Windows 11 systems,
         checking PRT exposure, token caches, Intune misconfigurations,
         and Azure AD-specific privilege escalation vectors.
Usage  : python win11_azuread_audit.py [options]

AUTHORISED USE ONLY. Run this tool only against systems you own or have
explicit written permission to test.
"""

# --- stdlib imports ---
import os
import sys
import json
import subprocess
import re
import winreg
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# --- third-party imports ---
import click

# --- constants / config ---
VERSION = "1.0.0"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents a security finding."""
    check_id: str
    title: str
    severity: Severity
    description: str
    details: Any
    remediation: str
    mitre_attack: Optional[str] = None

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['severity'] = self.severity.value
        return d


class AzureADAuditor:
    """Azure AD Security Auditor for Windows 11."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: List[Finding] = []
        self.device_info: Dict = {}
        self.aad_status: Dict = {}

    def log(self, msg: str, level: str = "INFO") -> None:
        """Log messages if verbose mode is enabled."""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            click.echo(f"[{timestamp}] [{level}] {msg}")

    def run_powershell(self, command: str, timeout: int = 30) -> Optional[str]:
        """Execute PowerShell command and return output."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out: {command[:50]}...", "WARN")
            return None
        except Exception as e:
            self.log(f"PowerShell error: {e}", "ERROR")
            return None

    def run_cmd(self, command: str, timeout: int = 30) -> Optional[str]:
        """Execute CMD command and return output."""
        try:
            result = subprocess.run(
                ["cmd", "/c", command],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip()
        except Exception as e:
            self.log(f"CMD error: {e}", "ERROR")
            return None

    def read_registry(self, hive: int, path: str, value: str) -> Optional[Any]:
        """Read a registry value safely."""
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                data, _ = winreg.QueryValueEx(key, value)
                return data
        except (FileNotFoundError, PermissionError):
            return None
        except Exception as e:
            self.log(f"Registry read error: {e}", "DEBUG")
            return None

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)
        if self.verbose:
            color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "yellow",
                Severity.MEDIUM: "cyan",
                Severity.LOW: "white",
                Severity.INFO: "green"
            }.get(finding.severity, "white")
            click.secho(f"[{finding.severity.value}] {finding.title}", fg=color)

    def parse_dsregcmd(self) -> Dict[str, str]:
        """Parse dsregcmd /status output into a dictionary."""
        output = self.run_cmd("dsregcmd /status")
        if not output:
            return {}
        
        result = {}
        for line in output.split('\n'):
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    result[key] = value
        return result

    # --- Azure AD Status Collection ---
    def collect_aad_status(self) -> None:
        """Collect Azure AD join status and device information."""
        self.log("Collecting Azure AD status...")
        
        self.aad_status = self.parse_dsregcmd()
        
        self.device_info = {
            "hostname": os.environ.get("COMPUTERNAME", "Unknown"),
            "username": os.environ.get("USERNAME", "Unknown"),
            "domain": os.environ.get("USERDOMAIN", "Unknown"),
            "azure_ad_joined": self.aad_status.get("AzureAdJoined", "NO"),
            "domain_joined": self.aad_status.get("DomainJoined", "NO"),
            "workplace_joined": self.aad_status.get("WorkplaceJoined", "NO"),
            "device_id": self.aad_status.get("DeviceId", "Unknown"),
            "tenant_id": self.aad_status.get("TenantId", "Unknown"),
            "tenant_name": self.aad_status.get("TenantName", "Unknown"),
            "mdm_enrolled": "YES" if self.aad_status.get("MdmUrl") else "NO",
            "key_provider": self.aad_status.get("KeyProvider", "Unknown"),
            "prt_present": self.aad_status.get("AzureAdPrt", "NO"),
            "ngc_set": self.aad_status.get("NgcSet", "NO"),
            "audit_time": datetime.now().isoformat(),
            "audit_tool_version": VERSION
        }

        # Determine join type
        if self.device_info["azure_ad_joined"] == "YES":
            if self.device_info["domain_joined"] == "YES":
                self.device_info["join_type"] = "Hybrid Azure AD Join"
            else:
                self.device_info["join_type"] = "Azure AD Join"
        elif self.device_info["workplace_joined"] == "YES":
            self.device_info["join_type"] = "Azure AD Registered"
        else:
            self.device_info["join_type"] = "Not Azure AD integrated"

    # --- Check 1: Key Protection ---
    def check_key_protection(self) -> None:
        """Check if device keys are TPM-protected."""
        self.log("Checking key protection...")
        
        key_provider = self.aad_status.get("KeyProvider", "")
        
        if "Software" in key_provider:
            self.add_finding(Finding(
                check_id="AAD-KEY-001",
                title="Device Keys Not TPM-Protected",
                severity=Severity.HIGH,
                description="Device keys are stored in software, not TPM. "
                           "This makes PRT extraction significantly easier.",
                details={
                    "key_provider": key_provider,
                    "risk": "Device keys can be extracted with SYSTEM access"
                },
                remediation="Re-register the device on a TPM-equipped machine or "
                           "ensure TPM is enabled in BIOS/UEFI.",
                mitre_attack="T1552.004 - Unsecured Credentials: Private Keys"
            ))

    # --- Check 2: PRT Status ---
    def check_prt_status(self) -> None:
        """Check Primary Refresh Token status and exposure risk."""
        self.log("Checking PRT status...")
        
        prt_present = self.aad_status.get("AzureAdPrt", "NO")
        prt_update = self.aad_status.get("AzureAdPrtUpdateTime", "")
        
        if prt_present == "YES":
            self.add_finding(Finding(
                check_id="AAD-PRT-001",
                title="Primary Refresh Token Present",
                severity=Severity.INFO,
                description="A Primary Refresh Token (PRT) is present on this device. "
                           "This token provides SSO to all Azure AD resources.",
                details={
                    "prt_present": True,
                    "last_update": prt_update,
                    "key_provider": self.aad_status.get("KeyProvider", "Unknown")
                },
                remediation="Ensure device keys are TPM-protected and Credential Guard is enabled.",
                mitre_attack="T1528 - Steal Application Access Token"
            ))

    # --- Check 3: Token Cache Locations ---
    def check_token_caches(self) -> None:
        """Check for accessible token cache locations."""
        self.log("Checking token cache locations...")
        
        cache_locations = {
            "TokenBroker": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\TokenBroker\Cache"),
            "IdentityCache": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\IdentityCache"),
            "IdentityService": os.path.expandvars(r"%LOCALAPPDATA%\.IdentityService"),
            "OneAuth": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\OneAuth"),
            "AADBrokerPlugin": os.path.expandvars(r"%LOCALAPPDATA%\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy"),
        }
        
        accessible_caches = []
        
        for name, path in cache_locations.items():
            if os.path.exists(path):
                try:
                    files = list(Path(path).rglob("*"))
                    file_count = len([f for f in files if f.is_file()])
                    accessible_caches.append({
                        "name": name,
                        "path": path,
                        "file_count": file_count,
                        "accessible": True
                    })
                except PermissionError:
                    accessible_caches.append({
                        "name": name,
                        "path": path,
                        "accessible": False
                    })

        if accessible_caches:
            readable = [c for c in accessible_caches if c.get("accessible")]
            if readable:
                self.add_finding(Finding(
                    check_id="AAD-CACHE-001",
                    title="Token Cache Directories Accessible",
                    severity=Severity.MEDIUM,
                    description="Azure AD token cache directories are accessible to current user. "
                               "These may contain access tokens, refresh tokens, or PRT cookies.",
                    details=accessible_caches,
                    remediation="Token caches are normal for user context. Ensure DPAPI protection "
                               "is intact and Credential Guard is enabled.",
                    mitre_attack="T1552.001 - Unsecured Credentials: Credentials In Files"
                ))

    # --- Check 4: Azure CLI/PowerShell Credentials ---
    def check_azure_cli_credentials(self) -> None:
        """Check for cached Azure CLI/PowerShell credentials."""
        self.log("Checking Azure CLI/PowerShell credentials...")
        
        azure_paths = {
            "Azure CLI": os.path.expandvars(r"%USERPROFILE%\.azure"),
            "Azure PowerShell": os.path.expandvars(r"%USERPROFILE%\.Azure"),
            "AzureRM Context": os.path.expandvars(r"%USERPROFILE%\.azure\AzureRmContext.json"),
        }
        
        found_creds = []
        
        for name, path in azure_paths.items():
            if os.path.exists(path):
                if os.path.isdir(path):
                    # Check for sensitive files
                    sensitive_files = [
                        "msal_token_cache.json",
                        "msal_token_cache.bin",
                        "accessTokens.json",
                        "servicePrincipalCredentials.json",
                        "azureProfile.json",
                        "AzureRmContext.json"
                    ]
                    for sf in sensitive_files:
                        sf_path = os.path.join(path, sf)
                        if os.path.exists(sf_path):
                            found_creds.append({
                                "type": name,
                                "file": sf,
                                "path": sf_path,
                                "size": os.path.getsize(sf_path)
                            })
                else:
                    found_creds.append({
                        "type": name,
                        "path": path,
                        "size": os.path.getsize(path)
                    })

        if found_creds:
            # Check for service principal credentials (most critical)
            has_sp = any("servicePrincipal" in c.get("file", "") for c in found_creds)
            
            self.add_finding(Finding(
                check_id="AAD-AZCLI-001",
                title="Azure CLI/PowerShell Credentials Cached",
                severity=Severity.CRITICAL if has_sp else Severity.HIGH,
                description="Azure CLI or Azure PowerShell has cached credentials. "
                           "These tokens can be extracted and used for Azure resource access.",
                details=found_creds,
                remediation="Run 'az logout' and 'Disconnect-AzAccount' after use. "
                           "For persistent access, use managed identities instead.",
                mitre_attack="T1552.001 - Unsecured Credentials: Credentials In Files"
            ))

    # --- Check 5: Credential Manager Azure Entries ---
    def check_credential_manager_azure(self) -> None:
        """Check Credential Manager for Azure-related entries."""
        self.log("Checking Credential Manager for Azure credentials...")
        
        output = self.run_cmd("cmdkey /list")
        if not output:
            return
        
        azure_patterns = [
            "azure", "microsoft", "office365", "graph.microsoft",
            "login.microsoftonline", "sharepoint", "onedrive",
            "teams", "outlook", "visualstudio", "dev.azure"
        ]
        
        azure_creds = []
        current_entry = {}
        
        for line in output.split('\n'):
            if "Target:" in line:
                if current_entry:
                    # Check if previous entry matches Azure patterns
                    target = current_entry.get("target", "").lower()
                    if any(p in target for p in azure_patterns):
                        azure_creds.append(current_entry)
                current_entry = {"target": line.split("Target:")[-1].strip()}
            elif "Type:" in line:
                current_entry["type"] = line.split("Type:")[-1].strip()
            elif "User:" in line:
                current_entry["user"] = line.split("User:")[-1].strip()
        
        # Check last entry
        if current_entry:
            target = current_entry.get("target", "").lower()
            if any(p in target for p in azure_patterns):
                azure_creds.append(current_entry)

        if azure_creds:
            self.add_finding(Finding(
                check_id="AAD-CRED-001",
                title="Azure Credentials in Credential Manager",
                severity=Severity.MEDIUM,
                description="Azure-related credentials are stored in Windows Credential Manager.",
                details=azure_creds,
                remediation="Review stored credentials and remove unnecessary entries. "
                           "Use SSO or managed identities where possible.",
                mitre_attack="T1555.004 - Credentials from Password Stores: Windows Credential Manager"
            ))

    # --- Check 6: Intune Configuration ---
    def check_intune_config(self) -> None:
        """Check Intune/MDM configuration and potential exposures."""
        self.log("Checking Intune configuration...")
        
        intune_base = os.path.expandvars(r"%ProgramData%\Microsoft\IntuneManagementExtension")
        
        if not os.path.exists(intune_base):
            return
        
        findings_data = {
            "intune_present": True,
            "logs": [],
            "scripts": [],
            "policies": []
        }
        
        # Check for scripts with potential credentials
        scripts_path = os.path.join(intune_base, "Policies", "Scripts")
        if os.path.exists(scripts_path):
            try:
                for ps1_file in Path(scripts_path).rglob("*.ps1"):
                    try:
                        content = ps1_file.read_text(errors='ignore')
                        sensitive_patterns = [
                            r'password\s*=', r'secret\s*=', r'apikey\s*=',
                            r'credential', r'convertto-securestring',
                            r'token\s*=', r'\$env:.*password', r'\$env:.*secret'
                        ]
                        
                        matches = []
                        for pattern in sensitive_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                matches.append(pattern)
                        
                        if matches:
                            findings_data["scripts"].append({
                                "path": str(ps1_file),
                                "potential_secrets": matches
                            })
                    except Exception:
                        pass
            except PermissionError:
                findings_data["scripts_access_denied"] = True

        # Check logs for sensitive data
        logs_path = os.path.join(intune_base, "Logs")
        if os.path.exists(logs_path):
            try:
                log_files = list(Path(logs_path).glob("*.log"))
                findings_data["logs"] = [str(f) for f in log_files[:5]]
            except PermissionError:
                findings_data["logs_access_denied"] = True

        if findings_data["scripts"]:
            self.add_finding(Finding(
                check_id="AAD-INTUNE-001",
                title="Intune Scripts with Potential Secrets",
                severity=Severity.HIGH,
                description="Intune-deployed PowerShell scripts may contain hardcoded credentials "
                           "or sensitive configuration data.",
                details=findings_data,
                remediation="Review Intune scripts for hardcoded credentials. Use Azure Key Vault "
                           "or Managed Identities instead.",
                mitre_attack="T1552.001 - Unsecured Credentials: Credentials In Files"
            ))
        elif findings_data["intune_present"]:
            self.add_finding(Finding(
                check_id="AAD-INTUNE-002",
                title="Intune Management Extension Present",
                severity=Severity.INFO,
                description="Device is managed by Intune.",
                details=findings_data,
                remediation="Regularly audit Intune policies and deployed scripts.",
                mitre_attack=None
            ))

    # --- Check 7: MDM Enrollment Details ---
    def check_mdm_enrollment(self) -> None:
        """Check MDM enrollment details."""
        self.log("Checking MDM enrollment...")
        
        try:
            enrollments = []
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\Microsoft\Enrollments") as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            enrollment = {"id": subkey_name}
                            for value_name in ["ProviderID", "EnrollmentType", "UPN"]:
                                try:
                                    enrollment[value_name] = winreg.QueryValueEx(subkey, value_name)[0]
                                except:
                                    pass
                            enrollments.append(enrollment)
                        i += 1
                    except OSError:
                        break
            
            if enrollments:
                self.add_finding(Finding(
                    check_id="AAD-MDM-001",
                    title="MDM Enrollments Found",
                    severity=Severity.INFO,
                    description="Device has MDM enrollments configured.",
                    details=enrollments,
                    remediation="Review MDM policies for security compliance.",
                    mitre_attack=None
                ))
        except (FileNotFoundError, PermissionError):
            pass

    # --- Check 8: Windows Hello for Business ---
    def check_whfb(self) -> None:
        """Check Windows Hello for Business configuration."""
        self.log("Checking Windows Hello for Business...")
        
        ngc_set = self.aad_status.get("NgcSet", "NO")
        key_provider = self.aad_status.get("KeyProvider", "")
        
        whfb_info = {
            "ngc_enabled": ngc_set == "YES",
            "key_provider": key_provider,
            "tpm_protected": "Platform Crypto" in key_provider
        }
        
        # Check PIN complexity policy
        pin_policy_path = r"SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity"
        pin_settings = {}
        
        for setting in ["MinimumPINLength", "MaximumPINLength", "RequireDigits", 
                       "RequireLowercase", "RequireUppercase", "RequireSpecialCharacters"]:
            value = self.read_registry(winreg.HKEY_LOCAL_MACHINE, pin_policy_path, setting)
            if value is not None:
                pin_settings[setting] = value
        
        whfb_info["pin_policy"] = pin_settings if pin_settings else "Default (no policy)"
        
        issues = []
        
        if ngc_set == "YES" and not whfb_info["tpm_protected"]:
            issues.append("WHfB keys not TPM-protected")
        
        if pin_settings:
            min_length = pin_settings.get("MinimumPINLength", 4)
            if min_length < 6:
                issues.append(f"PIN minimum length is {min_length} (should be >= 6)")
        
        if issues:
            self.add_finding(Finding(
                check_id="AAD-WHFB-001",
                title="Windows Hello for Business Configuration Issues",
                severity=Severity.MEDIUM,
                description="Windows Hello for Business has configuration weaknesses.",
                details={"config": whfb_info, "issues": issues},
                remediation="Enforce TPM-backed keys and strong PIN policies via Intune/GPO.",
                mitre_attack="T1556 - Modify Authentication Process"
            ))

    # --- Check 9: Cached Logon Count ---
    def check_cached_logons(self) -> None:
        """Check cached logon configuration."""
        self.log("Checking cached logon settings...")
        
        cached_count = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "CachedLogonsCount"
        )
        
        if cached_count is not None:
            try:
                count = int(cached_count)
                if count > 4:
                    self.add_finding(Finding(
                        check_id="AAD-CACHE-002",
                        title="High Cached Logon Count",
                        severity=Severity.LOW,
                        description=f"Device caches {count} logons. High values increase "
                                   "risk of credential theft via offline attacks.",
                        details={"cached_logons_count": count},
                        remediation="Reduce CachedLogonsCount to 2-4 for balanced security. "
                                   "Set to 0-1 for high-security environments.",
                        mitre_attack="T1003.005 - OS Credential Dumping: Cached Domain Credentials"
                    ))
            except ValueError:
                pass

    # --- Check 10: Azure AD Roles in Local Admin ---
    def check_aad_local_admins(self) -> None:
        """Check for Azure AD accounts in local Administrators group."""
        self.log("Checking Azure AD accounts in local Administrators...")
        
        ps_cmd = """
        Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | 
            Select-Object Name, SID, PrincipalSource | ConvertTo-Json
        """
        
        output = self.run_powershell(ps_cmd)
        if output:
            try:
                members = json.loads(output)
                if not isinstance(members, list):
                    members = [members]
                
                # Azure AD SIDs start with S-1-12-1-
                aad_admins = [m for m in members 
                             if m.get("SID", "").startswith("S-1-12-1-") 
                             or m.get("PrincipalSource") == "AzureAD"]
                
                if aad_admins:
                    self.add_finding(Finding(
                        check_id="AAD-ADMIN-001",
                        title="Azure AD Accounts in Local Administrators",
                        severity=Severity.INFO,
                        description="Azure AD accounts have local administrator privileges.",
                        details=aad_admins,
                        remediation="Review Azure AD role assignments. Use Azure AD "
                                   "'Azure AD Joined Device Local Administrator' role sparingly.",
                        mitre_attack="T1078.004 - Valid Accounts: Cloud Accounts"
                    ))
            except json.JSONDecodeError:
                pass

    # --- Check 11: Browser SSO Configuration ---
    def check_browser_sso(self) -> None:
        """Check browser SSO and PRT cookie configuration."""
        self.log("Checking browser SSO configuration...")
        
        # Check BrowserCore presence
        browsercore_paths = [
            os.path.expandvars(r"%ProgramFiles%\Windows Security\BrowserCore\browsercore.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Windows Security\BrowserCore\browsercore.exe")
        ]
        
        browsercore_exists = any(os.path.exists(p) for p in browsercore_paths)
        
        # Check Edge/Chrome SSO settings
        chrome_policy = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Google\Chrome",
            "CloudAPAuthEnabled"
        )
        
        sso_config = {
            "browsercore_present": browsercore_exists,
            "chrome_cloudap_auth": chrome_policy
        }
        
        # Check for WAM (Web Account Manager) integration
        edge_profile = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default")
        if os.path.exists(edge_profile):
            sso_config["edge_profile_exists"] = True
        
        self.add_finding(Finding(
            check_id="AAD-SSO-001",
            title="Browser SSO Configuration",
            severity=Severity.INFO,
            description="Browser SSO allows PRT-based authentication to web applications.",
            details=sso_config,
            remediation="Browser SSO is normal for Azure AD devices. Ensure session "
                       "policies and Conditional Access are properly configured.",
            mitre_attack=None
        ))

    # --- Check 12: Credential Guard Status ---
    def check_credential_guard(self) -> None:
        """Check if Credential Guard is enabled."""
        self.log("Checking Credential Guard status...")
        
        ps_cmd = """
        Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue |
            Select-Object SecurityServicesRunning, VirtualizationBasedSecurityStatus | ConvertTo-Json
        """
        
        output = self.run_powershell(ps_cmd)
        
        cg_status = {
            "configured": False,
            "running": False,
            "vbs_status": "Unknown"
        }
        
        if output:
            try:
                data = json.loads(output)
                services = data.get("SecurityServicesRunning", [])
                vbs = data.get("VirtualizationBasedSecurityStatus", 0)
                
                # SecurityServicesRunning: 1 = Credential Guard
                cg_status["configured"] = 1 in services if services else False
                cg_status["running"] = vbs == 2  # 2 = Running
                cg_status["vbs_status"] = "Running" if vbs == 2 else "Not Running"
                cg_status["services"] = services
            except json.JSONDecodeError:
                pass
        
        if not cg_status["running"]:
            self.add_finding(Finding(
                check_id="AAD-CG-001",
                title="Credential Guard Not Running",
                severity=Severity.HIGH,
                description="Credential Guard is not running. DPAPI keys and cached credentials "
                           "are more vulnerable to extraction.",
                details=cg_status,
                remediation="Enable Credential Guard via Intune or Group Policy. "
                           "Requires VBS-capable hardware.",
                mitre_attack="T1003 - OS Credential Dumping"
            ))

    # --- Check 13: Hybrid Join Status ---
    def check_hybrid_join(self) -> None:
        """Check hybrid Azure AD join specific risks."""
        self.log("Checking hybrid join status...")
        
        if self.device_info.get("join_type") != "Hybrid Azure AD Join":
            return
        
        hybrid_info = {
            "azure_ad_joined": self.aad_status.get("AzureAdJoined"),
            "domain_joined": self.aad_status.get("DomainJoined"),
            "domain_name": self.aad_status.get("DomainName"),
            "on_prem_tgt": self.aad_status.get("OnPremTgt"),
            "cloud_tgt": self.aad_status.get("CloudTgt")
        }
        
        self.add_finding(Finding(
            check_id="AAD-HYBRID-001",
            title="Hybrid Azure AD Join Detected",
            severity=Severity.INFO,
            description="Device is hybrid Azure AD joined. Both on-premises AD and "
                       "Azure AD attack vectors apply.",
            details=hybrid_info,
            remediation="Ensure both on-prem AD and Azure AD security controls are aligned.",
            mitre_attack=None
        ))
        
        # Check for Seamless SSO (AZUREADSSOACC)
        klist_output = self.run_cmd("klist")
        if klist_output and "AZUREADSSOACC" in klist_output:
            self.add_finding(Finding(
                check_id="AAD-HYBRID-002",
                title="Seamless SSO Ticket Present",
                severity=Severity.INFO,
                description="Seamless SSO Kerberos ticket is present, enabling silent "
                           "authentication to Azure AD from domain-joined context.",
                details={"seamless_sso_active": True},
                remediation="Seamless SSO is convenient but increases attack surface. "
                           "Consider moving to Windows Hello for Business.",
                mitre_attack="T1558 - Steal or Forge Kerberos Tickets"
            ))

    # --- Check 14: DPAPI Protection ---
    def check_dpapi_protection(self) -> None:
        """Check DPAPI master key accessibility."""
        self.log("Checking DPAPI protection...")
        
        dpapi_path = os.path.expandvars(r"%APPDATA%\Microsoft\Protect")
        
        if os.path.exists(dpapi_path):
            try:
                master_keys = list(Path(dpapi_path).rglob("*"))
                key_info = []
                
                for mk in master_keys[:10]:
                    if mk.is_file():
                        key_info.append({
                            "name": mk.name,
                            "path": str(mk),
                            "size": mk.stat().st_size,
                            "modified": datetime.fromtimestamp(
                                mk.stat().st_mtime
                            ).isoformat()
                        })
                
                self.add_finding(Finding(
                    check_id="AAD-DPAPI-001",
                    title="DPAPI Master Keys Accessible",
                    severity=Severity.INFO,
                    description="DPAPI master keys are accessible. These protect Azure AD tokens, "
                               "browser passwords, and other sensitive data.",
                    details={
                        "path": dpapi_path,
                        "key_count": len(key_info),
                        "keys": key_info
                    },
                    remediation="DPAPI keys are protected by user password. Enable Credential Guard "
                               "to provide additional protection.",
                    mitre_attack="T1555.003 - Credentials from Password Stores: Credentials from Web Browsers"
                ))
            except PermissionError:
                pass

    # --- Check 15: Attack Tool Artifacts ---
    def check_attack_tool_artifacts(self) -> None:
        """Check for known Azure AD attack tool artifacts."""
        self.log("Checking for attack tool artifacts...")
        
        artifacts = {
            "roadtools": [
                os.path.expandvars(r"%USERPROFILE%\.roadtools_auth"),
                os.path.expandvars(r"%USERPROFILE%\roadrecon.db"),
            ],
            "aadInternals": [
                os.path.expandvars(r"%TEMP%\AADInternals"),
            ],
            "azurehound": [
                os.path.expandvars(r"%USERPROFILE%\azurehound"),
            ],
            "graphrunner": [
                os.path.expandvars(r"%USERPROFILE%\.graphrunner"),
            ]
        }
        
        found = []
        
        for tool, paths in artifacts.items():
            for path in paths:
                if os.path.exists(path):
                    found.append({"tool": tool, "path": path})
        
        # Check PowerShell history
        ps_history = os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        )
        
        suspicious_commands = []
        if os.path.exists(ps_history):
            try:
                with open(ps_history, 'r', errors='ignore') as f:
                    content = f.read()
                    patterns = [
                        "Get-AADInt", "Invoke-AADInt", "roadtools", "ROADrecon",
                        "azurehound", "GraphRunner", "TokenTactics", "AADInternals"
                    ]
                    for pattern in patterns:
                        if pattern.lower() in content.lower():
                            suspicious_commands.append(pattern)
            except Exception:
                pass
        
        if found or suspicious_commands:
            self.add_finding(Finding(
                check_id="AAD-IOC-001",
                title="Azure AD Attack Tool Indicators",
                severity=Severity.HIGH,
                description="Artifacts from known Azure AD attack tools detected.",
                details={
                    "file_artifacts": found,
                    "ps_history_matches": suspicious_commands
                },
                remediation="Investigate potential compromise. Review Azure AD sign-in logs "
                           "and audit logs for suspicious activity.",
                mitre_attack="T1588.002 - Obtain Capabilities: Tool"
            ))

    def run_all_checks(self) -> None:
        """Execute all Azure AD security checks."""
        self.collect_aad_status()
        
        # Skip if not Azure AD integrated
        if self.device_info.get("join_type") == "Not Azure AD integrated":
            click.secho("[!] Device is not Azure AD integrated. Skipping Azure AD checks.", 
                       fg="yellow")
            return
        
        checks = [
            self.check_key_protection,
            self.check_prt_status,
            self.check_token_caches,
            self.check_azure_cli_credentials,
            self.check_credential_manager_azure,
            self.check_intune_config,
            self.check_mdm_enrollment,
            self.check_whfb,
            self.check_cached_logons,
            self.check_aad_local_admins,
            self.check_browser_sso,
            self.check_credential_guard,
            self.check_hybrid_join,
            self.check_dpapi_protection,
            self.check_attack_tool_artifacts,
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                self.log(f"Check failed: {check.__name__}: {e}", "ERROR")

    def generate_report(self) -> Dict:
        """Generate the final audit report."""
        return {
            "device_info": self.device_info,
            "aad_status": {
                k: v for k, v in self.aad_status.items() 
                if k in ["AzureAdJoined", "DomainJoined", "DeviceId", "TenantId", 
                        "TenantName", "KeyProvider", "AzureAdPrt", "NgcSet"]
            },
            "summary": {
                "total_findings": len(self.findings),
                "critical": len([f for f in self.findings if f.severity == Severity.CRITICAL]),
                "high": len([f for f in self.findings if f.severity == Severity.HIGH]),
                "medium": len([f for f in self.findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in self.findings if f.severity == Severity.LOW]),
                "info": len([f for f in self.findings if f.severity == Severity.INFO])
            },
            "findings": [f.to_dict() for f in self.findings]
        }


# --- CLI entrypoint (Click) ---
@click.command()
@click.option("-o", "--output", type=click.Path(), help="Output JSON file path")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.option("--html", type=click.Path(), help="Generate HTML report")
@click.version_option(version=VERSION)
def cli(output: Optional[str], verbose: bool, html: Optional[str]) -> None:
    """Azure AD Security Auditor for Windows 11"""
    
    click.secho("\n╔══════════════════════════════════════════════════════════╗", fg="cyan")
    click.secho("║       Windows 11 Azure AD Security Audit v" + VERSION + "          ║", fg="cyan")
    click.secho("║       PRT, Token Cache & Cloud Identity Checks           ║", fg="cyan")
    click.secho("╚══════════════════════════════════════════════════════════╝\n", fg="cyan")
    
    auditor = AzureADAuditor(verbose=verbose)
    
    click.echo("[*] Starting Azure AD security audit...")
    auditor.run_all_checks()
    
    report = auditor.generate_report()
    
    # Print device info
    click.echo("\n" + "=" * 60)
    click.secho("DEVICE INFORMATION", fg="white", bold=True)
    click.echo("=" * 60)
    click.echo(f"Hostname:   {report['device_info'].get('hostname')}")
    click.echo(f"User:       {report['device_info'].get('domain')}\\{report['device_info'].get('username')}")
    click.echo(f"Join Type:  {report['device_info'].get('join_type')}")
    click.echo(f"Tenant:     {report['device_info'].get('tenant_name')}")
    click.echo(f"Device ID:  {report['device_info'].get('device_id')}")
    click.echo(f"PRT:        {report['device_info'].get('prt_present')}")
    click.echo(f"WHfB:       {report['device_info'].get('ngc_set')}")
    click.echo(f"MDM:        {report['device_info'].get('mdm_enrolled')}")
    
    # Print summary
    click.echo("\n" + "=" * 60)
    click.secho("AUDIT SUMMARY", fg="white", bold=True)
    click.echo("=" * 60)
    
    summary = report["summary"]
    click.secho(f"CRITICAL: {summary['critical']}", fg="red" if summary['critical'] > 0 else "white")
    click.secho(f"HIGH:     {summary['high']}", fg="yellow" if summary['high'] > 0 else "white")
    click.secho(f"MEDIUM:   {summary['medium']}", fg="cyan" if summary['medium'] > 0 else "white")
    click.secho(f"LOW:      {summary['low']}", fg="white")
    click.secho(f"INFO:     {summary['info']}", fg="green")
    click.echo("=" * 60)
    
    # Output to file
    if output:
        with open(output, 'w') as f:
            json.dump(report, f, indent=2)
        click.echo(f"\n[+] JSON report saved to: {output}")
    
    # Generate HTML report
    if html:
        html_content = generate_html_report(report)
        with open(html, 'w') as f:
            f.write(html_content)
        click.echo(f"[+] HTML report saved to: {html}")


def generate_html_report(report: Dict) -> str:
    """Generate an HTML report from the audit results."""
    severity_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#6c757d",
        "INFO": "#28a745"
    }
    
    findings_html = ""
    for f in report["findings"]:
        color = severity_colors.get(f["severity"], "#6c757d")
        mitre = f"<p><em>MITRE ATT&CK: {f['mitre_attack']}</em></p>" if f.get('mitre_attack') else ""
        
        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color};">
            <h3><span class="severity" style="background-color: {color};">{f['severity']}</span> 
                [{f['check_id']}] {f['title']}</h3>
            <p><strong>Description:</strong> {f['description']}</p>
            <p><strong>Details:</strong></p>
            <pre>{json.dumps(f['details'], indent=2)}</pre>
            <p><strong>Remediation:</strong> {f['remediation']}</p>
            {mitre}
        </div>
        """
    
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Azure AD Security Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
        .summary-item {{ padding: 15px 25px; border-radius: 6px; color: white; text-align: center; min-width: 100px; }}
        .finding {{ background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 6px; }}
        .finding h3 {{ margin-top: 0; }}
        .severity {{ padding: 4px 10px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; }}
        pre {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 4px; overflow-x: auto; }}
        .info {{ background: #e7f3ff; padding: 15px; border-radius: 6px; margin-bottom: 20px; }}
        .device-info {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }}
        .device-info div {{ padding: 10px; background: #f0f0f0; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Azure AD Security Audit Report</h1>
        
        <h2>Device Information</h2>
        <div class="device-info">
            <div><strong>Hostname:</strong> {report['device_info'].get('hostname')}</div>
            <div><strong>User:</strong> {report['device_info'].get('username')}</div>
            <div><strong>Join Type:</strong> {report['device_info'].get('join_type')}</div>
            <div><strong>Tenant:</strong> {report['device_info'].get('tenant_name', 'N/A')}</div>
            <div><strong>Device ID:</strong> {report['device_info'].get('device_id', 'N/A')[:20]}...</div>
            <div><strong>PRT Present:</strong> {report['device_info'].get('prt_present')}</div>
            <div><strong>WHfB:</strong> {report['device_info'].get('ngc_set')}</div>
            <div><strong>MDM:</strong> {report['device_info'].get('mdm_enrolled')}</div>
            <div><strong>Audit Time:</strong> {report['device_info'].get('audit_time')}</div>
        </div>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-item" style="background: #dc3545;">CRITICAL<br><strong>{report['summary']['critical']}</strong></div>
            <div class="summary-item" style="background: #fd7e14;">HIGH<br><strong>{report['summary']['high']}</strong></div>
            <div class="summary-item" style="background: #ffc107; color: #333;">MEDIUM<br><strong>{report['summary']['medium']}</strong></div>
            <div class="summary-item" style="background: #6c757d;">LOW<br><strong>{report['summary']['low']}</strong></div>
            <div class="summary-item" style="background: #28a745;">INFO<br><strong>{report['summary']['info']}</strong></div>
        </div>
        
        <h2>Findings</h2>
        {findings_html if findings_html else '<p>No findings detected.</p>'}
    </div>
</body>
</html>"""


if __name__ == "__main__":
    cli()
