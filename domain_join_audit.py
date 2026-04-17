#!/usr/bin/env python3
"""
domain_join_audit.py — Windows Domain/Azure AD Join Security Auditor
Author : ss
Purpose: Comprehensive audit of how a Windows PC is joined to domain (Workgroup,
         On-Prem AD, Azure AD, Hybrid) and identification of security weaknesses
         in the join configuration, authentication mechanisms, and trust relationships.
Usage  : python domain_join_audit.py [options]

AUTHORISED USE ONLY. Run this tool only against systems you own or have
explicit written permission to test.
"""

# --- stdlib imports ---
import os
import sys
import json
import subprocess
import re
import socket
import winreg
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict

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


class JoinType(Enum):
    WORKGROUP = "Workgroup (Standalone)"
    ONPREM_AD = "On-Premises Active Directory"
    AZURE_AD = "Azure AD Join"
    HYBRID_AAD = "Hybrid Azure AD Join"
    AAD_REGISTERED = "Azure AD Registered (Workplace Join)"
    UNKNOWN = "Unknown"


@dataclass
class Finding:
    """Represents a security finding."""
    check_id: str
    title: str
    severity: Severity
    category: str
    description: str
    details: Any
    remediation: str
    references: List[str] = field(default_factory=list)
    mitre_attack: Optional[str] = None

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['severity'] = self.severity.value
        return d


@dataclass
class JoinInfo:
    """Domain/Azure AD join information."""
    join_type: JoinType
    hostname: str
    domain_name: Optional[str] = None
    dns_domain: Optional[str] = None
    dc_name: Optional[str] = None
    dc_ip: Optional[str] = None
    site_name: Optional[str] = None
    forest_name: Optional[str] = None
    tenant_id: Optional[str] = None
    tenant_name: Optional[str] = None
    device_id: Optional[str] = None
    mdm_url: Optional[str] = None
    key_provider: Optional[str] = None
    prt_present: bool = False
    ngc_enabled: bool = False
    sso_enabled: bool = False
    machine_account: Optional[str] = None
    domain_sid: Optional[str] = None
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d['join_type'] = self.join_type.value
        return d


class DomainJoinAuditor:
    """Comprehensive Domain/Azure AD Join Security Auditor."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: List[Finding] = []
        self.join_info: Optional[JoinInfo] = None
        self.dsregcmd_data: Dict[str, str] = {}
        self.nltest_data: Dict[str, str] = {}

    def log(self, msg: str, level: str = "INFO") -> None:
        """Log messages if verbose mode is enabled."""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            colors = {"INFO": "white", "WARN": "yellow", "ERROR": "red", "DEBUG": "cyan"}
            click.secho(f"[{timestamp}] [{level}] {msg}", fg=colors.get(level, "white"))

    def run_cmd(self, command: str, timeout: int = 30) -> Tuple[Optional[str], Optional[str]]:
        """Execute command and return stdout, stderr."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out: {command[:50]}...", "WARN")
            return None, "Timeout"
        except Exception as e:
            self.log(f"Command error: {e}", "ERROR")
            return None, str(e)

    def run_powershell(self, command: str, timeout: int = 30) -> Optional[str]:
        """Execute PowerShell command and return output."""
        stdout, _ = self.run_cmd(
            f'powershell -NoProfile -NonInteractive -Command "{command}"',
            timeout
        )
        return stdout

    def read_registry(self, hive: int, path: str, value: str) -> Optional[Any]:
        """Read a registry value safely."""
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                data, _ = winreg.QueryValueEx(key, value)
                return data
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def read_registry_subkeys(self, hive: int, path: str) -> List[str]:
        """Read all subkey names from a registry path."""
        subkeys = []
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        subkeys.append(winreg.EnumKey(key, i))
                        i += 1
                    except OSError:
                        break
        except (FileNotFoundError, PermissionError):
            pass
        return subkeys

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)
        if self.verbose:
            color_map = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "yellow", 
                Severity.MEDIUM: "cyan",
                Severity.LOW: "white",
                Severity.INFO: "green"
            }
            click.secho(
                f"[{finding.severity.value}] [{finding.category}] {finding.title}",
                fg=color_map.get(finding.severity, "white")
            )

    # =========================================================================
    # PHASE 1: Determine Join Type
    # =========================================================================
    
    def parse_dsregcmd(self) -> Dict[str, str]:
        """Parse dsregcmd /status output."""
        output, _ = self.run_cmd("dsregcmd /status")
        if not output:
            return {}
        
        result = {}
        current_section = ""
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('+'):
                current_section = line.strip('+-').strip()
            elif ':' in line and not line.startswith('|'):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    result[key] = value
        
        self.dsregcmd_data = result
        return result

    def parse_nltest(self) -> Dict[str, str]:
        """Parse nltest /dsgetdc output for DC info."""
        output, _ = self.run_cmd("nltest /dsgetdc:")
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
        
        self.nltest_data = result
        return result

    def determine_join_type(self) -> JoinInfo:
        """Determine the domain/Azure AD join type and collect join information."""
        self.log("Determining join type...")
        
        # Parse dsregcmd first
        dsreg = self.parse_dsregcmd()
        
        # Get basic info
        hostname = os.environ.get("COMPUTERNAME", socket.gethostname())
        
        # Check join states
        azure_ad_joined = dsreg.get("AzureAdJoined", "NO") == "YES"
        domain_joined = dsreg.get("DomainJoined", "NO") == "YES"
        workplace_joined = dsreg.get("WorkplaceJoined", "NO") == "YES"
        
        # Determine join type
        if azure_ad_joined and domain_joined:
            join_type = JoinType.HYBRID_AAD
        elif azure_ad_joined and not domain_joined:
            join_type = JoinType.AZURE_AD
        elif workplace_joined:
            join_type = JoinType.AAD_REGISTERED
        elif domain_joined:
            join_type = JoinType.ONPREM_AD
        else:
            join_type = JoinType.WORKGROUP
        
        # Build join info
        join_info = JoinInfo(
            join_type=join_type,
            hostname=hostname,
            domain_name=dsreg.get("DomainName") or os.environ.get("USERDOMAIN"),
            dns_domain=dsreg.get("DnsDomainName"),
            tenant_id=dsreg.get("TenantId"),
            tenant_name=dsreg.get("TenantName"),
            device_id=dsreg.get("DeviceId"),
            mdm_url=dsreg.get("MdmUrl"),
            key_provider=dsreg.get("KeyProvider"),
            prt_present=dsreg.get("AzureAdPrt", "NO") == "YES",
            ngc_enabled=dsreg.get("NgcSet", "NO") == "YES",
        )
        
        # Get DC info for domain-joined machines
        if domain_joined:
            nltest = self.parse_nltest()
            join_info.dc_name = nltest.get("DC")
            join_info.dc_ip = nltest.get("Address")
            join_info.site_name = nltest.get("Our Site Name")
            join_info.forest_name = nltest.get("Forest Name")
            
            # Get machine account name
            join_info.machine_account = f"{hostname}$"
        
        # Check for Seamless SSO
        if domain_joined or azure_ad_joined:
            # Check for AZUREADSSOACC computer account usage
            klist_out, _ = self.run_cmd("klist")
            if klist_out and "AZUREADSSOACC" in klist_out:
                join_info.sso_enabled = True
        
        self.join_info = join_info
        return join_info

    # =========================================================================
    # PHASE 2: Generic Weaknesses (All Join Types)
    # =========================================================================

    def check_machine_account_password_age(self) -> None:
        """Check machine account password age (domain-joined only)."""
        if self.join_info.join_type not in [JoinType.ONPREM_AD, JoinType.HYBRID_AAD]:
            return
        
        self.log("Checking machine account password age...")
        
        # Check registry for last password change
        pwd_last_set = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
            "PwdLastSet"
        )
        
        # Check machine account password age policy
        max_age = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
            "MaximumPasswordAge"
        )
        
        disable_pwd_change = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
            "DisablePasswordChange"
        )
        
        if disable_pwd_change == 1:
            self.add_finding(Finding(
                check_id="JOIN-PWD-001",
                title="Machine Account Password Change Disabled",
                severity=Severity.HIGH,
                category="Machine Account",
                description="Machine account password automatic rotation is disabled. "
                           "This increases risk of credential theft and replay attacks.",
                details={
                    "DisablePasswordChange": True,
                    "MaximumPasswordAge": max_age
                },
                remediation="Set DisablePasswordChange to 0 and ensure MaximumPasswordAge "
                           "is set to 30 days or less.",
                references=["https://docs.microsoft.com/en-us/windows-server/security/kerberos/password-policy"],
                mitre_attack="T1098 - Account Manipulation"
            ))

    def check_secure_channel(self) -> None:
        """Check Netlogon secure channel configuration."""
        if self.join_info.join_type not in [JoinType.ONPREM_AD, JoinType.HYBRID_AAD]:
            return
        
        self.log("Checking secure channel configuration...")
        
        # Test secure channel
        output, err = self.run_cmd("nltest /sc_verify:" + (self.join_info.domain_name or ""))
        
        sc_status = {
            "command_output": output,
            "error": err
        }
        
        if output and "NERR_Success" not in output:
            self.add_finding(Finding(
                check_id="JOIN-SC-001",
                title="Secure Channel Verification Failed",
                severity=Severity.HIGH,
                category="Domain Trust",
                description="The secure channel between this machine and the domain controller "
                           "could not be verified. This may indicate trust relationship issues.",
                details=sc_status,
                remediation="Run 'Test-ComputerSecureChannel -Repair' or rejoin the domain.",
                references=["https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/secure-channel-broken"],
                mitre_attack="T1484.002 - Domain Trust Modification"
            ))
        
        # Check secure channel signing/sealing requirements
        sign_secure = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
            "SignSecureChannel"
        )
        
        seal_secure = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
            "SealSecureChannel"
        )
        
        require_sign = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
            "RequireSignOrSeal"
        )
        
        if require_sign != 1:
            self.add_finding(Finding(
                check_id="JOIN-SC-002",
                title="Secure Channel Signing/Sealing Not Required",
                severity=Severity.MEDIUM,
                category="Domain Trust",
                description="Secure channel signing or sealing is not required. "
                           "This allows potential MITM attacks on domain traffic.",
                details={
                    "SignSecureChannel": sign_secure,
                    "SealSecureChannel": seal_secure,
                    "RequireSignOrSeal": require_sign
                },
                remediation="Set RequireSignOrSeal to 1 in Netlogon parameters.",
                references=["CIS Benchmark 2.3.6.x"],
                mitre_attack="T1557 - Adversary-in-the-Middle"
            ))

    def check_ldap_signing(self) -> None:
        """Check LDAP signing requirements."""
        if self.join_info.join_type not in [JoinType.ONPREM_AD, JoinType.HYBRID_AAD]:
            return
        
        self.log("Checking LDAP signing configuration...")
        
        ldap_signing = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LDAP",
            "LDAPClientIntegrity"
        )
        
        # 0 = signing disabled, 1 = negotiate, 2 = required
        if ldap_signing is None or ldap_signing < 2:
            self.add_finding(Finding(
                check_id="JOIN-LDAP-001",
                title="LDAP Signing Not Required",
                severity=Severity.MEDIUM,
                category="LDAP Security",
                description="LDAP client signing is not required. This enables LDAP "
                           "relay attacks and credential interception.",
                details={
                    "LDAPClientIntegrity": ldap_signing,
                    "recommended": 2
                },
                remediation="Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity to 2.",
                references=["CVE-2017-8563", "CIS Benchmark 2.3.11.8"],
                mitre_attack="T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay"
            ))

    def check_smb_signing(self) -> None:
        """Check SMB signing configuration."""
        self.log("Checking SMB signing configuration...")
        
        # Client settings
        client_sign = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            "RequireSecuritySignature"
        )
        
        client_enable = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            "EnableSecuritySignature"
        )
        
        # Server settings
        server_sign = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "RequireSecuritySignature"
        )
        
        smb_config = {
            "client_require_signing": client_sign == 1,
            "client_enable_signing": client_enable == 1,
            "server_require_signing": server_sign == 1
        }
        
        if client_sign != 1:
            self.add_finding(Finding(
                check_id="JOIN-SMB-001",
                title="SMB Client Signing Not Required",
                severity=Severity.HIGH,
                category="SMB Security",
                description="SMB client signing is not required. This enables SMB relay "
                           "attacks against this machine.",
                details=smb_config,
                remediation="Enable 'Microsoft network client: Digitally sign communications (always)'.",
                references=["CIS Benchmark 2.3.8.1", "CVE-2020-1472"],
                mitre_attack="T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay"
            ))

    def check_ntlm_settings(self) -> None:
        """Check NTLM authentication settings."""
        self.log("Checking NTLM configuration...")
        
        lsa_path = r"SYSTEM\CurrentControlSet\Control\Lsa"
        
        # LMCompatibilityLevel
        lm_compat = self.read_registry(winreg.HKEY_LOCAL_MACHINE, lsa_path, "LmCompatibilityLevel")
        
        # NTLMMinClientSec / NTLMMinServerSec
        ntlm_client_sec = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
            "NTLMMinClientSec"
        )
        
        ntlm_server_sec = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
            "NTLMMinServerSec"
        )
        
        # RestrictSendingNTLMTraffic
        restrict_ntlm = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
            "RestrictSendingNTLMTraffic"
        )
        
        ntlm_config = {
            "LmCompatibilityLevel": lm_compat,
            "NTLMMinClientSec": ntlm_client_sec,
            "NTLMMinServerSec": ntlm_server_sec,
            "RestrictSendingNTLMTraffic": restrict_ntlm
        }
        
        issues = []
        
        # LM Compatibility should be 5 (NTLMv2 only)
        if lm_compat is None or lm_compat < 3:
            issues.append(f"LM/NTLM allowed (LmCompatibilityLevel={lm_compat})")
        
        # NTLM minimum security should require 128-bit encryption
        if ntlm_client_sec is None or not (ntlm_client_sec & 0x20000000):
            issues.append("NTLM client doesn't require 128-bit encryption")
        
        if issues:
            self.add_finding(Finding(
                check_id="JOIN-NTLM-001",
                title="Weak NTLM Configuration",
                severity=Severity.HIGH,
                category="Authentication",
                description="NTLM authentication is not configured securely. "
                           "This allows pass-the-hash and relay attacks.",
                details={"config": ntlm_config, "issues": issues},
                remediation="Set LmCompatibilityLevel to 5, enable NTLMv2 only, "
                           "require 128-bit encryption.",
                references=["CIS Benchmark 2.3.11.7", "MS-NLMP"],
                mitre_attack="T1550.002 - Pass the Hash"
            ))

    def check_kerberos_settings(self) -> None:
        """Check Kerberos configuration."""
        if self.join_info.join_type not in [JoinType.ONPREM_AD, JoinType.HYBRID_AAD]:
            return
        
        self.log("Checking Kerberos configuration...")
        
        krb_path = r"SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
        
        # Check supported encryption types
        supported_etypes = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE, krb_path, "SupportedEncryptionTypes"
        )
        
        # Check Kerberos delegation settings
        allow_tgt_delegation = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE, krb_path, "AllowTgtSessionKey"
        )
        
        # Decode encryption types
        etypes_decoded = []
        if supported_etypes:
            if supported_etypes & 0x1:
                etypes_decoded.append("DES_CBC_CRC (WEAK)")
            if supported_etypes & 0x2:
                etypes_decoded.append("DES_CBC_MD5 (WEAK)")
            if supported_etypes & 0x4:
                etypes_decoded.append("RC4_HMAC")
            if supported_etypes & 0x8:
                etypes_decoded.append("AES128_HMAC")
            if supported_etypes & 0x10:
                etypes_decoded.append("AES256_HMAC")
        
        krb_config = {
            "SupportedEncryptionTypes": supported_etypes,
            "DecodedTypes": etypes_decoded,
            "AllowTgtSessionKey": allow_tgt_delegation
        }
        
        # Check for weak encryption
        if supported_etypes and (supported_etypes & 0x3):
            self.add_finding(Finding(
                check_id="JOIN-KRB-001",
                title="Weak Kerberos Encryption Enabled",
                severity=Severity.MEDIUM,
                category="Kerberos",
                description="DES encryption is enabled for Kerberos. DES is cryptographically "
                           "broken and should be disabled.",
                details=krb_config,
                remediation="Disable DES encryption types via Group Policy. Enable only "
                           "AES128 and AES256.",
                references=["CIS Benchmark 18.3.x", "MS-KILE"],
                mitre_attack="T1558 - Steal or Forge Kerberos Tickets"
            ))

    def check_credential_caching(self) -> None:
        """Check credential caching configuration."""
        self.log("Checking credential caching...")
        
        # Cached logons count
        cached_logons = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "CachedLogonsCount"
        )
        
        # WDigest plain-text passwords
        wdigest_uselogon = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "UseLogonCredential"
        )
        
        cache_config = {
            "CachedLogonsCount": cached_logons,
            "WDigestUseLogonCredential": wdigest_uselogon
        }
        
        if wdigest_uselogon == 1:
            self.add_finding(Finding(
                check_id="JOIN-CACHE-001",
                title="WDigest Plain-Text Credentials Enabled",
                severity=Severity.CRITICAL,
                category="Credential Storage",
                description="WDigest is configured to store plain-text passwords in memory. "
                           "This enables trivial credential theft with tools like Mimikatz.",
                details=cache_config,
                remediation="Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential to 0.",
                references=["KB2871997", "CIS Benchmark"],
                mitre_attack="T1003.001 - LSASS Memory"
            ))
        
        try:
            count = int(cached_logons) if cached_logons else 10
            if count > 4:
                self.add_finding(Finding(
                    check_id="JOIN-CACHE-002",
                    title="High Cached Logon Count",
                    severity=Severity.LOW,
                    category="Credential Storage",
                    description=f"Device caches {count} domain logons. High values increase "
                               "offline credential attack risk.",
                    details=cache_config,
                    remediation="Reduce CachedLogonsCount to 2-4.",
                    references=["CIS Benchmark 18.9.14.1"],
                    mitre_attack="T1003.005 - Cached Domain Credentials"
                ))
        except (ValueError, TypeError):
            pass

    def check_lsa_protection(self) -> None:
        """Check LSA protection settings."""
        self.log("Checking LSA protection...")
        
        lsa_path = r"SYSTEM\CurrentControlSet\Control\Lsa"
        
        run_as_ppl = self.read_registry(winreg.HKEY_LOCAL_MACHINE, lsa_path, "RunAsPPL")
        
        # Check Credential Guard
        cg_config = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "EnableVirtualizationBasedSecurity"
        )
        
        lsa_cfg_flags = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "LsaCfgFlags"
        )
        
        protection_status = {
            "RunAsPPL": run_as_ppl,
            "VBS_Enabled": cg_config,
            "LsaCfgFlags": lsa_cfg_flags,
            "CredentialGuard": lsa_cfg_flags == 1 if lsa_cfg_flags else False
        }
        
        if run_as_ppl != 1:
            self.add_finding(Finding(
                check_id="JOIN-LSA-001",
                title="LSA Protection (PPL) Not Enabled",
                severity=Severity.HIGH,
                category="Credential Protection",
                description="LSA is not running as a Protected Process Light. This makes "
                           "credential extraction from LSASS easier.",
                details=protection_status,
                remediation="Enable LSA Protection: Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL to 1.",
                references=["https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"],
                mitre_attack="T1003.001 - LSASS Memory"
            ))
        
        if not protection_status["CredentialGuard"]:
            self.add_finding(Finding(
                check_id="JOIN-LSA-002",
                title="Credential Guard Not Enabled",
                severity=Severity.MEDIUM,
                category="Credential Protection",
                description="Credential Guard is not enabled. VBS-based isolation of "
                           "credentials provides strong protection against credential theft.",
                details=protection_status,
                remediation="Enable Credential Guard via Intune or Group Policy on supported hardware.",
                references=["https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard"],
                mitre_attack="T1003 - OS Credential Dumping"
            ))

    # =========================================================================
    # PHASE 3: On-Premises AD Specific Weaknesses
    # =========================================================================

    def check_spn_configuration(self) -> None:
        """Check for SPN-related issues (Kerberoasting exposure)."""
        if self.join_info.join_type not in [JoinType.ONPREM_AD, JoinType.HYBRID_AAD]:
            return
        
        self.log("Checking SPN configuration...")
        
        # Check if current machine has SPNs registered
        output = self.run_powershell(
            "setspn -L $env:COMPUTERNAME 2>$null"
        )
        
        spns = []
        if output:
            for line in output.split('\n'):
                line = line.strip()
                if line and '/' in line:
                    spns.append(line)
        
        if spns:
            self.add_finding(Finding(
                check_id="JOIN-SPN-001",
                title="Service Principal Names Registered",
                severity=Severity.INFO,
                category="Kerberos",
                description="This machine has SPNs registered. These are normal for "
                           "domain-joined machines but can be targets for Kerberoasting if "
                           "associated with user accounts.",
                details={"spns": spns},
                remediation="Review SPNs and ensure they are associated with machine accounts "
                           "or use Group Managed Service Accounts (gMSA).",
                references=["https://attack.mitre.org/techniques/T1558/003/"],
                mitre_attack="T1558.003 - Kerberoasting"
            ))

    def check_delegation_settings(self) -> None:
        """Check for dangerous delegation configurations."""
        if self.join_info.join_type not in [JoinType.ONPREM_AD, JoinType.HYBRID_AAD]:
            return
        
        self.log("Checking delegation settings...")
        
        # Check machine account delegation (requires AD query, may not work without admin)
        # We'll check local indicators
        
        allow_delegation = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters",
            "AllowTgtSessionKey"
        )
        
        if allow_delegation == 1:
            self.add_finding(Finding(
                check_id="JOIN-DELEG-001",
                title="TGT Session Key Export Allowed",
                severity=Severity.MEDIUM,
                category="Kerberos Delegation",
                description="TGT session key export is allowed. This can facilitate "
                           "Kerberos delegation attacks.",
                details={"AllowTgtSessionKey": True},
                remediation="Set AllowTgtSessionKey to 0 unless specifically required.",
                references=["MS-KILE", "S4U2Self"],
                mitre_attack="T1558.001 - Golden Ticket"
            ))

    def check_dc_connectivity(self) -> None:
        """Check domain controller connectivity and health."""
        if self.join_info.join_type not in [JoinType.ONPREM_AD, JoinType.HYBRID_AAD]:
            return
        
        self.log("Checking DC connectivity...")
        
        # Run nltest to check DC
        output, err = self.run_cmd(f"nltest /dsgetdc:{self.join_info.domain_name}")
        
        dc_info = {
            "output": output,
            "error": err,
            "dc_name": self.join_info.dc_name,
            "dc_ip": self.join_info.dc_ip
        }
        
        # Check for DC failure
        if err or (output and "ERROR" in output.upper()):
            self.add_finding(Finding(
                check_id="JOIN-DC-001",
                title="Domain Controller Connectivity Issue",
                severity=Severity.HIGH,
                category="Domain Trust",
                description="Unable to contact domain controller. This may cause "
                           "authentication failures and policy update issues.",
                details=dc_info,
                remediation="Verify network connectivity to domain controllers. Check DNS settings.",
                references=["https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/how-domain-controllers-are-located"],
                mitre_attack=None
            ))

    def check_gpo_security(self) -> None:
        """Check Group Policy security settings."""
        if self.join_info.join_type not in [JoinType.ONPREM_AD, JoinType.HYBRID_AAD]:
            return
        
        self.log("Checking Group Policy security...")
        
        # Check GPO refresh interval
        gpo_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine"
        
        # Get last GPO refresh time
        last_refresh = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            gpo_path,
            "LastGPORefreshTime"
        )
        
        # Check background refresh
        bg_refresh_disabled = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\System",
            "DisableBkGndGroupPolicy"
        )
        
        gpo_status = {
            "last_refresh": last_refresh,
            "background_refresh_disabled": bg_refresh_disabled == 1
        }
        
        if bg_refresh_disabled == 1:
            self.add_finding(Finding(
                check_id="JOIN-GPO-001",
                title="Background Group Policy Refresh Disabled",
                severity=Severity.MEDIUM,
                category="Group Policy",
                description="Background GPO refresh is disabled. Security policies may not "
                           "be applied in a timely manner.",
                details=gpo_status,
                remediation="Enable background Group Policy refresh.",
                references=["https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn265973(v=ws.11)"],
                mitre_attack="T1484.001 - Group Policy Modification"
            ))

    # =========================================================================
    # PHASE 4: Azure AD Specific Weaknesses
    # =========================================================================

    def check_prt_protection(self) -> None:
        """Check PRT protection level."""
        if self.join_info.join_type not in [JoinType.AZURE_AD, JoinType.HYBRID_AAD, JoinType.AAD_REGISTERED]:
            return
        
        self.log("Checking PRT protection...")
        
        key_provider = self.dsregcmd_data.get("KeyProvider", "")
        prt_present = self.dsregcmd_data.get("AzureAdPrt", "NO") == "YES"
        
        prt_status = {
            "prt_present": prt_present,
            "key_provider": key_provider,
            "tpm_protected": "Platform Crypto" in key_provider
        }
        
        if prt_present and "Software" in key_provider:
            self.add_finding(Finding(
                check_id="JOIN-PRT-001",
                title="PRT Keys Not TPM-Protected",
                severity=Severity.HIGH,
                category="Azure AD",
                description="Primary Refresh Token is protected by software keys, not TPM. "
                           "This makes PRT extraction significantly easier with SYSTEM access.",
                details=prt_status,
                remediation="Re-register the device on TPM-equipped hardware with TPM enabled in BIOS.",
                references=["https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token"],
                mitre_attack="T1528 - Steal Application Access Token"
            ))

    def check_device_registration_security(self) -> None:
        """Check Azure AD device registration security."""
        if self.join_info.join_type not in [JoinType.AZURE_AD, JoinType.HYBRID_AAD, JoinType.AAD_REGISTERED]:
            return
        
        self.log("Checking device registration security...")
        
        # Check device certificate
        device_cert_thumbprint = self.dsregcmd_data.get("Thumbprint")
        transport_key = self.dsregcmd_data.get("TransportKeyExists", "NO") == "YES"
        device_auth_status = self.dsregcmd_data.get("DeviceAuthStatus")
        
        reg_status = {
            "device_id": self.join_info.device_id,
            "thumbprint": device_cert_thumbprint,
            "transport_key_exists": transport_key,
            "device_auth_status": device_auth_status
        }
        
        if device_auth_status and "SUCCESS" not in device_auth_status.upper():
            self.add_finding(Finding(
                check_id="JOIN-REG-001",
                title="Device Authentication Status Issue",
                severity=Severity.MEDIUM,
                category="Azure AD",
                description="Device authentication status indicates potential issues with "
                           "Azure AD registration.",
                details=reg_status,
                remediation="Run 'dsregcmd /status' to diagnose. Consider re-registering the device.",
                references=["https://docs.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-device-dsregcmd"],
                mitre_attack=None
            ))

    def check_mdm_configuration(self) -> None:
        """Check MDM/Intune enrollment and configuration."""
        if not self.join_info.mdm_url:
            if self.join_info.join_type in [JoinType.AZURE_AD, JoinType.HYBRID_AAD]:
                self.add_finding(Finding(
                    check_id="JOIN-MDM-001",
                    title="Device Not MDM Enrolled",
                    severity=Severity.LOW,
                    category="Device Management",
                    description="Azure AD joined device is not enrolled in MDM/Intune. "
                               "Device may lack security policies and compliance monitoring.",
                    details={"mdm_url": None, "join_type": self.join_info.join_type.value},
                    remediation="Enroll the device in Intune for policy management and compliance.",
                    references=["https://docs.microsoft.com/en-us/mem/intune/enrollment/windows-enrollment-methods"],
                    mitre_attack=None
                ))
            return
        
        self.log("Checking MDM configuration...")
        
        # Check MDM enrollment details
        mdm_info = {
            "mdm_url": self.join_info.mdm_url,
            "compliance_url": self.dsregcmd_data.get("MdmComplianceUrl"),
            "tou_url": self.dsregcmd_data.get("MdmTouUrl")
        }
        
        # Check enrollment registry
        enrollments = self.read_registry_subkeys(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Enrollments"
        )
        
        mdm_info["enrollment_count"] = len(enrollments)
        
        self.add_finding(Finding(
            check_id="JOIN-MDM-002",
            title="MDM Enrollment Status",
            severity=Severity.INFO,
            category="Device Management",
            description="Device is enrolled in MDM.",
            details=mdm_info,
            remediation="Ensure compliance policies are properly configured.",
            references=["https://docs.microsoft.com/en-us/mem/intune/protect/compliance-policy-monitor"],
            mitre_attack=None
        ))

    def check_conditional_access_indicators(self) -> None:
        """Check indicators related to Conditional Access."""
        if self.join_info.join_type not in [JoinType.AZURE_AD, JoinType.HYBRID_AAD]:
            return
        
        self.log("Checking Conditional Access indicators...")
        
        # Check device compliance state
        is_compliant = self.dsregcmd_data.get("IsCompliant")
        is_managed = self.dsregcmd_data.get("IsManagedByMdm")
        
        ca_status = {
            "is_compliant": is_compliant,
            "is_managed_by_mdm": is_managed,
            "whfb_enabled": self.join_info.ngc_enabled
        }
        
        if is_compliant == "NO":
            self.add_finding(Finding(
                check_id="JOIN-CA-001",
                title="Device Not Compliant",
                severity=Severity.MEDIUM,
                category="Conditional Access",
                description="Device is not marked as compliant. This may block access to "
                           "resources protected by compliance-based Conditional Access policies.",
                details=ca_status,
                remediation="Review Intune compliance policies and remediate non-compliant settings.",
                references=["https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-conditions"],
                mitre_attack=None
            ))

    def check_whfb_configuration(self) -> None:
        """Check Windows Hello for Business configuration."""
        if self.join_info.join_type not in [JoinType.AZURE_AD, JoinType.HYBRID_AAD]:
            return
        
        self.log("Checking Windows Hello for Business...")
        
        ngc_set = self.dsregcmd_data.get("NgcSet", "NO") == "YES"
        key_provider = self.dsregcmd_data.get("KeyProvider", "")
        
        # Check PIN complexity policy
        pin_path = r"SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity"
        
        pin_config = {}
        for setting in ["MinimumPINLength", "MaximumPINLength", "RequireDigits",
                       "RequireLowercase", "RequireUppercase", "RequireSpecialCharacters",
                       "History", "Expiration"]:
            val = self.read_registry(winreg.HKEY_LOCAL_MACHINE, pin_path, setting)
            if val is not None:
                pin_config[setting] = val
        
        whfb_status = {
            "enabled": ngc_set,
            "key_provider": key_provider,
            "tpm_protected": "Platform Crypto" in key_provider,
            "pin_policy": pin_config if pin_config else "Default (no policy)"
        }
        
        issues = []
        
        if ngc_set and "Software" in key_provider:
            issues.append("WHfB keys not TPM-protected")
        
        if not ngc_set and self.join_info.join_type == JoinType.AZURE_AD:
            issues.append("WHfB not enabled on Azure AD joined device")
        
        min_pin = pin_config.get("MinimumPINLength", 4)
        if isinstance(min_pin, int) and min_pin < 6:
            issues.append(f"PIN minimum length is {min_pin} (should be >= 6)")
        
        if issues:
            self.add_finding(Finding(
                check_id="JOIN-WHFB-001",
                title="Windows Hello for Business Configuration Issues",
                severity=Severity.MEDIUM,
                category="Authentication",
                description="Windows Hello for Business is not optimally configured.",
                details={"status": whfb_status, "issues": issues},
                remediation="Enable WHfB with TPM-backed keys and enforce strong PIN policy.",
                references=["https://docs.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-overview"],
                mitre_attack="T1556 - Modify Authentication Process"
            ))

    # =========================================================================
    # PHASE 5: Hybrid-Specific Weaknesses
    # =========================================================================

    def check_hybrid_sync_status(self) -> None:
        """Check hybrid Azure AD join sync status."""
        if self.join_info.join_type != JoinType.HYBRID_AAD:
            return
        
        self.log("Checking hybrid sync status...")
        
        aad_joined = self.dsregcmd_data.get("AzureAdJoined") == "YES"
        domain_joined = self.dsregcmd_data.get("DomainJoined") == "YES"
        
        # Check for sync issues
        aad_prt = self.dsregcmd_data.get("AzureAdPrt", "NO") == "YES"
        enterprise_prt = self.dsregcmd_data.get("EnterprisePrt", "NO") == "YES"
        
        sync_status = {
            "azure_ad_joined": aad_joined,
            "domain_joined": domain_joined,
            "aad_prt": aad_prt,
            "enterprise_prt": enterprise_prt,
            "device_id": self.join_info.device_id,
            "tenant": self.join_info.tenant_name
        }
        
        if not aad_prt:
            self.add_finding(Finding(
                check_id="JOIN-HYBRID-001",
                title="Hybrid Join PRT Not Present",
                severity=Severity.MEDIUM,
                category="Hybrid Join",
                description="Device is hybrid joined but no Azure AD PRT is present. "
                           "SSO to Azure AD resources may not work.",
                details=sync_status,
                remediation="Run 'dsregcmd /join' or check Azure AD Connect sync status.",
                references=["https://docs.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-hybrid-join-windows-current"],
                mitre_attack=None
            ))

    def check_seamless_sso(self) -> None:
        """Check Seamless SSO configuration."""
        if self.join_info.join_type not in [JoinType.ONPREM_AD, JoinType.HYBRID_AAD]:
            return
        
        self.log("Checking Seamless SSO...")
        
        # Check for AZUREADSSOACC tickets
        klist_out, _ = self.run_cmd("klist")
        
        sso_detected = False
        if klist_out and "AZUREADSSOACC" in klist_out:
            sso_detected = True
        
        sso_status = {
            "seamless_sso_active": sso_detected,
            "klist_output": klist_out[:500] if klist_out else None
        }
        
        if sso_detected:
            self.add_finding(Finding(
                check_id="JOIN-SSO-001",
                title="Seamless SSO Detected",
                severity=Severity.INFO,
                category="Authentication",
                description="Seamless SSO is active. The AZUREADSSOACC computer account is "
                           "being used for silent authentication to Azure AD.",
                details=sso_status,
                remediation="Seamless SSO is convenient but the AZUREADSSOACC account password "
                           "should be rotated regularly (every 30 days recommended).",
                references=["https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sso"],
                mitre_attack="T1558 - Steal or Forge Kerberos Tickets"
            ))

    def check_trust_relationships(self) -> None:
        """Check domain trust relationships."""
        if self.join_info.join_type not in [JoinType.ONPREM_AD, JoinType.HYBRID_AAD]:
            return
        
        self.log("Checking trust relationships...")
        
        # List domain trusts
        output, _ = self.run_cmd("nltest /domain_trusts")
        
        trusts = []
        if output:
            for line in output.split('\n'):
                if line.strip() and not line.startswith('List'):
                    trusts.append(line.strip())
        
        if trusts:
            self.add_finding(Finding(
                check_id="JOIN-TRUST-001",
                title="Domain Trusts Detected",
                severity=Severity.INFO,
                category="Domain Trust",
                description="Domain trust relationships detected. Review for unnecessary trusts.",
                details={"trusts": trusts},
                remediation="Audit trust relationships regularly. Remove unnecessary trusts. "
                           "Ensure SID filtering is enabled on external trusts.",
                references=["https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc731335(v=ws.10)"],
                mitre_attack="T1482 - Domain Trust Discovery"
            ))

    # =========================================================================
    # PHASE 6: Workgroup-Specific Weaknesses
    # =========================================================================

    def check_workgroup_security(self) -> None:
        """Check security settings for workgroup machines."""
        if self.join_info.join_type != JoinType.WORKGROUP:
            return
        
        self.log("Checking workgroup security settings...")
        
        # Check local account security
        local_accounts_output = self.run_powershell(
            "Get-LocalUser | Select-Object Name, Enabled, PasswordRequired | ConvertTo-Json"
        )
        
        local_accounts = []
        if local_accounts_output:
            try:
                accounts = json.loads(local_accounts_output)
                if not isinstance(accounts, list):
                    accounts = [accounts]
                local_accounts = accounts
            except json.JSONDecodeError:
                pass
        
        # Check for accounts without passwords required
        weak_accounts = [
            a for a in local_accounts 
            if a.get("Enabled") and not a.get("PasswordRequired")
        ]
        
        if weak_accounts:
            self.add_finding(Finding(
                check_id="JOIN-WG-001",
                title="Local Accounts Without Password Requirements",
                severity=Severity.HIGH,
                category="Local Security",
                description="Local accounts exist that do not require passwords.",
                details={"accounts": weak_accounts},
                remediation="Require passwords for all local accounts or disable unused accounts.",
                references=["CIS Benchmark"],
                mitre_attack="T1078.003 - Valid Accounts: Local Accounts"
            ))
        
        # Check network access settings for workgroup
        restrict_anon = self.read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "RestrictAnonymous"
        )
        
        if restrict_anon != 2:
            self.add_finding(Finding(
                check_id="JOIN-WG-002",
                title="Anonymous Network Access Not Fully Restricted",
                severity=Severity.MEDIUM,
                category="Network Security",
                description="Anonymous access to network resources is not fully restricted.",
                details={"RestrictAnonymous": restrict_anon},
                remediation="Set RestrictAnonymous to 2 for maximum restriction.",
                references=["CIS Benchmark 2.3.10.5"],
                mitre_attack="T1135 - Network Share Discovery"
            ))

    # =========================================================================
    # Run All Checks
    # =========================================================================

    def run_all_checks(self) -> None:
        """Execute all security checks based on join type."""
        # Phase 1: Determine join type
        self.determine_join_type()
        
        click.secho(f"\n[*] Detected Join Type: {self.join_info.join_type.value}", fg="cyan", bold=True)
        
        # Phase 2: Generic checks (all join types)
        self.check_machine_account_password_age()
        self.check_secure_channel()
        self.check_ldap_signing()
        self.check_smb_signing()
        self.check_ntlm_settings()
        self.check_kerberos_settings()
        self.check_credential_caching()
        self.check_lsa_protection()
        
        # Phase 3: On-Premises AD specific
        if self.join_info.join_type in [JoinType.ONPREM_AD, JoinType.HYBRID_AAD]:
            self.check_spn_configuration()
            self.check_delegation_settings()
            self.check_dc_connectivity()
            self.check_gpo_security()
            self.check_trust_relationships()
        
        # Phase 4: Azure AD specific
        if self.join_info.join_type in [JoinType.AZURE_AD, JoinType.HYBRID_AAD, JoinType.AAD_REGISTERED]:
            self.check_prt_protection()
            self.check_device_registration_security()
            self.check_mdm_configuration()
            self.check_conditional_access_indicators()
            self.check_whfb_configuration()
        
        # Phase 5: Hybrid specific
        if self.join_info.join_type == JoinType.HYBRID_AAD:
            self.check_hybrid_sync_status()
            self.check_seamless_sso()
        
        # Phase 6: Workgroup specific
        if self.join_info.join_type == JoinType.WORKGROUP:
            self.check_workgroup_security()

    def generate_report(self) -> Dict:
        """Generate the final audit report."""
        # Group findings by category
        by_category = defaultdict(list)
        for f in self.findings:
            by_category[f.category].append(f.to_dict())
        
        return {
            "audit_info": {
                "tool_version": VERSION,
                "audit_time": datetime.now().isoformat(),
                "hostname": self.join_info.hostname if self.join_info else "Unknown"
            },
            "join_info": self.join_info.to_dict() if self.join_info else {},
            "summary": {
                "join_type": self.join_info.join_type.value if self.join_info else "Unknown",
                "total_findings": len(self.findings),
                "critical": len([f for f in self.findings if f.severity == Severity.CRITICAL]),
                "high": len([f for f in self.findings if f.severity == Severity.HIGH]),
                "medium": len([f for f in self.findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in self.findings if f.severity == Severity.LOW]),
                "info": len([f for f in self.findings if f.severity == Severity.INFO])
            },
            "findings_by_category": dict(by_category),
            "all_findings": [f.to_dict() for f in self.findings]
        }


def generate_html_report(report: Dict) -> str:
    """Generate an HTML report."""
    severity_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#6c757d",
        "INFO": "#28a745"
    }
    
    findings_html = ""
    for category, findings in report.get("findings_by_category", {}).items():
        findings_html += f"<h3>{category}</h3>"
        for f in findings:
            color = severity_colors.get(f["severity"], "#6c757d")
            refs = "".join([f"<li><a href='{r}'>{r}</a></li>" for r in f.get("references", [])])
            mitre = f"<p><em>MITRE ATT&CK: {f['mitre_attack']}</em></p>" if f.get('mitre_attack') else ""
            
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <h4><span class="severity" style="background-color: {color};">{f['severity']}</span>
                    [{f['check_id']}] {f['title']}</h4>
                <p><strong>Description:</strong> {f['description']}</p>
                <details>
                    <summary><strong>Details</strong></summary>
                    <pre>{json.dumps(f['details'], indent=2)}</pre>
                </details>
                <p><strong>Remediation:</strong> {f['remediation']}</p>
                {f'<p><strong>References:</strong><ul>{refs}</ul></p>' if refs else ''}
                {mitre}
            </div>
            """
    
    join_info = report.get("join_info", {})
    summary = report.get("summary", {})
    
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Domain Join Security Audit Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f0f2f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a1a; border-bottom: 3px solid #0078d4; padding-bottom: 15px; }}
        h2 {{ color: #333; margin-top: 30px; }}
        h3 {{ color: #444; border-bottom: 1px solid #ddd; padding-bottom: 8px; margin-top: 25px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ padding: 20px; border-radius: 8px; text-align: center; color: white; }}
        .finding {{ background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 6px; }}
        .finding h4 {{ margin-top: 0; }}
        .severity {{ padding: 4px 12px; border-radius: 4px; color: white; font-size: 11px; font-weight: bold; margin-right: 10px; }}
        pre {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 12px; }}
        details {{ margin: 10px 0; }}
        summary {{ cursor: pointer; font-weight: bold; }}
        .join-info {{ background: #e7f3ff; padding: 20px; border-radius: 8px; margin-bottom: 25px; }}
        .join-info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }}
        .join-info-item {{ padding: 8px 12px; background: white; border-radius: 4px; }}
        .join-type-badge {{ display: inline-block; padding: 8px 16px; background: #0078d4; color: white; border-radius: 20px; font-weight: bold; margin-bottom: 15px; }}
        a {{ color: #0078d4; }}
        ul {{ margin: 5px 0; padding-left: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Domain Join Security Audit Report</h1>
        
        <div class="join-info">
            <span class="join-type-badge">{join_info.get('join_type', 'Unknown')}</span>
            <div class="join-info-grid">
                <div class="join-info-item"><strong>Hostname:</strong> {join_info.get('hostname', 'N/A')}</div>
                <div class="join-info-item"><strong>Domain:</strong> {join_info.get('domain_name', 'N/A')}</div>
                <div class="join-info-item"><strong>DNS Domain:</strong> {join_info.get('dns_domain', 'N/A')}</div>
                <div class="join-info-item"><strong>DC:</strong> {join_info.get('dc_name', 'N/A')}</div>
                <div class="join-info-item"><strong>Tenant:</strong> {join_info.get('tenant_name', 'N/A')}</div>
                <div class="join-info-item"><strong>Device ID:</strong> {str(join_info.get('device_id', 'N/A'))[:20]}...</div>
                <div class="join-info-item"><strong>PRT:</strong> {'Yes' if join_info.get('prt_present') else 'No'}</div>
                <div class="join-info-item"><strong>WHfB:</strong> {'Enabled' if join_info.get('ngc_enabled') else 'Disabled'}</div>
            </div>
        </div>
        
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-card" style="background: #dc3545;">CRITICAL<br><strong style="font-size: 24px;">{summary.get('critical', 0)}</strong></div>
            <div class="summary-card" style="background: #fd7e14;">HIGH<br><strong style="font-size: 24px;">{summary.get('high', 0)}</strong></div>
            <div class="summary-card" style="background: #ffc107; color: #333;">MEDIUM<br><strong style="font-size: 24px;">{summary.get('medium', 0)}</strong></div>
            <div class="summary-card" style="background: #6c757d;">LOW<br><strong style="font-size: 24px;">{summary.get('low', 0)}</strong></div>
            <div class="summary-card" style="background: #28a745;">INFO<br><strong style="font-size: 24px;">{summary.get('info', 0)}</strong></div>
        </div>
        
        <h2>Findings</h2>
        {findings_html if findings_html else '<p>No findings detected.</p>'}
        
        <hr style="margin-top: 40px;">
        <p style="color: #666; font-size: 12px;">
            Generated by Domain Join Security Auditor v{VERSION} at {report.get('audit_info', {}).get('audit_time', 'N/A')}
        </p>
    </div>
</body>
</html>"""


# --- CLI entrypoint (Click) ---
@click.command()
@click.option("-o", "--output", type=click.Path(), help="Output JSON file path")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.option("--html", type=click.Path(), help="Generate HTML report")
@click.version_option(version=VERSION)
def cli(output: Optional[str], verbose: bool, html: Optional[str]) -> None:
    """Domain Join Security Auditor - Detect join type and identify weaknesses"""
    
    click.secho("\n╔══════════════════════════════════════════════════════════════╗", fg="cyan")
    click.secho("║         Domain Join Security Auditor v" + VERSION + "                  ║", fg="cyan")
    click.secho("║   Workgroup | On-Prem AD | Azure AD | Hybrid Join Analysis    ║", fg="cyan")
    click.secho("╚══════════════════════════════════════════════════════════════╝\n", fg="cyan")
    
    auditor = DomainJoinAuditor(verbose=verbose)
    
    click.echo("[*] Starting domain join security audit...")
    auditor.run_all_checks()
    
    report = auditor.generate_report()
    
    # Print summary
    click.echo("\n" + "=" * 75)
    click.secho("DEVICE INFORMATION", fg="white", bold=True)
    click.echo("=" * 75)
    
    join_info = report["join_info"]
    click.echo(f"Join Type:    {join_info.get('join_type', 'Unknown')}")
    click.echo(f"Hostname:     {join_info.get('hostname', 'N/A')}")
    click.echo(f"Domain:       {join_info.get('domain_name', 'N/A')}")
    
    if join_info.get('tenant_name'):
        click.echo(f"Tenant:       {join_info.get('tenant_name')}")
    if join_info.get('dc_name'):
        click.echo(f"DC:           {join_info.get('dc_name')}")
    if join_info.get('device_id'):
        click.echo(f"Device ID:    {join_info.get('device_id')[:36]}...")
    
    click.echo(f"PRT Present:  {'Yes' if join_info.get('prt_present') else 'No'}")
    click.echo(f"WHfB:         {'Enabled' if join_info.get('ngc_enabled') else 'Disabled'}")
    
    # Print findings grouped by severity
    click.echo("\n" + "=" * 75)
    click.secho("FINDINGS", fg="white", bold=True)
    click.echo("=" * 75)
    
    summary = report["summary"]
    all_findings = report.get("all_findings", [])
    
    # Sort findings by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(all_findings, key=lambda x: severity_order.get(x["severity"], 5))
    
    # Color mapping
    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "cyan",
        "LOW": "white",
        "INFO": "green"
    }
    
    # Print each finding
    if sorted_findings:
        current_severity = None
        for f in sorted_findings:
            sev = f["severity"]
            
            # Print severity header when it changes
            if sev != current_severity:
                current_severity = sev
                click.echo("")
                click.secho(f"─── {sev} ({len([x for x in sorted_findings if x['severity'] == sev])}) ───", 
                           fg=severity_colors.get(sev, "white"), bold=True)
            
            # Print finding
            color = severity_colors.get(sev, "white")
            click.secho(f"  [{f['check_id']}] {f['title']}", fg=color)
            click.echo(f"      Category: {f['category']}")
            click.echo(f"      {f['description'][:80]}{'...' if len(f['description']) > 80 else ''}")
            if f.get('mitre_attack'):
                click.secho(f"      MITRE: {f['mitre_attack']}", fg="magenta")
    else:
        click.secho("  No findings detected.", fg="green")
    
    # Print summary counts
    click.echo("\n" + "=" * 75)
    click.secho("SUMMARY COUNTS", fg="white", bold=True)
    click.echo("=" * 75)
    click.secho(f"  CRITICAL: {summary['critical']}", fg="red" if summary['critical'] > 0 else "white")
    click.secho(f"  HIGH:     {summary['high']}", fg="yellow" if summary['high'] > 0 else "white")
    click.secho(f"  MEDIUM:   {summary['medium']}", fg="cyan" if summary['medium'] > 0 else "white")
    click.secho(f"  LOW:      {summary['low']}", fg="white")
    click.secho(f"  INFO:     {summary['info']}", fg="green")
    click.echo(f"  TOTAL:    {summary['total_findings']}")
    click.echo("=" * 75)
    
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
    
    # Exit code based on findings
    if summary['critical'] > 0:
        sys.exit(2)
    elif summary['high'] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    cli()
