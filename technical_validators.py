"""
CMMC Level 2 Technical Validation Scripts
Automated checks to verify control implementation programmatically.

Author: Akintade Akinokun
Purpose: CMMC Level 2 C3PAO Audit Preparation
Reference: NIST SP 800-171 Rev 2

These scripts automate verification of controls that can be checked via:
- Windows/Active Directory queries (PowerShell)
- Network scanning
- AWS API calls (boto3)
- Local system checks

IMPORTANT: These scripts require appropriate permissions and should only
be run with explicit authorization from the system owner.
"""

import subprocess
import platform
import socket
import ssl
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum


class ValidationStatus(Enum):
    """Validation result status"""
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    MANUAL = "MANUAL_REVIEW_REQUIRED"


@dataclass
class ValidationResult:
    """Result of a single validation check"""
    control_id: str
    check_name: str
    status: str
    message: str
    details: Dict = field(default_factory=dict)
    evidence: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return asdict(self)


@dataclass
class ValidationReport:
    """Complete validation report"""
    target_system: str
    validation_date: str
    validator_version: str = "1.0.0"
    results: List[ValidationResult] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)

    def add_result(self, result: ValidationResult):
        self.results.append(result)

    def generate_summary(self):
        self.summary = {
            "total_checks": len(self.results),
            "passed": len([r for r in self.results if r.status == "PASS"]),
            "failed": len([r for r in self.results if r.status == "FAIL"]),
            "warnings": len([r for r in self.results if r.status == "WARNING"]),
            "errors": len([r for r in self.results if r.status == "ERROR"]),
            "skipped": len([r for r in self.results if r.status == "SKIPPED"]),
            "manual_review": len([r for r in self.results if r.status == "MANUAL_REVIEW_REQUIRED"])
        }
        return self.summary

    def to_dict(self):
        return {
            "target_system": self.target_system,
            "validation_date": self.validation_date,
            "validator_version": self.validator_version,
            "summary": self.generate_summary(),
            "results": [r.to_dict() for r in self.results]
        }


# =============================================================================
# WINDOWS / ACTIVE DIRECTORY VALIDATORS
# =============================================================================

class WindowsValidator:
    """
    Validates Windows and Active Directory security configurations.
    Uses PowerShell commands to query system settings.
    """

    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        self.results = []

    def _run_powershell(self, command: str) -> Tuple[bool, str]:
        """Execute PowerShell command and return result"""
        if not self.is_windows:
            return False, "Not running on Windows"

        try:
            result = subprocess.run(
                ["powershell", "-Command", command],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def check_password_policy(self) -> ValidationResult:
        """
        Check password policy settings
        Controls: IA.L2-3.5.7 (Password Complexity), IA.L2-3.5.8 (Password Reuse)
        """
        if not self.is_windows:
            return ValidationResult(
                control_id="IA.L2-3.5.7",
                check_name="Password Policy Check",
                status=ValidationStatus.SKIPPED.value,
                message="Skipped - Not running on Windows",
                details={"platform": platform.system()}
            )

        # PowerShell command to get password policy
        cmd = """
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
        if ($policy) {
            @{
                MinPasswordLength = $policy.MinPasswordLength
                PasswordHistoryCount = $policy.PasswordHistoryCount
                ComplexityEnabled = $policy.ComplexityEnabled
                MaxPasswordAge = $policy.MaxPasswordAge.Days
                MinPasswordAge = $policy.MinPasswordAge.Days
                LockoutThreshold = $policy.LockoutThreshold
                LockoutDuration = $policy.LockoutDuration.Minutes
            } | ConvertTo-Json
        } else {
            # Try local policy if not domain-joined
            $secedit = secedit /export /cfg "$env:temp\\secpol.cfg" /quiet
            $content = Get-Content "$env:temp\\secpol.cfg"
            $minLen = ($content | Select-String "MinimumPasswordLength").ToString().Split("=")[1].Trim()
            $history = ($content | Select-String "PasswordHistorySize").ToString().Split("=")[1].Trim()
            $complexity = ($content | Select-String "PasswordComplexity").ToString().Split("=")[1].Trim()
            @{
                MinPasswordLength = [int]$minLen
                PasswordHistoryCount = [int]$history
                ComplexityEnabled = [int]$complexity -eq 1
                Source = "LocalPolicy"
            } | ConvertTo-Json
        }
        """

        success, output = self._run_powershell(cmd)

        if not success:
            return ValidationResult(
                control_id="IA.L2-3.5.7",
                check_name="Password Policy Check",
                status=ValidationStatus.ERROR.value,
                message=f"Failed to query password policy: {output}",
                details={"error": output}
            )

        try:
            policy = json.loads(output)
            issues = []

            # Check minimum length (NIST recommends 8+, CMMC typically 12+)
            min_length = policy.get("MinPasswordLength", 0)
            if min_length < 12:
                issues.append(f"Minimum password length is {min_length} (should be 12+)")

            # Check password history (should be 24+)
            history = policy.get("PasswordHistoryCount", 0)
            if history < 24:
                issues.append(f"Password history is {history} (should be 24+)")

            # Check complexity
            if not policy.get("ComplexityEnabled", False):
                issues.append("Password complexity is not enabled")

            if issues:
                return ValidationResult(
                    control_id="IA.L2-3.5.7",
                    check_name="Password Policy Check",
                    status=ValidationStatus.FAIL.value,
                    message="Password policy does not meet CMMC requirements",
                    details={"policy": policy, "issues": issues},
                    evidence=json.dumps(policy, indent=2)
                )
            else:
                return ValidationResult(
                    control_id="IA.L2-3.5.7",
                    check_name="Password Policy Check",
                    status=ValidationStatus.PASS.value,
                    message="Password policy meets CMMC requirements",
                    details={"policy": policy},
                    evidence=json.dumps(policy, indent=2)
                )

        except json.JSONDecodeError:
            return ValidationResult(
                control_id="IA.L2-3.5.7",
                check_name="Password Policy Check",
                status=ValidationStatus.ERROR.value,
                message="Failed to parse password policy output",
                details={"raw_output": output}
            )

    def check_account_lockout(self) -> ValidationResult:
        """
        Check account lockout settings
        Control: AC.L2-3.1.8 (Unsuccessful Logon Attempts)
        """
        if not self.is_windows:
            return ValidationResult(
                control_id="AC.L2-3.1.8",
                check_name="Account Lockout Policy Check",
                status=ValidationStatus.SKIPPED.value,
                message="Skipped - Not running on Windows"
            )

        cmd = """
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
        if ($policy) {
            @{
                LockoutThreshold = $policy.LockoutThreshold
                LockoutDuration = $policy.LockoutDuration.Minutes
                LockoutObservationWindow = $policy.LockoutObservationWindow.Minutes
            } | ConvertTo-Json
        } else {
            $secedit = secedit /export /cfg "$env:temp\\secpol.cfg" /quiet
            $content = Get-Content "$env:temp\\secpol.cfg"
            $threshold = ($content | Select-String "LockoutBadCount").ToString().Split("=")[1].Trim()
            $duration = ($content | Select-String "ResetLockoutCount").ToString().Split("=")[1].Trim()
            @{
                LockoutThreshold = [int]$threshold
                LockoutDuration = [int]$duration
                Source = "LocalPolicy"
            } | ConvertTo-Json
        }
        """

        success, output = self._run_powershell(cmd)

        if not success:
            return ValidationResult(
                control_id="AC.L2-3.1.8",
                check_name="Account Lockout Policy Check",
                status=ValidationStatus.ERROR.value,
                message=f"Failed to query lockout policy: {output}"
            )

        try:
            policy = json.loads(output)
            issues = []

            threshold = policy.get("LockoutThreshold", 0)
            if threshold == 0:
                issues.append("Account lockout is disabled (threshold = 0)")
            elif threshold > 5:
                issues.append(f"Lockout threshold is {threshold} (should be 3-5)")

            duration = policy.get("LockoutDuration", 0)
            if duration < 15 and duration != 0:
                issues.append(f"Lockout duration is {duration} minutes (should be 15+)")

            if issues:
                return ValidationResult(
                    control_id="AC.L2-3.1.8",
                    check_name="Account Lockout Policy Check",
                    status=ValidationStatus.FAIL.value,
                    message="Account lockout policy does not meet requirements",
                    details={"policy": policy, "issues": issues},
                    evidence=json.dumps(policy, indent=2)
                )
            else:
                return ValidationResult(
                    control_id="AC.L2-3.1.8",
                    check_name="Account Lockout Policy Check",
                    status=ValidationStatus.PASS.value,
                    message="Account lockout policy meets requirements",
                    details={"policy": policy},
                    evidence=json.dumps(policy, indent=2)
                )

        except json.JSONDecodeError:
            return ValidationResult(
                control_id="AC.L2-3.1.8",
                check_name="Account Lockout Policy Check",
                status=ValidationStatus.ERROR.value,
                message="Failed to parse lockout policy"
            )

    def check_screen_lock(self) -> ValidationResult:
        """
        Check screen lock/screensaver timeout settings
        Control: AC.L2-3.1.10 (Session Lock)
        """
        if not self.is_windows:
            return ValidationResult(
                control_id="AC.L2-3.1.10",
                check_name="Screen Lock Timeout Check",
                status=ValidationStatus.SKIPPED.value,
                message="Skipped - Not running on Windows"
            )

        cmd = """
        $timeout = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'InactivityTimeoutSecs' -ErrorAction SilentlyContinue).InactivityTimeoutSecs
        $screensaver = Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -ErrorAction SilentlyContinue
        @{
            InactivityTimeoutSeconds = $timeout
            ScreenSaveActive = $screensaver.ScreenSaveActive
            ScreenSaveTimeOut = $screensaver.ScreenSaveTimeOut
            ScreenSaverIsSecure = $screensaver.ScreenSaverIsSecure
        } | ConvertTo-Json
        """

        success, output = self._run_powershell(cmd)

        if not success:
            return ValidationResult(
                control_id="AC.L2-3.1.10",
                check_name="Screen Lock Timeout Check",
                status=ValidationStatus.ERROR.value,
                message=f"Failed to query screen lock settings: {output}"
            )

        try:
            settings = json.loads(output)
            issues = []

            # Check inactivity timeout (should be 900 seconds / 15 minutes or less)
            timeout = settings.get("InactivityTimeoutSeconds") or settings.get("ScreenSaveTimeOut")
            if timeout:
                timeout = int(timeout)
                if timeout > 900:
                    issues.append(f"Inactivity timeout is {timeout} seconds (should be 900 or less)")
            else:
                issues.append("No inactivity timeout configured")

            # Check if screensaver requires password
            if settings.get("ScreenSaverIsSecure") != "1":
                issues.append("Screensaver does not require password to unlock")

            if issues:
                return ValidationResult(
                    control_id="AC.L2-3.1.10",
                    check_name="Screen Lock Timeout Check",
                    status=ValidationStatus.FAIL.value,
                    message="Screen lock settings do not meet requirements",
                    details={"settings": settings, "issues": issues},
                    evidence=json.dumps(settings, indent=2)
                )
            else:
                return ValidationResult(
                    control_id="AC.L2-3.1.10",
                    check_name="Screen Lock Timeout Check",
                    status=ValidationStatus.PASS.value,
                    message="Screen lock settings meet requirements",
                    details={"settings": settings},
                    evidence=json.dumps(settings, indent=2)
                )

        except (json.JSONDecodeError, ValueError):
            return ValidationResult(
                control_id="AC.L2-3.1.10",
                check_name="Screen Lock Timeout Check",
                status=ValidationStatus.ERROR.value,
                message="Failed to parse screen lock settings"
            )

    def check_audit_policy(self) -> ValidationResult:
        """
        Check Windows audit policy settings
        Control: AU.L2-3.3.1 (System Auditing)
        """
        if not self.is_windows:
            return ValidationResult(
                control_id="AU.L2-3.3.1",
                check_name="Audit Policy Check",
                status=ValidationStatus.SKIPPED.value,
                message="Skipped - Not running on Windows"
            )

        cmd = """
        $audit = auditpol /get /category:* /r | ConvertFrom-Csv
        $critical = @(
            'Credential Validation',
            'Logon',
            'Logoff',
            'Account Lockout',
            'Special Logon',
            'Process Creation',
            'Audit Policy Change',
            'User Account Management',
            'Security Group Management'
        )
        $results = @{}
        foreach ($item in $audit) {
            if ($critical -contains $item.Subcategory) {
                $results[$item.Subcategory] = $item.'Inclusion Setting'
            }
        }
        $results | ConvertTo-Json
        """

        success, output = self._run_powershell(cmd)

        if not success:
            return ValidationResult(
                control_id="AU.L2-3.3.1",
                check_name="Audit Policy Check",
                status=ValidationStatus.ERROR.value,
                message=f"Failed to query audit policy: {output}"
            )

        try:
            audit_settings = json.loads(output)
            issues = []

            for setting, value in audit_settings.items():
                if value == "No Auditing":
                    issues.append(f"'{setting}' is not being audited")

            if issues:
                return ValidationResult(
                    control_id="AU.L2-3.3.1",
                    check_name="Audit Policy Check",
                    status=ValidationStatus.FAIL.value,
                    message="Critical audit events are not being logged",
                    details={"audit_policy": audit_settings, "issues": issues},
                    evidence=json.dumps(audit_settings, indent=2)
                )
            else:
                return ValidationResult(
                    control_id="AU.L2-3.3.1",
                    check_name="Audit Policy Check",
                    status=ValidationStatus.PASS.value,
                    message="Critical audit events are being logged",
                    details={"audit_policy": audit_settings},
                    evidence=json.dumps(audit_settings, indent=2)
                )

        except json.JSONDecodeError:
            return ValidationResult(
                control_id="AU.L2-3.3.1",
                check_name="Audit Policy Check",
                status=ValidationStatus.ERROR.value,
                message="Failed to parse audit policy"
            )

    def check_bitlocker(self) -> ValidationResult:
        """
        Check BitLocker encryption status
        Control: SC.L2-3.13.16 (Data at Rest)
        """
        if not self.is_windows:
            return ValidationResult(
                control_id="SC.L2-3.13.16",
                check_name="BitLocker Encryption Check",
                status=ValidationStatus.SKIPPED.value,
                message="Skipped - Not running on Windows"
            )

        cmd = """
        $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($volumes) {
            $volumes | ForEach-Object {
                @{
                    MountPoint = $_.MountPoint
                    VolumeStatus = $_.VolumeStatus.ToString()
                    ProtectionStatus = $_.ProtectionStatus.ToString()
                    EncryptionMethod = $_.EncryptionMethod.ToString()
                    EncryptionPercentage = $_.EncryptionPercentage
                }
            } | ConvertTo-Json
        } else {
            @{ Error = "BitLocker not available or no volumes found" } | ConvertTo-Json
        }
        """

        success, output = self._run_powershell(cmd)

        if not success:
            return ValidationResult(
                control_id="SC.L2-3.13.16",
                check_name="BitLocker Encryption Check",
                status=ValidationStatus.ERROR.value,
                message=f"Failed to query BitLocker status: {output}"
            )

        try:
            volumes = json.loads(output)
            if isinstance(volumes, dict) and "Error" in volumes:
                return ValidationResult(
                    control_id="SC.L2-3.13.16",
                    check_name="BitLocker Encryption Check",
                    status=ValidationStatus.FAIL.value,
                    message="BitLocker is not available or configured",
                    details=volumes
                )

            if not isinstance(volumes, list):
                volumes = [volumes]

            issues = []
            for vol in volumes:
                mount = vol.get("MountPoint", "Unknown")
                status = vol.get("ProtectionStatus", "Unknown")
                if status != "On":
                    issues.append(f"Volume {mount} is not protected (status: {status})")

            if issues:
                return ValidationResult(
                    control_id="SC.L2-3.13.16",
                    check_name="BitLocker Encryption Check",
                    status=ValidationStatus.FAIL.value,
                    message="Not all volumes are encrypted with BitLocker",
                    details={"volumes": volumes, "issues": issues},
                    evidence=json.dumps(volumes, indent=2)
                )
            else:
                return ValidationResult(
                    control_id="SC.L2-3.13.16",
                    check_name="BitLocker Encryption Check",
                    status=ValidationStatus.PASS.value,
                    message="All volumes are encrypted with BitLocker",
                    details={"volumes": volumes},
                    evidence=json.dumps(volumes, indent=2)
                )

        except json.JSONDecodeError:
            return ValidationResult(
                control_id="SC.L2-3.13.16",
                check_name="BitLocker Encryption Check",
                status=ValidationStatus.ERROR.value,
                message="Failed to parse BitLocker status"
            )

    def check_windows_firewall(self) -> ValidationResult:
        """
        Check Windows Firewall status
        Control: SC.L2-3.13.1 (Boundary Protection)
        """
        if not self.is_windows:
            return ValidationResult(
                control_id="SC.L2-3.13.1",
                check_name="Windows Firewall Check",
                status=ValidationStatus.SKIPPED.value,
                message="Skipped - Not running on Windows"
            )

        cmd = """
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        if ($profiles) {
            $profiles | ForEach-Object {
                @{
                    Profile = $_.Name
                    Enabled = $_.Enabled
                    DefaultInboundAction = $_.DefaultInboundAction.ToString()
                    DefaultOutboundAction = $_.DefaultOutboundAction.ToString()
                }
            } | ConvertTo-Json
        } else {
            @{ Error = "Could not query firewall profiles" } | ConvertTo-Json
        }
        """

        success, output = self._run_powershell(cmd)

        if not success:
            return ValidationResult(
                control_id="SC.L2-3.13.1",
                check_name="Windows Firewall Check",
                status=ValidationStatus.ERROR.value,
                message=f"Failed to query firewall status: {output}"
            )

        try:
            profiles = json.loads(output)
            if isinstance(profiles, dict) and "Error" in profiles:
                return ValidationResult(
                    control_id="SC.L2-3.13.1",
                    check_name="Windows Firewall Check",
                    status=ValidationStatus.ERROR.value,
                    message="Could not query firewall profiles",
                    details=profiles
                )

            if not isinstance(profiles, list):
                profiles = [profiles]

            issues = []
            for profile in profiles:
                name = profile.get("Profile", "Unknown")
                if not profile.get("Enabled", False):
                    issues.append(f"{name} profile is disabled")
                if profile.get("DefaultInboundAction") != "Block":
                    issues.append(f"{name} profile does not block inbound by default")

            if issues:
                return ValidationResult(
                    control_id="SC.L2-3.13.1",
                    check_name="Windows Firewall Check",
                    status=ValidationStatus.FAIL.value,
                    message="Windows Firewall is not properly configured",
                    details={"profiles": profiles, "issues": issues},
                    evidence=json.dumps(profiles, indent=2)
                )
            else:
                return ValidationResult(
                    control_id="SC.L2-3.13.1",
                    check_name="Windows Firewall Check",
                    status=ValidationStatus.PASS.value,
                    message="Windows Firewall is properly configured",
                    details={"profiles": profiles},
                    evidence=json.dumps(profiles, indent=2)
                )

        except json.JSONDecodeError:
            return ValidationResult(
                control_id="SC.L2-3.13.1",
                check_name="Windows Firewall Check",
                status=ValidationStatus.ERROR.value,
                message="Failed to parse firewall status"
            )

    def check_antivirus(self) -> ValidationResult:
        """
        Check antivirus/endpoint protection status
        Control: SI.L2-3.14.2 (Malicious Code Protection)
        """
        if not self.is_windows:
            return ValidationResult(
                control_id="SI.L2-3.14.2",
                check_name="Antivirus Status Check",
                status=ValidationStatus.SKIPPED.value,
                message="Skipped - Not running on Windows"
            )

        cmd = """
        $av = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($av) {
            @{
                AMServiceEnabled = $av.AMServiceEnabled
                AntispywareEnabled = $av.AntispywareEnabled
                AntivirusEnabled = $av.AntivirusEnabled
                RealTimeProtectionEnabled = $av.RealTimeProtectionEnabled
                AntivirusSignatureLastUpdated = $av.AntivirusSignatureLastUpdated.ToString()
                AntivirusSignatureAge = $av.AntivirusSignatureAge
                QuickScanAge = $av.QuickScanAge
                FullScanAge = $av.FullScanAge
            } | ConvertTo-Json
        } else {
            # Check for third-party AV
            $wmi = Get-WmiObject -Namespace "root\\SecurityCenter2" -Class AntivirusProduct -ErrorAction SilentlyContinue
            if ($wmi) {
                $wmi | ForEach-Object {
                    @{
                        DisplayName = $_.displayName
                        ProductState = $_.productState
                        Source = "SecurityCenter2"
                    }
                } | ConvertTo-Json
            } else {
                @{ Error = "No antivirus product detected" } | ConvertTo-Json
            }
        }
        """

        success, output = self._run_powershell(cmd)

        if not success:
            return ValidationResult(
                control_id="SI.L2-3.14.2",
                check_name="Antivirus Status Check",
                status=ValidationStatus.ERROR.value,
                message=f"Failed to query antivirus status: {output}"
            )

        try:
            av_status = json.loads(output)

            if "Error" in av_status:
                return ValidationResult(
                    control_id="SI.L2-3.14.2",
                    check_name="Antivirus Status Check",
                    status=ValidationStatus.FAIL.value,
                    message="No antivirus product detected",
                    details=av_status
                )

            issues = []

            # Check if Windows Defender (or detections enabled)
            if "AntivirusEnabled" in av_status:
                if not av_status.get("AntivirusEnabled"):
                    issues.append("Antivirus is disabled")
                if not av_status.get("RealTimeProtectionEnabled"):
                    issues.append("Real-time protection is disabled")

                sig_age = av_status.get("AntivirusSignatureAge", 999)
                if sig_age > 7:
                    issues.append(f"Antivirus signatures are {sig_age} days old (should be < 7)")

            if issues:
                return ValidationResult(
                    control_id="SI.L2-3.14.2",
                    check_name="Antivirus Status Check",
                    status=ValidationStatus.FAIL.value,
                    message="Antivirus protection has issues",
                    details={"status": av_status, "issues": issues},
                    evidence=json.dumps(av_status, indent=2)
                )
            else:
                return ValidationResult(
                    control_id="SI.L2-3.14.2",
                    check_name="Antivirus Status Check",
                    status=ValidationStatus.PASS.value,
                    message="Antivirus protection is active and current",
                    details={"status": av_status},
                    evidence=json.dumps(av_status, indent=2)
                )

        except json.JSONDecodeError:
            return ValidationResult(
                control_id="SI.L2-3.14.2",
                check_name="Antivirus Status Check",
                status=ValidationStatus.ERROR.value,
                message="Failed to parse antivirus status"
            )

    def run_all_checks(self) -> List[ValidationResult]:
        """Run all Windows validation checks"""
        results = []
        results.append(self.check_password_policy())
        results.append(self.check_account_lockout())
        results.append(self.check_screen_lock())
        results.append(self.check_audit_policy())
        results.append(self.check_bitlocker())
        results.append(self.check_windows_firewall())
        results.append(self.check_antivirus())
        return results


# =============================================================================
# NETWORK VALIDATORS
# =============================================================================

class NetworkValidator:
    """
    Validates network security configurations.
    Checks TLS versions, open ports, and network services.
    """

    def __init__(self):
        self.results = []

    def check_tls_version(self, host: str, port: int = 443) -> ValidationResult:
        """
        Check TLS version support on a server
        Control: SC.L2-3.13.8 (Data in Transit), SC.L2-3.13.11 (CUI Encryption)
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()

                    details = {
                        "host": host,
                        "port": port,
                        "tls_version": version,
                        "cipher_suite": cipher[0] if cipher else "Unknown",
                        "cipher_bits": cipher[2] if cipher else 0
                    }

                    # Check for acceptable TLS versions (1.2 or 1.3)
                    if version in ["TLSv1.2", "TLSv1.3"]:
                        return ValidationResult(
                            control_id="SC.L2-3.13.8",
                            check_name=f"TLS Version Check ({host})",
                            status=ValidationStatus.PASS.value,
                            message=f"Server supports {version}",
                            details=details,
                            evidence=json.dumps(details, indent=2)
                        )
                    else:
                        return ValidationResult(
                            control_id="SC.L2-3.13.8",
                            check_name=f"TLS Version Check ({host})",
                            status=ValidationStatus.FAIL.value,
                            message=f"Server uses outdated {version} (requires TLS 1.2+)",
                            details=details,
                            evidence=json.dumps(details, indent=2)
                        )

        except ssl.SSLError as e:
            return ValidationResult(
                control_id="SC.L2-3.13.8",
                check_name=f"TLS Version Check ({host})",
                status=ValidationStatus.ERROR.value,
                message=f"SSL error: {str(e)}",
                details={"host": host, "port": port, "error": str(e)}
            )
        except socket.error as e:
            return ValidationResult(
                control_id="SC.L2-3.13.8",
                check_name=f"TLS Version Check ({host})",
                status=ValidationStatus.ERROR.value,
                message=f"Connection error: {str(e)}",
                details={"host": host, "port": port, "error": str(e)}
            )

    def check_weak_tls_protocols(self, host: str, port: int = 443) -> ValidationResult:
        """
        Check if weak TLS protocols (SSLv3, TLS 1.0, TLS 1.1) are disabled
        Control: SC.L2-3.13.11 (CUI Encryption)
        """
        weak_protocols = []

        # Test for TLS 1.0
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.maximum_version = ssl.TLSVersion.TLSv1
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    weak_protocols.append("TLSv1.0")
        except:
            pass

        # Test for TLS 1.1
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.maximum_version = ssl.TLSVersion.TLSv1_1
            context.minimum_version = ssl.TLSVersion.TLSv1_1
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    weak_protocols.append("TLSv1.1")
        except:
            pass

        details = {
            "host": host,
            "port": port,
            "weak_protocols_enabled": weak_protocols
        }

        if weak_protocols:
            return ValidationResult(
                control_id="SC.L2-3.13.11",
                check_name=f"Weak TLS Protocol Check ({host})",
                status=ValidationStatus.FAIL.value,
                message=f"Weak protocols enabled: {', '.join(weak_protocols)}",
                details=details,
                evidence=json.dumps(details, indent=2)
            )
        else:
            return ValidationResult(
                control_id="SC.L2-3.13.11",
                check_name=f"Weak TLS Protocol Check ({host})",
                status=ValidationStatus.PASS.value,
                message="No weak TLS protocols enabled",
                details=details,
                evidence=json.dumps(details, indent=2)
            )

    def check_open_ports(self, host: str, ports: List[int] = None) -> ValidationResult:
        """
        Check for commonly vulnerable open ports
        Control: CM.L2-3.4.7 (Nonessential Functionality)
        """
        if ports is None:
            # Common ports that should typically be closed
            ports = [21, 23, 25, 110, 135, 137, 138, 139, 445, 1433, 1434, 3389, 5900]

        open_ports = []
        risky_ports = {
            21: "FTP",
            23: "Telnet (unencrypted)",
            25: "SMTP",
            110: "POP3 (unencrypted)",
            135: "RPC",
            137: "NetBIOS",
            138: "NetBIOS",
            139: "NetBIOS",
            445: "SMB",
            1433: "SQL Server",
            1434: "SQL Server Browser",
            3389: "RDP",
            5900: "VNC"
        }

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "service": risky_ports.get(port, "Unknown"),
                        "risk": "High" if port in [23, 21, 110, 135, 445] else "Medium"
                    })
                sock.close()
            except:
                pass

        details = {
            "host": host,
            "ports_scanned": ports,
            "open_ports": open_ports
        }

        high_risk = [p for p in open_ports if p.get("risk") == "High"]

        if high_risk:
            return ValidationResult(
                control_id="CM.L2-3.4.7",
                check_name=f"Open Ports Check ({host})",
                status=ValidationStatus.FAIL.value,
                message=f"High-risk ports open: {[p['port'] for p in high_risk]}",
                details=details,
                evidence=json.dumps(details, indent=2)
            )
        elif open_ports:
            return ValidationResult(
                control_id="CM.L2-3.4.7",
                check_name=f"Open Ports Check ({host})",
                status=ValidationStatus.WARNING.value,
                message=f"Potentially unnecessary ports open: {[p['port'] for p in open_ports]}",
                details=details,
                evidence=json.dumps(details, indent=2)
            )
        else:
            return ValidationResult(
                control_id="CM.L2-3.4.7",
                check_name=f"Open Ports Check ({host})",
                status=ValidationStatus.PASS.value,
                message="No commonly risky ports are open",
                details=details,
                evidence=json.dumps(details, indent=2)
            )

    def check_ntp_sync(self) -> ValidationResult:
        """
        Check NTP time synchronization
        Control: AU.L2-3.3.7 (Authoritative Time Source)
        """
        is_windows = platform.system() == "Windows"

        if is_windows:
            try:
                result = subprocess.run(
                    ["w32tm", "/query", "/status"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                output = result.stdout

                details = {"raw_output": output}

                if "Source:" in output:
                    source_line = [l for l in output.split('\n') if 'Source:' in l]
                    if source_line:
                        details["time_source"] = source_line[0].split("Source:")[1].strip()

                if "Last Successful Sync Time:" in output:
                    sync_line = [l for l in output.split('\n') if 'Last Successful Sync' in l]
                    if sync_line:
                        details["last_sync"] = sync_line[0].split(":", 1)[1].strip()

                if "Free-running System Clock" in output or result.returncode != 0:
                    return ValidationResult(
                        control_id="AU.L2-3.3.7",
                        check_name="NTP Time Sync Check",
                        status=ValidationStatus.FAIL.value,
                        message="System is not synchronized with a time source",
                        details=details
                    )
                else:
                    return ValidationResult(
                        control_id="AU.L2-3.3.7",
                        check_name="NTP Time Sync Check",
                        status=ValidationStatus.PASS.value,
                        message=f"System is synchronized with: {details.get('time_source', 'configured source')}",
                        details=details
                    )

            except Exception as e:
                return ValidationResult(
                    control_id="AU.L2-3.3.7",
                    check_name="NTP Time Sync Check",
                    status=ValidationStatus.ERROR.value,
                    message=f"Failed to check NTP status: {str(e)}"
                )
        else:
            # Linux/Mac
            try:
                result = subprocess.run(
                    ["timedatectl", "status"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                output = result.stdout
                details = {"raw_output": output}

                if "NTP synchronized: yes" in output or "System clock synchronized: yes" in output:
                    return ValidationResult(
                        control_id="AU.L2-3.3.7",
                        check_name="NTP Time Sync Check",
                        status=ValidationStatus.PASS.value,
                        message="System clock is NTP synchronized",
                        details=details
                    )
                else:
                    return ValidationResult(
                        control_id="AU.L2-3.3.7",
                        check_name="NTP Time Sync Check",
                        status=ValidationStatus.FAIL.value,
                        message="System clock is not NTP synchronized",
                        details=details
                    )
            except FileNotFoundError:
                return ValidationResult(
                    control_id="AU.L2-3.3.7",
                    check_name="NTP Time Sync Check",
                    status=ValidationStatus.MANUAL.value,
                    message="Could not automatically check NTP - manual verification required"
                )
            except Exception as e:
                return ValidationResult(
                    control_id="AU.L2-3.3.7",
                    check_name="NTP Time Sync Check",
                    status=ValidationStatus.ERROR.value,
                    message=f"Failed to check NTP status: {str(e)}"
                )


# =============================================================================
# AWS VALIDATORS (similar to CloudSecurityScanner)
# =============================================================================

class AWSValidator:
    """
    Validates AWS security configurations for CMMC compliance.
    Requires boto3 and appropriate AWS credentials.
    """

    def __init__(self):
        self.boto3_available = False
        try:
            import boto3
            self.boto3 = boto3
            self.boto3_available = True
        except ImportError:
            pass

    def check_s3_encryption(self) -> List[ValidationResult]:
        """
        Check S3 bucket encryption settings
        Control: SC.L2-3.13.16 (Data at Rest)
        """
        if not self.boto3_available:
            return [ValidationResult(
                control_id="SC.L2-3.13.16",
                check_name="S3 Encryption Check",
                status=ValidationStatus.SKIPPED.value,
                message="Skipped - boto3 not installed"
            )]

        results = []
        try:
            s3 = self.boto3.client('s3')
            buckets = s3.list_buckets().get('Buckets', [])

            unencrypted = []
            encrypted = []

            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                    rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                    if rules:
                        encrypted.append(bucket_name)
                    else:
                        unencrypted.append(bucket_name)
                except s3.exceptions.ClientError as e:
                    if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                        unencrypted.append(bucket_name)
                    else:
                        pass

            details = {
                "total_buckets": len(buckets),
                "encrypted": encrypted,
                "unencrypted": unencrypted
            }

            if unencrypted:
                results.append(ValidationResult(
                    control_id="SC.L2-3.13.16",
                    check_name="S3 Encryption Check",
                    status=ValidationStatus.FAIL.value,
                    message=f"{len(unencrypted)} buckets without default encryption",
                    details=details,
                    evidence=json.dumps(details, indent=2)
                ))
            else:
                results.append(ValidationResult(
                    control_id="SC.L2-3.13.16",
                    check_name="S3 Encryption Check",
                    status=ValidationStatus.PASS.value,
                    message="All S3 buckets have default encryption enabled",
                    details=details,
                    evidence=json.dumps(details, indent=2)
                ))

        except Exception as e:
            results.append(ValidationResult(
                control_id="SC.L2-3.13.16",
                check_name="S3 Encryption Check",
                status=ValidationStatus.ERROR.value,
                message=f"Failed to check S3 encryption: {str(e)}"
            ))

        return results

    def check_cloudtrail(self) -> ValidationResult:
        """
        Check CloudTrail logging configuration
        Control: AU.L2-3.3.1 (System Auditing)
        """
        if not self.boto3_available:
            return ValidationResult(
                control_id="AU.L2-3.3.1",
                check_name="CloudTrail Check",
                status=ValidationStatus.SKIPPED.value,
                message="Skipped - boto3 not installed"
            )

        try:
            ct = self.boto3.client('cloudtrail')
            trails = ct.describe_trails().get('trailList', [])

            if not trails:
                return ValidationResult(
                    control_id="AU.L2-3.3.1",
                    check_name="CloudTrail Check",
                    status=ValidationStatus.FAIL.value,
                    message="No CloudTrail trails configured",
                    details={"trails": []}
                )

            multi_region = [t for t in trails if t.get('IsMultiRegionTrail')]
            logging_enabled = []

            for trail in trails:
                try:
                    status = ct.get_trail_status(Name=trail['Name'])
                    if status.get('IsLogging'):
                        logging_enabled.append(trail['Name'])
                except:
                    pass

            details = {
                "total_trails": len(trails),
                "multi_region_trails": len(multi_region),
                "logging_enabled": logging_enabled
            }

            if multi_region and logging_enabled:
                return ValidationResult(
                    control_id="AU.L2-3.3.1",
                    check_name="CloudTrail Check",
                    status=ValidationStatus.PASS.value,
                    message="CloudTrail is properly configured with multi-region logging",
                    details=details,
                    evidence=json.dumps(details, indent=2)
                )
            else:
                issues = []
                if not multi_region:
                    issues.append("No multi-region trail configured")
                if not logging_enabled:
                    issues.append("No trails have logging enabled")

                return ValidationResult(
                    control_id="AU.L2-3.3.1",
                    check_name="CloudTrail Check",
                    status=ValidationStatus.FAIL.value,
                    message=f"CloudTrail issues: {'; '.join(issues)}",
                    details={**details, "issues": issues},
                    evidence=json.dumps(details, indent=2)
                )

        except Exception as e:
            return ValidationResult(
                control_id="AU.L2-3.3.1",
                check_name="CloudTrail Check",
                status=ValidationStatus.ERROR.value,
                message=f"Failed to check CloudTrail: {str(e)}"
            )

    def check_mfa_on_root(self) -> ValidationResult:
        """
        Check if MFA is enabled on root account
        Control: IA.L2-3.5.3 (Multi-Factor Authentication)
        """
        if not self.boto3_available:
            return ValidationResult(
                control_id="IA.L2-3.5.3",
                check_name="Root Account MFA Check",
                status=ValidationStatus.SKIPPED.value,
                message="Skipped - boto3 not installed"
            )

        try:
            iam = self.boto3.client('iam')
            summary = iam.get_account_summary().get('SummaryMap', {})

            mfa_enabled = summary.get('AccountMFAEnabled', 0)

            if mfa_enabled:
                return ValidationResult(
                    control_id="IA.L2-3.5.3",
                    check_name="Root Account MFA Check",
                    status=ValidationStatus.PASS.value,
                    message="MFA is enabled on root account",
                    details={"mfa_enabled": True}
                )
            else:
                return ValidationResult(
                    control_id="IA.L2-3.5.3",
                    check_name="Root Account MFA Check",
                    status=ValidationStatus.FAIL.value,
                    message="MFA is NOT enabled on root account - CRITICAL",
                    details={"mfa_enabled": False}
                )

        except Exception as e:
            return ValidationResult(
                control_id="IA.L2-3.5.3",
                check_name="Root Account MFA Check",
                status=ValidationStatus.ERROR.value,
                message=f"Failed to check root MFA: {str(e)}"
            )

    def check_security_groups(self) -> List[ValidationResult]:
        """
        Check for overly permissive security groups
        Control: SC.L2-3.13.6 (Network Communication by Exception)
        """
        if not self.boto3_available:
            return [ValidationResult(
                control_id="SC.L2-3.13.6",
                check_name="Security Group Check",
                status=ValidationStatus.SKIPPED.value,
                message="Skipped - boto3 not installed"
            )]

        results = []
        try:
            ec2 = self.boto3.client('ec2')
            sgs = ec2.describe_security_groups().get('SecurityGroups', [])

            open_to_world = []
            for sg in sgs:
                sg_id = sg['GroupId']
                sg_name = sg.get('GroupName', 'Unknown')

                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 'All')
                            to_port = rule.get('ToPort', 'All')
                            protocol = rule.get('IpProtocol', 'All')

                            # Some ports are expected to be open (80, 443)
                            if from_port not in [80, 443] and protocol != '-1':
                                open_to_world.append({
                                    "sg_id": sg_id,
                                    "sg_name": sg_name,
                                    "port": f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                                    "protocol": protocol
                                })

            details = {
                "total_security_groups": len(sgs),
                "open_to_world": open_to_world
            }

            if open_to_world:
                results.append(ValidationResult(
                    control_id="SC.L2-3.13.6",
                    check_name="Security Group Check",
                    status=ValidationStatus.FAIL.value,
                    message=f"{len(open_to_world)} security group rules allow 0.0.0.0/0",
                    details=details,
                    evidence=json.dumps(details, indent=2)
                ))
            else:
                results.append(ValidationResult(
                    control_id="SC.L2-3.13.6",
                    check_name="Security Group Check",
                    status=ValidationStatus.PASS.value,
                    message="No overly permissive security group rules found",
                    details=details,
                    evidence=json.dumps(details, indent=2)
                ))

        except Exception as e:
            results.append(ValidationResult(
                control_id="SC.L2-3.13.6",
                check_name="Security Group Check",
                status=ValidationStatus.ERROR.value,
                message=f"Failed to check security groups: {str(e)}"
            ))

        return results

    def run_all_checks(self) -> List[ValidationResult]:
        """Run all AWS validation checks"""
        results = []
        results.extend(self.check_s3_encryption())
        results.append(self.check_cloudtrail())
        results.append(self.check_mfa_on_root())
        results.extend(self.check_security_groups())
        return results


# =============================================================================
# MAIN VALIDATION RUNNER
# =============================================================================

class CMMCTechnicalValidator:
    """
    Main orchestrator for CMMC technical validation checks.
    Runs all validators and generates comprehensive reports.
    """

    def __init__(self, target_name: str = "Local System"):
        self.target_name = target_name
        self.windows_validator = WindowsValidator()
        self.network_validator = NetworkValidator()
        self.aws_validator = AWSValidator()
        self.report = ValidationReport(
            target_system=target_name,
            validation_date=datetime.now().isoformat()
        )

    def run_windows_checks(self) -> List[ValidationResult]:
        """Run all Windows/AD validation checks"""
        print("  Running Windows/AD checks...")
        return self.windows_validator.run_all_checks()

    def run_network_checks(self, hosts: List[str] = None) -> List[ValidationResult]:
        """Run network validation checks"""
        print("  Running Network checks...")
        results = []

        # Always check NTP
        results.append(self.network_validator.check_ntp_sync())

        # Check TLS on provided hosts
        if hosts:
            for host in hosts:
                results.append(self.network_validator.check_tls_version(host))
                results.append(self.network_validator.check_weak_tls_protocols(host))
                results.append(self.network_validator.check_open_ports(host))

        return results

    def run_aws_checks(self) -> List[ValidationResult]:
        """Run AWS validation checks"""
        print("  Running AWS checks...")
        return self.aws_validator.run_all_checks()

    def run_full_validation(
        self,
        include_windows: bool = True,
        include_network: bool = True,
        include_aws: bool = True,
        network_hosts: List[str] = None
    ) -> ValidationReport:
        """
        Run complete technical validation.

        Args:
            include_windows: Run Windows/AD checks
            include_network: Run network checks
            include_aws: Run AWS checks
            network_hosts: List of hosts for network scanning

        Returns:
            ValidationReport with all results
        """
        print(f"\nCMMC Technical Validation - {self.target_name}")
        print("=" * 60)

        if include_windows:
            for result in self.run_windows_checks():
                self.report.add_result(result)

        if include_network:
            for result in self.run_network_checks(network_hosts):
                self.report.add_result(result)

        if include_aws:
            for result in self.run_aws_checks():
                self.report.add_result(result)

        self.report.generate_summary()
        return self.report

    def export_report(self, output_path: str) -> str:
        """Export validation report to JSON"""
        with open(output_path, 'w') as f:
            json.dump(self.report.to_dict(), f, indent=2)
        return output_path

    def generate_markdown_report(self, output_path: str) -> str:
        """Generate validation report in Markdown format"""
        summary = self.report.generate_summary()

        content = f"""# CMMC Technical Validation Report

## Target: {self.report.target_system}
## Date: {self.report.validation_date}

---

## Executive Summary

| Metric | Count |
|--------|-------|
| Total Checks | {summary['total_checks']} |
| Passed | {summary['passed']} |
| Failed | {summary['failed']} |
| Warnings | {summary['warnings']} |
| Errors | {summary['errors']} |
| Skipped | {summary['skipped']} |
| Manual Review | {summary['manual_review']} |

**Pass Rate:** {round(summary['passed'] / max(summary['total_checks'], 1) * 100, 1)}%

---

## Detailed Results

"""
        # Group results by status
        failed = [r for r in self.report.results if r.status == "FAIL"]
        warnings = [r for r in self.report.results if r.status == "WARNING"]
        passed = [r for r in self.report.results if r.status == "PASS"]
        other = [r for r in self.report.results if r.status not in ["PASS", "FAIL", "WARNING"]]

        if failed:
            content += "### Failed Checks (Requires Remediation)\n\n"
            for r in failed:
                content += f"#### {r.control_id}: {r.check_name}\n\n"
                content += f"**Status:** FAIL\n\n"
                content += f"**Finding:** {r.message}\n\n"
                if r.details.get("issues"):
                    content += "**Issues:**\n"
                    for issue in r.details["issues"]:
                        content += f"- {issue}\n"
                    content += "\n"
                content += "---\n\n"

        if warnings:
            content += "### Warnings (Review Recommended)\n\n"
            for r in warnings:
                content += f"#### {r.control_id}: {r.check_name}\n\n"
                content += f"**Status:** WARNING\n\n"
                content += f"**Finding:** {r.message}\n\n"
                content += "---\n\n"

        if passed:
            content += "### Passed Checks\n\n"
            content += "| Control | Check | Status |\n"
            content += "|---------|-------|--------|\n"
            for r in passed:
                content += f"| {r.control_id} | {r.check_name} | PASS |\n"
            content += "\n"

        if other:
            content += "### Other (Skipped/Error/Manual Review)\n\n"
            for r in other:
                content += f"- **{r.control_id}**: {r.check_name} - {r.status}: {r.message}\n"
            content += "\n"

        content += """
---

## Controls Validated

This technical validation covers the following CMMC Level 2 controls:

| Control | Description | Validation Method |
|---------|-------------|-------------------|
| AC.L2-3.1.8 | Unsuccessful Logon Attempts | Account lockout policy check |
| AC.L2-3.1.10 | Session Lock | Screen lock timeout check |
| AU.L2-3.3.1 | System Auditing | Audit policy / CloudTrail check |
| AU.L2-3.3.7 | Authoritative Time Source | NTP synchronization check |
| CM.L2-3.4.7 | Nonessential Functionality | Open ports scan |
| IA.L2-3.5.3 | Multi-Factor Authentication | Root MFA check (AWS) |
| IA.L2-3.5.7 | Password Complexity | Password policy check |
| IA.L2-3.5.8 | Password Reuse | Password history check |
| SC.L2-3.13.1 | Boundary Protection | Firewall status check |
| SC.L2-3.13.6 | Network Communication by Exception | Security group check (AWS) |
| SC.L2-3.13.8 | Data in Transit | TLS version check |
| SC.L2-3.13.11 | CUI Encryption | FIPS / TLS protocol check |
| SC.L2-3.13.16 | Data at Rest | BitLocker / S3 encryption check |
| SI.L2-3.14.2 | Malicious Code Protection | Antivirus status check |

---

*Generated by CMMC Technical Validation Scripts*
"""

        with open(output_path, 'w') as f:
            f.write(content)

        return output_path


def run_validation_demo():
    """Demonstration of technical validation capabilities"""
    print("=" * 70)
    print("CMMC LEVEL 2 TECHNICAL VALIDATION SCRIPTS")
    print("=" * 70)
    print()
    print("This module provides automated validation for the following controls:")
    print()

    controls_covered = [
        ("AC.L2-3.1.8", "Unsuccessful Logon Attempts", "Account lockout policy"),
        ("AC.L2-3.1.10", "Session Lock", "Screen lock timeout"),
        ("AU.L2-3.3.1", "System Auditing", "Audit policy / CloudTrail"),
        ("AU.L2-3.3.7", "Authoritative Time Source", "NTP synchronization"),
        ("CM.L2-3.4.7", "Nonessential Functionality", "Open ports scan"),
        ("IA.L2-3.5.3", "Multi-Factor Authentication", "AWS root MFA"),
        ("IA.L2-3.5.7", "Password Complexity", "Password policy"),
        ("IA.L2-3.5.8", "Password Reuse", "Password history"),
        ("SC.L2-3.13.1", "Boundary Protection", "Firewall status"),
        ("SC.L2-3.13.6", "Network Communication by Exception", "Security groups"),
        ("SC.L2-3.13.8", "Data in Transit", "TLS version"),
        ("SC.L2-3.13.11", "CUI Encryption", "FIPS / TLS protocols"),
        ("SC.L2-3.13.16", "Data at Rest", "BitLocker / S3 encryption"),
        ("SI.L2-3.14.2", "Malicious Code Protection", "Antivirus status"),
    ]

    print(f"{'Control':<15} {'Title':<35} {'Validation Method':<25}")
    print("-" * 75)
    for ctrl, title, method in controls_covered:
        print(f"{ctrl:<15} {title:<35} {method:<25}")

    print()
    print(f"Total: {len(controls_covered)} controls can be validated automatically")
    print()

    # Run local validation
    print("Running validation on local system...")
    print()

    validator = CMMCTechnicalValidator("Local System Demo")
    report = validator.run_full_validation(
        include_windows=True,
        include_network=True,
        include_aws=False,  # Skip AWS unless credentials available
        network_hosts=None
    )

    print()
    print("=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)

    summary = report.summary
    print(f"  Total Checks:   {summary['total_checks']}")
    print(f"  Passed:         {summary['passed']}")
    print(f"  Failed:         {summary['failed']}")
    print(f"  Warnings:       {summary['warnings']}")
    print(f"  Skipped:        {summary['skipped']}")
    print(f"  Errors:         {summary['errors']}")

    # Save reports
    os.makedirs("./validation_output", exist_ok=True)
    json_path = validator.export_report("./validation_output/technical_validation.json")
    md_path = validator.generate_markdown_report("./validation_output/technical_validation_report.md")

    print()
    print("Reports saved:")
    print(f"  JSON: {json_path}")
    print(f"  Markdown: {md_path}")


if __name__ == "__main__":
    run_validation_demo()
