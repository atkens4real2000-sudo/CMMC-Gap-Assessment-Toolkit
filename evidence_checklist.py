"""
CMMC Level 2 Evidence Collection Checklist Generator
Generates comprehensive artifact request lists for pre-assessment evidence gathering.

Author: Akintade Akinokun
Purpose: CMMC Level 2 C3PAO Audit Preparation
Reference: NIST SP 800-171A Assessment Procedures

This module creates the evidence request documentation that should be sent to
an organization BEFORE conducting a CMMC assessment. This mirrors the actual
C3PAO assessment process where assessors request evidence in advance.
"""

from datetime import datetime
from typing import Dict, List
import os

# Evidence categories aligned with C3PAO assessment methodology
EVIDENCE_CATALOG = {
    "policies_and_procedures": {
        "category_name": "Policies and Procedures",
        "description": "Written documentation establishing organizational security requirements",
        "artifacts": [
            {
                "name": "Information Security Policy",
                "description": "Master security policy establishing organizational commitment to security",
                "controls": ["All domains"],
                "required": True
            },
            {
                "name": "Access Control Policy",
                "description": "Policy governing user access, authentication, and authorization",
                "controls": ["AC.L2-3.1.1", "AC.L2-3.1.2", "AC.L2-3.1.5", "AC.L2-3.1.6"],
                "required": True
            },
            {
                "name": "Acceptable Use Policy",
                "description": "Rules for acceptable use of organizational systems",
                "controls": ["AC.L2-3.1.9", "SI.L2-3.14.7"],
                "required": True
            },
            {
                "name": "Remote Access Policy",
                "description": "Policy governing remote access to organizational systems",
                "controls": ["AC.L2-3.1.12", "AC.L2-3.1.13", "AC.L2-3.1.14", "AC.L2-3.1.15"],
                "required": True
            },
            {
                "name": "Wireless Security Policy",
                "description": "Policy governing wireless network access and security",
                "controls": ["AC.L2-3.1.16", "AC.L2-3.1.17"],
                "required": True
            },
            {
                "name": "Mobile Device Policy",
                "description": "Policy governing mobile device usage and security requirements",
                "controls": ["AC.L2-3.1.18", "AC.L2-3.1.19"],
                "required": True
            },
            {
                "name": "Media Protection Policy",
                "description": "Policy governing handling, storage, and disposal of media",
                "controls": ["MP.L2-3.8.1", "MP.L2-3.8.2", "MP.L2-3.8.3", "MP.L2-3.8.7"],
                "required": True
            },
            {
                "name": "Removable Media Policy",
                "description": "Policy specifically addressing USB and removable storage devices",
                "controls": ["AC.L2-3.1.21", "MP.L2-3.8.7", "MP.L2-3.8.8"],
                "required": True
            },
            {
                "name": "Password Policy",
                "description": "Policy defining password complexity, age, and handling requirements",
                "controls": ["IA.L2-3.5.7", "IA.L2-3.5.8", "IA.L2-3.5.9", "IA.L2-3.5.10"],
                "required": True
            },
            {
                "name": "Audit and Logging Policy",
                "description": "Policy defining what is logged, retention periods, and review procedures",
                "controls": ["AU.L2-3.3.1", "AU.L2-3.3.2", "AU.L2-3.3.3", "AU.L2-3.3.8"],
                "required": True
            },
            {
                "name": "Configuration Management Policy",
                "description": "Policy governing system configurations, baselines, and change control",
                "controls": ["CM.L2-3.4.1", "CM.L2-3.4.2", "CM.L2-3.4.3"],
                "required": True
            },
            {
                "name": "Change Management Policy/Procedure",
                "description": "Procedure for requesting, reviewing, approving, and implementing changes",
                "controls": ["CM.L2-3.4.3", "CM.L2-3.4.4", "CM.L2-3.4.5"],
                "required": True
            },
            {
                "name": "Incident Response Plan",
                "description": "Plan detailing incident handling procedures from detection to recovery",
                "controls": ["IR.L2-3.6.1", "IR.L2-3.6.2"],
                "required": True
            },
            {
                "name": "Incident Reporting Procedures",
                "description": "Procedures for reporting incidents internally and to external parties (DIBNet)",
                "controls": ["IR.L2-3.6.2"],
                "required": True
            },
            {
                "name": "Maintenance Policy/Procedures",
                "description": "Policy governing system maintenance activities and personnel",
                "controls": ["MA.L2-3.7.1", "MA.L2-3.7.2", "MA.L2-3.7.6"],
                "required": True
            },
            {
                "name": "Personnel Security Policy",
                "description": "Policy governing background checks and personnel actions",
                "controls": ["PS.L2-3.9.1", "PS.L2-3.9.2"],
                "required": True
            },
            {
                "name": "Physical Security Policy",
                "description": "Policy governing physical access to facilities and systems",
                "controls": ["PE.L2-3.10.1", "PE.L2-3.10.3", "PE.L2-3.10.5"],
                "required": True
            },
            {
                "name": "Visitor Policy",
                "description": "Policy governing visitor access, escorts, and logging",
                "controls": ["PE.L2-3.10.3"],
                "required": True
            },
            {
                "name": "Telework/Remote Work Policy",
                "description": "Policy governing security requirements for alternate work sites",
                "controls": ["PE.L2-3.10.6"],
                "required": True
            },
            {
                "name": "Risk Assessment Policy/Procedure",
                "description": "Policy defining risk assessment methodology and frequency",
                "controls": ["RA.L2-3.11.1"],
                "required": True
            },
            {
                "name": "Vulnerability Management Policy",
                "description": "Policy governing vulnerability scanning and remediation",
                "controls": ["RA.L2-3.11.2", "RA.L2-3.11.3"],
                "required": True
            },
            {
                "name": "Patch Management Policy",
                "description": "Policy defining patching requirements and timelines",
                "controls": ["SI.L2-3.14.1"],
                "required": True
            },
            {
                "name": "Data/Media Sanitization Procedures",
                "description": "Procedures for sanitizing media before disposal or reuse (aligned with NIST 800-88)",
                "controls": ["MP.L2-3.8.3", "MA.L2-3.7.3"],
                "required": True
            },
            {
                "name": "CUI Handling Procedures",
                "description": "Procedures specific to identifying, marking, and handling CUI",
                "controls": ["MP.L2-3.8.4", "AC.L2-3.1.3", "AC.L2-3.1.22"],
                "required": True
            },
            {
                "name": "Key Management Procedures",
                "description": "Procedures for cryptographic key generation, storage, rotation, and destruction",
                "controls": ["SC.L2-3.13.10"],
                "required": True
            },
            {
                "name": "Account Management Procedures",
                "description": "Procedures for account provisioning, modification, and deprovisioning",
                "controls": ["AC.L2-3.1.1", "IA.L2-3.5.5", "IA.L2-3.5.6"],
                "required": True
            },
            {
                "name": "Separation of Duties Matrix",
                "description": "Documentation showing separation of incompatible duties",
                "controls": ["AC.L2-3.1.4"],
                "required": True
            },
            {
                "name": "Software Installation Policy",
                "description": "Policy governing user-installed software and approved software lists",
                "controls": ["CM.L2-3.4.8", "CM.L2-3.4.9"],
                "required": True
            }
        ]
    },
    "system_security_documentation": {
        "category_name": "System Security Documentation",
        "description": "Documentation describing system architecture, boundaries, and security implementation",
        "artifacts": [
            {
                "name": "System Security Plan (SSP)",
                "description": "Comprehensive document describing how all 110 controls are implemented",
                "controls": ["CA.L2-3.12.4"],
                "required": True
            },
            {
                "name": "Network Architecture Diagram",
                "description": "Diagram showing network topology, segmentation, and security zones",
                "controls": ["SC.L2-3.13.1", "SC.L2-3.13.5", "AC.L2-3.1.3"],
                "required": True
            },
            {
                "name": "Data Flow Diagram",
                "description": "Diagram showing how CUI flows through the organization",
                "controls": ["AC.L2-3.1.3"],
                "required": True
            },
            {
                "name": "System Boundary Documentation",
                "description": "Documentation defining what is in scope for CMMC assessment",
                "controls": ["CA.L2-3.12.4"],
                "required": True
            },
            {
                "name": "Hardware Asset Inventory",
                "description": "Complete inventory of hardware including servers, workstations, network devices",
                "controls": ["CM.L2-3.4.1"],
                "required": True
            },
            {
                "name": "Software Asset Inventory",
                "description": "Complete inventory of installed software and versions",
                "controls": ["CM.L2-3.4.1"],
                "required": True
            },
            {
                "name": "CUI Asset Inventory",
                "description": "Inventory of systems that process, store, or transmit CUI",
                "controls": ["CM.L2-3.4.1", "AC.L2-3.1.3"],
                "required": True
            },
            {
                "name": "System Interconnection Agreements",
                "description": "ISAs or MOUs documenting connections with external systems",
                "controls": ["AC.L2-3.1.20", "CA.L2-3.12.4"],
                "required": False
            },
            {
                "name": "External Service Provider List",
                "description": "List of cloud services, MSPs, and other external providers with FedRAMP status",
                "controls": ["AC.L2-3.1.20"],
                "required": True
            },
            {
                "name": "Baseline Configuration Documentation",
                "description": "Documentation of approved baseline configurations (golden images, hardening guides)",
                "controls": ["CM.L2-3.4.1", "CM.L2-3.4.2"],
                "required": True
            },
            {
                "name": "Security Architecture Documentation",
                "description": "Documentation of defense-in-depth and security engineering principles",
                "controls": ["SC.L2-3.13.2"],
                "required": True
            }
        ]
    },
    "technical_configurations": {
        "category_name": "Technical Configuration Evidence",
        "description": "Screenshots, exports, and documentation of actual system configurations",
        "artifacts": [
            {
                "name": "Active Directory Group Policy Export",
                "description": "Export or screenshots of GPO settings for password, lockout, and session policies",
                "controls": ["AC.L2-3.1.8", "AC.L2-3.1.10", "AC.L2-3.1.11", "IA.L2-3.5.7", "IA.L2-3.5.8"],
                "required": True
            },
            {
                "name": "MFA Configuration Evidence",
                "description": "Screenshots showing MFA enrollment and enforcement settings",
                "controls": ["IA.L2-3.5.3"],
                "required": True
            },
            {
                "name": "VPN Configuration",
                "description": "VPN encryption settings, authentication requirements, split tunnel settings",
                "controls": ["AC.L2-3.1.12", "AC.L2-3.1.13", "SC.L2-3.13.7"],
                "required": True
            },
            {
                "name": "Firewall Rules Export",
                "description": "Export of firewall rules showing default deny and allowed traffic",
                "controls": ["SC.L2-3.13.1", "SC.L2-3.13.6"],
                "required": True
            },
            {
                "name": "SIEM/Log Management Configuration",
                "description": "Configuration showing what events are logged and retention settings",
                "controls": ["AU.L2-3.3.1", "AU.L2-3.3.5", "AU.L2-3.3.6"],
                "required": True
            },
            {
                "name": "NTP Configuration",
                "description": "Evidence showing time synchronization with authoritative source",
                "controls": ["AU.L2-3.3.7"],
                "required": True
            },
            {
                "name": "Endpoint Protection Configuration",
                "description": "Antivirus/EDR deployment settings, update configurations, scan schedules",
                "controls": ["SI.L2-3.14.2", "SI.L2-3.14.4", "SI.L2-3.14.5"],
                "required": True
            },
            {
                "name": "Disk Encryption Configuration",
                "description": "BitLocker/LUKS settings showing encryption enabled on CUI systems",
                "controls": ["SC.L2-3.13.16"],
                "required": True
            },
            {
                "name": "Mobile Device Management Configuration",
                "description": "MDM policies showing encryption, passcode, and remote wipe requirements",
                "controls": ["AC.L2-3.1.18", "AC.L2-3.1.19"],
                "required": True
            },
            {
                "name": "Wireless Network Configuration",
                "description": "Wireless encryption (WPA2/WPA3-Enterprise), authentication settings",
                "controls": ["AC.L2-3.1.16", "AC.L2-3.1.17"],
                "required": True
            },
            {
                "name": "Email Security Gateway Configuration",
                "description": "Spam filtering, malware scanning, and email encryption settings",
                "controls": ["SI.L2-3.14.2", "SC.L2-3.13.8"],
                "required": True
            },
            {
                "name": "Web Proxy/Filter Configuration",
                "description": "Web filtering and mobile code control settings",
                "controls": ["SC.L2-3.13.13"],
                "required": True
            },
            {
                "name": "USB/Device Control Configuration",
                "description": "Endpoint device control settings for removable media",
                "controls": ["MP.L2-3.8.7", "AC.L2-3.1.21"],
                "required": True
            },
            {
                "name": "Application Whitelisting/Blacklisting Configuration",
                "description": "Application control policy settings",
                "controls": ["CM.L2-3.4.8"],
                "required": False
            },
            {
                "name": "TLS/SSL Configuration",
                "description": "Evidence showing TLS 1.2+ enforcement, cipher suites",
                "controls": ["SC.L2-3.13.8", "SC.L2-3.13.11"],
                "required": True
            },
            {
                "name": "FIPS Mode Configuration",
                "description": "Evidence showing FIPS 140-2 validated cryptography is enabled",
                "controls": ["SC.L2-3.13.11"],
                "required": True
            },
            {
                "name": "Backup Configuration",
                "description": "Backup encryption settings and storage security",
                "controls": ["MP.L2-3.8.9"],
                "required": True
            },
            {
                "name": "Login Banner Configuration",
                "description": "Screenshots of login banners displaying privacy/security notices",
                "controls": ["AC.L2-3.1.9"],
                "required": True
            },
            {
                "name": "Session Timeout Settings",
                "description": "Evidence of inactivity timeout and session termination settings",
                "controls": ["AC.L2-3.1.10", "AC.L2-3.1.11", "SC.L2-3.13.9"],
                "required": True
            },
            {
                "name": "Privileged Access Management Configuration",
                "description": "PAM tool configuration showing privileged account controls",
                "controls": ["AC.L2-3.1.5", "AC.L2-3.1.7"],
                "required": True
            },
            {
                "name": "Network Segmentation Evidence",
                "description": "VLAN configurations, firewall rules showing CUI network isolation",
                "controls": ["SC.L2-3.13.1", "SC.L2-3.13.3", "SC.L2-3.13.5"],
                "required": True
            },
            {
                "name": "IDS/IPS Configuration",
                "description": "Intrusion detection/prevention system deployment and rules",
                "controls": ["SI.L2-3.14.6"],
                "required": True
            },
            {
                "name": "Vulnerability Scanner Configuration",
                "description": "Scan schedules, scope, and credential settings",
                "controls": ["RA.L2-3.11.2"],
                "required": True
            }
        ]
    },
    "operational_records": {
        "category_name": "Operational Records and Logs",
        "description": "Evidence of ongoing operations and compliance activities",
        "artifacts": [
            {
                "name": "User Account List with Roles",
                "description": "Export of all user accounts showing roles and access levels",
                "controls": ["AC.L2-3.1.1", "AC.L2-3.1.2"],
                "required": True
            },
            {
                "name": "Privileged Account Inventory",
                "description": "List of all privileged/admin accounts with justification",
                "controls": ["AC.L2-3.1.5"],
                "required": True
            },
            {
                "name": "Service Account Inventory",
                "description": "List of service accounts with purpose and owner",
                "controls": ["IA.L2-3.5.1"],
                "required": True
            },
            {
                "name": "Access Review Records",
                "description": "Evidence of periodic access reviews (quarterly/annual)",
                "controls": ["AC.L2-3.1.1", "AC.L2-3.1.2"],
                "required": True
            },
            {
                "name": "Security Awareness Training Records",
                "description": "Training completion records showing all personnel trained",
                "controls": ["AT.L2-3.2.1", "AT.L2-3.2.2", "AT.L2-3.2.3"],
                "required": True
            },
            {
                "name": "Role-Based Training Records",
                "description": "Specialized training records for security personnel",
                "controls": ["AT.L2-3.2.2"],
                "required": True
            },
            {
                "name": "Sample Audit Logs",
                "description": "Sample logs showing user activity, authentication, privileged actions",
                "controls": ["AU.L2-3.3.1", "AU.L2-3.3.2", "AU.L2-3.3.7"],
                "required": True
            },
            {
                "name": "Log Review Records",
                "description": "Evidence that logs are reviewed (meeting notes, tickets, reports)",
                "controls": ["AU.L2-3.3.3", "AU.L2-3.3.5"],
                "required": True
            },
            {
                "name": "Change Management Records",
                "description": "Sample change requests showing review and approval process",
                "controls": ["CM.L2-3.4.3", "CM.L2-3.4.4", "CM.L2-3.4.5"],
                "required": True
            },
            {
                "name": "Vulnerability Scan Reports",
                "description": "Recent vulnerability scan results",
                "controls": ["RA.L2-3.11.2"],
                "required": True
            },
            {
                "name": "Vulnerability Remediation Records",
                "description": "Evidence of vulnerability patching/remediation",
                "controls": ["RA.L2-3.11.3", "SI.L2-3.14.1"],
                "required": True
            },
            {
                "name": "Patch Management Records",
                "description": "Evidence of regular patching activities",
                "controls": ["SI.L2-3.14.1"],
                "required": True
            },
            {
                "name": "Incident Response Records",
                "description": "Documentation of past security incidents and responses",
                "controls": ["IR.L2-3.6.1", "IR.L2-3.6.2"],
                "required": True
            },
            {
                "name": "Incident Response Test/Exercise Records",
                "description": "Documentation of tabletop exercises or IR drills",
                "controls": ["IR.L2-3.6.3"],
                "required": True
            },
            {
                "name": "Risk Assessment Reports",
                "description": "Most recent risk assessment documentation",
                "controls": ["RA.L2-3.11.1"],
                "required": True
            },
            {
                "name": "Security Assessment Reports",
                "description": "Self-assessment or third-party assessment results",
                "controls": ["CA.L2-3.12.1"],
                "required": True
            },
            {
                "name": "Plan of Action and Milestones (POA&M)",
                "description": "Current POA&M tracking known deficiencies",
                "controls": ["CA.L2-3.12.2"],
                "required": True
            },
            {
                "name": "Background Check Records",
                "description": "Evidence that personnel screening is performed (policy compliance, not PII)",
                "controls": ["PS.L2-3.9.1"],
                "required": True
            },
            {
                "name": "Termination/Transfer Records",
                "description": "Sample termination checklists showing access revocation",
                "controls": ["PS.L2-3.9.2"],
                "required": True
            },
            {
                "name": "Physical Access Logs",
                "description": "Badge system logs or sign-in sheets for secure areas",
                "controls": ["PE.L2-3.10.4"],
                "required": True
            },
            {
                "name": "Visitor Logs",
                "description": "Records of visitor access to facilities",
                "controls": ["PE.L2-3.10.3"],
                "required": True
            },
            {
                "name": "Maintenance Records",
                "description": "Records of system maintenance activities",
                "controls": ["MA.L2-3.7.1", "MA.L2-3.7.2"],
                "required": True
            },
            {
                "name": "Media Sanitization Records",
                "description": "Records/certificates of media destruction or sanitization",
                "controls": ["MP.L2-3.8.3"],
                "required": True
            },
            {
                "name": "Key/Badge Issuance Records",
                "description": "Records of physical access device issuance",
                "controls": ["PE.L2-3.10.5"],
                "required": True
            },
            {
                "name": "Continuous Monitoring Reports",
                "description": "Evidence of ongoing security monitoring activities",
                "controls": ["CA.L2-3.12.3"],
                "required": True
            },
            {
                "name": "Security Alert Subscription Evidence",
                "description": "Evidence of subscription to security advisories (US-CERT, vendors)",
                "controls": ["SI.L2-3.14.3"],
                "required": True
            }
        ]
    },
    "third_party_documentation": {
        "category_name": "Third-Party and Vendor Documentation",
        "description": "Documentation from external service providers and vendors",
        "artifacts": [
            {
                "name": "Cloud Service Provider FedRAMP Authorization",
                "description": "FedRAMP authorization letters or marketplace listing for CSPs handling CUI",
                "controls": ["AC.L2-3.1.20"],
                "required": True
            },
            {
                "name": "Vendor Security Assessments",
                "description": "Security questionnaires or assessments for third-party vendors",
                "controls": ["AC.L2-3.1.20"],
                "required": True
            },
            {
                "name": "FIPS 140-2 Certificates",
                "description": "Certificates validating FIPS-compliant cryptographic modules",
                "controls": ["SC.L2-3.13.11"],
                "required": True
            },
            {
                "name": "Penetration Test Reports",
                "description": "Third-party penetration testing results (if performed)",
                "controls": ["CA.L2-3.12.1"],
                "required": False
            },
            {
                "name": "SOC 2 Reports from Service Providers",
                "description": "SOC 2 Type II reports from key service providers",
                "controls": ["AC.L2-3.1.20"],
                "required": False
            }
        ]
    }
}

# Interview guide organized by role
INTERVIEW_GUIDE = {
    "ciso_security_manager": {
        "role": "CISO / Information Security Manager",
        "topics": [
            {
                "topic": "Security Program Overview",
                "questions": [
                    "Describe your overall security program structure and governance.",
                    "How is security integrated into business operations?",
                    "What frameworks guide your security program (NIST, ISO, etc.)?",
                    "How do you ensure security policies are communicated and enforced?"
                ],
                "controls": ["All domains"]
            },
            {
                "topic": "Risk Management",
                "questions": [
                    "How often do you conduct risk assessments?",
                    "What methodology do you use for risk assessments?",
                    "How are risk assessment findings prioritized and addressed?",
                    "Who approves risk acceptance decisions?"
                ],
                "controls": ["RA.L2-3.11.1", "RA.L2-3.11.3"]
            },
            {
                "topic": "Incident Response",
                "questions": [
                    "Describe your incident response process from detection to recovery.",
                    "How do you report cyber incidents to the DoD (DIBNet)?",
                    "When was your last incident response exercise?",
                    "How do you track and learn from security incidents?"
                ],
                "controls": ["IR.L2-3.6.1", "IR.L2-3.6.2", "IR.L2-3.6.3"]
            },
            {
                "topic": "Third-Party Risk",
                "questions": [
                    "How do you assess security of third-party vendors?",
                    "How do you ensure cloud providers meet FedRAMP requirements?",
                    "What ongoing monitoring do you perform for vendors?"
                ],
                "controls": ["AC.L2-3.1.20"]
            },
            {
                "topic": "Continuous Monitoring",
                "questions": [
                    "How do you continuously monitor security control effectiveness?",
                    "What metrics do you track and report to leadership?",
                    "How often do you review and update the SSP?"
                ],
                "controls": ["CA.L2-3.12.3", "CA.L2-3.12.4"]
            }
        ]
    },
    "system_administrator": {
        "role": "System Administrator",
        "topics": [
            {
                "topic": "Account Management",
                "questions": [
                    "Walk me through the process of creating a new user account.",
                    "How do you handle account requests for elevated privileges?",
                    "How are accounts disabled when employees leave?",
                    "How do you identify and disable inactive accounts?"
                ],
                "controls": ["AC.L2-3.1.1", "AC.L2-3.1.5", "IA.L2-3.5.6", "PS.L2-3.9.2"]
            },
            {
                "topic": "System Configuration",
                "questions": [
                    "How do you establish and maintain baseline configurations?",
                    "What security baselines do you follow (CIS, DISA STIGs)?",
                    "How do you ensure only essential services are running?",
                    "How do you verify systems comply with baselines?"
                ],
                "controls": ["CM.L2-3.4.1", "CM.L2-3.4.2", "CM.L2-3.4.6", "CM.L2-3.4.7"]
            },
            {
                "topic": "Change Management",
                "questions": [
                    "Describe your change management process.",
                    "How are changes tested before production deployment?",
                    "Who approves changes to production systems?",
                    "How is security impact assessed for changes?"
                ],
                "controls": ["CM.L2-3.4.3", "CM.L2-3.4.4", "CM.L2-3.4.5"]
            },
            {
                "topic": "Patch Management",
                "questions": [
                    "How do you identify systems needing patches?",
                    "What is your patching timeline for critical vulnerabilities?",
                    "How do you verify patches are successfully applied?",
                    "How do you handle systems that cannot be patched?"
                ],
                "controls": ["SI.L2-3.14.1", "RA.L2-3.11.3"]
            },
            {
                "topic": "Logging and Monitoring",
                "questions": [
                    "What events are logged on your systems?",
                    "Where are logs stored and for how long?",
                    "How do you protect logs from tampering?",
                    "How are logs reviewed and by whom?"
                ],
                "controls": ["AU.L2-3.3.1", "AU.L2-3.3.2", "AU.L2-3.3.8", "AU.L2-3.3.9"]
            },
            {
                "topic": "Backup and Recovery",
                "questions": [
                    "How are backups performed and how often?",
                    "Are backups encrypted?",
                    "How do you test backup restoration?",
                    "Where are backups stored?"
                ],
                "controls": ["MP.L2-3.8.9"]
            }
        ]
    },
    "network_administrator": {
        "role": "Network Administrator",
        "topics": [
            {
                "topic": "Network Architecture",
                "questions": [
                    "Describe your network segmentation approach.",
                    "How is the CUI environment separated from other networks?",
                    "What controls exist at network boundaries?",
                    "How do you implement defense-in-depth?"
                ],
                "controls": ["SC.L2-3.13.1", "SC.L2-3.13.5", "SC.L2-3.13.2"]
            },
            {
                "topic": "Firewall Management",
                "questions": [
                    "Is your default firewall policy deny-all?",
                    "How are firewall rule changes requested and approved?",
                    "How often are firewall rules reviewed?",
                    "How do you remove obsolete rules?"
                ],
                "controls": ["SC.L2-3.13.6"]
            },
            {
                "topic": "Remote Access",
                "questions": [
                    "What remote access methods are approved?",
                    "How is remote access authenticated?",
                    "Is split tunneling disabled on VPN?",
                    "How do you monitor remote access sessions?"
                ],
                "controls": ["AC.L2-3.1.12", "AC.L2-3.1.13", "AC.L2-3.1.14", "SC.L2-3.13.7"]
            },
            {
                "topic": "Wireless Security",
                "questions": [
                    "What wireless encryption is used?",
                    "How are wireless devices authenticated?",
                    "How do you detect rogue access points?",
                    "Is wireless traffic on a separate network segment?"
                ],
                "controls": ["AC.L2-3.1.16", "AC.L2-3.1.17"]
            },
            {
                "topic": "Network Monitoring",
                "questions": [
                    "What network monitoring tools are deployed?",
                    "How do you detect potential attacks?",
                    "How is east-west traffic monitored?",
                    "What happens when suspicious traffic is detected?"
                ],
                "controls": ["SI.L2-3.14.6", "SC.L2-3.13.1"]
            }
        ]
    },
    "security_analyst": {
        "role": "Security Analyst / SOC",
        "topics": [
            {
                "topic": "Security Monitoring",
                "questions": [
                    "What SIEM platform do you use?",
                    "What log sources feed into the SIEM?",
                    "How do you correlate events across sources?",
                    "What are your key detection use cases?"
                ],
                "controls": ["AU.L2-3.3.5", "AU.L2-3.3.6", "SI.L2-3.14.6"]
            },
            {
                "topic": "Alerting and Response",
                "questions": [
                    "How are security alerts prioritized?",
                    "What is your average time to respond to alerts?",
                    "How do you escalate potential incidents?",
                    "How do you handle false positives?"
                ],
                "controls": ["AU.L2-3.3.4", "IR.L2-3.6.1"]
            },
            {
                "topic": "Vulnerability Management",
                "questions": [
                    "How often do you scan for vulnerabilities?",
                    "What scanning tools do you use?",
                    "How do you prioritize vulnerability remediation?",
                    "How do you track remediation progress?"
                ],
                "controls": ["RA.L2-3.11.2", "RA.L2-3.11.3"]
            },
            {
                "topic": "Malware Protection",
                "questions": [
                    "What endpoint protection solution is deployed?",
                    "How do you ensure all endpoints have protection?",
                    "How quickly are signature updates applied?",
                    "How do you handle detected malware?"
                ],
                "controls": ["SI.L2-3.14.2", "SI.L2-3.14.4", "SI.L2-3.14.5"]
            },
            {
                "topic": "Threat Intelligence",
                "questions": [
                    "What threat intelligence sources do you use?",
                    "How do you incorporate threat intel into detection?",
                    "How do you stay current on emerging threats?",
                    "How do you share threat information?"
                ],
                "controls": ["SI.L2-3.14.3"]
            }
        ]
    },
    "hr_personnel": {
        "role": "Human Resources",
        "topics": [
            {
                "topic": "Personnel Screening",
                "questions": [
                    "What background checks are performed for new hires?",
                    "Are background checks performed before access is granted?",
                    "How do you handle adverse background findings?",
                    "Are background checks refreshed periodically?"
                ],
                "controls": ["PS.L2-3.9.1"]
            },
            {
                "topic": "Onboarding",
                "questions": [
                    "Is security training part of new hire onboarding?",
                    "Do employees sign acceptable use agreements?",
                    "How are access requirements communicated to IT?"
                ],
                "controls": ["AT.L2-3.2.1", "PS.L2-3.9.1"]
            },
            {
                "topic": "Termination Process",
                "questions": [
                    "Describe your termination process.",
                    "How quickly is IT notified of terminations?",
                    "How do you ensure all access is revoked?",
                    "How is company property recovered?"
                ],
                "controls": ["PS.L2-3.9.2"]
            },
            {
                "topic": "Transfers",
                "questions": [
                    "How are access changes handled when employees transfer?",
                    "Is old access removed when new access is granted?",
                    "Who authorizes access changes for transfers?"
                ],
                "controls": ["PS.L2-3.9.2"]
            }
        ]
    },
    "facilities_physical_security": {
        "role": "Facilities / Physical Security",
        "topics": [
            {
                "topic": "Physical Access Control",
                "questions": [
                    "How is physical access to server rooms controlled?",
                    "What authentication is required (badge, PIN, biometric)?",
                    "Who authorizes physical access requests?",
                    "How often is physical access reviewed?"
                ],
                "controls": ["PE.L2-3.10.1", "PE.L2-3.10.5"]
            },
            {
                "topic": "Visitor Management",
                "questions": [
                    "How are visitors registered and identified?",
                    "Are visitors always escorted in secure areas?",
                    "How long are visitor logs retained?",
                    "How are visitor badges distinguished from employee badges?"
                ],
                "controls": ["PE.L2-3.10.3"]
            },
            {
                "topic": "Monitoring",
                "questions": [
                    "Are secure areas monitored by cameras?",
                    "How long is surveillance footage retained?",
                    "Are there intrusion detection systems?",
                    "How is environmental monitoring performed (fire, water, HVAC)?"
                ],
                "controls": ["PE.L2-3.10.2"]
            },
            {
                "topic": "Access Logs",
                "questions": [
                    "How are physical access logs maintained?",
                    "How long are access logs retained?",
                    "How often are logs reviewed?",
                    "How are anomalies investigated?"
                ],
                "controls": ["PE.L2-3.10.4"]
            }
        ]
    },
    "end_users": {
        "role": "End Users (Sample)",
        "topics": [
            {
                "topic": "Security Awareness",
                "questions": [
                    "Have you completed security awareness training?",
                    "How would you report a suspected phishing email?",
                    "How would you report a potential security incident?",
                    "Do you know what CUI is and how to handle it?"
                ],
                "controls": ["AT.L2-3.2.1", "AT.L2-3.2.3"]
            },
            {
                "topic": "Access and Passwords",
                "questions": [
                    "Do you share your password with anyone?",
                    "Do you use multi-factor authentication?",
                    "What do you do if you forget your password?",
                    "Do you lock your workstation when stepping away?"
                ],
                "controls": ["IA.L2-3.5.3", "AC.L2-3.1.10"]
            },
            {
                "topic": "Data Handling",
                "questions": [
                    "How do you identify CUI in your work?",
                    "How do you securely share sensitive documents?",
                    "Do you store work data on personal devices?",
                    "How do you handle sensitive printed documents?"
                ],
                "controls": ["MP.L2-3.8.1", "AC.L2-3.1.3"]
            }
        ]
    }
}


def generate_evidence_checklist_markdown(organization_name: str, output_path: str) -> str:
    """
    Generate a comprehensive evidence collection checklist in Markdown format.

    This document should be sent to an organization before conducting
    a CMMC assessment to request all necessary artifacts.
    """

    content = f"""# CMMC Level 2 Evidence Collection Checklist

## Pre-Assessment Artifact Request

---

**Prepared For:** {organization_name}
**Prepared By:** [Assessor Name]
**Date:** {datetime.now().strftime('%Y-%m-%d')}
**Assessment Type:** CMMC Level 2 Gap Assessment

---

## Purpose

This checklist identifies the documentation, configurations, and records needed to assess compliance with CMMC Level 2 requirements (110 NIST SP 800-171 Rev 2 controls). Please gather and organize these artifacts before the assessment begins.

**Instructions:**
1. Review each item and check the box when collected
2. Note any items that do not exist or are not applicable
3. Provide items in electronic format where possible
4. Redact sensitive personal information (SSNs, etc.) but preserve security-relevant details

---

## Evidence Submission

**Submission Deadline:** [DATE]
**Submission Method:** [Secure file transfer / Encrypted email / etc.]
**Questions Contact:** [Contact Name and Email]

---

"""

    # Add each evidence category
    for category_id, category_data in EVIDENCE_CATALOG.items():
        content += f"""## {category_data['category_name']}

{category_data['description']}

| Status | Artifact | Description | Required |
|--------|----------|-------------|----------|
"""
        for artifact in category_data['artifacts']:
            required = "**Yes**" if artifact['required'] else "No"
            content += f"| [ ] | {artifact['name']} | {artifact['description']} | {required} |\n"

        content += "\n**Notes/Comments:**\n\n[Space for organization to note any items that don't exist or require clarification]\n\n---\n\n"

    # Add organization preparation section
    content += """## Organization Preparation Checklist

Before the assessment, please ensure:

- [ ] All requested documentation has been collected
- [ ] Technical staff are available for configuration demonstrations
- [ ] Key personnel are scheduled for interviews
- [ ] Access to systems for observation/testing has been arranged
- [ ] Conference room or workspace for assessor is available
- [ ] Network access for assessor (if needed) has been provisioned

---

## Interview Schedule Request

Please identify personnel to be available for interviews:

| Role | Name | Email | Phone | Availability |
|------|------|-------|-------|--------------|
| CISO / Security Manager | | | | |
| System Administrator | | | | |
| Network Administrator | | | | |
| Security Analyst / SOC | | | | |
| HR Representative | | | | |
| Facilities / Physical Security | | | | |
| End User (Sample) | | | | |

---

## Technical Demonstration Schedule

Please schedule time for the following demonstrations:

| Demonstration | System/Tool | Duration | Scheduled Time |
|---------------|-------------|----------|----------------|
| Account provisioning process | Active Directory | 30 min | |
| MFA authentication flow | MFA Solution | 15 min | |
| VPN connection and configuration | VPN | 15 min | |
| SIEM dashboard and log review | SIEM | 30 min | |
| Vulnerability scan execution | Scanner | 30 min | |
| Endpoint protection console | EDR/AV | 30 min | |
| Firewall rule review | Firewall | 30 min | |
| Incident response walkthrough | Ticketing/IR Tool | 30 min | |

---

## Questions Before Assessment

Please answer the following questions to help scope the assessment:

1. **How many total employees have access to CUI systems?** ____

2. **How many physical locations process CUI?** ____

3. **What cloud services are used for CUI?**
   - [ ] Microsoft 365 / Azure
   - [ ] AWS
   - [ ] Google Cloud
   - [ ] Other: ____

4. **Do you have an existing SSP?** [ ] Yes [ ] No

5. **Do you have an existing POA&M?** [ ] Yes [ ] No

6. **Have you had a previous CMMC or NIST 800-171 assessment?** [ ] Yes [ ] No
   - If yes, when? ____

7. **What is your current SPRS score (if known)?** ____

---

## Confidentiality Notice

All information collected will be treated as confidential and used solely for the purpose of conducting the CMMC gap assessment. Sensitive information will be protected in accordance with applicable requirements.

---

*Generated by CMMC Level 2 Gap Assessment Toolkit*
"""

    with open(output_path, 'w') as f:
        f.write(content)

    return output_path


def generate_interview_guide_markdown(output_path: str) -> str:
    """
    Generate a comprehensive interview guide for CMMC assessments.
    """

    content = """# CMMC Level 2 Assessment Interview Guide

## Interview Questions by Role

---

**Purpose:** This guide provides structured interview questions for each role to validate control implementation. Interviews supplement documentation review and technical validation.

**Interview Tips:**
- Start with open-ended questions to understand processes
- Follow up with specific questions about control implementation
- Ask for examples and evidence during the interview
- Take notes on gaps or inconsistencies for further investigation

---

"""

    for role_id, role_data in INTERVIEW_GUIDE.items():
        content += f"""## {role_data['role']}

"""
        for topic in role_data['topics']:
            content += f"""### {topic['topic']}

**Related Controls:** {', '.join(topic['controls'])}

"""
            for i, question in enumerate(topic['questions'], 1):
                content += f"{i}. {question}\n"

            content += "\n**Notes:**\n\n[Space for assessor notes]\n\n---\n\n"

    content += """## Interview Summary Template

After each interview, document:

1. **Interviewee:** [Name, Title]
2. **Date/Time:** [Date and Time]
3. **Duration:** [Duration]
4. **Topics Covered:** [List topics]
5. **Key Findings:**
   - [Finding 1]
   - [Finding 2]
6. **Gaps Identified:**
   - [Gap 1]
   - [Gap 2]
7. **Follow-up Needed:**
   - [Item 1]
   - [Item 2]
8. **Evidence Requested:**
   - [Evidence 1]
   - [Evidence 2]

---

*Generated by CMMC Level 2 Gap Assessment Toolkit*
"""

    with open(output_path, 'w') as f:
        f.write(content)

    return output_path


def generate_evidence_by_domain_markdown(output_path: str) -> str:
    """
    Generate evidence requirements organized by CMMC domain.
    """

    # Build a mapping of controls to evidence
    control_evidence_map = {}

    for category_id, category_data in EVIDENCE_CATALOG.items():
        for artifact in category_data['artifacts']:
            for control in artifact['controls']:
                if control not in control_evidence_map:
                    control_evidence_map[control] = []
                control_evidence_map[control].append({
                    'artifact': artifact['name'],
                    'category': category_data['category_name'],
                    'required': artifact['required']
                })

    content = """# CMMC Level 2 Evidence Requirements by Domain

## Evidence Needed for Each Security Domain

---

This document maps specific evidence requirements to each CMMC domain, helping you understand what artifacts support which controls.

---

"""

    from cmmc_controls import CMMC_LEVEL2_CONTROLS

    for domain_id, domain_data in CMMC_LEVEL2_CONTROLS.items():
        content += f"""## {domain_id}: {domain_data['domain_name']}

{domain_data['domain_description']}

| Control | Title | Evidence Required |
|---------|-------|-------------------|
"""
        for control_id, control_info in domain_data['controls'].items():
            # Get evidence for this control
            evidence_list = control_evidence_map.get(control_id, [])
            if not evidence_list:
                # Check if domain-wide evidence exists
                evidence_list = control_evidence_map.get("All domains", [])

            evidence_names = [e['artifact'] for e in evidence_list[:3]]  # Limit to 3
            evidence_str = ", ".join(evidence_names) if evidence_names else "See control-specific evidence"

            content += f"| {control_id} | {control_info['title']} | {evidence_str} |\n"

        content += "\n---\n\n"

    content += """
## Evidence Collection Priority

### Critical Path Evidence (Collect First)

1. **System Security Plan (SSP)** - Foundation document
2. **Network Diagram** - Defines assessment boundary
3. **Asset Inventory** - Identifies what to assess
4. **MFA Configuration** - High-impact control
5. **Encryption Evidence** - FIPS validation required

### Supporting Evidence (Collect Second)

1. Security policies and procedures
2. Training records
3. Vulnerability scan reports
4. Log configurations and samples
5. Access control configurations

### Operational Evidence (Collect During Assessment)

1. Live demonstrations
2. Interview responses
3. Real-time system checks
4. Sample record reviews

---

*Generated by CMMC Level 2 Gap Assessment Toolkit*
"""

    with open(output_path, 'w') as f:
        f.write(content)

    return output_path


def generate_all_evidence_documents(organization_name: str, output_dir: str) -> Dict[str, str]:
    """
    Generate all evidence collection documents.

    Args:
        organization_name: Name of the organization being assessed
        output_dir: Directory to save documents

    Returns:
        Dictionary mapping document type to file path
    """
    os.makedirs(output_dir, exist_ok=True)

    documents = {}

    # Generate evidence checklist
    documents['evidence_checklist'] = generate_evidence_checklist_markdown(
        organization_name,
        os.path.join(output_dir, f"Evidence_Collection_Checklist_{organization_name.replace(' ', '_')}.md")
    )

    # Generate interview guide
    documents['interview_guide'] = generate_interview_guide_markdown(
        os.path.join(output_dir, "Interview_Guide.md")
    )

    # Generate evidence by domain
    documents['evidence_by_domain'] = generate_evidence_by_domain_markdown(
        os.path.join(output_dir, "Evidence_Requirements_by_Domain.md")
    )

    return documents


if __name__ == "__main__":
    print("CMMC Level 2 Evidence Collection Checklist Generator")
    print("=" * 60)

    # Generate sample documents
    org_name = "Sample Defense Contractor"
    output_dir = "./evidence_documents"

    print(f"\nGenerating evidence collection documents for: {org_name}")

    docs = generate_all_evidence_documents(org_name, output_dir)

    print("\nDocuments generated:")
    for doc_type, path in docs.items():
        print(f"  {doc_type}: {path}")

    # Print summary statistics
    total_artifacts = sum(
        len(cat['artifacts'])
        for cat in EVIDENCE_CATALOG.values()
    )
    required_artifacts = sum(
        sum(1 for a in cat['artifacts'] if a['required'])
        for cat in EVIDENCE_CATALOG.values()
    )

    print(f"\nEvidence Catalog Summary:")
    print(f"  Total artifact types: {total_artifacts}")
    print(f"  Required artifacts: {required_artifacts}")
    print(f"  Optional artifacts: {total_artifacts - required_artifacts}")
    print(f"  Evidence categories: {len(EVIDENCE_CATALOG)}")
    print(f"  Interview roles: {len(INTERVIEW_GUIDE)}")
