"""
CMMC Level 2 Controls Database
All 110 NIST SP 800-171 Rev 2 security requirements organized by CMMC domain.
Each control includes assessment objectives and remediation guidance.

Author: Akintade Akinokun
Purpose: CMMC Level 2 C3PAO Audit Preparation
Reference: NIST SP 800-171 Rev 2, CMMC Model Overview v2.13
"""

CMMC_LEVEL2_CONTROLS = {
    "AC": {
        "domain_name": "Access Control",
        "domain_description": "Limit information system access to authorized users, processes, or devices, and to authorized types of transactions and functions.",
        "controls": {
            "AC.L2-3.1.1": {
                "title": "Authorized Access Control",
                "requirement": "Limit information system access to authorized users, processes acting on behalf of authorized users, or devices (including other information systems).",
                "assessment_objectives": [
                    "Authorized users are identified",
                    "Processes acting on behalf of authorized users are identified",
                    "Devices (and other systems) authorized to connect are identified",
                    "System access is limited to authorized users",
                    "System access is limited to processes acting on behalf of authorized users",
                    "System access is limited to authorized devices"
                ],
                "evidence_examples": [
                    "Access control policy",
                    "User account lists with authorization documentation",
                    "System/device inventory with authorization status",
                    "Access control configuration screenshots"
                ],
                "remediation_guidance": "Implement role-based access control (RBAC). Maintain current lists of authorized users, processes, and devices. Review and validate access permissions quarterly."
            },
            "AC.L2-3.1.2": {
                "title": "Transaction & Function Control",
                "requirement": "Limit information system access to the types of transactions and functions that authorized users are permitted to execute.",
                "assessment_objectives": [
                    "Types of transactions and functions authorized users can execute are defined",
                    "System access is limited to defined transactions and functions"
                ],
                "evidence_examples": [
                    "Role definitions with permitted transactions",
                    "Function-level access control configurations",
                    "Application permission matrices"
                ],
                "remediation_guidance": "Define and document permitted transactions by role. Implement least privilege principle for all user functions."
            },
            "AC.L2-3.1.3": {
                "title": "Control CUI Flow",
                "requirement": "Control the flow of CUI in accordance with approved authorizations.",
                "assessment_objectives": [
                    "Information flow control policies are defined",
                    "Methods/mechanisms to control CUI flow are defined",
                    "Designated sources/destinations for CUI are identified",
                    "Authorizations for CUI flow are defined",
                    "Approved authorizations for CUI flow are enforced"
                ],
                "evidence_examples": [
                    "Data flow diagrams showing CUI paths",
                    "Network segmentation documentation",
                    "DLP policy configurations",
                    "Approved CUI transfer procedures"
                ],
                "remediation_guidance": "Map all CUI data flows. Implement network segmentation and DLP solutions to control information movement."
            },
            "AC.L2-3.1.4": {
                "title": "Separation of Duties",
                "requirement": "Separate the duties of individuals to reduce the risk of malevolent activity without collusion.",
                "assessment_objectives": [
                    "Duties requiring separation are defined",
                    "Responsibilities for duties requiring separation are assigned to separate individuals"
                ],
                "evidence_examples": [
                    "Separation of duties matrix",
                    "Role assignments demonstrating separation",
                    "Workflow approvals requiring multiple individuals"
                ],
                "remediation_guidance": "Identify critical functions requiring separation (e.g., requesting/approving, developing/deploying). Assign conflicting duties to different individuals."
            },
            "AC.L2-3.1.5": {
                "title": "Least Privilege",
                "requirement": "Employ the principle of least privilege, including for specific security functions and privileged accounts.",
                "assessment_objectives": [
                    "Privileged accounts are identified",
                    "Access to privileged accounts is limited per least privilege",
                    "Security functions are identified",
                    "Access to security functions is limited per least privilege"
                ],
                "evidence_examples": [
                    "Privileged account inventory",
                    "Privilege access management (PAM) configurations",
                    "Access justification documentation"
                ],
                "remediation_guidance": "Inventory all privileged accounts. Implement PAM solution. Require justification for elevated access. Review privileges quarterly."
            },
            "AC.L2-3.1.6": {
                "title": "Non-Privileged Account Use",
                "requirement": "Use non-privileged accounts or roles when accessing nonsecurity functions.",
                "assessment_objectives": [
                    "Nonsecurity functions are identified",
                    "Users use non-privileged accounts/roles for nonsecurity functions"
                ],
                "evidence_examples": [
                    "Policy requiring standard accounts for daily work",
                    "Separate admin and user account evidence",
                    "Login logs showing appropriate account usage"
                ],
                "remediation_guidance": "Require administrators to have separate standard user accounts. Enforce use of standard accounts for email, web browsing, and daily tasks."
            },
            "AC.L2-3.1.7": {
                "title": "Privileged Functions",
                "requirement": "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.",
                "assessment_objectives": [
                    "Privileged functions are defined",
                    "Non-privileged users are prevented from executing privileged functions",
                    "Execution of privileged functions is captured in audit logs"
                ],
                "evidence_examples": [
                    "Access control configurations preventing privilege escalation",
                    "Audit logs capturing privileged function execution",
                    "SIEM alerts for privileged actions"
                ],
                "remediation_guidance": "Configure systems to require elevated credentials for privileged functions. Enable comprehensive logging of all privileged actions."
            },
            "AC.L2-3.1.8": {
                "title": "Unsuccessful Logon Attempts",
                "requirement": "Limit unsuccessful logon attempts.",
                "assessment_objectives": [
                    "Means of limiting unsuccessful logon attempts is defined",
                    "Defined measures are implemented"
                ],
                "evidence_examples": [
                    "Account lockout policy (threshold, duration)",
                    "Group Policy or IAM settings screenshots",
                    "Evidence of lockout enforcement"
                ],
                "remediation_guidance": "Implement account lockout after 3-5 failed attempts. Define lockout duration (15-30 minutes minimum). Consider progressive delays."
            },
            "AC.L2-3.1.9": {
                "title": "Privacy & Security Notices",
                "requirement": "Provide privacy and security notices consistent with applicable CUI rules.",
                "assessment_objectives": [
                    "Privacy and security notices are consistent with CUI requirements",
                    "Privacy and security notices are displayed"
                ],
                "evidence_examples": [
                    "Login banner text",
                    "Screenshots of displayed notices",
                    "Policy defining notice requirements"
                ],
                "remediation_guidance": "Implement login banners on all systems. Include warnings about authorized use, monitoring, and consequences of unauthorized access."
            },
            "AC.L2-3.1.10": {
                "title": "Session Lock",
                "requirement": "Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity.",
                "assessment_objectives": [
                    "Inactivity period for session lock is defined",
                    "Session locks are initiated after inactivity period",
                    "Pattern-hiding displays conceal information"
                ],
                "evidence_examples": [
                    "Screensaver/lock settings (GPO or MDM)",
                    "Inactivity timeout configurations",
                    "Screenshots showing lock behavior"
                ],
                "remediation_guidance": "Configure automatic screen lock after 15 minutes of inactivity maximum. Require password to unlock. Use pattern-hiding (blank screen or screensaver)."
            },
            "AC.L2-3.1.11": {
                "title": "Session Termination",
                "requirement": "Terminate (automatically) a user session after a defined condition.",
                "assessment_objectives": [
                    "Conditions requiring session termination are defined",
                    "User sessions are automatically terminated after defined conditions"
                ],
                "evidence_examples": [
                    "Session timeout policies",
                    "Application timeout configurations",
                    "VPN disconnect settings"
                ],
                "remediation_guidance": "Define session termination conditions (inactivity timeout, time-of-day restrictions). Configure applications and network connections to enforce limits."
            },
            "AC.L2-3.1.12": {
                "title": "Control Remote Access",
                "requirement": "Monitor and control remote access sessions.",
                "assessment_objectives": [
                    "Remote access sessions are permitted",
                    "Types of permitted remote access are identified",
                    "Remote access sessions are controlled",
                    "Remote access sessions are monitored"
                ],
                "evidence_examples": [
                    "Remote access policy",
                    "VPN configurations and logs",
                    "Remote session monitoring tools",
                    "Approved remote access methods documentation"
                ],
                "remediation_guidance": "Document approved remote access methods. Implement VPN with logging. Monitor remote sessions for anomalies. Require MFA for remote access."
            },
            "AC.L2-3.1.13": {
                "title": "Remote Access Confidentiality",
                "requirement": "Employ cryptographic mechanisms to protect the confidentiality of remote access sessions.",
                "assessment_objectives": [
                    "Cryptographic mechanisms for remote access are identified",
                    "Cryptographic mechanisms are implemented"
                ],
                "evidence_examples": [
                    "VPN encryption settings (AES-256, TLS 1.2+)",
                    "SSH configurations",
                    "Remote desktop encryption settings"
                ],
                "remediation_guidance": "Configure VPN with FIPS-validated cryptography. Use TLS 1.2 or higher. Disable weak ciphers. Verify encryption in remote access tools."
            },
            "AC.L2-3.1.14": {
                "title": "Remote Access Routing",
                "requirement": "Route remote access via managed access control points.",
                "assessment_objectives": [
                    "Managed access control points are identified",
                    "Remote access is routed through managed access control points"
                ],
                "evidence_examples": [
                    "Network diagram showing remote access entry points",
                    "Firewall rules for remote access",
                    "VPN concentrator configuration"
                ],
                "remediation_guidance": "Establish dedicated remote access points (VPN concentrators, jump servers). Block direct remote access bypassing managed points."
            },
            "AC.L2-3.1.15": {
                "title": "Privileged Remote Access",
                "requirement": "Authorize remote execution of privileged commands and remote access to security-relevant information.",
                "assessment_objectives": [
                    "Privileged commands authorized for remote execution are identified",
                    "Security-relevant information authorized for remote access is identified",
                    "Remote execution of privileged commands is authorized",
                    "Remote access to security-relevant information is authorized"
                ],
                "evidence_examples": [
                    "Approved privileged remote access list",
                    "PAM tool configurations for remote sessions",
                    "Authorization records for remote privileged access"
                ],
                "remediation_guidance": "Define and document authorized remote privileged commands. Implement privileged access management for remote sessions. Log all remote privileged activity."
            },
            "AC.L2-3.1.16": {
                "title": "Wireless Access Authorization",
                "requirement": "Authorize wireless access prior to allowing such connections.",
                "assessment_objectives": [
                    "Wireless access points are identified",
                    "Wireless access is authorized before connections allowed"
                ],
                "evidence_examples": [
                    "Wireless access policy",
                    "Approved wireless device list",
                    "802.1X or certificate-based authentication configs"
                ],
                "remediation_guidance": "Implement wireless authentication (WPA3-Enterprise or WPA2-Enterprise with 802.1X). Maintain approved wireless device inventory. Disable unauthorized wireless."
            },
            "AC.L2-3.1.17": {
                "title": "Wireless Access Protection",
                "requirement": "Protect wireless access using authentication and encryption.",
                "assessment_objectives": [
                    "Wireless access is protected via authentication",
                    "Wireless access is protected via encryption"
                ],
                "evidence_examples": [
                    "Wireless encryption settings (WPA3/WPA2-Enterprise)",
                    "RADIUS/authentication server configurations",
                    "Wireless security assessment results"
                ],
                "remediation_guidance": "Configure WPA3 or WPA2-Enterprise with AES encryption. Use certificate-based or RADIUS authentication. Disable WEP and WPA-Personal."
            },
            "AC.L2-3.1.18": {
                "title": "Mobile Device Connection",
                "requirement": "Control connection of mobile devices.",
                "assessment_objectives": [
                    "Mobile devices that process, store, or transmit CUI are identified",
                    "Mobile device connections are authorized",
                    "Mobile device connections are monitored",
                    "Mobile device connections are controlled"
                ],
                "evidence_examples": [
                    "MDM/EMM solution deployment",
                    "Mobile device policy",
                    "Enrolled device inventory",
                    "Connection restrictions and compliance rules"
                ],
                "remediation_guidance": "Implement Mobile Device Management (MDM). Require device enrollment before CUI access. Enforce encryption, passcodes, and remote wipe capability."
            },
            "AC.L2-3.1.19": {
                "title": "Encrypt CUI on Mobile",
                "requirement": "Encrypt CUI on mobile devices and mobile computing platforms.",
                "assessment_objectives": [
                    "Mobile devices/platforms storing or transmitting CUI are identified",
                    "Encryption is employed on identified devices/platforms"
                ],
                "evidence_examples": [
                    "MDM encryption enforcement policies",
                    "Device encryption verification reports",
                    "Mobile encryption configuration evidence"
                ],
                "remediation_guidance": "Require full-device encryption on all mobile devices accessing CUI. Verify encryption through MDM compliance checks. Block non-compliant devices."
            },
            "AC.L2-3.1.20": {
                "title": "External Connections",
                "requirement": "Verify and control/limit connections to and use of external information systems.",
                "assessment_objectives": [
                    "Connections to external systems are identified",
                    "Use of external systems is identified",
                    "Connections to external systems are verified",
                    "Connections to external systems are controlled/limited",
                    "Use of external systems is controlled/limited"
                ],
                "evidence_examples": [
                    "External system connection inventory",
                    "Network diagrams showing external connections",
                    "Firewall rules controlling external access",
                    "Third-party connection agreements"
                ],
                "remediation_guidance": "Inventory all external system connections. Document business need and security controls for each. Implement firewall rules to limit external access."
            },
            "AC.L2-3.1.21": {
                "title": "Portable Storage Use",
                "requirement": "Limit use of portable storage devices on external systems.",
                "assessment_objectives": [
                    "Use of portable storage devices is identified",
                    "Use of portable storage devices on external systems is limited"
                ],
                "evidence_examples": [
                    "USB/removable media policy",
                    "Device control software configurations",
                    "Approved portable storage inventory"
                ],
                "remediation_guidance": "Implement endpoint device control to manage USB/removable media. Whitelist approved devices. Block unauthorized portable storage on systems with CUI access."
            },
            "AC.L2-3.1.22": {
                "title": "Control Public Information",
                "requirement": "Control information posted or processed on publicly accessible information systems.",
                "assessment_objectives": [
                    "Publicly accessible systems are identified",
                    "Procedures for posting information are defined",
                    "Content reviews are conducted before posting",
                    "Mechanisms are in place to remove nonpublic information"
                ],
                "evidence_examples": [
                    "Public-facing system inventory",
                    "Content review and approval procedures",
                    "Training records for authorized posters",
                    "Audit logs of posted content"
                ],
                "remediation_guidance": "Identify all public-facing systems. Implement content review process before posting. Train authorized users on CUI identification. Conduct periodic reviews."
            }
        }
    },
    "AT": {
        "domain_name": "Awareness and Training",
        "domain_description": "Ensure that managers, systems administrators, and users are aware of security risks and applicable policies, standards, and procedures.",
        "controls": {
            "AT.L2-3.2.1": {
                "title": "Role-Based Risk Awareness",
                "requirement": "Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems.",
                "assessment_objectives": [
                    "Security risks associated with organizational activities are identified",
                    "Applicable security policies, standards, and procedures are identified",
                    "Managers, sysadmins, and users are made aware of risks",
                    "Managers, sysadmins, and users are made aware of policies"
                ],
                "evidence_examples": [
                    "Security awareness training program documentation",
                    "Training completion records",
                    "Acknowledgment forms for policies",
                    "Risk communication records"
                ],
                "remediation_guidance": "Develop role-based security awareness program. Include threat landscape, policies, and procedures. Track completion. Require annual refresher training."
            },
            "AT.L2-3.2.2": {
                "title": "Role-Based Training",
                "requirement": "Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities.",
                "assessment_objectives": [
                    "Information security-related duties and responsibilities are identified",
                    "Security training is provided to personnel with assigned duties"
                ],
                "evidence_examples": [
                    "Role-specific training curricula",
                    "Training completion certificates",
                    "Training schedule and records",
                    "Competency assessments"
                ],
                "remediation_guidance": "Identify security responsibilities by role. Develop role-specific training (admin training, developer secure coding, etc.). Track and verify competency."
            },
            "AT.L2-3.2.3": {
                "title": "Insider Threat Awareness",
                "requirement": "Provide security awareness training on recognizing and reporting potential indicators of insider threat.",
                "assessment_objectives": [
                    "Potential indicators of insider threat are identified",
                    "Training on recognizing/reporting indicators is provided"
                ],
                "evidence_examples": [
                    "Insider threat training materials",
                    "Training completion records",
                    "Insider threat reporting procedures",
                    "Awareness campaign documentation"
                ],
                "remediation_guidance": "Include insider threat module in security awareness program. Cover behavioral indicators, reporting procedures, and consequences. Provide clear reporting channels."
            }
        }
    },
    "AU": {
        "domain_name": "Audit and Accountability",
        "domain_description": "Create, protect, and retain information system audit records to enable monitoring, analysis, investigation, and reporting.",
        "controls": {
            "AU.L2-3.3.1": {
                "title": "System Auditing",
                "requirement": "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.",
                "assessment_objectives": [
                    "Audit logs needed for monitoring are specified",
                    "Audit logs needed for analysis are specified",
                    "Audit logs needed for investigation are specified",
                    "Audit logs needed for reporting are specified",
                    "Defined audit logs are created",
                    "Defined audit logs are retained"
                ],
                "evidence_examples": [
                    "Audit logging policy",
                    "Logging configurations on systems",
                    "Log retention settings",
                    "Sample audit logs"
                ],
                "remediation_guidance": "Enable comprehensive logging on all systems. Define log categories (authentication, authorization, changes). Configure retention (minimum 90 days, recommend 1 year)."
            },
            "AU.L2-3.3.2": {
                "title": "User Accountability",
                "requirement": "Ensure that the actions of individual system users can be uniquely traced to those users so they can be held accountable for their actions.",
                "assessment_objectives": [
                    "Content of audit records needed for accountability is defined",
                    "Audit records are created with defined content",
                    "Audit records are retained for accountability purposes"
                ],
                "evidence_examples": [
                    "Audit log samples showing user identification",
                    "No shared account policy",
                    "User attribution in logs evidence"
                ],
                "remediation_guidance": "Prohibit shared accounts. Ensure all audit logs include unique user identification, timestamp, action performed, and outcome. Implement user activity monitoring."
            },
            "AU.L2-3.3.3": {
                "title": "Event Review",
                "requirement": "Review and update logged events.",
                "assessment_objectives": [
                    "Logged events are reviewed",
                    "Logged events are updated (as needed based on review)"
                ],
                "evidence_examples": [
                    "Log review procedures",
                    "Review meeting minutes/records",
                    "Evidence of logging configuration updates"
                ],
                "remediation_guidance": "Establish periodic log review (annual minimum). Assess whether logged events are sufficient. Update logging based on threat changes and incidents."
            },
            "AU.L2-3.3.4": {
                "title": "Audit Failure Alerting",
                "requirement": "Alert in the event of an audit logging process failure.",
                "assessment_objectives": [
                    "Personnel or roles to receive audit failure alerts are identified",
                    "Audit logging failures generate alerts"
                ],
                "evidence_examples": [
                    "Alert configuration for logging failures",
                    "SIEM rules for audit system monitoring",
                    "Notification procedures",
                    "Sample alerts"
                ],
                "remediation_guidance": "Configure monitoring of audit subsystems. Alert security team on logging failures. Include disk space monitoring for log storage. Test alert functionality."
            },
            "AU.L2-3.3.5": {
                "title": "Audit Correlation",
                "requirement": "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.",
                "assessment_objectives": [
                    "Audit review, analysis, and reporting processes are defined",
                    "Processes are integrated for correlation",
                    "Processes support investigation and response"
                ],
                "evidence_examples": [
                    "SIEM deployment and configuration",
                    "Correlation rules documentation",
                    "Investigation procedures using logs",
                    "Sample correlation reports"
                ],
                "remediation_guidance": "Deploy SIEM solution. Aggregate logs from all systems. Create correlation rules for suspicious activity. Establish investigation procedures using correlated data."
            },
            "AU.L2-3.3.6": {
                "title": "Reduction & Reporting",
                "requirement": "Provide audit record reduction and report generation to support on-demand analysis and reporting.",
                "assessment_objectives": [
                    "Audit record reduction capability is provided",
                    "Report generation capability is provided",
                    "On-demand analysis is supported",
                    "On-demand reporting is supported"
                ],
                "evidence_examples": [
                    "SIEM dashboards and reports",
                    "Report templates",
                    "Query/search capabilities",
                    "Sample generated reports"
                ],
                "remediation_guidance": "Configure SIEM dashboards for quick analysis. Create report templates for common queries. Enable ad-hoc search capability. Train staff on log analysis tools."
            },
            "AU.L2-3.3.7": {
                "title": "Authoritative Time Source",
                "requirement": "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records.",
                "assessment_objectives": [
                    "Internal clocks are compared with authoritative time source",
                    "Internal clocks are synchronized with authoritative time source",
                    "Time stamps for audit records are generated"
                ],
                "evidence_examples": [
                    "NTP server configurations",
                    "Time sync status verification",
                    "Audit records showing consistent timestamps"
                ],
                "remediation_guidance": "Configure NTP on all systems pointing to authoritative source (internal NTP server or trusted external). Verify synchronization. Ensure UTC or consistent timezone."
            },
            "AU.L2-3.3.8": {
                "title": "Audit Protection",
                "requirement": "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.",
                "assessment_objectives": [
                    "Audit information is protected from unauthorized access",
                    "Audit information is protected from unauthorized modification",
                    "Audit information is protected from unauthorized deletion",
                    "Audit logging tools are protected from unauthorized access, modification, and deletion"
                ],
                "evidence_examples": [
                    "Log file permissions",
                    "SIEM access controls",
                    "Write-once log storage configuration",
                    "Audit log backup procedures"
                ],
                "remediation_guidance": "Restrict log access to authorized personnel. Implement write-once storage where possible. Back up logs to separate system. Monitor for log tampering attempts."
            },
            "AU.L2-3.3.9": {
                "title": "Audit Management",
                "requirement": "Limit management of audit logging functionality to a subset of privileged users.",
                "assessment_objectives": [
                    "Privileged users allowed to manage audit logging are identified",
                    "Management of audit logging is limited to those users"
                ],
                "evidence_examples": [
                    "List of users with audit management access",
                    "Access control configurations for audit tools",
                    "Separation of duties for audit management"
                ],
                "remediation_guidance": "Limit audit configuration access to designated administrators. Separate audit management from general system administration where possible. Log all changes to audit settings."
            }
        }
    },
    "CM": {
        "domain_name": "Configuration Management",
        "domain_description": "Establish and maintain baseline configurations and inventories of organizational information systems throughout their system development life cycles.",
        "controls": {
            "CM.L2-3.4.1": {
                "title": "System Baselining",
                "requirement": "Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.",
                "assessment_objectives": [
                    "Baseline configurations are established and maintained",
                    "System inventories are established and maintained",
                    "Baseline configs and inventories cover hardware",
                    "Baseline configs and inventories cover software",
                    "Baseline configs and inventories cover firmware",
                    "Baseline configs and inventories cover documentation"
                ],
                "evidence_examples": [
                    "Hardware/software inventory",
                    "Baseline configuration documentation",
                    "CMDB or asset management system",
                    "Golden image documentation"
                ],
                "remediation_guidance": "Implement asset inventory system. Document baseline configurations (golden images, hardening guides). Update inventories as changes occur. Review quarterly."
            },
            "CM.L2-3.4.2": {
                "title": "Security Configuration Enforcement",
                "requirement": "Establish and enforce security configuration settings for information technology products employed in organizational systems.",
                "assessment_objectives": [
                    "Security configuration settings are established",
                    "Security configuration settings are enforced"
                ],
                "evidence_examples": [
                    "Security baselines (CIS, DISA STIGs)",
                    "GPO or configuration management tool settings",
                    "Compliance scan results",
                    "Hardening guides"
                ],
                "remediation_guidance": "Adopt security baselines (CIS Benchmarks or DISA STIGs). Implement via GPO, Ansible, or similar. Scan for compliance regularly. Remediate deviations."
            },
            "CM.L2-3.4.3": {
                "title": "System Change Management",
                "requirement": "Track, review, approve or disapprove, and log changes to organizational systems.",
                "assessment_objectives": [
                    "Changes to systems are tracked",
                    "Changes to systems are reviewed",
                    "Changes are approved or disapproved",
                    "Changes are logged"
                ],
                "evidence_examples": [
                    "Change management policy",
                    "Change request tickets",
                    "Change advisory board records",
                    "Change logs"
                ],
                "remediation_guidance": "Implement formal change management process. Require documented requests, reviews, and approvals. Maintain change log. Include security review in process."
            },
            "CM.L2-3.4.4": {
                "title": "Security Impact Analysis",
                "requirement": "Analyze the security impact of changes prior to implementation.",
                "assessment_objectives": [
                    "Security impact of changes is analyzed prior to implementation"
                ],
                "evidence_examples": [
                    "Security impact assessment templates",
                    "Change requests with security review",
                    "Risk assessments for changes",
                    "Security sign-off records"
                ],
                "remediation_guidance": "Include security impact analysis in change process. Require security review for changes affecting CUI systems. Document analysis results before approval."
            },
            "CM.L2-3.4.5": {
                "title": "Access Restrictions for Change",
                "requirement": "Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems.",
                "assessment_objectives": [
                    "Physical access restrictions for changes are defined",
                    "Logical access restrictions for changes are defined",
                    "Access restrictions for changes are documented",
                    "Access restrictions for changes are approved",
                    "Physical access restrictions for changes are enforced",
                    "Logical access restrictions for changes are enforced"
                ],
                "evidence_examples": [
                    "Access control for change management systems",
                    "Privileged access for deployment tools",
                    "Separation of dev/test/prod environments",
                    "Physical access logs for data centers"
                ],
                "remediation_guidance": "Limit who can make changes to production systems. Implement separate environments. Require approvals before production deployment. Log all change activities."
            },
            "CM.L2-3.4.6": {
                "title": "Least Functionality",
                "requirement": "Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities.",
                "assessment_objectives": [
                    "Essential system capabilities are defined",
                    "Systems are configured to provide only essential capabilities"
                ],
                "evidence_examples": [
                    "Minimal installation configurations",
                    "Disabled unnecessary services documentation",
                    "Port/protocol restrictions",
                    "Application whitelisting configurations"
                ],
                "remediation_guidance": "Document required services per system role. Disable unnecessary services, ports, and protocols. Implement application whitelisting where possible. Review periodically."
            },
            "CM.L2-3.4.7": {
                "title": "Nonessential Functionality",
                "requirement": "Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services.",
                "assessment_objectives": [
                    "Essential programs, functions, ports, protocols, and services are defined",
                    "Nonessential items are restricted, disabled, or prevented"
                ],
                "evidence_examples": [
                    "Firewall rules restricting ports/protocols",
                    "Disabled services configuration",
                    "Application control policies",
                    "Vulnerability scan results showing minimal attack surface"
                ],
                "remediation_guidance": "Audit running services and open ports. Disable unnecessary items. Block unused ports at host and network firewalls. Document exceptions with justification."
            },
            "CM.L2-3.4.8": {
                "title": "Application Execution Policy",
                "requirement": "Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software.",
                "assessment_objectives": [
                    "Execution policy (whitelist or blacklist) is specified",
                    "Software allowed or denied is specified",
                    "Policy is applied"
                ],
                "evidence_examples": [
                    "Application control tool deployment",
                    "Whitelist/blacklist configurations",
                    "Software restriction policies",
                    "Execution control logs"
                ],
                "remediation_guidance": "Implement application control solution (AppLocker, Carbon Black, etc.). Define allowed/blocked applications. Start with blacklist if whitelist too restrictive. Progress toward whitelist for CUI systems."
            },
            "CM.L2-3.4.9": {
                "title": "User-Installed Software",
                "requirement": "Control and monitor user-installed software.",
                "assessment_objectives": [
                    "Policy for user-installed software is defined",
                    "User-installed software is controlled",
                    "User-installed software is monitored"
                ],
                "evidence_examples": [
                    "Software installation policy",
                    "Admin rights restrictions",
                    "Software inventory tools",
                    "Installation monitoring/alerts"
                ],
                "remediation_guidance": "Remove local admin rights from standard users. Implement software request process. Monitor for unauthorized installations. Inventory software regularly."
            }
        }
    },
    "IA": {
        "domain_name": "Identification and Authentication",
        "domain_description": "Identify and authenticate users, processes, and devices as a prerequisite to allowing access to organizational information systems.",
        "controls": {
            "IA.L2-3.5.1": {
                "title": "Identification",
                "requirement": "Identify information system users, processes acting on behalf of users, or devices.",
                "assessment_objectives": [
                    "System users are identified",
                    "Processes acting on behalf of users are identified",
                    "Devices accessing the system are identified"
                ],
                "evidence_examples": [
                    "User account naming standards",
                    "Service account inventory",
                    "Device naming/identification standards",
                    "Identity management system"
                ],
                "remediation_guidance": "Establish unique identifier standards for users, service accounts, and devices. Implement centralized identity management. Prohibit shared identifiers."
            },
            "IA.L2-3.5.2": {
                "title": "Authentication",
                "requirement": "Authenticate (or verify) the identities of those users, processes, or devices, as a prerequisite to allowing access to organizational information systems.",
                "assessment_objectives": [
                    "User identities are authenticated as prerequisite to access",
                    "Process identities are authenticated as prerequisite to access",
                    "Device identities are authenticated as prerequisite to access"
                ],
                "evidence_examples": [
                    "Authentication mechanisms (passwords, MFA, certificates)",
                    "Authentication configurations",
                    "Device authentication methods (802.1X, certificates)"
                ],
                "remediation_guidance": "Require authentication for all access. Implement multi-factor authentication. Use certificates or strong authentication for devices and service accounts."
            },
            "IA.L2-3.5.3": {
                "title": "Multi-Factor Authentication",
                "requirement": "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.",
                "assessment_objectives": [
                    "Privileged accounts are identified",
                    "MFA is implemented for local access to privileged accounts",
                    "MFA is implemented for network access to privileged accounts",
                    "MFA is implemented for network access to non-privileged accounts"
                ],
                "evidence_examples": [
                    "MFA solution deployment documentation",
                    "MFA enforcement configurations",
                    "MFA enrollment records",
                    "Evidence of MFA prompts"
                ],
                "remediation_guidance": "Deploy MFA solution (hardware tokens, authenticator apps, or push notifications). Enforce MFA for all network access to CUI systems. Prioritize privileged accounts."
            },
            "IA.L2-3.5.4": {
                "title": "Replay-Resistant Authentication",
                "requirement": "Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.",
                "assessment_objectives": [
                    "Replay-resistant mechanisms are implemented for privileged account network access",
                    "Replay-resistant mechanisms are implemented for non-privileged account network access"
                ],
                "evidence_examples": [
                    "Authentication protocol configurations (Kerberos, TLS with mutual auth)",
                    "Time-based OTP configurations",
                    "Challenge-response mechanisms"
                ],
                "remediation_guidance": "Use Kerberos, TLS mutual authentication, or time-based one-time passwords. Avoid NTLM where possible. Ensure session tokens are not replayable."
            },
            "IA.L2-3.5.5": {
                "title": "Identifier Reuse",
                "requirement": "Prevent reuse of identifiers for a defined period.",
                "assessment_objectives": [
                    "Period within which identifiers cannot be reused is defined",
                    "Identifier reuse is prevented within defined period"
                ],
                "evidence_examples": [
                    "Account management policy specifying reuse restrictions",
                    "Identity management system configurations",
                    "Evidence of unique identifier assignment"
                ],
                "remediation_guidance": "Define identifier reuse period (recommend permanent for users). Configure identity systems to prevent reuse. Maintain historical identifier records."
            },
            "IA.L2-3.5.6": {
                "title": "Identifier Handling",
                "requirement": "Disable identifiers after a defined period of inactivity.",
                "assessment_objectives": [
                    "Inactivity period for disabling identifiers is defined",
                    "Identifiers are disabled after inactivity period"
                ],
                "evidence_examples": [
                    "Account inactivity policy",
                    "Automated account disable configurations",
                    "Reports of disabled inactive accounts"
                ],
                "remediation_guidance": "Define inactivity threshold (90 days maximum per CIS 1.12). Configure automated disabling. Review inactive accounts regularly. Implement reactivation process."
            },
            "IA.L2-3.5.7": {
                "title": "Password Complexity",
                "requirement": "Enforce a minimum password complexity and change of characters when new passwords are created.",
                "assessment_objectives": [
                    "Password complexity requirements are defined",
                    "Character change requirements are defined",
                    "Password complexity is enforced",
                    "Character change requirements are enforced"
                ],
                "evidence_examples": [
                    "Password policy documentation",
                    "GPO or identity provider password settings",
                    "Technical enforcement configurations"
                ],
                "remediation_guidance": "Require minimum 12+ characters, mix of character types. Prevent use of previous passwords. Consider NIST 800-63B guidance (length over complexity). Implement password strength meters."
            },
            "IA.L2-3.5.8": {
                "title": "Password Reuse",
                "requirement": "Prohibit password reuse for a specified number of generations.",
                "assessment_objectives": [
                    "Number of password generations prohibited is specified",
                    "Password reuse is prohibited for specified generations"
                ],
                "evidence_examples": [
                    "Password history requirements",
                    "GPO or identity provider configurations",
                    "Technical enforcement evidence"
                ],
                "remediation_guidance": "Configure password history to remember at least 24 previous passwords. Enforce via GPO, identity provider, or application settings."
            },
            "IA.L2-3.5.9": {
                "title": "Temporary Passwords",
                "requirement": "Allow temporary password use for system logons with an immediate change to a permanent password.",
                "assessment_objectives": [
                    "Temporary password procedures are defined",
                    "Immediate change to permanent password is required"
                ],
                "evidence_examples": [
                    "Account provisioning procedures",
                    "Force password change at first login configurations",
                    "Self-service password reset procedures"
                ],
                "remediation_guidance": "Configure 'must change password at next login' for new and reset accounts. Use secure temporary password delivery. Set short expiration on temporary passwords."
            },
            "IA.L2-3.5.10": {
                "title": "Cryptographically-Protected Passwords",
                "requirement": "Store and transmit only cryptographically-protected passwords.",
                "assessment_objectives": [
                    "Passwords are cryptographically protected in storage",
                    "Passwords are cryptographically protected in transmission"
                ],
                "evidence_examples": [
                    "Password hashing configurations (bcrypt, PBKDF2, Argon2)",
                    "TLS configurations for authentication",
                    "Database encryption for credential stores"
                ],
                "remediation_guidance": "Use strong password hashing (Argon2, bcrypt, or PBKDF2 with high iterations). Never store plaintext passwords. Require TLS for all authentication traffic."
            },
            "IA.L2-3.5.11": {
                "title": "Obscure Feedback",
                "requirement": "Obscure feedback of authentication information.",
                "assessment_objectives": [
                    "Authentication information is obscured during authentication process"
                ],
                "evidence_examples": [
                    "Password masking in login screens",
                    "Generic error messages for failed authentication",
                    "No password echo in command-line tools"
                ],
                "remediation_guidance": "Mask password fields in all applications. Use generic login failure messages (don't reveal if username exists). Disable password echo in CLI tools."
            }
        }
    },
    "IR": {
        "domain_name": "Incident Response",
        "domain_description": "Establish operational incident-handling capabilities that include adequate preparation, detection, analysis, containment, recovery, and user response activities.",
        "controls": {
            "IR.L2-3.6.1": {
                "title": "Incident Handling",
                "requirement": "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.",
                "assessment_objectives": [
                    "Incident handling capability is established",
                    "Capability includes preparation",
                    "Capability includes detection",
                    "Capability includes analysis",
                    "Capability includes containment",
                    "Capability includes recovery",
                    "Capability includes user response activities"
                ],
                "evidence_examples": [
                    "Incident response plan",
                    "IR team roster and responsibilities",
                    "Detection tools (SIEM, EDR)",
                    "Containment procedures",
                    "Recovery procedures"
                ],
                "remediation_guidance": "Develop comprehensive incident response plan. Establish IR team with defined roles. Implement detection tools. Create playbooks for common incidents. Test through exercises."
            },
            "IR.L2-3.6.2": {
                "title": "Incident Reporting",
                "requirement": "Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.",
                "assessment_objectives": [
                    "Incidents are tracked",
                    "Incidents are documented",
                    "Incidents are reported to designated internal personnel",
                    "Incidents are reported to designated external entities (as required)"
                ],
                "evidence_examples": [
                    "Incident tracking system",
                    "Incident report templates",
                    "Escalation procedures",
                    "External reporting procedures (DIBNet, law enforcement)",
                    "Sample incident reports"
                ],
                "remediation_guidance": "Implement incident tracking system. Define reporting requirements (DIBNet for cyber incidents per DFARS). Create report templates. Train staff on reporting procedures."
            },
            "IR.L2-3.6.3": {
                "title": "Incident Response Testing",
                "requirement": "Test the organizational incident response capability.",
                "assessment_objectives": [
                    "Incident response capability is tested"
                ],
                "evidence_examples": [
                    "Tabletop exercise documentation",
                    "IR drill records",
                    "Lessons learned reports",
                    "Post-exercise improvement actions"
                ],
                "remediation_guidance": "Conduct annual incident response exercises. Include tabletop discussions and technical drills. Document lessons learned. Update procedures based on results."
            }
        }
    },
    "MA": {
        "domain_name": "Maintenance",
        "domain_description": "Perform timely maintenance on organizational information systems.",
        "controls": {
            "MA.L2-3.7.1": {
                "title": "Perform Maintenance",
                "requirement": "Perform maintenance on organizational systems.",
                "assessment_objectives": [
                    "System maintenance is defined",
                    "Maintenance is performed per defined schedule/requirements"
                ],
                "evidence_examples": [
                    "Maintenance schedules",
                    "Patch management records",
                    "Maintenance work orders",
                    "System update logs"
                ],
                "remediation_guidance": "Define maintenance requirements by system type. Establish maintenance schedules. Document all maintenance activities. Include patching in maintenance procedures."
            },
            "MA.L2-3.7.2": {
                "title": "System Maintenance Control",
                "requirement": "Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.",
                "assessment_objectives": [
                    "Maintenance tools are controlled",
                    "Maintenance techniques are controlled",
                    "Maintenance mechanisms are controlled",
                    "Maintenance personnel are controlled"
                ],
                "evidence_examples": [
                    "Approved maintenance tools list",
                    "Maintenance procedures documentation",
                    "Personnel authorization records",
                    "Tool integrity verification processes"
                ],
                "remediation_guidance": "Maintain approved tools inventory. Verify tool integrity before use. Authorize maintenance personnel. Supervise external maintenance staff. Document procedures."
            },
            "MA.L2-3.7.3": {
                "title": "Equipment Sanitization",
                "requirement": "Ensure equipment removed for off-site maintenance is sanitized of any CUI.",
                "assessment_objectives": [
                    "Equipment requiring off-site maintenance is identified",
                    "CUI is sanitized from equipment before off-site maintenance"
                ],
                "evidence_examples": [
                    "Media sanitization procedures",
                    "Off-site maintenance authorization forms",
                    "Sanitization verification records",
                    "Chain of custody documentation"
                ],
                "remediation_guidance": "Develop equipment sanitization procedures. Remove or encrypt CUI before off-site transfer. Document sanitization. Consider on-site maintenance for sensitive systems."
            },
            "MA.L2-3.7.4": {
                "title": "Media Inspection",
                "requirement": "Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems.",
                "assessment_objectives": [
                    "Media containing diagnostic/test programs is identified",
                    "Media is checked for malicious code before use"
                ],
                "evidence_examples": [
                    "Media scanning procedures",
                    "Antivirus scan logs",
                    "Vendor media verification processes",
                    "Approved media inventory"
                ],
                "remediation_guidance": "Scan all diagnostic media before use. Maintain known-good copies of diagnostic tools. Verify vendor media integrity. Use air-gapped scanning stations for sensitive environments."
            },
            "MA.L2-3.7.5": {
                "title": "Nonlocal Maintenance",
                "requirement": "Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete.",
                "assessment_objectives": [
                    "MFA is required for nonlocal maintenance sessions",
                    "Nonlocal maintenance sessions are terminated when complete"
                ],
                "evidence_examples": [
                    "Remote maintenance access configurations",
                    "MFA enforcement for remote maintenance",
                    "Session termination procedures",
                    "Remote session logs"
                ],
                "remediation_guidance": "Require MFA for all remote maintenance access. Establish session time limits. Implement session termination procedures. Log all remote maintenance activities."
            },
            "MA.L2-3.7.6": {
                "title": "Maintenance Personnel",
                "requirement": "Supervise the maintenance activities of maintenance personnel without required access authorization.",
                "assessment_objectives": [
                    "Maintenance personnel requiring supervision are identified",
                    "Supervision procedures are defined",
                    "Maintenance activities are supervised for identified personnel"
                ],
                "evidence_examples": [
                    "Escort/supervision procedures",
                    "Visitor/contractor logs",
                    "Supervision records",
                    "Background check requirements"
                ],
                "remediation_guidance": "Require escorts for unauthorized maintenance personnel. Document supervision. Verify credentials before granting access. Review maintenance activities performed."
            }
        }
    },
    "MP": {
        "domain_name": "Media Protection",
        "domain_description": "Protect system media, limit access to CUI on system media, and sanitize or destroy system media before disposal or reuse.",
        "controls": {
            "MP.L2-3.8.1": {
                "title": "Media Protection",
                "requirement": "Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital.",
                "assessment_objectives": [
                    "System media containing CUI is identified",
                    "Paper media containing CUI is physically controlled",
                    "Digital media containing CUI is physically controlled",
                    "Paper media containing CUI is securely stored",
                    "Digital media containing CUI is securely stored"
                ],
                "evidence_examples": [
                    "Media handling procedures",
                    "Secure storage locations (safes, locked cabinets)",
                    "Media inventory logs",
                    "Access controls for media storage"
                ],
                "remediation_guidance": "Identify all CUI media. Implement secure storage (locked cabinets/safes). Control access to storage locations. Maintain media inventories. Label media appropriately."
            },
            "MP.L2-3.8.2": {
                "title": "Media Access",
                "requirement": "Limit access to CUI on system media to authorized users.",
                "assessment_objectives": [
                    "Users authorized to access CUI on media are identified",
                    "Access to CUI on media is limited to authorized users"
                ],
                "evidence_examples": [
                    "Media access control procedures",
                    "Authorized user lists",
                    "Check-out/check-in logs",
                    "Access control mechanisms"
                ],
                "remediation_guidance": "Define who can access CUI media. Implement check-out procedures. Track media access. Encrypt digital media. Store media in access-controlled areas."
            },
            "MP.L2-3.8.3": {
                "title": "Media Sanitization",
                "requirement": "Sanitize or destroy system media containing CUI before disposal or release for reuse.",
                "assessment_objectives": [
                    "System media containing CUI is sanitized before disposal",
                    "System media containing CUI is sanitized before reuse",
                    "System media containing CUI is destroyed before disposal (if not sanitized)"
                ],
                "evidence_examples": [
                    "Media sanitization procedures (aligned with NIST SP 800-88)",
                    "Sanitization tool configurations",
                    "Destruction certificates",
                    "Sanitization/destruction logs"
                ],
                "remediation_guidance": "Follow NIST SP 800-88 guidelines. Use approved sanitization tools. Physically destroy media when sanitization insufficient. Document all sanitization/destruction activities."
            },
            "MP.L2-3.8.4": {
                "title": "Media Markings",
                "requirement": "Mark media with necessary CUI markings and distribution limitations.",
                "assessment_objectives": [
                    "Media requiring CUI markings is identified",
                    "Media is marked with CUI markings",
                    "Media is marked with distribution limitations"
                ],
                "evidence_examples": [
                    "CUI marking guide",
                    "Label templates",
                    "Examples of marked media",
                    "Staff training on marking requirements"
                ],
                "remediation_guidance": "Develop CUI marking procedures. Create label templates. Train staff on marking requirements. Audit media for proper markings. Reference CUI Registry for categories."
            },
            "MP.L2-3.8.5": {
                "title": "Media Accountability",
                "requirement": "Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.",
                "assessment_objectives": [
                    "Access to media is controlled",
                    "Accountability for media is maintained during transport"
                ],
                "evidence_examples": [
                    "Media tracking logs",
                    "Chain of custody forms",
                    "Transport authorization procedures",
                    "Secure transport methods"
                ],
                "remediation_guidance": "Implement media tracking system. Use chain of custody for transport. Require transport authorization. Use secure courier or encrypted transfer methods."
            },
            "MP.L2-3.8.6": {
                "title": "Portable Storage Encryption",
                "requirement": "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards.",
                "assessment_objectives": [
                    "Cryptographic mechanisms are identified",
                    "Cryptographic mechanisms are implemented for CUI on portable media",
                    "Alternative physical safeguards are identified (if used instead)"
                ],
                "evidence_examples": [
                    "Encryption requirements for portable media",
                    "Encrypted USB/drive configurations",
                    "Hardware encrypted device inventory",
                    "Alternative safeguard documentation"
                ],
                "remediation_guidance": "Require encryption for all portable media with CUI. Use hardware-encrypted drives or software encryption. Document encryption standards. Verify encryption before transport."
            },
            "MP.L2-3.8.7": {
                "title": "Removable Media",
                "requirement": "Control the use of removable media on system components.",
                "assessment_objectives": [
                    "Use of removable media is controlled"
                ],
                "evidence_examples": [
                    "Removable media policy",
                    "Endpoint device control configurations",
                    "Approved device lists",
                    "USB blocking evidence"
                ],
                "remediation_guidance": "Implement endpoint device control. Block unauthorized removable media. Whitelist approved devices. Monitor removable media usage. Train users on policy."
            },
            "MP.L2-3.8.8": {
                "title": "Shared Media",
                "requirement": "Prohibit the use of portable storage devices when such devices have no identifiable owner.",
                "assessment_objectives": [
                    "Use of ownerless portable storage is prohibited"
                ],
                "evidence_examples": [
                    "Policy prohibiting unowned media",
                    "Device registration procedures",
                    "Asset tagging for portable media",
                    "Training materials"
                ],
                "remediation_guidance": "Prohibit use of unregistered media. Implement device registration process. Tag and track all portable storage. Train users to report found media."
            },
            "MP.L2-3.8.9": {
                "title": "Protect Backups",
                "requirement": "Protect the confidentiality of backup CUI at storage locations.",
                "assessment_objectives": [
                    "Backup storage locations are identified",
                    "Confidentiality of CUI backups is protected at storage locations"
                ],
                "evidence_examples": [
                    "Backup encryption configurations",
                    "Secure backup storage locations",
                    "Backup access controls",
                    "Offsite storage security verification"
                ],
                "remediation_guidance": "Encrypt all backups containing CUI. Secure physical backup storage. Control access to backup systems. Verify offsite storage provider security. Test backup restoration."
            }
        }
    },
    "PS": {
        "domain_name": "Personnel Security",
        "domain_description": "Screen individuals prior to authorization and ensure CUI is protected during and after personnel actions.",
        "controls": {
            "PS.L2-3.9.1": {
                "title": "Screen Individuals",
                "requirement": "Screen individuals prior to authorizing access to organizational systems containing CUI.",
                "assessment_objectives": [
                    "Individuals are screened prior to CUI access authorization"
                ],
                "evidence_examples": [
                    "Background check policy",
                    "Screening procedures documentation",
                    "Background check completion records",
                    "Screening criteria"
                ],
                "remediation_guidance": "Define screening requirements. Conduct background checks before CUI access. Document screening completion. Consider risk-based screening levels."
            },
            "PS.L2-3.9.2": {
                "title": "Personnel Actions",
                "requirement": "Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers.",
                "assessment_objectives": [
                    "Systems are protected during personnel terminations",
                    "Systems are protected after personnel terminations",
                    "Systems are protected during personnel transfers",
                    "Systems are protected after personnel transfers"
                ],
                "evidence_examples": [
                    "Termination procedures",
                    "Transfer procedures",
                    "Access revocation timelines",
                    "Exit interview records",
                    "Account disable/modification logs"
                ],
                "remediation_guidance": "Develop termination and transfer procedures. Revoke access promptly upon termination. Modify access for transfers. Retrieve equipment and credentials. Conduct exit interviews."
            }
        }
    },
    "PE": {
        "domain_name": "Physical Protection",
        "domain_description": "Limit physical access to systems, equipment, and operating environments to authorized individuals.",
        "controls": {
            "PE.L2-3.10.1": {
                "title": "Limit Physical Access",
                "requirement": "Limit physical access to organizational information systems, equipment, and the respective operating environments to authorized individuals.",
                "assessment_objectives": [
                    "Authorized individuals are identified",
                    "Physical access to systems is limited to authorized individuals",
                    "Physical access to equipment is limited to authorized individuals",
                    "Physical access to operating environments is limited to authorized individuals"
                ],
                "evidence_examples": [
                    "Physical access control systems (badge readers, locks)",
                    "Authorized access lists",
                    "Data center access procedures",
                    "Physical access logs"
                ],
                "remediation_guidance": "Implement physical access controls (badge systems, locks). Maintain authorized personnel lists. Control access to data centers and server rooms. Review access lists periodically."
            },
            "PE.L2-3.10.2": {
                "title": "Monitor Physical Access",
                "requirement": "Protect and monitor the physical facility and support infrastructure for organizational systems.",
                "assessment_objectives": [
                    "Physical facility is protected",
                    "Physical facility is monitored",
                    "Support infrastructure is protected",
                    "Support infrastructure is monitored"
                ],
                "evidence_examples": [
                    "Security cameras",
                    "Intrusion detection systems",
                    "Environmental monitoring (HVAC, fire, water)",
                    "Security guard logs",
                    "Monitoring procedures"
                ],
                "remediation_guidance": "Install surveillance systems. Implement intrusion detection. Monitor environmental conditions. Deploy security personnel as appropriate. Review monitoring data regularly."
            },
            "PE.L2-3.10.3": {
                "title": "Escort Visitors",
                "requirement": "Escort visitors and monitor visitor activity.",
                "assessment_objectives": [
                    "Visitors are escorted",
                    "Visitor activity is monitored"
                ],
                "evidence_examples": [
                    "Visitor policy",
                    "Visitor logs",
                    "Escort procedures",
                    "Visitor badge system"
                ],
                "remediation_guidance": "Require visitor sign-in. Issue visitor badges. Assign escorts for sensitive areas. Document visitor purpose and duration. Review visitor logs regularly."
            },
            "PE.L2-3.10.4": {
                "title": "Physical Access Logs",
                "requirement": "Maintain audit logs of physical access.",
                "assessment_objectives": [
                    "Physical access audit logs are maintained"
                ],
                "evidence_examples": [
                    "Badge system logs",
                    "Sign-in sheets",
                    "Access log retention documentation",
                    "Sample access logs"
                ],
                "remediation_guidance": "Configure badge systems to log access. Maintain manual logs where electronic not available. Define log retention period (minimum 90 days). Review logs for anomalies."
            },
            "PE.L2-3.10.5": {
                "title": "Manage Physical Access",
                "requirement": "Control and manage physical access devices.",
                "assessment_objectives": [
                    "Physical access devices are identified",
                    "Physical access devices are controlled",
                    "Physical access devices are managed"
                ],
                "evidence_examples": [
                    "Key/badge inventory",
                    "Access device issuance procedures",
                    "Device recovery procedures",
                    "Combination/PIN change procedures"
                ],
                "remediation_guidance": "Inventory all physical access devices (keys, badges, PINs). Control device issuance. Recover devices upon termination. Change combinations periodically. Track lost devices."
            },
            "PE.L2-3.10.6": {
                "title": "Alternative Work Sites",
                "requirement": "Enforce safeguarding measures for CUI at alternate work sites.",
                "assessment_objectives": [
                    "Alternate work sites where CUI is processed/stored are identified",
                    "Safeguarding measures are defined for alternate sites",
                    "Safeguarding measures are enforced at alternate sites"
                ],
                "evidence_examples": [
                    "Telework/remote work policy",
                    "Home office security requirements",
                    "Alternate site security assessments",
                    "User agreements for remote work"
                ],
                "remediation_guidance": "Define alternate work site security requirements. Require secure storage for CUI. Implement VPN and encrypted devices. Conduct remote site assessments. Train remote workers."
            }
        }
    },
    "RA": {
        "domain_name": "Risk Assessment",
        "domain_description": "Periodically assess risks to organizational operations, assets, and individuals.",
        "controls": {
            "RA.L2-3.11.1": {
                "title": "Risk Assessments",
                "requirement": "Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI.",
                "assessment_objectives": [
                    "Risk assessment frequency is defined",
                    "Risk assessments are conducted per defined frequency",
                    "Assessments include risk to operations",
                    "Assessments include risk to assets",
                    "Assessments include risk to individuals"
                ],
                "evidence_examples": [
                    "Risk assessment policy",
                    "Risk assessment reports",
                    "Risk register",
                    "Assessment methodology documentation"
                ],
                "remediation_guidance": "Establish risk assessment program. Conduct assessments annually minimum. Use defined methodology (NIST, FAIR, etc.). Maintain risk register. Update assessments when significant changes occur."
            },
            "RA.L2-3.11.2": {
                "title": "Vulnerability Scan",
                "requirement": "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified.",
                "assessment_objectives": [
                    "Vulnerability scan frequency is defined",
                    "Vulnerability scans are conducted per defined frequency",
                    "Vulnerability scans are conducted when new vulnerabilities are identified"
                ],
                "evidence_examples": [
                    "Vulnerability scanning policy",
                    "Scan schedules",
                    "Vulnerability scan reports",
                    "Scanning tool configurations"
                ],
                "remediation_guidance": "Implement vulnerability scanning program. Scan at least monthly. Subscribe to vulnerability feeds. Conduct additional scans when critical vulnerabilities announced. Integrate with patch management."
            },
            "RA.L2-3.11.3": {
                "title": "Vulnerability Remediation",
                "requirement": "Remediate vulnerabilities in accordance with risk assessments.",
                "assessment_objectives": [
                    "Vulnerabilities are remediated per risk assessments"
                ],
                "evidence_examples": [
                    "Remediation procedures",
                    "Remediation timelines by severity",
                    "Remediation tracking records",
                    "Before/after scan comparisons"
                ],
                "remediation_guidance": "Define remediation timelines by severity (critical: 7 days, high: 30 days, etc.). Track remediation progress. Validate fixes through rescanning. Accept or mitigate risks for items that cannot be remediated."
            }
        }
    },
    "CA": {
        "domain_name": "Security Assessment",
        "domain_description": "Periodically assess security controls and monitor security controls on an ongoing basis.",
        "controls": {
            "CA.L2-3.12.1": {
                "title": "Security Control Assessment",
                "requirement": "Periodically assess the security controls in organizational systems to determine if the controls are effective in their application.",
                "assessment_objectives": [
                    "Assessment frequency is defined",
                    "Security control assessments are conducted per defined frequency",
                    "Assessments determine control effectiveness"
                ],
                "evidence_examples": [
                    "Security assessment plan",
                    "Assessment reports",
                    "Control testing results",
                    "Self-assessment documentation"
                ],
                "remediation_guidance": "Establish security assessment program. Conduct annual self-assessments minimum. Use defined assessment methodology. Document findings and effectiveness determinations."
            },
            "CA.L2-3.12.2": {
                "title": "Plan of Action",
                "requirement": "Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems.",
                "assessment_objectives": [
                    "POA&Ms are developed for deficiencies/vulnerabilities",
                    "POA&Ms are implemented"
                ],
                "evidence_examples": [
                    "POA&M documentation",
                    "Remediation plans",
                    "Progress tracking records",
                    "Closure evidence"
                ],
                "remediation_guidance": "Create POA&M for identified deficiencies. Include milestones, resources, and target dates. Track progress regularly. Update POA&M status. Close items with evidence."
            },
            "CA.L2-3.12.3": {
                "title": "Security Control Monitoring",
                "requirement": "Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls.",
                "assessment_objectives": [
                    "Security controls are monitored on ongoing basis",
                    "Monitoring ensures continued effectiveness"
                ],
                "evidence_examples": [
                    "Continuous monitoring strategy",
                    "Automated monitoring tool outputs",
                    "Control status dashboards",
                    "Periodic control reviews"
                ],
                "remediation_guidance": "Implement continuous monitoring program. Automate control monitoring where possible. Define monitoring frequencies by control. Report on control status regularly."
            },
            "CA.L2-3.12.4": {
                "title": "System Security Plan",
                "requirement": "Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.",
                "assessment_objectives": [
                    "SSP is developed",
                    "SSP is documented",
                    "SSP is periodically updated",
                    "SSP describes system boundaries",
                    "SSP describes operating environments",
                    "SSP describes security requirement implementation",
                    "SSP describes system relationships/connections"
                ],
                "evidence_examples": [
                    "System Security Plan document",
                    "SSP review/update records",
                    "System boundary documentation",
                    "Network diagrams",
                    "Interconnection documentation"
                ],
                "remediation_guidance": "Develop comprehensive SSP following NIST SP 800-171A guidance. Document all control implementations. Include system diagrams and boundaries. Review and update annually or upon significant changes."
            }
        }
    },
    "SC": {
        "domain_name": "System and Communications Protection",
        "domain_description": "Monitor, control, and protect organizational communications at external boundaries and key internal boundaries.",
        "controls": {
            "SC.L2-3.13.1": {
                "title": "Boundary Protection",
                "requirement": "Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems.",
                "assessment_objectives": [
                    "External boundaries are identified",
                    "Key internal boundaries are identified",
                    "Communications at external boundaries are monitored",
                    "Communications at external boundaries are controlled",
                    "Communications at external boundaries are protected",
                    "Communications at key internal boundaries are monitored",
                    "Communications at key internal boundaries are controlled",
                    "Communications at key internal boundaries are protected"
                ],
                "evidence_examples": [
                    "Network architecture diagrams",
                    "Firewall configurations",
                    "IDS/IPS deployment",
                    "Network segmentation documentation",
                    "Traffic monitoring tools"
                ],
                "remediation_guidance": "Document network boundaries. Deploy firewalls at all boundaries. Implement IDS/IPS. Segment networks with CUI. Monitor boundary traffic. Log and alert on anomalies."
            },
            "SC.L2-3.13.2": {
                "title": "Security Engineering",
                "requirement": "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems.",
                "assessment_objectives": [
                    "Architectural designs promoting security are employed",
                    "Software development techniques promoting security are employed",
                    "Systems engineering principles promoting security are employed"
                ],
                "evidence_examples": [
                    "Security architecture documentation",
                    "Secure development lifecycle documentation",
                    "Security requirements in design documents",
                    "Defense-in-depth implementation"
                ],
                "remediation_guidance": "Incorporate security into system design. Implement defense-in-depth. Use secure development practices. Conduct security architecture reviews. Document security design decisions."
            },
            "SC.L2-3.13.3": {
                "title": "Role Separation",
                "requirement": "Separate user functionality from system management functionality.",
                "assessment_objectives": [
                    "User functionality is identified",
                    "System management functionality is identified",
                    "User functionality is separated from management functionality"
                ],
                "evidence_examples": [
                    "Separate admin interfaces/jump servers",
                    "Network segmentation for management",
                    "Different accounts for admin vs user tasks",
                    "Privileged access workstations"
                ],
                "remediation_guidance": "Implement separate management networks/VLANs. Use dedicated admin workstations. Require separate accounts for admin functions. Restrict management interface access."
            },
            "SC.L2-3.13.4": {
                "title": "Shared Resource Control",
                "requirement": "Prevent unauthorized and unintended information transfer via shared system resources.",
                "assessment_objectives": [
                    "Shared system resources are identified",
                    "Unauthorized transfer via shared resources is prevented",
                    "Unintended transfer via shared resources is prevented"
                ],
                "evidence_examples": [
                    "Object reuse controls",
                    "Memory/storage clearing configurations",
                    "Virtual machine isolation settings",
                    "Shared resource access controls"
                ],
                "remediation_guidance": "Implement object reuse controls. Clear memory/storage before reallocation. Configure proper VM isolation. Control access to shared resources. Review shared resource configurations."
            },
            "SC.L2-3.13.5": {
                "title": "Public-Access System Separation",
                "requirement": "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.",
                "assessment_objectives": [
                    "Publicly accessible system components are identified",
                    "Subnetworks for public components are implemented",
                    "Subnetworks are physically or logically separated from internal networks"
                ],
                "evidence_examples": [
                    "DMZ architecture documentation",
                    "Network diagrams showing separation",
                    "Firewall rules between zones",
                    "Public-facing system inventory"
                ],
                "remediation_guidance": "Implement DMZ for public-facing systems. Use firewalls to separate zones. Limit traffic from DMZ to internal networks. Monitor DMZ traffic closely."
            },
            "SC.L2-3.13.6": {
                "title": "Network Communication by Exception",
                "requirement": "Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).",
                "assessment_objectives": [
                    "Network traffic is denied by default",
                    "Network traffic is allowed by exception"
                ],
                "evidence_examples": [
                    "Default deny firewall policies",
                    "Firewall rule documentation",
                    "Rule review and approval records",
                    "Exception justifications"
                ],
                "remediation_guidance": "Configure firewalls with default deny. Document all allowed traffic rules. Require justification for exceptions. Review rules periodically. Remove unused rules."
            },
            "SC.L2-3.13.7": {
                "title": "Split Tunneling",
                "requirement": "Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling).",
                "assessment_objectives": [
                    "Split tunneling is prevented for remote devices"
                ],
                "evidence_examples": [
                    "VPN configurations preventing split tunneling",
                    "Client configurations",
                    "Policy documentation",
                    "Technical enforcement evidence"
                ],
                "remediation_guidance": "Configure VPN clients to disable split tunneling. Force all traffic through VPN when connected. Verify configurations through testing. Monitor for policy violations."
            },
            "SC.L2-3.13.8": {
                "title": "Data in Transit",
                "requirement": "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.",
                "assessment_objectives": [
                    "Cryptographic mechanisms are identified for transmission protection",
                    "Cryptographic mechanisms are implemented",
                    "Alternative physical safeguards are identified (if applicable)"
                ],
                "evidence_examples": [
                    "TLS configurations",
                    "VPN encryption settings",
                    "SFTP/SCP usage",
                    "Email encryption (S/MIME, PGP)",
                    "FIPS 140-2 validated cryptography"
                ],
                "remediation_guidance": "Require TLS 1.2+ for all CUI transmission. Implement encrypted email for CUI. Use secure file transfer protocols. Verify FIPS 140-2 validated modules where required."
            },
            "SC.L2-3.13.9": {
                "title": "Network Disconnect",
                "requirement": "Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity.",
                "assessment_objectives": [
                    "Inactivity period for session termination is defined",
                    "Network connections are terminated at end of sessions",
                    "Network connections are terminated after inactivity period"
                ],
                "evidence_examples": [
                    "Session timeout configurations",
                    "VPN timeout settings",
                    "Application session management settings",
                    "Network device configurations"
                ],
                "remediation_guidance": "Configure session timeouts on all systems. Implement VPN disconnect after inactivity. Set application session limits. Document timeout values."
            },
            "SC.L2-3.13.10": {
                "title": "Key Management",
                "requirement": "Establish and manage cryptographic keys for cryptography employed in organizational systems.",
                "assessment_objectives": [
                    "Cryptographic keys are established",
                    "Cryptographic keys are managed throughout lifecycle"
                ],
                "evidence_examples": [
                    "Key management policy",
                    "Key generation procedures",
                    "Key storage security",
                    "Key rotation schedules",
                    "Key destruction procedures"
                ],
                "remediation_guidance": "Develop key management procedures. Generate keys securely. Store keys in hardware security modules or secure vaults. Rotate keys periodically. Destroy expired keys properly."
            },
            "SC.L2-3.13.11": {
                "title": "CUI Encryption",
                "requirement": "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.",
                "assessment_objectives": [
                    "FIPS-validated cryptography is employed for CUI protection"
                ],
                "evidence_examples": [
                    "FIPS 140-2 certificate documentation",
                    "Cryptographic module inventory",
                    "Encryption configurations showing FIPS mode",
                    "Vendor FIPS compliance documentation"
                ],
                "remediation_guidance": "Verify cryptographic modules are FIPS 140-2 validated. Enable FIPS mode where available. Document FIPS certificate numbers. Replace non-FIPS cryptography for CUI."
            },
            "SC.L2-3.13.12": {
                "title": "Collaborative Device Control",
                "requirement": "Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.",
                "assessment_objectives": [
                    "Collaborative computing devices are identified",
                    "Remote activation is prohibited",
                    "Indication of devices in use is provided to users"
                ],
                "evidence_examples": [
                    "Conference room technology configurations",
                    "Webcam/microphone control settings",
                    "Visual indicators for active devices",
                    "Remote activation blocking evidence"
                ],
                "remediation_guidance": "Identify collaborative devices (cameras, microphones, displays). Disable remote activation. Provide visual/audio indicators when active. Implement physical controls (covers, disconnects)."
            },
            "SC.L2-3.13.13": {
                "title": "Mobile Code",
                "requirement": "Control and monitor the use of mobile code.",
                "assessment_objectives": [
                    "Mobile code is defined/identified",
                    "Use of mobile code is controlled",
                    "Use of mobile code is monitored"
                ],
                "evidence_examples": [
                    "Mobile code policy (JavaScript, ActiveX, Flash, Java)",
                    "Browser security configurations",
                    "Application whitelisting",
                    "Monitoring for mobile code execution"
                ],
                "remediation_guidance": "Define acceptable mobile code. Configure browsers to restrict untrusted code. Implement application whitelisting. Monitor for malicious mobile code. Keep browsers and plugins updated."
            },
            "SC.L2-3.13.14": {
                "title": "Voice over IP",
                "requirement": "Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.",
                "assessment_objectives": [
                    "Use of VoIP is controlled",
                    "Use of VoIP is monitored"
                ],
                "evidence_examples": [
                    "VoIP policy",
                    "VoIP network segmentation",
                    "VoIP encryption configurations",
                    "Call monitoring/logging capabilities"
                ],
                "remediation_guidance": "Segment VoIP traffic from data networks. Encrypt VoIP communications. Implement call logging. Monitor for unauthorized VoIP usage. Secure VoIP infrastructure."
            },
            "SC.L2-3.13.15": {
                "title": "Communications Authenticity",
                "requirement": "Protect the authenticity of communications sessions.",
                "assessment_objectives": [
                    "Authenticity of communications sessions is protected"
                ],
                "evidence_examples": [
                    "TLS certificate configurations",
                    "Session authentication mechanisms",
                    "Digital signature usage",
                    "Anti-spoofing measures"
                ],
                "remediation_guidance": "Implement TLS with proper certificate validation. Use mutual authentication where appropriate. Implement anti-spoofing controls. Verify communication endpoints."
            },
            "SC.L2-3.13.16": {
                "title": "Data at Rest",
                "requirement": "Protect the confidentiality of CUI at rest.",
                "assessment_objectives": [
                    "CUI at rest is identified",
                    "Confidentiality of CUI at rest is protected"
                ],
                "evidence_examples": [
                    "Disk encryption configurations (BitLocker, LUKS)",
                    "Database encryption settings",
                    "File-level encryption usage",
                    "FIPS 140-2 validation for encryption"
                ],
                "remediation_guidance": "Encrypt all storage containing CUI. Use full-disk encryption on endpoints. Implement database encryption. Verify FIPS-validated encryption. Secure encryption keys."
            }
        }
    },
    "SI": {
        "domain_name": "System and Information Integrity",
        "domain_description": "Identify, report, and correct information and information system flaws in a timely manner.",
        "controls": {
            "SI.L2-3.14.1": {
                "title": "Flaw Remediation",
                "requirement": "Identify, report, and correct system flaws in a timely manner.",
                "assessment_objectives": [
                    "System flaws are identified",
                    "System flaws are reported",
                    "System flaws are corrected in timely manner"
                ],
                "evidence_examples": [
                    "Patch management policy",
                    "Flaw identification procedures",
                    "Patch deployment records",
                    "Vulnerability scan results showing remediation"
                ],
                "remediation_guidance": "Implement patch management program. Monitor vendor bulletins. Test patches before deployment. Define remediation timelines. Track patching compliance."
            },
            "SI.L2-3.14.2": {
                "title": "Malicious Code Protection",
                "requirement": "Provide protection from malicious code at appropriate locations within organizational systems.",
                "assessment_objectives": [
                    "Appropriate locations for malware protection are identified",
                    "Malware protection is provided at identified locations"
                ],
                "evidence_examples": [
                    "Antimalware deployment documentation",
                    "Endpoint protection configurations",
                    "Email gateway security",
                    "Web proxy malware scanning"
                ],
                "remediation_guidance": "Deploy endpoint protection on all systems. Implement email security gateway. Use web proxy with malware scanning. Deploy network-based malware detection."
            },
            "SI.L2-3.14.3": {
                "title": "Security Alerts & Advisories",
                "requirement": "Monitor system security alerts and advisories and take action in response.",
                "assessment_objectives": [
                    "System security alerts/advisories are monitored",
                    "Actions are taken in response to alerts/advisories"
                ],
                "evidence_examples": [
                    "Threat intelligence subscriptions",
                    "Alert monitoring procedures",
                    "Response action records",
                    "Advisory review meeting notes"
                ],
                "remediation_guidance": "Subscribe to relevant security advisories (US-CERT, vendor alerts). Establish alert review process. Document response actions. Update defenses based on threat intelligence."
            },
            "SI.L2-3.14.4": {
                "title": "Update Malicious Code Protection",
                "requirement": "Update malicious code protection mechanisms when new releases are available.",
                "assessment_objectives": [
                    "Malicious code protection mechanisms are updated when releases available"
                ],
                "evidence_examples": [
                    "Automatic update configurations",
                    "Signature update logs",
                    "Update verification reports",
                    "Update compliance dashboards"
                ],
                "remediation_guidance": "Enable automatic signature updates. Monitor update status. Alert on update failures. Verify updates applied to all endpoints."
            },
            "SI.L2-3.14.5": {
                "title": "System & File Scanning",
                "requirement": "Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed.",
                "assessment_objectives": [
                    "Periodic system scans are performed",
                    "Real-time scans of external files are performed on download/open/execute"
                ],
                "evidence_examples": [
                    "Scheduled scan configurations",
                    "Real-time protection settings",
                    "Scan reports",
                    "Detected malware logs"
                ],
                "remediation_guidance": "Configure weekly full system scans. Enable real-time scanning for all file operations. Monitor scan completion. Investigate and remediate detections."
            },
            "SI.L2-3.14.6": {
                "title": "Monitor Communications",
                "requirement": "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.",
                "assessment_objectives": [
                    "Systems are monitored for attacks",
                    "Inbound communications are monitored for attacks",
                    "Outbound communications are monitored for attacks",
                    "Indicators of potential attacks are monitored"
                ],
                "evidence_examples": [
                    "SIEM deployment",
                    "IDS/IPS configurations",
                    "Network traffic analysis tools",
                    "Alert rules and thresholds",
                    "Monitoring dashboards"
                ],
                "remediation_guidance": "Deploy SIEM with log aggregation. Implement IDS/IPS. Configure detection rules for known attack patterns. Monitor both inbound and outbound traffic. Establish alert thresholds."
            },
            "SI.L2-3.14.7": {
                "title": "Identify Unauthorized Use",
                "requirement": "Identify unauthorized use of organizational systems.",
                "assessment_objectives": [
                    "Authorized use is defined",
                    "Unauthorized use is identified"
                ],
                "evidence_examples": [
                    "Acceptable use policy",
                    "User behavior analytics",
                    "Anomaly detection rules",
                    "Unauthorized use incident reports"
                ],
                "remediation_guidance": "Define acceptable use. Implement user behavior analytics. Create baselines for normal activity. Alert on anomalous behavior. Investigate potential unauthorized use."
            }
        }
    }
}

def get_all_controls():
    """Return all CMMC Level 2 controls in a flat list."""
    all_controls = []
    for domain_id, domain_data in CMMC_LEVEL2_CONTROLS.items():
        for control_id, control_data in domain_data["controls"].items():
            all_controls.append({
                "control_id": control_id,
                "domain_id": domain_id,
                "domain_name": domain_data["domain_name"],
                **control_data
            })
    return all_controls

def get_domain_summary():
    """Return summary of all domains with control counts."""
    summary = []
    for domain_id, domain_data in CMMC_LEVEL2_CONTROLS.items():
        summary.append({
            "domain_id": domain_id,
            "domain_name": domain_data["domain_name"],
            "domain_description": domain_data["domain_description"],
            "control_count": len(domain_data["controls"])
        })
    return summary

def get_controls_by_domain(domain_id):
    """Return all controls for a specific domain."""
    if domain_id in CMMC_LEVEL2_CONTROLS:
        domain = CMMC_LEVEL2_CONTROLS[domain_id]
        return {
            "domain_id": domain_id,
            "domain_name": domain["domain_name"],
            "domain_description": domain["domain_description"],
            "controls": domain["controls"]
        }
    return None

if __name__ == "__main__":
    # Print summary
    print("CMMC Level 2 Controls Database")
    print("=" * 50)
    total = 0
    for domain in get_domain_summary():
        print(f"{domain['domain_id']}: {domain['domain_name']} - {domain['control_count']} controls")
        total += domain['control_count']
    print("=" * 50)
    print(f"Total Controls: {total}")
