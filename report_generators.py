"""
CMMC Report Generators
Generates SSP templates, POA&M documents, and assessment reports.

Author: Akintade Akinokun
Purpose: CMMC Level 2 C3PAO Audit Preparation
Reference: NIST SP 800-171A, CMMC Assessment Guide Level 2
"""

import json
import csv
import os
from datetime import datetime
from typing import Dict, List
from cmmc_controls import CMMC_LEVEL2_CONTROLS, get_all_controls, get_domain_summary
from assessment_engine import CMMCAssessment, calculate_sprs_score


class SSPGenerator:
    """
    System Security Plan (SSP) Template Generator

    Generates SSP documentation aligned with NIST SP 800-171 and
    CMMC Level 2 requirements.
    """

    def __init__(self, assessment: CMMCAssessment):
        self.assessment = assessment

    def generate_ssp_template(self, output_path: str) -> str:
        """Generate a comprehensive SSP template in Markdown format"""

        ssp_content = f"""# System Security Plan (SSP)
## CMMC Level 2 Compliance Documentation

---

**Organization:** {self.assessment.organization_name}
**Document Version:** 1.0
**Last Updated:** {datetime.now().strftime('%Y-%m-%d')}
**Classification:** CUI // SP-SSP

---

> **FALSE CLAIMS ACT COMPLIANCE NOTICE**
>
> This System Security Plan is a legally significant document. Under the False Claims Act
> (31 U.S.C. § 3729) and the DOJ Civil Cyber-Fraud Initiative (2021), defense contractors
> who misrepresent their cybersecurity compliance status -- including inaccurate SSP
> documentation or inflated SPRS self-assessment scores -- face treble damages, penalties
> exceeding $11,000 per false claim, and potential debarment from government contracting.
> All control implementation statements in this document must accurately reflect the
> organization's current security posture. Notable enforcement: Aerojet Rocketdyne paid
> $9M (2022) for NIST 800-171 compliance misrepresentations.
>
> **Responsible Official:** [ENTER NAME AND TITLE]
> **Certification Date:** [ENTER DATE]

---

## Table of Contents

1. [System Identification](#1-system-identification)
2. [System Environment](#2-system-environment)
3. [System Interconnections](#3-system-interconnections)
4. [Security Control Implementation](#4-security-control-implementation)
5. [Continuous Monitoring](#5-continuous-monitoring)
6. [Attachments](#6-attachments)

---

## 1. System Identification

### 1.1 System Name and Identifier
| Field | Value |
|-------|-------|
| System Name | [ENTER SYSTEM NAME] |
| System Identifier | [ENTER UNIQUE ID] |
| System Owner | [ENTER NAME/TITLE] |
| Authorizing Official | [ENTER NAME/TITLE] |

### 1.2 System Description
[Provide a general description of the system's function and purpose. Include the types of information processed, stored, or transmitted.]

### 1.3 System Type and Purpose
- [ ] General Support System
- [ ] Major Application
- [ ] Cloud Service (specify: IaaS / PaaS / SaaS)

**Primary Functions:**
1. [Function 1]
2. [Function 2]
3. [Function 3]

### 1.4 CUI Categories Handled
| CUI Category | Marking | Description |
|--------------|---------|-------------|
| [Category] | [Marking] | [Description of CUI type] |

---

## 2. System Environment

### 2.1 System Boundary
[Describe the authorization boundary. Include what is in scope and out of scope for this SSP.]

**In-Scope Components:**
- [Component 1]
- [Component 2]

**Out-of-Scope Components:**
- [Component 1 - Reason]

### 2.2 Network Architecture
[Insert network diagram or reference to network diagram document]

**Key Network Segments:**
| Segment | Purpose | Security Zone |
|---------|---------|---------------|
| [Segment] | [Purpose] | [Zone] |

### 2.3 Asset Inventory Summary

#### 2.3.1 Hardware Assets
| Asset Type | Quantity | CUI Processing |
|------------|----------|----------------|
| Servers | [#] | Yes/No |
| Workstations | [#] | Yes/No |
| Network Devices | [#] | Yes/No |
| Mobile Devices | [#] | Yes/No |

#### 2.3.2 Software Assets
| Software | Version | Purpose | CUI Processing |
|----------|---------|---------|----------------|
| [Software] | [Version] | [Purpose] | Yes/No |

### 2.4 Data Flow
[Describe how CUI flows through the system. Reference data flow diagrams.]

**CUI Entry Points:**
1. [Entry point 1]
2. [Entry point 2]

**CUI Exit Points:**
1. [Exit point 1]
2. [Exit point 2]

### 2.5 User Roles and Responsibilities

| Role | Responsibilities | CUI Access Level |
|------|------------------|------------------|
| System Administrator | [Responsibilities] | Full |
| Security Administrator | [Responsibilities] | Full |
| Standard User | [Responsibilities] | Limited |
| External User | [Responsibilities] | Read-Only |

---

## 3. System Interconnections

### 3.1 Interconnected Systems

| System Name | Organization | Type | Agreement | Data Exchanged |
|-------------|--------------|------|-----------|----------------|
| [System] | [Org] | [Type] | ISA/MOU | [Data types] |

### 3.2 External Service Providers (ESPs)

| Provider | Service | FedRAMP Status | Agreement |
|----------|---------|----------------|-----------|
| [Provider] | [Service] | [Status] | [Agreement] |

**Note:** Per DFARS 252.204-7012, cloud service providers must meet FedRAMP Moderate baseline or equivalent.

---

## 4. Security Control Implementation

This section documents the implementation status of all 110 NIST SP 800-171 Rev 2 security requirements organized by CMMC Level 2 domain.

"""
        # Add each domain's controls
        for domain in get_domain_summary():
            domain_id = domain["domain_id"]
            domain_data = CMMC_LEVEL2_CONTROLS[domain_id]

            ssp_content += f"""
### 4.{list(CMMC_LEVEL2_CONTROLS.keys()).index(domain_id) + 1} {domain["domain_name"]} ({domain_id})

**Domain Description:** {domain["domain_description"]}

**Controls in this domain:** {domain["control_count"]}

"""
            for control_id, control_data in domain_data["controls"].items():
                assessment = self.assessment.assessments.get(control_id)
                status = assessment.status if assessment else "NOT_ASSESSED"
                implementation = assessment.implementation_description if assessment else "[DOCUMENT IMPLEMENTATION]"

                ssp_content += f"""
#### {control_id}: {control_data["title"]}

**Requirement:** {control_data["requirement"]}

**Implementation Status:** {status}

**Implementation Description:**
{implementation if implementation else "[DOCUMENT HOW THIS CONTROL IS IMPLEMENTED]"}

**Assessment Objectives:**
"""
                for obj in control_data["assessment_objectives"]:
                    ssp_content += f"- [ ] {obj}\n"

                ssp_content += f"""
**Evidence:**
"""
                if assessment and assessment.evidence_provided:
                    for evidence in assessment.evidence_provided:
                        ssp_content += f"- {evidence}\n"
                else:
                    ssp_content += "- [LIST EVIDENCE ARTIFACTS]\n"

                ssp_content += "\n---\n"

        ssp_content += """
## 5. Continuous Monitoring

### 5.1 Monitoring Strategy

| Activity | Frequency | Responsible Party | Tool/Method |
|----------|-----------|-------------------|-------------|
| Vulnerability Scanning | [Frequency] | [Party] | [Tool] |
| Log Review | [Frequency] | [Party] | [Tool] |
| Configuration Audits | [Frequency] | [Party] | [Tool] |
| Access Reviews | [Frequency] | [Party] | [Tool] |
| Security Assessments | [Frequency] | [Party] | [Method] |

### 5.2 Incident Response

**Incident Response Plan Reference:** [Document Name/Location]

**Key Contacts:**
| Role | Name | Contact |
|------|------|---------|
| Incident Commander | [Name] | [Contact] |
| Security Lead | [Name] | [Contact] |
| Legal/Compliance | [Name] | [Contact] |

### 5.3 POA&M Management

Current POA&M items are tracked in [POA&M Document Reference].

**POA&M Review Frequency:** [Monthly/Quarterly]

---

## 6. Attachments

### 6.1 Referenced Documents

| Document | Version | Location |
|----------|---------|----------|
| Network Diagram | [Ver] | [Location] |
| Data Flow Diagram | [Ver] | [Location] |
| Asset Inventory | [Ver] | [Location] |
| Incident Response Plan | [Ver] | [Location] |
| POA&M | [Ver] | [Location] |
| Risk Assessment | [Ver] | [Location] |

### 6.2 Acronyms and Definitions

| Acronym | Definition |
|---------|------------|
| CUI | Controlled Unclassified Information |
| CMMC | Cybersecurity Maturity Model Certification |
| C3PAO | Certified Third-Party Assessor Organization |
| ESP | External Service Provider |
| FedRAMP | Federal Risk and Authorization Management Program |
| NIST | National Institute of Standards and Technology |
| POA&M | Plan of Action and Milestones |
| SSP | System Security Plan |

---

## Document Approval

| Role | Name | Signature | Date |
|------|------|-----------|------|
| System Owner | | | |
| ISSO | | | |
| Authorizing Official | | | |

---

*This document contains CUI and must be protected in accordance with applicable laws, regulations, and government-wide policies.*
"""

        # Write to file
        with open(output_path, 'w') as f:
            f.write(ssp_content)

        return output_path


class POAMGenerator:
    """
    Plan of Action and Milestones (POA&M) Generator

    Creates POA&M documentation for tracking remediation of security gaps.
    """

    def __init__(self, assessment: CMMCAssessment):
        self.assessment = assessment

    def generate_poam_csv(self, output_path: str) -> str:
        """Generate POA&M in CSV format for easy tracking"""

        headers = [
            "POA&M ID",
            "Control ID",
            "Weakness Description",
            "Severity",
            "Remediation Plan",
            "Resources Required",
            "Responsible Party",
            "Scheduled Completion",
            "Milestones",
            "Status",
            "Actual Completion",
            "Comments"
        ]

        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for item in self.assessment.poam_items:
                milestones_str = "; ".join([
                    f"{m['description']} ({m['due_date']})"
                    for m in item.milestones
                ])

                writer.writerow([
                    item.poam_id,
                    item.control_id,
                    item.weakness_description,
                    item.severity,
                    item.remediation_plan,
                    item.resources_required,
                    item.responsible_party,
                    item.scheduled_completion,
                    milestones_str,
                    item.status,
                    item.actual_completion,
                    ""
                ])

        return output_path

    def generate_poam_template(self, output_path: str) -> str:
        """Generate comprehensive POA&M template in Markdown format"""

        gaps = self.assessment.get_gaps_report()

        poam_content = f"""# Plan of Action and Milestones (POA&M)
## CMMC Level 2 Remediation Tracking

---

**Organization:** {self.assessment.organization_name}
**Document Version:** 1.0
**Last Updated:** {datetime.now().strftime('%Y-%m-%d')}
**Next Review Date:** [ENTER DATE]

---

## Executive Summary

| Metric | Count |
|--------|-------|
| Total Open Items | {len([i for i in self.assessment.poam_items if i.status == "OPEN"])} |
| Critical Severity | {len([i for i in self.assessment.poam_items if i.severity == "CRITICAL"])} |
| High Severity | {len([i for i in self.assessment.poam_items if i.severity == "HIGH"])} |
| Moderate Severity | {len([i for i in self.assessment.poam_items if i.severity == "MODERATE"])} |
| Low Severity | {len([i for i in self.assessment.poam_items if i.severity == "LOW"])} |
| Controls Not Met | {len(gaps)} |

---

## False Claims Act (FCA) Compliance Notice

**IMPORTANT:** Each unresolved gap in this POA&M represents a control that does NOT meet
NIST SP 800-171 requirements. If the organization submits an SPRS self-assessment score
that does not account for these gaps, it may constitute a violation of the **False Claims Act
(31 U.S.C. § 3729)**.

Under the **DOJ Civil Cyber-Fraud Initiative** (launched October 2021):
- Contractors who knowingly misrepresent their cybersecurity compliance face **treble damages**
- Penalties exceed **$11,000 per false claim** submitted to the government
- Qui tam (whistleblower) provisions allow employees to report violations
- **Aerojet Rocketdyne** paid **$9M in 2022** for NIST 800-171 compliance misrepresentations

**Required Actions:**
1. Do NOT submit SPRS scores that claim compliance for controls listed as NOT MET below
2. Document all gaps honestly in SPRS self-assessment
3. Maintain this POA&M as evidence of good-faith remediation efforts
4. Update SPRS scores as remediation milestones are completed

---

## Remediation Timeline

### Critical Items (Remediate within 30 days)
"""
        critical_items = [i for i in self.assessment.poam_items if i.severity == "CRITICAL"]
        if critical_items:
            for item in critical_items:
                poam_content += f"- {item.poam_id}: {item.control_id} - {item.weakness_description[:50]}...\n"
        else:
            poam_content += "- No critical items\n"

        poam_content += """
### High Items (Remediate within 90 days)
"""
        high_items = [i for i in self.assessment.poam_items if i.severity == "HIGH"]
        if high_items:
            for item in high_items:
                poam_content += f"- {item.poam_id}: {item.control_id} - {item.weakness_description[:50]}...\n"
        else:
            poam_content += "- No high items\n"

        poam_content += """
---

## Detailed POA&M Items

"""
        if self.assessment.poam_items:
            for item in self.assessment.poam_items:
                poam_content += f"""
### {item.poam_id}: {item.control_id}

| Field | Value |
|-------|-------|
| **Weakness** | {item.weakness_description} |
| **Severity** | {item.severity} |
| **Status** | {item.status} |
| **Responsible Party** | {item.responsible_party or "[ASSIGN]"} |
| **Scheduled Completion** | {item.scheduled_completion or "[SET DATE]"} |
| **Resources Required** | {item.resources_required or "[IDENTIFY]"} |

**Remediation Plan:**
{item.remediation_plan}

**Milestones:**
"""
                if item.milestones:
                    for m in item.milestones:
                        poam_content += f"- [ ] {m['description']} - Due: {m['due_date']}\n"
                else:
                    poam_content += "- [ ] [ADD MILESTONES]\n"

                poam_content += "\n---\n"
        else:
            poam_content += "*No POA&M items currently tracked.*\n"

        # Add template for gaps without POA&M items
        poam_content += """
## Gaps Requiring POA&M Items

The following control gaps have been identified but do not yet have POA&M items:

"""
        existing_poam_controls = [item.control_id for item in self.assessment.poam_items]
        gaps_without_poam = [g for g in gaps if g["control_id"] not in existing_poam_controls]

        if gaps_without_poam:
            for gap in gaps_without_poam:
                poam_content += f"""
### {gap["control_id"]}: {gap["title"]}

**Requirement:** {gap["requirement"]}

**Gaps Identified:**
"""
                for g in gap["gaps_identified"]:
                    poam_content += f"- {g}\n"

                poam_content += f"""
**Recommended Remediation:**
{gap["remediation_guidance"]}

**Suggested Evidence:**
"""
                for e in gap["evidence_examples"]:
                    poam_content += f"- {e}\n"

                poam_content += "\n---\n"
        else:
            poam_content += "*All identified gaps have POA&M items.*\n"

        poam_content += """
---

## POA&M Management Process

### Review Frequency
- **Critical/High Items:** Weekly review
- **Moderate/Low Items:** Monthly review
- **Full POA&M Review:** Quarterly

### Status Definitions
| Status | Definition |
|--------|------------|
| OPEN | Remediation not yet started |
| IN_PROGRESS | Remediation activities underway |
| DELAYED | Behind schedule - requires escalation |
| COMPLETED | Remediation verified and closed |
| RISK_ACCEPTED | Risk formally accepted by AO |

### Escalation Path
1. Item Owner → Security Manager (5 days past due)
2. Security Manager → CISO (15 days past due)
3. CISO → Authorizing Official (30 days past due)

---

## Approval and Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Manager | | | |
| CISO | | | |
| Authorizing Official | | | |

---

*This POA&M is a living document and must be updated as remediation activities progress.*
"""

        with open(output_path, 'w') as f:
            f.write(poam_content)

        return output_path


class HTMLReportGenerator:
    """
    HTML Report Generator for Executive and Technical Audiences
    """

    def __init__(self, assessment: CMMCAssessment):
        self.assessment = assessment

    def generate_executive_report(self, output_path: str) -> str:
        """Generate executive summary HTML report"""

        summary = self.assessment.get_assessment_summary()
        sprs = calculate_sprs_score(self.assessment)
        gaps = self.assessment.get_gaps_report()

        # Determine overall status color
        if summary["compliance_score"] >= 90:
            status_color = "#27ae60"
            status_text = "Strong"
        elif summary["compliance_score"] >= 70:
            status_color = "#f39c12"
            status_text = "Moderate"
        else:
            status_color = "#e74c3c"
            status_text = "Needs Improvement"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CMMC Level 2 Assessment Report - {self.assessment.organization_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #1a5276, #2c3e50);
            color: white;
            padding: 40px;
            border-radius: 10px 10px 0 0;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.2em;
        }}
        .report-body {{
            background: white;
            padding: 40px;
            border-radius: 0 0 10px 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        .score-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .score-card {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid;
        }}
        .score-card.compliance {{
            border-color: {status_color};
        }}
        .score-card.sprs {{
            border-color: #3498db;
        }}
        .score-card.gaps {{
            border-color: #e74c3c;
        }}
        .score-card.poam {{
            border-color: #9b59b6;
        }}
        .score-card .value {{
            font-size: 3em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .score-card .label {{
            color: #7f8c8d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .section {{
            margin: 40px 0;
        }}
        .section h2 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .domain-chart {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
        }}
        .domain-bar {{
            flex: 1;
            min-width: 200px;
            background: #ecf0f1;
            border-radius: 5px;
            padding: 15px;
        }}
        .domain-bar .name {{
            font-weight: bold;
            margin-bottom: 8px;
        }}
        .domain-bar .bar {{
            height: 20px;
            background: #bdc3c7;
            border-radius: 10px;
            overflow: hidden;
        }}
        .domain-bar .fill {{
            height: 100%;
            background: linear-gradient(90deg, #27ae60, #2ecc71);
            border-radius: 10px;
            transition: width 0.5s ease;
        }}
        .domain-bar .stats {{
            font-size: 0.85em;
            color: #7f8c8d;
            margin-top: 5px;
        }}
        .gap-list {{
            list-style: none;
        }}
        .gap-list li {{
            padding: 15px;
            margin: 10px 0;
            background: #fff5f5;
            border-left: 4px solid #e74c3c;
            border-radius: 0 5px 5px 0;
        }}
        .gap-list li.high {{
            border-color: #e67e22;
            background: #fef5e7;
        }}
        .gap-list li.moderate {{
            border-color: #f1c40f;
            background: #fef9e7;
        }}
        .gap-list .control-id {{
            font-weight: bold;
            color: #2c3e50;
        }}
        .gap-list .domain {{
            font-size: 0.85em;
            color: #7f8c8d;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }}
        .status-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .status-met {{
            background: #d4edda;
            color: #155724;
        }}
        .status-not-met {{
            background: #f8d7da;
            color: #721c24;
        }}
        .status-not-assessed {{
            background: #e2e3e5;
            color: #383d41;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        @media print {{
            body {{
                background: white;
            }}
            .container {{
                max-width: 100%;
            }}
            .score-card {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CMMC Level 2 Assessment Report</h1>
            <div class="subtitle">{self.assessment.organization_name}</div>
            <div class="subtitle">Assessment Date: {datetime.now().strftime('%B %d, %Y')}</div>
        </div>

        <div class="report-body">
            <div class="score-cards">
                <div class="score-card compliance">
                    <div class="value">{summary['compliance_score']}%</div>
                    <div class="label">Compliance Score</div>
                    <div style="color: {status_color}; margin-top: 5px;">{status_text}</div>
                </div>
                <div class="score-card sprs">
                    <div class="value">{sprs['final_score']}</div>
                    <div class="label">SPRS Score</div>
                    <div style="font-size: 0.8em; color: #7f8c8d;">Max: 110</div>
                </div>
                <div class="score-card gaps">
                    <div class="value">{summary['by_status']['NOT_MET']}</div>
                    <div class="label">Controls Not Met</div>
                </div>
                <div class="score-card poam">
                    <div class="value">{summary['poam_items']}</div>
                    <div class="label">POA&M Items</div>
                </div>
            </div>

            <div class="section">
                <h2>Assessment Status Summary</h2>
                <table>
                    <tr>
                        <th>Status</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                    <tr>
                        <td><span class="status-badge status-met">MET</span></td>
                        <td>{summary['by_status']['MET']}</td>
                        <td>{round(summary['by_status']['MET']/110*100, 1)}%</td>
                    </tr>
                    <tr>
                        <td><span class="status-badge status-not-met">NOT MET</span></td>
                        <td>{summary['by_status']['NOT_MET']}</td>
                        <td>{round(summary['by_status']['NOT_MET']/110*100, 1)}%</td>
                    </tr>
                    <tr>
                        <td><span class="status-badge status-not-assessed">NOT ASSESSED</span></td>
                        <td>{summary['by_status']['NOT_ASSESSED']}</td>
                        <td>{round(summary['by_status']['NOT_ASSESSED']/110*100, 1)}%</td>
                    </tr>
                </table>
            </div>

            <div class="section">
                <h2>Compliance by Domain</h2>
                <div class="domain-chart">
"""
        # Add domain bars
        for domain_id, domain_stats in summary['by_domain'].items():
            total = domain_stats['total']
            met = domain_stats['met']
            pct = round(met / total * 100) if total > 0 else 0

            html_content += f"""
                    <div class="domain-bar">
                        <div class="name">{domain_stats['name']}</div>
                        <div class="bar">
                            <div class="fill" style="width: {pct}%;"></div>
                        </div>
                        <div class="stats">{met}/{total} controls met ({pct}%)</div>
                    </div>
"""

        html_content += """
                </div>
            </div>
"""

        # Add gaps section if any
        if gaps:
            html_content += """
            <div class="section">
                <h2>Priority Remediation Items</h2>
                <ul class="gap-list">
"""
            for gap in gaps[:10]:  # Show top 10 gaps
                html_content += f"""
                    <li>
                        <span class="control-id">{gap['control_id']}</span>: {gap['title']}
                        <div class="domain">{gap['domain']}</div>
                    </li>
"""
            html_content += """
                </ul>
            </div>
"""

        html_content += f"""
            <div class="section">
                <h2>Recommendations</h2>
                <ol>
                    <li><strong>Address Critical Gaps First:</strong> Focus on controls affecting CUI confidentiality (Access Control, System & Communications Protection).</li>
                    <li><strong>Document Everything:</strong> Ensure all control implementations have supporting evidence ready for C3PAO review.</li>
                    <li><strong>Complete POA&M Items:</strong> Resolve all POA&M items before scheduling C3PAO assessment.</li>
                    <li><strong>Conduct Pre-Assessment:</strong> Consider engaging a Registered Provider Organization (RPO) for readiness review.</li>
                    <li><strong>Maintain Continuous Monitoring:</strong> Implement ongoing assessment to maintain compliance posture.</li>
                </ol>
            </div>

            <div class="section">
                <h2>C3PAO Assessment Readiness</h2>
                <table>
                    <tr>
                        <th>Readiness Indicator</th>
                        <th>Status</th>
                    </tr>
                    <tr>
                        <td>All controls assessed</td>
                        <td>{'✅' if summary['by_status']['NOT_ASSESSED'] == 0 else '❌'} {summary['by_status']['NOT_ASSESSED']} remaining</td>
                    </tr>
                    <tr>
                        <td>Compliance score ≥ 100%</td>
                        <td>{'✅' if summary['compliance_score'] == 100 else '❌'} Currently {summary['compliance_score']}%</td>
                    </tr>
                    <tr>
                        <td>SSP documented</td>
                        <td>⚠️ Verify SSP is current</td>
                    </tr>
                    <tr>
                        <td>POA&M items closed</td>
                        <td>{'✅' if len(self.assessment.poam_items) == 0 else '⚠️'} {len(self.assessment.poam_items)} open items</td>
                    </tr>
                </table>
                <p style="margin-top: 15px; padding: 15px; background: #e8f4f8; border-radius: 5px;">
                    <strong>Note:</strong> CMMC Level 2 certification requires ALL 110 controls to be MET.
                    Any NOT_MET controls will result in a conditional certification or failure, requiring
                    POA&M closure before certification is granted.
                </p>
            </div>
        </div>

        <div class="section">
            <h2 style="color: #c0392b;">⚠ False Claims Act (FCA) Compliance Notice</h2>
            <div style="background: #fdf2f2; border-left: 4px solid #c0392b; padding: 20px; border-radius: 5px;">
                <p><strong>False Claims Act (31 U.S.C. § 3729):</strong> Submitting inaccurate SPRS
                self-assessment scores or misrepresenting NIST SP 800-171 compliance status to the
                Department of Defense constitutes a potential violation of the False Claims Act.</p>

                <p style="margin-top: 10px;"><strong>DOJ Civil Cyber-Fraud Initiative (2021):</strong>
                The Department of Justice actively pursues defense contractors who knowingly submit
                false cybersecurity compliance claims. Penalties include:</p>
                <ul style="margin-top: 5px;">
                    <li><strong>Treble damages</strong> (3x the government's losses)</li>
                    <li><strong>Per-claim penalties</strong> exceeding $11,000 per false claim</li>
                    <li><strong>Debarment</strong> from future government contracting</li>
                    <li><strong>Qui tam provisions</strong> allowing whistleblower lawsuits</li>
                </ul>

                <p style="margin-top: 10px;"><strong>Precedent:</strong> Aerojet Rocketdyne paid
                <strong>$9 million</strong> (2022) to settle FCA allegations related to NIST SP 800-171
                compliance misrepresentations.</p>

                <p style="margin-top: 10px; font-weight: bold; color: #c0392b;">
                Ensure all SPRS scores and compliance claims accurately reflect the findings in this report.
                Document all gaps in your POA&M and update SPRS scores as remediation progresses.</p>
            </div>
        </div>

        <div class="footer">
            <p>Generated by CMMC Level 2 Gap Assessment Toolkit</p>
            <p>Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p style="margin-top: 10px; font-style: italic;">
                This assessment is for internal planning purposes. Official CMMC certification
                requires assessment by an authorized C3PAO. All compliance claims are subject to
                the False Claims Act (31 U.S.C. § 3729).
            </p>
        </div>
    </div>
</body>
</html>
"""

        with open(output_path, 'w') as f:
            f.write(html_content)

        return output_path


def generate_all_reports(assessment: CMMCAssessment, output_dir: str) -> Dict[str, str]:
    """
    Generate all report types for an assessment.

    Args:
        assessment: The CMMCAssessment object
        output_dir: Directory to save reports

    Returns:
        Dictionary mapping report type to file path
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    reports = {}

    # Generate SSP
    ssp_gen = SSPGenerator(assessment)
    reports['ssp'] = ssp_gen.generate_ssp_template(
        os.path.join(output_dir, f"SSP_Template_{timestamp}.md")
    )

    # Generate POA&M
    poam_gen = POAMGenerator(assessment)
    reports['poam_md'] = poam_gen.generate_poam_template(
        os.path.join(output_dir, f"POAM_{timestamp}.md")
    )
    reports['poam_csv'] = poam_gen.generate_poam_csv(
        os.path.join(output_dir, f"POAM_{timestamp}.csv")
    )

    # Generate HTML Report
    html_gen = HTMLReportGenerator(assessment)
    reports['executive_report'] = html_gen.generate_executive_report(
        os.path.join(output_dir, f"Executive_Report_{timestamp}.html")
    )

    # Export raw assessment data
    reports['assessment_json'] = assessment.export_assessment(
        os.path.join(output_dir, f"Assessment_Data_{timestamp}.json")
    )

    return reports


if __name__ == "__main__":
    # Demo report generation
    from assessment_engine import AssessmentStatus, FindingSeverity

    print("Generating Demo Reports...")

    # Create and populate demo assessment
    assessment = CMMCAssessment("Demo Manufacturing Corp")

    # Simulate some assessments
    demo_results = [
        ("AC.L2-3.1.1", AssessmentStatus.MET),
        ("AC.L2-3.1.2", AssessmentStatus.MET),
        ("AC.L2-3.1.3", AssessmentStatus.NOT_MET),
        ("AC.L2-3.1.5", AssessmentStatus.MET),
        ("IA.L2-3.5.3", AssessmentStatus.NOT_MET),
        ("SC.L2-3.13.11", AssessmentStatus.MET),
    ]

    for control_id, status in demo_results:
        assessment.assess_control(
            control_id,
            status,
            implementation_description=f"Demo implementation for {control_id}",
            evidence_provided=["Evidence 1", "Evidence 2"] if status == AssessmentStatus.MET else [],
            gaps_identified=["Gap identified"] if status == AssessmentStatus.NOT_MET else []
        )

    # Add POA&M items for NOT_MET controls
    assessment.add_poam_item(
        "AC.L2-3.1.3",
        "CUI flow controls not implemented",
        FindingSeverity.HIGH,
        "Implement DLP and data flow controls"
    )

    # Generate reports
    reports = generate_all_reports(assessment, "./demo_reports")

    print("\nReports Generated:")
    for report_type, path in reports.items():
        print(f"  {report_type}: {path}")
