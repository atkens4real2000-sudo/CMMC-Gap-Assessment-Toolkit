# CMMC Level 2 Gap Assessment Toolkit

A comprehensive Python-based tool for conducting pre-assessments against all 110 NIST SP 800-171 Rev 2 security requirements, aligned with CMMC (Cybersecurity Maturity Model Certification) Level 2 C3PAO assessment methodology.

## Overview

This toolkit enables Defense Industrial Base (DIB) contractors to:

- **Assess** compliance against all 110 CMMC Level 2 security requirements
- **Score** using methodology aligned with C3PAO (Certified Third-Party Assessor Organization) assessments
- **Identify** gaps and generate remediation guidance
- **Generate** SSP (System Security Plan) templates
- **Track** POA&M (Plan of Action and Milestones) items
- **Calculate** estimated SPRS (Supplier Performance Risk System) scores
- **Produce** executive and technical reports for stakeholders

## CMMC Background

The Cybersecurity Maturity Model Certification (CMMC) is the Department of Defense's framework for assessing and enhancing the cybersecurity posture of DIB contractors. CMMC Level 2 requires implementation of all 110 security requirements from NIST SP 800-171 Rev 2, organized across 14 security domains:

| Domain | Controls | Description |
|--------|----------|-------------|
| AC | 22 | Access Control |
| AT | 3 | Awareness and Training |
| AU | 9 | Audit and Accountability |
| CM | 9 | Configuration Management |
| IA | 11 | Identification and Authentication |
| IR | 3 | Incident Response |
| MA | 6 | Maintenance |
| MP | 9 | Media Protection |
| PS | 2 | Personnel Security |
| PE | 6 | Physical Protection |
| RA | 3 | Risk Assessment |
| CA | 4 | Security Assessment |
| SC | 16 | System and Communications Protection |
| SI | 7 | System and Information Integrity |

**Total: 110 Security Requirements**

## Features

### Assessment Engine
- Complete coverage of all 110 NIST SP 800-171 Rev 2 requirements
- C3PAO-aligned MET/NOT_MET/NOT_APPLICABLE scoring
- Assessment objectives for each control
- Evidence guidance and examples
- Remediation recommendations

### Interactive CLI
- Domain-by-domain assessment workflow
- Quick assessment mode for rapid evaluation
- Real-time compliance scoring
- Color-coded status indicators

### Report Generation
- **SSP Template**: Comprehensive System Security Plan in Markdown format
- **POA&M**: Plan of Action and Milestones in Markdown and CSV formats
- **Executive Report**: Visual HTML report with charts and metrics
- **JSON Export**: Full assessment data for integration with other tools

### Compliance Metrics
- Overall compliance percentage
- SPRS score estimation
- Domain-level compliance breakdown
- Gap identification and prioritization

## Installation

```bash
# Clone or download the toolkit
git clone https://github.com/atkens4real2000-sudo/CMMC-Gap-Assessment-Toolkit.git
cd CMMC-Gap-Assessment-Toolkit

# No external dependencies required - uses Python standard library
python3 cmmc_assessor.py
```

**Requirements:**
- Python 3.8 or higher
- No external packages required (uses standard library only)

## Usage

### Interactive Mode

```bash
python3 cmmc_assessor.py
```

This launches the interactive assessment interface where you can:
1. Create a new assessment for your organization
2. Assess controls domain by domain
3. View compliance status and gaps
4. Generate reports

### Command Line Options

```bash
# Start new assessment
python3 cmmc_assessor.py --new "Your Organization Name"

# Load existing assessment
python3 cmmc_assessor.py --load assessment.json

# Generate reports from saved assessment
python3 cmmc_assessor.py --report assessment.json --output ./reports

# Display summary only
python3 cmmc_assessor.py --load assessment.json --summary
```

### Programmatic Use

```python
from assessment_engine import CMMCAssessment, AssessmentStatus, FindingSeverity
from report_generators import generate_all_reports

# Create assessment
assessment = CMMCAssessment("Acme Defense Corp")

# Assess a control
assessment.assess_control(
    "AC.L2-3.1.1",
    AssessmentStatus.MET,
    implementation_description="RBAC implemented via Active Directory",
    evidence_provided=["AD Group Policy documentation", "Access control matrix"],
    assessor_notes="Quarterly access reviews in place"
)

# Assess another control (NOT MET)
assessment.assess_control(
    "AC.L2-3.1.3",
    AssessmentStatus.NOT_MET,
    gaps_identified=["CUI data flows not documented", "No DLP solution deployed"]
)

# Add POA&M item
assessment.add_poam_item(
    control_id="AC.L2-3.1.3",
    weakness_description="CUI flow controls not implemented",
    severity=FindingSeverity.HIGH,
    remediation_plan="1. Map CUI data flows\n2. Deploy DLP solution\n3. Document authorized transfers",
    scheduled_completion="2024-06-30"
)

# Generate summary
summary = assessment.get_assessment_summary()
print(f"Compliance Score: {summary['compliance_score']}%")

# Generate all reports
reports = generate_all_reports(assessment, "./output")
```

## Output Examples

### Assessment Dashboard

```
╔═══════════════════════════════════════════════════════════════╗
║                    ASSESSMENT DASHBOARD                        ║
╚═══════════════════════════════════════════════════════════════╝

  Organization: Acme Defense Corp
  Assessment:   CMMC_Assessment_20240125
  Date:         2024-01-25

  ┌─────────────────────────────────────────────────────────────┐
  │ COMPLIANCE METRICS                                          │
  ├─────────────────────────────────────────────────────────────┤
  │  Compliance Score:   72.5%                                  │
  │  SPRS Score:           85   (Max: 110)                      │
  └─────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────┐
  │ CONTROL STATUS                                              │
  ├─────────────────────────────────────────────────────────────┤
  │  ● MET:            80                                       │
  │  ● NOT MET:        25                                       │
  │  ● NOT ASSESSED:    5                                       │
  │  ○ N/A:             0                                       │
  └─────────────────────────────────────────────────────────────┘
```

### Domain Status

```
═══ DOMAIN COMPLIANCE STATUS ═══

  AC   Access Control
       ████████████████░░░░░░░░░░░░░░  73% (16/22)

  IA   Identification and Authentication
       ██████████████████████░░░░░░░░  82% (9/11)

  SC   System and Communications Protection
       ████████████░░░░░░░░░░░░░░░░░░  56% (9/16)
```

## Project Structure

```
CMMC_Gap_Assessment_Toolkit/
├── cmmc_assessor.py        # Main CLI application
├── cmmc_controls.py        # Complete 110 control database
├── assessment_engine.py    # Assessment logic and scoring
├── report_generators.py    # SSP, POA&M, and HTML report generation
├── requirements.txt        # Python dependencies
└── README.md               # This documentation
```

## Key References

This toolkit is built upon official CMMC and NIST documentation:

- **CMMC Model Overview v2.13** (DoD-CIO-00001)
- **NIST SP 800-171 Rev 2**: Protecting CUI in Nonfederal Systems
- **NIST SP 800-171A**: Assessing Security Requirements for CUI
- **CMMC Assessment Guide Level 2**
- **CMMC Scoping Guide Level 2**

Official resources: https://dodcio.defense.gov/cmmc/Resources-Documentation/

## CMMC Assessment Process

This toolkit supports the pre-assessment phase of the CMMC certification process:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Self-Assessment │ --> │   Gap Analysis   │ --> │   Remediation   │
│   (This Tool)    │     │   (This Tool)    │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                          │
                                                          v
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   C3PAO Audit   │ <-- │  Pre-Assessment  │ <-- │   SSP/POA&M     │
│  (Third Party)   │     │   (Optional RPO) │     │   (This Tool)   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Scoring Methodology

### MET vs NOT_MET

A control is scored as **MET** only when ALL assessment objectives for that control are satisfied. This aligns with C3PAO assessment methodology where partial implementation results in **NOT_MET**.

### SPRS Score Calculation

The Supplier Performance Risk System (SPRS) score starts at 110 and deducts points for each NOT_MET control:

- **Critical controls**: 5 points deducted
- **Important controls**: 3 points deducted
- **Standard controls**: 1 point deducted

Minimum SPRS score: -203

## Disclaimer

This toolkit is designed for **pre-assessment and internal planning purposes**. Official CMMC certification requires assessment by an authorized Certified Third-Party Assessor Organization (C3PAO). Results from this tool should not be represented as official CMMC assessment results.

## Author

**Akintade Akinokun**
- Senior Cybersecurity Professional
- CEH, ECIH, CHFI, CND, CC, CCZT, CCSK, TAISE | CISA (In Progress)
- Specializing in compliance frameworks and security program development

## License

MIT License - See LICENSE file for details.

---

*Built for DIB contractors preparing for CMMC Level 2 certification.*
