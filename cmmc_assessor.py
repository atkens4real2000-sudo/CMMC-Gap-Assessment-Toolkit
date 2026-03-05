#!/usr/bin/env python3
"""
CMMC Level 2 Gap Assessment Toolkit
Interactive CLI for conducting CMMC pre-assessments aligned with C3PAO methodology.

Author: Akintade Akinokun
Purpose: CMMC Level 2 C3PAO Audit Preparation
Reference: NIST SP 800-171 Rev 2, CMMC Model Overview v2.13

Usage:
    python cmmc_assessor.py                    # Interactive mode
    python cmmc_assessor.py --new              # Start new assessment
    python cmmc_assessor.py --load <file>      # Load existing assessment
    python cmmc_assessor.py --report <file>    # Generate reports from assessment
"""

import argparse
import os
import sys
from datetime import datetime
from typing import Optional

from cmmc_controls import CMMC_LEVEL2_CONTROLS, get_domain_summary, get_all_controls
from assessment_engine import (
    CMMCAssessment,
    AssessmentStatus,
    FindingSeverity,
    AssessmentQuestionnaire,
    calculate_sprs_score
)
from report_generators import generate_all_reports
from evidence_checklist import generate_all_evidence_documents
from technical_validators import CMMCTechnicalValidator
from document_converter import (
    convert_all_documents, check_dependencies, install_dependencies,
    generate_excel_checklist, generate_controls_visualization,
    generate_documents_from_assessment
)


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Display application banner"""
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                                 ║
║   {Colors.BOLD}CMMC LEVEL 2 GAP ASSESSMENT TOOLKIT{Colors.ENDC}{Colors.CYAN}                                         ║
║   ─────────────────────────────────────                                         ║
║   Aligned with NIST SP 800-171 Rev 2 and C3PAO Assessment Methodology          ║
║                                                                                 ║
║   {Colors.YELLOW}110 Security Requirements{Colors.CYAN} | {Colors.YELLOW}14 Domains{Colors.CYAN} | {Colors.YELLOW}SSP & POA&M Generation{Colors.CYAN}            ║
║                                                                                 ║
╚═══════════════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
    print(banner)


def print_menu(title: str, options: list):
    """Display a formatted menu"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}═══ {title} ═══{Colors.ENDC}")
    for i, option in enumerate(options, 1):
        print(f"  {Colors.CYAN}[{i}]{Colors.ENDC} {option}")
    print(f"  {Colors.CYAN}[0]{Colors.ENDC} Back/Exit")
    print()


def get_input(prompt: str, valid_options: list = None) -> str:
    """Get validated user input"""
    while True:
        try:
            response = input(f"{Colors.GREEN}>{Colors.ENDC} {prompt}: ").strip()
            if valid_options and response not in valid_options:
                print(f"{Colors.RED}Invalid option. Please try again.{Colors.ENDC}")
                continue
            return response
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Colors.YELLOW}Operation cancelled.{Colors.ENDC}")
            return "0"


def display_summary(assessment: CMMCAssessment):
    """Display assessment summary dashboard"""
    summary = assessment.get_assessment_summary()
    sprs = calculate_sprs_score(assessment)

    # Determine compliance color
    if summary['compliance_score'] >= 90:
        score_color = Colors.GREEN
    elif summary['compliance_score'] >= 70:
        score_color = Colors.YELLOW
    else:
        score_color = Colors.RED

    print(f"""
{Colors.BOLD}╔═══════════════════════════════════════════════════════════════╗
║                    ASSESSMENT DASHBOARD                        ║
╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}

  {Colors.BOLD}Organization:{Colors.ENDC} {assessment.organization_name}
  {Colors.BOLD}Assessment:{Colors.ENDC}   {assessment.assessment_name}
  {Colors.BOLD}Date:{Colors.ENDC}         {assessment.assessment_date[:10]}

  ┌─────────────────────────────────────────────────────────────┐
  │ {Colors.BOLD}COMPLIANCE METRICS{Colors.ENDC}                                          │
  ├─────────────────────────────────────────────────────────────┤
  │  Compliance Score: {score_color}{Colors.BOLD}{summary['compliance_score']:>6.1f}%{Colors.ENDC}                                │
  │  SPRS Score:       {Colors.BOLD}{sprs['final_score']:>6}{Colors.ENDC}   (Max: 110)                      │
  ├─────────────────────────────────────────────────────────────┤
  │  {Colors.YELLOW}⚠ FCA: Verify score accuracy before SPRS submission{Colors.ENDC}      │
  └─────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────┐
  │ {Colors.BOLD}CONTROL STATUS{Colors.ENDC}                                              │
  ├─────────────────────────────────────────────────────────────┤
  │  {Colors.GREEN}● MET:{Colors.ENDC}           {summary['by_status']['MET']:>4}                                       │
  │  {Colors.RED}● NOT MET:{Colors.ENDC}       {summary['by_status']['NOT_MET']:>4}                                       │
  │  {Colors.YELLOW}● NOT ASSESSED:{Colors.ENDC} {summary['by_status']['NOT_ASSESSED']:>4}                                       │
  │  ○ N/A:          {summary['by_status']['NOT_APPLICABLE']:>4}                                       │
  ├─────────────────────────────────────────────────────────────┤
  │  {Colors.BOLD}TOTAL:{Colors.ENDC}          {summary['total_controls']:>4}                                       │
  └─────────────────────────────────────────────────────────────┘

  {Colors.BOLD}POA&M Items:{Colors.ENDC} {summary['poam_items']}
""")


def display_domain_status(assessment: CMMCAssessment):
    """Display status by domain"""
    summary = assessment.get_assessment_summary()

    print(f"\n{Colors.BOLD}═══ DOMAIN COMPLIANCE STATUS ═══{Colors.ENDC}\n")

    for domain_id, stats in summary['by_domain'].items():
        total = stats['total']
        met = stats['met']
        pct = round(met / total * 100) if total > 0 else 0

        # Create visual bar
        bar_width = 30
        filled = int(bar_width * pct / 100)
        bar = f"{'█' * filled}{'░' * (bar_width - filled)}"

        # Color based on percentage
        if pct >= 90:
            color = Colors.GREEN
        elif pct >= 70:
            color = Colors.YELLOW
        else:
            color = Colors.RED

        print(f"  {domain_id:4} {stats['name'][:25]:<25}")
        print(f"       {color}{bar}{Colors.ENDC} {pct:>3}% ({met}/{total})")
        print()


def assess_domain_interactive(assessment: CMMCAssessment, domain_id: str):
    """Interactive assessment for a specific domain"""
    questionnaire = AssessmentQuestionnaire(assessment)
    domain_data = CMMC_LEVEL2_CONTROLS[domain_id]

    print(f"\n{Colors.BOLD}═══ Assessing Domain: {domain_data['domain_name']} ({domain_id}) ═══{Colors.ENDC}")
    print(f"{Colors.CYAN}{domain_data['domain_description']}{Colors.ENDC}")
    print(f"\nThis domain has {len(domain_data['controls'])} controls to assess.\n")

    control_list = list(domain_data['controls'].keys())

    for i, control_id in enumerate(control_list, 1):
        control = domain_data['controls'][control_id]
        current = assessment.assessments[control_id]

        print(f"\n{Colors.BOLD}─── Control {i}/{len(control_list)}: {control_id} ───{Colors.ENDC}")
        print(f"{Colors.BOLD}Title:{Colors.ENDC} {control['title']}")
        print(f"\n{Colors.BOLD}Requirement:{Colors.ENDC}")
        print(f"  {control['requirement']}")

        print(f"\n{Colors.BOLD}Assessment Objectives:{Colors.ENDC}")
        for j, obj in enumerate(control['assessment_objectives'], 1):
            print(f"  {j}. {obj}")

        print(f"\n{Colors.BOLD}Current Status:{Colors.ENDC} {current.status}")

        print(f"\n{Colors.CYAN}Select assessment result:{Colors.ENDC}")
        print(f"  [1] MET - Control fully implemented")
        print(f"  [2] NOT MET - Control not implemented or partially implemented")
        print(f"  [3] N/A - Control not applicable")
        print(f"  [4] Skip - Leave as NOT ASSESSED")
        print(f"  [0] Return to menu")

        choice = get_input("Enter choice")

        if choice == "0":
            return
        elif choice == "1":
            status = AssessmentStatus.MET
        elif choice == "2":
            status = AssessmentStatus.NOT_MET
        elif choice == "3":
            status = AssessmentStatus.NOT_APPLICABLE
        elif choice == "4":
            continue
        else:
            continue

        # Get implementation details
        impl_desc = ""
        evidence = []
        gaps = []

        if status in [AssessmentStatus.MET, AssessmentStatus.NOT_MET]:
            print(f"\n{Colors.CYAN}Describe how this control is implemented (or press Enter to skip):{Colors.ENDC}")
            impl_desc = input(f"{Colors.GREEN}>{Colors.ENDC} ").strip()

        if status == AssessmentStatus.MET:
            print(f"\n{Colors.CYAN}List evidence artifacts (comma-separated, or press Enter to skip):{Colors.ENDC}")
            print(f"  {Colors.YELLOW}Examples: {', '.join(control['evidence_examples'][:3])}{Colors.ENDC}")
            evidence_input = input(f"{Colors.GREEN}>{Colors.ENDC} ").strip()
            if evidence_input:
                evidence = [e.strip() for e in evidence_input.split(',')]

        if status == AssessmentStatus.NOT_MET:
            print(f"\n{Colors.CYAN}Identify gaps (comma-separated, or press Enter to skip):{Colors.ENDC}")
            gaps_input = input(f"{Colors.GREEN}>{Colors.ENDC} ").strip()
            if gaps_input:
                gaps = [g.strip() for g in gaps_input.split(',')]

            # Offer to create POA&M
            print(f"\n{Colors.YELLOW}Create POA&M item for this gap? [y/N]{Colors.ENDC}")
            if input(f"{Colors.GREEN}>{Colors.ENDC} ").strip().lower() == 'y':
                create_poam_interactive(assessment, control_id, control, gaps)

        # Record assessment
        assessment.assess_control(
            control_id,
            status,
            implementation_description=impl_desc,
            evidence_provided=evidence,
            gaps_identified=gaps
        )

        print(f"\n{Colors.GREEN}✓ Control {control_id} assessed as {status.value}{Colors.ENDC}")


def create_poam_interactive(
    assessment: CMMCAssessment,
    control_id: str,
    control: dict,
    gaps: list
):
    """Interactive POA&M creation"""
    print(f"\n{Colors.BOLD}─── Create POA&M Item ───{Colors.ENDC}")

    weakness = ", ".join(gaps) if gaps else input("Weakness description: ").strip()

    print("\nSeverity:")
    print("  [1] CRITICAL - Immediate remediation required")
    print("  [2] HIGH - Remediate within 90 days")
    print("  [3] MODERATE - Remediate within 180 days")
    print("  [4] LOW - Remediate within 365 days")

    sev_choice = get_input("Select severity", ["1", "2", "3", "4"])
    severity_map = {
        "1": FindingSeverity.CRITICAL,
        "2": FindingSeverity.HIGH,
        "3": FindingSeverity.MODERATE,
        "4": FindingSeverity.LOW
    }
    severity = severity_map.get(sev_choice, FindingSeverity.MODERATE)

    print(f"\n{Colors.CYAN}Recommended remediation:{Colors.ENDC}")
    print(f"  {control['remediation_guidance']}")

    remediation = input("\nRemediation plan (or press Enter to use recommendation): ").strip()
    if not remediation:
        remediation = control['remediation_guidance']

    responsible = input("Responsible party (or press Enter to skip): ").strip()
    completion = input("Target completion date (YYYY-MM-DD, or press Enter to skip): ").strip()

    assessment.add_poam_item(
        control_id=control_id,
        weakness_description=weakness,
        severity=severity,
        remediation_plan=remediation,
        responsible_party=responsible,
        scheduled_completion=completion
    )

    print(f"\n{Colors.GREEN}✓ POA&M item created{Colors.ENDC}")


def quick_assessment(assessment: CMMCAssessment, domain_id: str):
    """Quick assessment mode - assess all controls in a domain rapidly"""
    domain_data = CMMC_LEVEL2_CONTROLS[domain_id]

    print(f"\n{Colors.BOLD}═══ Quick Assessment: {domain_data['domain_name']} ═══{Colors.ENDC}")
    print("Rapidly assess all controls in this domain.")
    print("Enter: M=MET, N=NOT MET, A=N/A, S=SKIP\n")

    for control_id, control in domain_data['controls'].items():
        current = assessment.assessments[control_id]

        # Show compact control info
        print(f"{Colors.BOLD}{control_id}{Colors.ENDC}: {control['title'][:60]}")
        print(f"  Current: {current.status}")

        response = input(f"  {Colors.GREEN}[M/N/A/S]>{Colors.ENDC} ").strip().upper()

        if response == 'M':
            assessment.assess_control(control_id, AssessmentStatus.MET)
            print(f"  {Colors.GREEN}→ MET{Colors.ENDC}")
        elif response == 'N':
            assessment.assess_control(control_id, AssessmentStatus.NOT_MET)
            print(f"  {Colors.RED}→ NOT MET{Colors.ENDC}")
        elif response == 'A':
            assessment.assess_control(control_id, AssessmentStatus.NOT_APPLICABLE)
            print(f"  {Colors.YELLOW}→ N/A{Colors.ENDC}")
        else:
            print(f"  → Skipped")

    print(f"\n{Colors.GREEN}✓ Domain assessment complete{Colors.ENDC}")


def generate_reports_menu(assessment: CMMCAssessment):
    """Report generation menu"""
    print(f"\n{Colors.BOLD}═══ Generate Reports ═══{Colors.ENDC}")

    output_dir = input("Output directory (default: ./reports): ").strip()
    if not output_dir:
        output_dir = "./reports"

    print(f"\n{Colors.CYAN}Generating reports...{Colors.ENDC}")

    try:
        reports = generate_all_reports(assessment, output_dir)

        print(f"\n{Colors.GREEN}✓ Reports generated successfully:{Colors.ENDC}")
        for report_type, path in reports.items():
            print(f"  • {report_type}: {path}")

    except Exception as e:
        print(f"\n{Colors.RED}Error generating reports: {e}{Colors.ENDC}")


def view_gaps(assessment: CMMCAssessment):
    """View all identified gaps"""
    gaps = assessment.get_gaps_report()

    if not gaps:
        print(f"\n{Colors.GREEN}No gaps identified - all assessed controls are MET!{Colors.ENDC}")
        return

    print(f"\n{Colors.BOLD}═══ Identified Gaps ({len(gaps)} controls) ═══{Colors.ENDC}\n")

    for gap in gaps:
        status_color = Colors.RED if gap['status'] == 'NOT_MET' else Colors.YELLOW
        print(f"{Colors.BOLD}{gap['control_id']}{Colors.ENDC}: {gap['title']}")
        print(f"  Domain: {gap['domain']}")
        print(f"  Status: {status_color}{gap['status']}{Colors.ENDC}")

        if gap['gaps_identified']:
            print(f"  Gaps:")
            for g in gap['gaps_identified']:
                print(f"    • {g}")

        print(f"  {Colors.CYAN}Remediation:{Colors.ENDC} {gap['remediation_guidance'][:100]}...")
        print()


def view_poam(assessment: CMMCAssessment):
    """View POA&M items"""
    if not assessment.poam_items:
        print(f"\n{Colors.YELLOW}No POA&M items tracked.{Colors.ENDC}")
        return

    print(f"\n{Colors.BOLD}═══ POA&M Items ({len(assessment.poam_items)}) ═══{Colors.ENDC}\n")

    for item in assessment.poam_items:
        severity_colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.YELLOW,
            'MODERATE': Colors.CYAN,
            'LOW': Colors.GREEN
        }
        sev_color = severity_colors.get(item.severity, Colors.ENDC)

        print(f"{Colors.BOLD}{item.poam_id}{Colors.ENDC} | {item.control_id}")
        print(f"  Severity: {sev_color}{item.severity}{Colors.ENDC}")
        print(f"  Status: {item.status}")
        print(f"  Weakness: {item.weakness_description[:80]}...")
        print(f"  Target: {item.scheduled_completion or 'Not set'}")
        print()


def main_menu(assessment: CMMCAssessment):
    """Main application menu"""
    while True:
        clear_screen()
        print_banner()
        display_summary(assessment)

        print_menu("MAIN MENU", [
            "Assess by Domain",
            "Quick Assessment Mode",
            "View Domain Status",
            "View Gaps",
            "View POA&M Items",
            "Generate Reports",
            "Generate Evidence Collection Checklist",
            "Convert Documents to PDF/Word",
            "Run Technical Validation Scripts",
            "Generate Excel + HTML Visualization (110 Controls)",
            "Save Assessment",
            "Load Assessment"
        ])

        choice = get_input("Select option", ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"])

        if choice == "0":
            save = get_input("Save assessment before exiting? [y/N]")
            if save.lower() == 'y':
                filename = input("Filename: ").strip() or f"assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                assessment.export_assessment(filename)
                print(f"{Colors.GREEN}✓ Saved to {filename}{Colors.ENDC}")
            print(f"\n{Colors.CYAN}Thank you for using CMMC Assessment Toolkit.{Colors.ENDC}")
            break

        elif choice == "1":
            # Domain selection
            domains = get_domain_summary()
            print_menu("SELECT DOMAIN", [
                f"{d['domain_id']} - {d['domain_name']} ({d['control_count']} controls)"
                for d in domains
            ])

            domain_choice = get_input("Select domain")
            if domain_choice == "0":
                continue

            try:
                domain_idx = int(domain_choice) - 1
                if 0 <= domain_idx < len(domains):
                    assess_domain_interactive(assessment, domains[domain_idx]['domain_id'])
            except ValueError:
                pass

        elif choice == "2":
            # Quick assessment
            domains = get_domain_summary()
            print_menu("SELECT DOMAIN FOR QUICK ASSESSMENT", [
                f"{d['domain_id']} - {d['domain_name']} ({d['control_count']} controls)"
                for d in domains
            ])

            domain_choice = get_input("Select domain")
            if domain_choice == "0":
                continue

            try:
                domain_idx = int(domain_choice) - 1
                if 0 <= domain_idx < len(domains):
                    quick_assessment(assessment, domains[domain_idx]['domain_id'])
            except ValueError:
                pass

        elif choice == "3":
            display_domain_status(assessment)
            input("\nPress Enter to continue...")

        elif choice == "4":
            view_gaps(assessment)
            input("\nPress Enter to continue...")

        elif choice == "5":
            view_poam(assessment)
            input("\nPress Enter to continue...")

        elif choice == "6":
            generate_reports_menu(assessment)
            input("\nPress Enter to continue...")

        elif choice == "7":
            # Generate Evidence Collection Checklist
            print(f"\n{Colors.BOLD}═══ Generate Evidence Collection Checklist ═══{Colors.ENDC}")
            print("\nThis generates documents to send to the organization BEFORE the assessment:")
            print("  • Evidence Collection Checklist - List of all artifacts to gather")
            print("  • Interview Guide - Questions to ask each role")
            print("  • Evidence by Domain - What evidence supports which controls")

            output_dir = input("\nOutput directory (default: ./evidence_request): ").strip()
            if not output_dir:
                output_dir = "./evidence_request"

            print(f"\n{Colors.CYAN}Generating evidence collection documents...{Colors.ENDC}")

            try:
                docs = generate_all_evidence_documents(assessment.organization_name, output_dir)
                print(f"\n{Colors.GREEN}✓ Documents generated:{Colors.ENDC}")
                for doc_type, path in docs.items():
                    print(f"  • {doc_type}: {path}")
                print(f"\n{Colors.YELLOW}Send these documents to the organization before starting the assessment.{Colors.ENDC}")
            except Exception as e:
                print(f"\n{Colors.RED}Error generating documents: {e}{Colors.ENDC}")

            input("\nPress Enter to continue...")

        elif choice == "8":
            # Convert Documents to PDF/Word
            print(f"\n{Colors.BOLD}═══ Convert Documents to PDF/Word ═══{Colors.ENDC}")

            # Check dependencies
            deps = check_dependencies()
            print("\nAvailable conversion tools:")
            for tool, available in deps.items():
                status = f"{Colors.GREEN}✓ Installed{Colors.ENDC}" if available else f"{Colors.RED}✗ Not installed{Colors.ENDC}"
                print(f"  {tool}: {status}")

            if not deps.get("python_docx") and not deps.get("weasyprint") and not deps.get("pandoc"):
                print(f"\n{Colors.YELLOW}No conversion tools installed.{Colors.ENDC}")
                print("\nTo enable PDF/Word conversion, install:")
                print("  pip install python-docx weasyprint")
                print("\nOr install pandoc:")
                print("  brew install pandoc  (macOS)")
                input("\nPress Enter to continue...")
                continue

            directory = input("\nDirectory with markdown files (default: ./evidence_request): ").strip()
            if not directory:
                directory = "./evidence_request"

            if not os.path.exists(directory):
                print(f"{Colors.RED}Directory not found: {directory}{Colors.ENDC}")
                input("\nPress Enter to continue...")
                continue

            print("\nConvert to:")
            print("  [1] PDF only")
            print("  [2] Word only")
            print("  [3] Both PDF and Word")
            format_choice = get_input("Select format", ["1", "2", "3"])

            format_map = {"1": "pdf", "2": "word", "3": "both"}
            output_format = format_map.get(format_choice, "both")

            print(f"\n{Colors.CYAN}Converting documents...{Colors.ENDC}")

            results = convert_all_documents(directory, output_format)

            print(f"\n{Colors.BOLD}Conversion Results:{Colors.ENDC}")
            for filename, result in results.items():
                print(f"\n  {filename}:")
                if "pdf" in result:
                    if result["pdf"]["success"]:
                        print(f"    {Colors.GREEN}PDF: ✓ {result['pdf']['path']}{Colors.ENDC}")
                    else:
                        print(f"    {Colors.RED}PDF: ✗ {result['pdf']['error']}{Colors.ENDC}")
                if "word" in result:
                    if result["word"]["success"]:
                        print(f"    {Colors.GREEN}Word: ✓ {result['word']['path']}{Colors.ENDC}")
                    else:
                        print(f"    {Colors.RED}Word: ✗ {result['word']['error']}{Colors.ENDC}")

            input("\nPress Enter to continue...")

        elif choice == "9":
            # Run Technical Validation Scripts
            print(f"\n{Colors.BOLD}═══ Run Technical Validation Scripts ═══{Colors.ENDC}")
            print("\nThis runs automated checks to validate control implementation:")
            print("  • Windows/AD: Password policy, lockout, audit, BitLocker, firewall, AV")
            print("  • Network: TLS versions, open ports, NTP sync")
            print("  • AWS: S3 encryption, CloudTrail, root MFA, security groups")
            print(f"\n{Colors.YELLOW}NOTE: Requires appropriate permissions. Only run with authorization.{Colors.ENDC}")

            print("\nSelect validation type:")
            print("  [1] Windows/Local System checks only")
            print("  [2] Network checks (requires target hosts)")
            print("  [3] AWS checks (requires boto3 and credentials)")
            print("  [4] All available checks")
            print("  [0] Cancel")

            val_choice = get_input("Select", ["0", "1", "2", "3", "4"])

            if val_choice != "0":
                output_dir = input("\nOutput directory (default: ./technical_validation): ").strip()
                if not output_dir:
                    output_dir = "./technical_validation"

                validator = CMMCTechnicalValidator(assessment.organization_name)

                include_windows = val_choice in ["1", "4"]
                include_network = val_choice in ["2", "4"]
                include_aws = val_choice in ["3", "4"]

                network_hosts = None
                if include_network:
                    hosts_input = input("Enter target hosts (comma-separated, e.g., 'server1.company.com,10.0.0.1'): ").strip()
                    if hosts_input:
                        network_hosts = [h.strip() for h in hosts_input.split(",")]

                print(f"\n{Colors.CYAN}Running validation...{Colors.ENDC}")

                report = validator.run_full_validation(
                    include_windows=include_windows,
                    include_network=include_network,
                    include_aws=include_aws,
                    network_hosts=network_hosts
                )

                os.makedirs(output_dir, exist_ok=True)
                json_path = validator.export_report(os.path.join(output_dir, "validation_results.json"))
                md_path = validator.generate_markdown_report(os.path.join(output_dir, "validation_report.md"))

                summary = report.summary
                print(f"\n{Colors.BOLD}Validation Complete:{Colors.ENDC}")
                print(f"  Total Checks: {summary['total_checks']}")
                print(f"  {Colors.GREEN}Passed: {summary['passed']}{Colors.ENDC}")
                print(f"  {Colors.RED}Failed: {summary['failed']}{Colors.ENDC}")
                print(f"  {Colors.YELLOW}Warnings: {summary['warnings']}{Colors.ENDC}")
                print(f"  Skipped: {summary['skipped']}")

                print(f"\n{Colors.GREEN}Reports saved:{Colors.ENDC}")
                print(f"  • {json_path}")
                print(f"  • {md_path}")

            input("\nPress Enter to continue...")

        elif choice == "10":
            # Generate Documents from Assessment Data
            print(f"\n{Colors.BOLD}═══ Generate Assessment Documents (Synced with Progress) ═══{Colors.ENDC}")
            print("\nThis generates documents reflecting your CURRENT assessment progress:")
            print(f"\n{Colors.CYAN}Documents Generated:{Colors.ENDC}")
            print("  • Excel Workbook - Evidence, Interviews, Controls with current status")
            print("  • HTML Dashboard - Visual C-Suite report with compliance metrics")
            print("  • Markdown Report - Text-based summary report")
            print("  • Word Document - Formal assessment report")
            print(f"\n{Colors.GREEN}✓ All documents sync with your saved assessment data!")
            print(f"✓ Run assessments → Save → Generate to update documents{Colors.ENDC}")

            # Show current progress
            summary = assessment.get_assessment_summary()
            ev_summary = assessment.get_evidence_summary()
            int_summary = assessment.get_interview_summary()

            print(f"\n{Colors.BOLD}Current Assessment Status:{Colors.ENDC}")
            print(f"  Controls: {summary['by_status']['MET']} MET / {summary['by_status']['NOT_MET']} NOT MET ({summary['compliance_score']}%)")
            print(f"  Evidence: {ev_summary['collected']}/{ev_summary['total']} collected ({ev_summary['progress_percent']}%)")
            print(f"  Interviews: {int_summary['completed']}/{int_summary['total']} completed ({int_summary['progress_percent']}%)")

            # Check for openpyxl
            deps = check_dependencies()
            if not deps.get("openpyxl"):
                print(f"\n{Colors.YELLOW}openpyxl not installed.{Colors.ENDC}")
                print("\nTo enable Excel export, install:")
                print("  pip install openpyxl")
                input("\nPress Enter to continue...")
                continue

            output_dir = input("\nOutput directory (default: ./assessment_reports): ").strip()
            if not output_dir:
                output_dir = "./assessment_reports"

            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            print(f"\n{Colors.CYAN}Generating documents from assessment data...{Colors.ENDC}")

            results = generate_documents_from_assessment(assessment, output_dir)

            print(f"\n{Colors.BOLD}Generated Files:{Colors.ENDC}")
            for fmt, (success, path) in results.items():
                if success:
                    print(f"  {Colors.GREEN}✓ {fmt.upper()}: {path}{Colors.ENDC}")
                else:
                    print(f"  {Colors.RED}✗ {fmt.upper()}: {path}{Colors.ENDC}")

            print(f"\n{Colors.YELLOW}Tip: Re-run this option after updating assessments to refresh documents{Colors.ENDC}")

            input("\nPress Enter to continue...")

        elif choice == "11":
            filename = input("Filename: ").strip() or f"assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            assessment.export_assessment(filename)
            print(f"{Colors.GREEN}✓ Saved to {filename}{Colors.ENDC}")

            # Auto-generate all documents from saved assessment
            print(f"\n{Colors.CYAN}Auto-updating all documents...{Colors.ENDC}")
            output_dir = "./assessment_reports"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            try:
                results = generate_documents_from_assessment(assessment, output_dir)
                print(f"\n{Colors.BOLD}Documents Updated:{Colors.ENDC}")
                for fmt, (success, path) in results.items():
                    if success:
                        print(f"  {Colors.GREEN}✓ {fmt.upper()}: {path}{Colors.ENDC}")
                    else:
                        print(f"  {Colors.RED}✗ {fmt.upper()}: {path}{Colors.ENDC}")
                print(f"\n{Colors.GREEN}All documents now reflect current assessment status.{Colors.ENDC}")

                # Offer to open reports
                print(f"\n{Colors.BOLD}Open reports?{Colors.ENDC}")
                print(f"  [1] HTML Dashboard (browser)")
                print(f"  [2] Excel Workbook")
                print(f"  [3] Word Report")
                print(f"  [4] All of the above")
                print(f"  [0] Skip")
                open_choice = get_input("Select", ["0", "1", "2", "3", "4"])

                import subprocess as sp
                if open_choice in ["1", "4"]:
                    html_file = results.get('html', (False, ''))[1]
                    if html_file and os.path.exists(html_file):
                        sp.Popen(["open", html_file])
                        print(f"  {Colors.CYAN}Opened HTML dashboard in browser{Colors.ENDC}")
                if open_choice in ["2", "4"]:
                    excel_file = results.get('excel', (False, ''))[1]
                    if excel_file and os.path.exists(excel_file):
                        sp.Popen(["open", excel_file])
                        print(f"  {Colors.CYAN}Opened Excel workbook{Colors.ENDC}")
                if open_choice in ["3", "4"]:
                    word_file = results.get('word', (False, ''))[1]
                    if word_file and os.path.exists(word_file):
                        sp.Popen(["open", word_file])
                        print(f"  {Colors.CYAN}Opened Word document{Colors.ENDC}")

            except Exception as e:
                print(f"{Colors.YELLOW}Note: Document generation skipped ({e}){Colors.ENDC}")

            input("\nPress Enter to continue...")

        elif choice == "12":
            filename = input("Filename to load: ").strip()
            if filename and os.path.exists(filename):
                assessment.import_assessment(filename)
                print(f"{Colors.GREEN}✓ Loaded from {filename}{Colors.ENDC}")
            else:
                print(f"{Colors.RED}File not found.{Colors.ENDC}")
            input("\nPress Enter to continue...")


def main():
    """Application entry point"""
    parser = argparse.ArgumentParser(
        description="CMMC Level 2 Gap Assessment Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cmmc_assessor.py                     Interactive mode
  python cmmc_assessor.py --new "Company"     Start new assessment
  python cmmc_assessor.py --load assess.json  Load existing assessment
  python cmmc_assessor.py --report assess.json --output ./reports
        """
    )

    parser.add_argument(
        '--new',
        metavar='ORG_NAME',
        help='Start new assessment for organization'
    )

    parser.add_argument(
        '--load',
        metavar='FILE',
        help='Load existing assessment from JSON file'
    )

    parser.add_argument(
        '--report',
        metavar='FILE',
        help='Generate reports from assessment file'
    )

    parser.add_argument(
        '--output',
        metavar='DIR',
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )

    parser.add_argument(
        '--summary',
        action='store_true',
        help='Display assessment summary and exit'
    )

    args = parser.parse_args()

    # Determine mode and create/load assessment
    if args.report:
        # Report generation mode
        if not os.path.exists(args.report):
            print(f"{Colors.RED}Error: File not found: {args.report}{Colors.ENDC}")
            sys.exit(1)

        assessment = CMMCAssessment("Temp")
        assessment.import_assessment(args.report)

        print(f"{Colors.CYAN}Generating reports from {args.report}...{Colors.ENDC}")
        reports = generate_all_reports(assessment, args.output)

        print(f"\n{Colors.GREEN}Reports generated:{Colors.ENDC}")
        for report_type, path in reports.items():
            print(f"  • {report_type}: {path}")

    elif args.load:
        # Load existing assessment
        if not os.path.exists(args.load):
            print(f"{Colors.RED}Error: File not found: {args.load}{Colors.ENDC}")
            sys.exit(1)

        assessment = CMMCAssessment("Temp")
        assessment.import_assessment(args.load)
        print(f"{Colors.GREEN}✓ Loaded assessment from {args.load}{Colors.ENDC}")

        if args.summary:
            display_summary(assessment)
            display_domain_status(assessment)
        else:
            main_menu(assessment)

    elif args.new:
        # New assessment
        assessment = CMMCAssessment(args.new)
        print(f"{Colors.GREEN}✓ Created new assessment for {args.new}{Colors.ENDC}")

        if args.summary:
            display_summary(assessment)
        else:
            main_menu(assessment)

    else:
        # Interactive mode - prompt for organization name
        clear_screen()
        print_banner()

        print(f"\n{Colors.BOLD}Welcome to the CMMC Level 2 Gap Assessment Toolkit{Colors.ENDC}")
        print("\nThis tool helps you assess your organization's compliance with")
        print("CMMC Level 2 requirements (all 110 NIST SP 800-171 Rev 2 controls).")
        print(f"\n{Colors.YELLOW}⚠  FALSE CLAIMS ACT NOTICE:{Colors.ENDC}")
        print(f"   Assessment results may be used for SPRS scoring and CMMC certification.")
        print(f"   Misrepresenting cybersecurity compliance status to the DoD is a potential")
        print(f"   violation of the False Claims Act (31 U.S.C. § 3729). The DOJ Civil")
        print(f"   Cyber-Fraud Initiative actively pursues contractors who submit inaccurate")
        print(f"   self-assessments. Ensure all assessment data is accurate and truthful.")

        print(f"\n{Colors.CYAN}Options:{Colors.ENDC}")
        print("  [1] Start new assessment")
        print("  [2] Load existing assessment")
        print("  [0] Exit")

        choice = get_input("Select option", ["0", "1", "2"])

        if choice == "0":
            print(f"\n{Colors.CYAN}Goodbye!{Colors.ENDC}")
            sys.exit(0)

        elif choice == "1":
            org_name = input("\nOrganization name: ").strip()
            if not org_name:
                org_name = "Unnamed Organization"
            assessment = CMMCAssessment(org_name)
            main_menu(assessment)

        elif choice == "2":
            filename = input("\nAssessment file to load: ").strip()
            if filename and os.path.exists(filename):
                assessment = CMMCAssessment("Temp")
                assessment.import_assessment(filename)
                print(f"{Colors.GREEN}✓ Loaded assessment{Colors.ENDC}")
                main_menu(assessment)
            else:
                print(f"{Colors.RED}File not found.{Colors.ENDC}")
                sys.exit(1)


if __name__ == "__main__":
    main()
