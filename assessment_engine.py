"""
CMMC Level 2 Assessment Engine
Provides gap assessment functionality aligned with C3PAO evaluation methodology.

Author: Akintade Akinokun
Purpose: CMMC Level 2 C3PAO Audit Preparation
Reference: NIST SP 800-171A, CMMC Assessment Guide Level 2
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum
from cmmc_controls import CMMC_LEVEL2_CONTROLS, get_all_controls, get_domain_summary


class AssessmentStatus(Enum):
    """C3PAO Assessment Result Categories"""
    MET = "MET"
    NOT_MET = "NOT_MET"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_ASSESSED = "NOT_ASSESSED"


class FindingSeverity(Enum):
    """POA&M Finding Severity Levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"


@dataclass
class ControlAssessment:
    """Individual control assessment result"""
    control_id: str
    domain_id: str
    status: str = "NOT_ASSESSED"
    implementation_description: str = ""
    evidence_provided: List[str] = field(default_factory=list)
    gaps_identified: List[str] = field(default_factory=list)
    assessor_notes: str = ""
    assessment_date: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class POAMItem:
    """Plan of Action and Milestones item"""
    poam_id: str
    control_id: str
    weakness_description: str
    severity: str
    remediation_plan: str
    resources_required: str
    responsible_party: str
    scheduled_completion: str
    milestones: List[Dict] = field(default_factory=list)
    status: str = "OPEN"
    actual_completion: str = ""

    def to_dict(self):
        return asdict(self)


class CMMCAssessment:
    """
    CMMC Level 2 Gap Assessment Tool

    Performs pre-assessment analysis against all 110 NIST SP 800-171 Rev 2 controls,
    using scoring methodology aligned with C3PAO assessment requirements.
    """

    def __init__(self, organization_name: str, assessment_name: str = None):
        self.organization_name = organization_name
        self.assessment_name = assessment_name or f"CMMC_Assessment_{datetime.now().strftime('%Y%m%d')}"
        self.assessment_date = datetime.now().isoformat()
        self.assessments: Dict[str, ControlAssessment] = {}
        self.poam_items: List[POAMItem] = []
        self.poam_counter = 1

        # Evidence and Interview tracking
        self.evidence_status: Dict[str, Dict] = {}  # artifact_id -> {status, notes, responsible, date}
        self.interview_status: Dict[str, Dict] = {}  # question_id -> {status, response, date}

        # Initialize all controls as NOT_ASSESSED
        self._initialize_assessments()
        self._initialize_evidence_tracking()
        self._initialize_interview_tracking()

    def _initialize_assessments(self):
        """Initialize assessment records for all 110 controls"""
        for control in get_all_controls():
            self.assessments[control["control_id"]] = ControlAssessment(
                control_id=control["control_id"],
                domain_id=control["domain_id"]
            )

    def _initialize_evidence_tracking(self):
        """Initialize evidence collection tracking for all artifacts"""
        try:
            from evidence_checklist import EVIDENCE_CATALOG
            artifact_id = 0
            for category_id, category_data in EVIDENCE_CATALOG.items():
                for artifact in category_data.get('artifacts', []):
                    artifact_id += 1
                    key = f"EV-{artifact_id:03d}"
                    self.evidence_status[key] = {
                        'artifact_id': key,
                        'category': category_data.get('category_name', category_id),
                        'name': artifact.get('name', ''),
                        'description': artifact.get('description', ''),
                        'controls': artifact.get('controls', []),
                        'required': artifact.get('required', False),
                        'status': 'Pending',  # Pending, Collected, N/A
                        'notes': '',
                        'responsible_party': '',
                        'collection_date': ''
                    }
        except ImportError:
            pass  # Evidence checklist not available

    def _initialize_interview_tracking(self):
        """Initialize interview tracking for all questions"""
        try:
            from evidence_checklist import INTERVIEW_GUIDE
            question_id = 0
            for role_id, role_data in INTERVIEW_GUIDE.items():
                role_name = role_data.get('role', role_id)
                for topic_data in role_data.get('topics', []):
                    topic_name = topic_data.get('topic', '')
                    for question in topic_data.get('questions', []):
                        question_id += 1
                        key = f"INT-{question_id:03d}"
                        self.interview_status[key] = {
                            'question_id': key,
                            'role': role_name,
                            'topic': topic_name,
                            'question': question,
                            'controls': topic_data.get('controls', []),
                            'status': 'Pending',  # Pending, Completed, Skipped
                            'response_notes': '',
                            'interview_date': ''
                        }
        except ImportError:
            pass  # Interview guide not available

    def update_evidence_status(self, artifact_id: str, status: str, notes: str = "",
                               responsible_party: str = ""):
        """Update the collection status of an evidence artifact"""
        if artifact_id in self.evidence_status:
            self.evidence_status[artifact_id]['status'] = status
            self.evidence_status[artifact_id]['notes'] = notes
            self.evidence_status[artifact_id]['responsible_party'] = responsible_party
            if status == 'Collected':
                self.evidence_status[artifact_id]['collection_date'] = datetime.now().isoformat()
            return True
        return False

    def update_interview_status(self, question_id: str, status: str, response_notes: str = ""):
        """Update the completion status of an interview question"""
        if question_id in self.interview_status:
            self.interview_status[question_id]['status'] = status
            self.interview_status[question_id]['response_notes'] = response_notes
            if status == 'Completed':
                self.interview_status[question_id]['interview_date'] = datetime.now().isoformat()
            return True
        return False

    def get_evidence_summary(self) -> Dict:
        """Get summary of evidence collection progress"""
        total = len(self.evidence_status)
        collected = sum(1 for e in self.evidence_status.values() if e['status'] == 'Collected')
        pending = sum(1 for e in self.evidence_status.values() if e['status'] == 'Pending')
        na = sum(1 for e in self.evidence_status.values() if e['status'] == 'N/A')
        return {
            'total': total,
            'collected': collected,
            'pending': pending,
            'not_applicable': na,
            'progress_percent': round((collected / (total - na)) * 100, 1) if (total - na) > 0 else 0
        }

    def get_interview_summary(self) -> Dict:
        """Get summary of interview progress"""
        total = len(self.interview_status)
        completed = sum(1 for i in self.interview_status.values() if i['status'] == 'Completed')
        pending = sum(1 for i in self.interview_status.values() if i['status'] == 'Pending')
        skipped = sum(1 for i in self.interview_status.values() if i['status'] == 'Skipped')
        return {
            'total': total,
            'completed': completed,
            'pending': pending,
            'skipped': skipped,
            'progress_percent': round((completed / (total - skipped)) * 100, 1) if (total - skipped) > 0 else 0
        }

    def assess_control(
        self,
        control_id: str,
        status: AssessmentStatus,
        implementation_description: str = "",
        evidence_provided: List[str] = None,
        gaps_identified: List[str] = None,
        assessor_notes: str = ""
    ) -> ControlAssessment:
        """
        Assess a single control.

        Args:
            control_id: The control identifier (e.g., "AC.L2-3.1.1")
            status: MET, NOT_MET, NOT_APPLICABLE, or NOT_ASSESSED
            implementation_description: How the control is implemented
            evidence_provided: List of evidence artifacts
            gaps_identified: List of identified gaps
            assessor_notes: Additional assessor comments

        Returns:
            Updated ControlAssessment object
        """
        if control_id not in self.assessments:
            raise ValueError(f"Unknown control ID: {control_id}")

        assessment = self.assessments[control_id]
        assessment.status = status.value
        assessment.implementation_description = implementation_description
        assessment.evidence_provided = evidence_provided or []
        assessment.gaps_identified = gaps_identified or []
        assessment.assessor_notes = assessor_notes
        assessment.assessment_date = datetime.now().isoformat()

        return assessment

    def add_poam_item(
        self,
        control_id: str,
        weakness_description: str,
        severity: FindingSeverity,
        remediation_plan: str,
        resources_required: str = "",
        responsible_party: str = "",
        scheduled_completion: str = "",
        milestones: List[Dict] = None
    ) -> POAMItem:
        """
        Add a POA&M item for a control finding.

        Args:
            control_id: Associated control identifier
            weakness_description: Description of the weakness/gap
            severity: CRITICAL, HIGH, MODERATE, or LOW
            remediation_plan: Steps to remediate
            resources_required: Resources needed for remediation
            responsible_party: Person/team responsible
            scheduled_completion: Target completion date
            milestones: List of milestone dictionaries with 'description' and 'due_date'

        Returns:
            Created POAMItem object
        """
        poam_id = f"POAM-{self.poam_counter:04d}"
        self.poam_counter += 1

        item = POAMItem(
            poam_id=poam_id,
            control_id=control_id,
            weakness_description=weakness_description,
            severity=severity.value,
            remediation_plan=remediation_plan,
            resources_required=resources_required,
            responsible_party=responsible_party,
            scheduled_completion=scheduled_completion,
            milestones=milestones or []
        )

        self.poam_items.append(item)
        return item

    def get_assessment_summary(self) -> Dict:
        """Generate summary statistics for the assessment"""
        summary = {
            "organization": self.organization_name,
            "assessment_name": self.assessment_name,
            "assessment_date": self.assessment_date,
            "total_controls": 110,
            "by_status": {
                "MET": 0,
                "NOT_MET": 0,
                "NOT_APPLICABLE": 0,
                "NOT_ASSESSED": 0
            },
            "by_domain": {},
            "compliance_score": 0.0,
            "poam_items": len(self.poam_items)
        }

        # Count by status
        for assessment in self.assessments.values():
            summary["by_status"][assessment.status] += 1

        # Count by domain
        for domain in get_domain_summary():
            domain_id = domain["domain_id"]
            domain_assessments = [
                a for a in self.assessments.values()
                if a.domain_id == domain_id
            ]
            summary["by_domain"][domain_id] = {
                "name": domain["domain_name"],
                "total": len(domain_assessments),
                "met": sum(1 for a in domain_assessments if a.status == "MET"),
                "not_met": sum(1 for a in domain_assessments if a.status == "NOT_MET"),
                "not_applicable": sum(1 for a in domain_assessments if a.status == "NOT_APPLICABLE"),
                "not_assessed": sum(1 for a in domain_assessments if a.status == "NOT_ASSESSED")
            }

        # Calculate compliance score (MET / (Total - NOT_APPLICABLE))
        applicable_controls = summary["by_status"]["MET"] + summary["by_status"]["NOT_MET"]
        if applicable_controls > 0:
            summary["compliance_score"] = round(
                (summary["by_status"]["MET"] / applicable_controls) * 100, 2
            )

        return summary

    def get_gaps_report(self) -> List[Dict]:
        """Generate a report of all identified gaps"""
        gaps = []

        for control in get_all_controls():
            assessment = self.assessments[control["control_id"]]

            if assessment.status == "NOT_MET" or assessment.gaps_identified:
                gaps.append({
                    "control_id": control["control_id"],
                    "domain": control["domain_name"],
                    "title": control["title"],
                    "requirement": control["requirement"],
                    "status": assessment.status,
                    "gaps_identified": assessment.gaps_identified,
                    "remediation_guidance": control["remediation_guidance"],
                    "evidence_examples": control["evidence_examples"]
                })

        return gaps

    def get_domain_readiness(self, domain_id: str) -> Dict:
        """Get detailed readiness status for a specific domain"""
        domain_data = CMMC_LEVEL2_CONTROLS.get(domain_id)
        if not domain_data:
            raise ValueError(f"Unknown domain: {domain_id}")

        readiness = {
            "domain_id": domain_id,
            "domain_name": domain_data["domain_name"],
            "description": domain_data["domain_description"],
            "controls": []
        }

        for control_id, control_data in domain_data["controls"].items():
            assessment = self.assessments[control_id]
            readiness["controls"].append({
                "control_id": control_id,
                "title": control_data["title"],
                "status": assessment.status,
                "implementation": assessment.implementation_description,
                "evidence": assessment.evidence_provided,
                "gaps": assessment.gaps_identified,
                "assessment_objectives": control_data["assessment_objectives"]
            })

        return readiness

    def export_assessment(self, filepath: str):
        """Export full assessment to JSON file"""
        export_data = {
            "organization": self.organization_name,
            "assessment_name": self.assessment_name,
            "assessment_date": self.assessment_date,
            "export_date": datetime.now().isoformat(),
            "summary": self.get_assessment_summary(),
            "assessments": {k: v.to_dict() for k, v in self.assessments.items()},
            "poam_items": [item.to_dict() for item in self.poam_items],
            "evidence_status": self.evidence_status,
            "interview_status": self.interview_status,
            "evidence_summary": self.get_evidence_summary(),
            "interview_summary": self.get_interview_summary()
        }

        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)

        return filepath

    def import_assessment(self, filepath: str):
        """Import assessment from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)

        self.organization_name = data["organization"]
        self.assessment_name = data["assessment_name"]
        self.assessment_date = data["assessment_date"]

        for control_id, assessment_data in data["assessments"].items():
            if control_id in self.assessments:
                self.assessments[control_id] = ControlAssessment(**assessment_data)

        self.poam_items = [POAMItem(**item) for item in data.get("poam_items", [])]
        if self.poam_items:
            self.poam_counter = max(
                int(item.poam_id.split("-")[1]) for item in self.poam_items
            ) + 1

        # Import evidence and interview status if present
        if "evidence_status" in data:
            for artifact_id, status_data in data["evidence_status"].items():
                if artifact_id in self.evidence_status:
                    self.evidence_status[artifact_id].update(status_data)
                else:
                    self.evidence_status[artifact_id] = status_data

        if "interview_status" in data:
            for question_id, status_data in data["interview_status"].items():
                if question_id in self.interview_status:
                    self.interview_status[question_id].update(status_data)
                else:
                    self.interview_status[question_id] = status_data


class AssessmentQuestionnaire:
    """
    Interactive questionnaire for conducting CMMC assessments.
    Provides guided questions based on assessment objectives.
    """

    def __init__(self, assessment: CMMCAssessment):
        self.assessment = assessment

    def get_control_questions(self, control_id: str) -> Dict:
        """
        Get assessment questions for a specific control.

        Returns structured questions based on the control's assessment objectives.
        """
        # Find the control
        control = None
        domain_id = None
        for did, domain_data in CMMC_LEVEL2_CONTROLS.items():
            if control_id in domain_data["controls"]:
                control = domain_data["controls"][control_id]
                domain_id = did
                break

        if not control:
            raise ValueError(f"Unknown control: {control_id}")

        questions = {
            "control_id": control_id,
            "domain": domain_id,
            "title": control["title"],
            "requirement": control["requirement"],
            "questions": []
        }

        # Generate questions from assessment objectives
        for i, objective in enumerate(control["assessment_objectives"], 1):
            questions["questions"].append({
                "id": f"{control_id}-Q{i}",
                "objective": objective,
                "question": f"Can you demonstrate that: {objective}?",
                "response_type": "yes_no_partial",
                "evidence_prompt": f"What evidence supports this? (Examples: {', '.join(control['evidence_examples'][:2])})"
            })

        questions["remediation_guidance"] = control["remediation_guidance"]
        questions["evidence_examples"] = control["evidence_examples"]

        return questions

    def get_domain_questionnaire(self, domain_id: str) -> List[Dict]:
        """Get all questions for a domain"""
        if domain_id not in CMMC_LEVEL2_CONTROLS:
            raise ValueError(f"Unknown domain: {domain_id}")

        questionnaire = []
        for control_id in CMMC_LEVEL2_CONTROLS[domain_id]["controls"]:
            questionnaire.append(self.get_control_questions(control_id))

        return questionnaire

    def evaluate_responses(
        self,
        control_id: str,
        responses: List[Dict]
    ) -> AssessmentStatus:
        """
        Evaluate questionnaire responses to determine control status.

        A control is MET only if ALL assessment objectives are satisfied.
        This aligns with C3PAO assessment methodology.

        Args:
            control_id: The control being assessed
            responses: List of response dictionaries with 'objective_id' and 'response'
                      where response is 'yes', 'no', or 'partial'

        Returns:
            AssessmentStatus indicating MET or NOT_MET
        """
        if not responses:
            return AssessmentStatus.NOT_ASSESSED

        all_met = True
        for response in responses:
            if response.get("response", "").lower() != "yes":
                all_met = False
                break

        return AssessmentStatus.MET if all_met else AssessmentStatus.NOT_MET


def calculate_sprs_score(assessment: CMMCAssessment) -> Dict:
    """
    Calculate SPRS (Supplier Performance Risk System) score.

    SPRS scoring: Start at 110, subtract points for each NOT_MET control.
    Point values vary by control (1, 3, or 5 points).

    Note: Actual SPRS point values should be verified against current DoD guidance.
    This implementation uses a simplified model for demonstration.
    """
    # Simplified point values (in practice, these vary by control)
    # Critical controls = 5 points, Important = 3 points, Standard = 1 point
    critical_controls = [
        "AC.L2-3.1.1", "AC.L2-3.1.3", "AC.L2-3.1.5", "AC.L2-3.1.12", "AC.L2-3.1.13",
        "IA.L2-3.5.3", "SC.L2-3.13.8", "SC.L2-3.13.11", "SC.L2-3.13.16"
    ]
    important_controls = [
        "AU.L2-3.3.1", "AU.L2-3.3.2", "CM.L2-3.4.1", "CM.L2-3.4.2",
        "IR.L2-3.6.1", "IR.L2-3.6.2", "RA.L2-3.11.2", "SI.L2-3.14.1", "SI.L2-3.14.2"
    ]

    base_score = 110
    deductions = 0
    deduction_details = []

    for control_id, control_assessment in assessment.assessments.items():
        if control_assessment.status == "NOT_MET":
            if control_id in critical_controls:
                points = 5
            elif control_id in important_controls:
                points = 3
            else:
                points = 1

            deductions += points
            deduction_details.append({
                "control_id": control_id,
                "points_deducted": points
            })

    final_score = max(base_score - deductions, -203)  # SPRS minimum is -203

    return {
        "base_score": base_score,
        "total_deductions": deductions,
        "final_score": final_score,
        "deduction_details": deduction_details,
        "assessment_date": assessment.assessment_date,
        "note": "This is a simplified SPRS calculation for demonstration. Verify actual point values against current DoD SPRS guidance.",
        "fca_warning": (
            "FALSE CLAIMS ACT NOTICE: Submitting inaccurate SPRS scores to the DoD Supplier Performance "
            "Risk System constitutes a potential violation of the False Claims Act (31 U.S.C. § 3729). "
            "Under the DOJ Civil Cyber-Fraud Initiative (2021), defense contractors who misrepresent their "
            "cybersecurity compliance status face treble damages and penalties exceeding $11,000 per false claim. "
            "Ensure this score accurately reflects your organization's current security posture before submission."
        )
    }


if __name__ == "__main__":
    # Demo usage
    print("CMMC Level 2 Assessment Engine Demo")
    print("=" * 50)

    # Create assessment
    assessment = CMMCAssessment("Demo Organization Inc.")

    # Assess a few controls for demonstration
    assessment.assess_control(
        "AC.L2-3.1.1",
        AssessmentStatus.MET,
        implementation_description="RBAC implemented via Active Directory with documented access policies.",
        evidence_provided=["AD Group Policy documentation", "Access control matrix", "User provisioning procedures"],
        assessor_notes="Strong implementation with quarterly reviews."
    )

    assessment.assess_control(
        "AC.L2-3.1.3",
        AssessmentStatus.NOT_MET,
        implementation_description="Basic network segmentation exists but CUI flow not fully documented.",
        gaps_identified=["CUI data flow diagrams incomplete", "DLP not deployed", "No formal authorization process for CUI transfers"],
        assessor_notes="Requires significant remediation effort."
    )

    # Add POA&M for the gap
    assessment.add_poam_item(
        control_id="AC.L2-3.1.3",
        weakness_description="CUI flow controls not fully implemented",
        severity=FindingSeverity.HIGH,
        remediation_plan="1. Complete CUI data flow mapping\n2. Deploy DLP solution\n3. Establish formal CUI transfer authorization process",
        resources_required="DLP software license, 80 hours labor",
        responsible_party="Information Security Manager",
        scheduled_completion="2024-06-30",
        milestones=[
            {"description": "Complete data flow mapping", "due_date": "2024-04-15"},
            {"description": "DLP vendor selection", "due_date": "2024-05-01"},
            {"description": "DLP deployment", "due_date": "2024-06-15"},
            {"description": "Policy documentation", "due_date": "2024-06-30"}
        ]
    )

    # Print summary
    summary = assessment.get_assessment_summary()
    print(f"\nOrganization: {summary['organization']}")
    print(f"Assessment: {summary['assessment_name']}")
    print(f"\nStatus Summary:")
    for status, count in summary["by_status"].items():
        print(f"  {status}: {count}")
    print(f"\nCompliance Score: {summary['compliance_score']}%")
    print(f"POA&M Items: {summary['poam_items']}")

    # Calculate SPRS
    sprs = calculate_sprs_score(assessment)
    print(f"\nSPRS Score: {sprs['final_score']}")
