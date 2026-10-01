"""
DFIR Recommendation Generator.

Generates structured, human-governed advisory security recommendations based on DFIR findings
and evidence gaps. Enforces requires_human_approval = True for all SOAR playbook recommendations.
"""

from typing import List
from app.ai.agents.dfir.schemas import DFIRFinding, EvidenceGap, DFIRRecommendation


class DFIRRecommendationGenerator:
    """Generator for human-governed DFIR forensic recommendations."""

    def generate_recommendations(
        self, findings: List[DFIRFinding], gaps: List[EvidenceGap]
    ) -> List[DFIRRecommendation]:
        """Generate human-governed forensic recommendations."""
        recommendations: List[DFIRRecommendation] = []

        # 1. Recommendations based on findings
        for finding in findings:
            if "LSASS" in finding.title or "Credential" in finding.title:
                recommendations.append(
                    DFIRRecommendation(
                        title="Collect Endpoint Forensic Memory Image & Rotate Credentials",
                        description="Acquire full host memory dump and force password reset for impacted user accounts.",
                        priority="URGENT",
                        rationale="Active credential access / memory dumping identified in forensic telemetry.",
                        related_finding=finding.finding_id,
                        suggested_playbook="PB-CONTAIN-ENDPOINT",
                        requires_human_approval=True, # STRICT HUMAN GOVERNANCE
                    )
                )
            if "Script" in finding.title or "PowerShell" in finding.title:
                recommendations.append(
                    DFIRRecommendation(
                        title="Acquire ScriptBlock Logs & Prefetch Artifacts",
                        description="Collect PowerShell Operational log (Event ID 4104) and Prefetch files for timeline analysis.",
                        priority="HIGH",
                        rationale="Obfuscated script payload execution detected in process telemetry.",
                        related_finding=finding.finding_id,
                        suggested_playbook="PB-COLLECT-DIAGNOSTICS",
                        requires_human_approval=True, # STRICT HUMAN GOVERNANCE
                    )
                )

        # 2. Recommendations based on evidence gaps
        for gap in gaps:
            recommendations.append(
                DFIRRecommendation(
                    title=f"Forensic Artifact Collection: {gap.recommended_collection}",
                    description=gap.description,
                    priority=gap.priority,
                    rationale="Remediate identified telemetry gap to improve forensic visibility.",
                    suggested_playbook="PB-FORENSIC-TRIAGE",
                    requires_human_approval=True, # STRICT HUMAN GOVERNANCE
                )
            )

        # Baseline Recommendation if empty
        if not recommendations:
            recommendations.append(
                DFIRRecommendation(
                    title="Review Endpoint Forensics Timeline",
                    description="Perform analyst review of reconstructed timeline events.",
                    priority="LOW",
                    rationale="Standard forensic review baseline.",
                    suggested_playbook=None,
                    requires_human_approval=False,
                )
            )

        return recommendations
