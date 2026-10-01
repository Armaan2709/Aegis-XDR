"""
Threat Intelligence Recommendation Generator.

Generates human-governed advisory security recommendations based on intelligence findings
and provider consensus. Enforces requires_human_approval = True for all SOAR recommendations.
"""

from typing import List
from app.ai.agents.threat_intel.schemas import (
    ThreatIntelligenceFinding,
    IntelligenceGap,
    ThreatIntelligenceRecommendation,
)


class ThreatIntelRecommendationGenerator:
    """Generator for human-governed threat intelligence recommendations."""

    def generate_recommendations(
        self, findings: List[ThreatIntelligenceFinding], gaps: List[IntelligenceGap]
    ) -> List[ThreatIntelligenceRecommendation]:
        """Generate human-governed advisory recommendations."""
        recommendations: List[ThreatIntelligenceRecommendation] = []

        # 1. Recommendations from Findings
        for finding in findings:
            if finding.threat_score >= 70.0:
                recommendations.append(
                    ThreatIntelligenceRecommendation(
                        title=f"Block & Contain High-Threat Indicators: {', '.join(finding.ioc_values[:2])}",
                        description="Enrich, block, and contain verified malicious indicators at perimeter firewall and proxy.",
                        priority="URGENT",
                        rationale=f"Verified high threat score ({finding.threat_score}/100) supported by provider consensus.",
                        related_finding=finding.finding_id,
                        suggested_playbook="PB-CONTAIN-ENDPOINT",
                        requires_human_approval=True,  # STRICT HUMAN GOVERNANCE
                    )
                )
            elif finding.threat_score >= 50.0:
                recommendations.append(
                    ThreatIntelligenceRecommendation(
                        title=f"Perimeter Monitoring & Threat Enrichment for {finding.ioc_values[0] if finding.ioc_values else 'IOC'}",
                        description="Apply enhanced monitoring and submit IOC for extended threat intelligence query.",
                        priority="HIGH",
                        rationale="Suspicious threat score generated during multi-provider consensus evaluation.",
                        related_finding=finding.finding_id,
                        suggested_playbook="PB-COLLECT-DIAGNOSTICS",
                        requires_human_approval=True,  # STRICT HUMAN GOVERNANCE
                    )
                )

        # 2. Recommendations from Intelligence Gaps
        for gap in gaps:
            recommendations.append(
                ThreatIntelligenceRecommendation(
                    title=f"Remediate Intelligence Gap: {gap.recommended_next_step}",
                    description=gap.description,
                    priority=gap.priority,
                    rationale="Address provider disagreement or missing reputation data.",
                    suggested_playbook="PB-FORENSIC-TRIAGE",
                    requires_human_approval=True,  # STRICT HUMAN GOVERNANCE
                )
            )

        # Baseline Recommendation if empty
        if not recommendations:
            recommendations.append(
                ThreatIntelligenceRecommendation(
                    title="Threat Intelligence Review Baseline",
                    description="Standard threat intelligence review and periodic feed synchronization.",
                    priority="LOW",
                    rationale="Maintain threat intelligence operational baseline.",
                    suggested_playbook=None,
                    requires_human_approval=False,
                )
            )

        return recommendations
