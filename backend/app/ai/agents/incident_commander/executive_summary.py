"""
Executive Summary Generator.

Produces non-technical SOC management executive summaries, technical impact details,
and business impact assessments.
"""

from typing import List, Dict, Any
from app.ai.orchestrator.state import InvestigationState
from app.ai.agents.incident_commander.schemas import ExecutiveIncidentSummary, CommanderFinding


class ExecutiveSummaryGenerator:
    """Executive summary generator producing SOC management reporting payloads."""

    def generate_summary(
        self,
        state: InvestigationState,
        title: str,
        severity: str,
        confidence: float,
        findings: List[CommanderFinding],
        likely_root_cause: str,
    ) -> ExecutiveIncidentSummary:
        """Generate structured executive incident summary payload."""
        summary_text = (
            f"An investigation ({state.investigation_id}) identified a potential {severity.lower()} severity security incident. "
            f"Analysis of telemetry indicates: {likely_root_cause}"
        )

        key_findings_list = [f.title for f in findings[:5]] or ["Ingested alert telemetry confirmed under active investigation."]
        recommended_actions_list = state.recommendations[:4] or [
            "Review endpoint telemetry for suspicious process activity.",
            "Verify network firewall drop logs for external C2 IP addresses.",
        ]

        return ExecutiveIncidentSummary(
            incident_title=title,
            executive_summary=summary_text,
            business_impact="Business impact not determined.",
            technical_impact=f"Observed alert ingestion and evidence analysis across {len(state.alerts)} alert(s) and {len(state.evidence)} evidence item(s).",
            current_status="UNDER_INVESTIGATION",
            severity=severity,
            confidence=confidence,
            key_findings=key_findings_list,
            recommended_actions=recommended_actions_list,
        )
