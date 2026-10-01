"""
Conservative Threat Attribution Engine.

Formulates evidence-backed, non-definitive attribution assessments adhering to strict threat intelligence guidelines.
STRICT GUARANTEE: Never makes absolute attribution statements without authoritative evidence.
"""

from typing import List
from app.ai.agents.threat_intel.schemas import (
    IntelligenceConsensus,
    ThreatCluster,
    AttributionAssessment,
    AttributionLevel,
)
from app.ai.orchestrator.state import InvestigationState


class ConservativeAttributionEngine:
    """Engine for formulating evidence-backed, conservative threat attribution statements."""

    def evaluate_attribution(
        self,
        consensuses: List[IntelligenceConsensus],
        clusters: List[ThreatCluster],
        state: InvestigationState,
    ) -> AttributionAssessment:
        """Evaluate provider consensus and cluster data to formulate conservative attribution assessment."""
        high_threat = [c for c in consensuses if c.consolidated_threat_score >= 70.0]
        indicators = [c.ioc_value for c in consensuses]
        ev_refs = [state.investigation_id]

        if len(high_threat) >= 2:
            return AttributionAssessment(
                level=AttributionLevel.POSSIBLE_THREAT_GROUP,
                statement="Possible threat group relationship based on high-severity provider consensus and correlated indicators.",
                confidence=0.75,
                evidence_refs=ev_refs,
                supporting_indicators=[c.ioc_value for c in high_threat],
            )
        elif len(high_threat) == 1:
            return AttributionAssessment(
                level=AttributionLevel.POTENTIAL_CAMPAIGN,
                statement="Potential campaign association observed across telemetry indicators.",
                confidence=0.60,
                evidence_refs=ev_refs,
                supporting_indicators=[c.ioc_value for c in high_threat],
            )
        elif len(indicators) > 0:
            return AttributionAssessment(
                level=AttributionLevel.INFRASTRUCTURE_RELATIONSHIP,
                statement="Related infrastructure observed; insufficient evidence for specific threat group attribution.",
                confidence=0.45,
                evidence_refs=ev_refs,
                supporting_indicators=indicators,
            )

        return AttributionAssessment(
            level=AttributionLevel.UNKNOWN,
            statement="Insufficient telemetry evidence for threat actor or campaign attribution.",
            confidence=0.20,
            evidence_refs=ev_refs,
            supporting_indicators=[],
        )
