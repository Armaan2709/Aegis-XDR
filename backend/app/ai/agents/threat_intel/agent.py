"""
Threat Intelligence Analyst Agent Implementation.

Specialized Threat Intelligence AI Agent for AegisAI XDR.
Inherits from BaseAgent. Executes analysis over InvestigationState.

STRICT SAFETY GUARANTEE:
- Strictly analysis-only execution.
- No binary execution, malware execution, active scanning, shell/Python execution, or file/system modifications.
- Human approval explicitly enforced for all response recommendations.
"""

import time
from typing import List, Dict, Any, Optional
from app.ai.agents.base import BaseAgent, AgentResult, AgentStatus
from app.ai.orchestrator.state import InvestigationState
from app.ai.tools.registry import ToolRegistry
from app.ai.tools.security_tools import QueryThreatIntelTool
from app.ai.agents.threat_intel.schemas import (
    ThreatIntelligenceFinding,
    ThreatIntelligenceRecommendation,
    IntelligenceGap,
    ThreatCluster,
    AttributionAssessment,
)
from app.ai.agents.threat_intel.ioc_analysis import IOCAnalyzer
from app.ai.agents.threat_intel.enrichment import ThreatEnrichmentConsensusEngine
from app.ai.agents.threat_intel.relationships import IOCRelationshipEngine, ThreatClusterGenerator
from app.ai.agents.threat_intel.attribution import ConservativeAttributionEngine
from app.ai.agents.threat_intel.findings import ThreatIntelFindingGenerator
from app.ai.agents.threat_intel.recommendations import ThreatIntelRecommendationGenerator
from app.ai.memory.short_term import ShortTermMemory
from app.ai.memory.case_memory import CaseMemory


class ThreatIntelligenceAnalystAgent(BaseAgent):
    """Specialized Threat Intelligence AI Agent for AegisAI XDR."""

    def __init__(self, tool_registry: Optional[ToolRegistry] = None):
        self._tool_registry = tool_registry or ToolRegistry()
        if not self._tool_registry.get("query_threat_intel"):
            self._tool_registry.register(QueryThreatIntelTool())

        self._ioc_analyzer = IOCAnalyzer()
        self._consensus_engine = ThreatEnrichmentConsensusEngine()
        self._relationship_engine = IOCRelationshipEngine()
        self._cluster_generator = ThreatClusterGenerator()
        self._attribution_engine = ConservativeAttributionEngine()
        self._finding_generator = ThreatIntelFindingGenerator()
        self._recommendation_generator = ThreatIntelRecommendationGenerator()
        self._short_memory = ShortTermMemory()
        self._case_memory = CaseMemory()

    @property
    def name(self) -> str:
        return "ThreatIntelligenceAnalystAgent"

    @property
    def description(self) -> str:
        return (
            "Specialized Threat Intelligence agent that evaluates indicator reputation, "
            "provider consensus, threat clusters, and conservative attribution."
        )

    @property
    def capabilities(self) -> List[str]:
        return [
            "Threat Intelligence Analysis",
            "IOC Enrichment",
            "Reputation Analysis",
            "IOC Correlation",
            "Threat Relationship Analysis",
            "MITRE Intelligence",
            "Campaign Pattern Analysis",
            "Threat Assessment",
            "Intelligence Reporting",
        ]

    def validate_input(self, state: InvestigationState) -> bool:
        """Validate state contains required investigation identifier."""
        return state is not None and bool(state.investigation_id)

    def health_check(self) -> bool:
        """Verify agent health."""
        return True

    async def execute(self, state: InvestigationState) -> AgentResult:
        """Execute threat intelligence analysis pipeline over InvestigationState."""
        start_time = time.time()

        if not self.validate_input(state):
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.FAILURE,
                metadata={"error": "Invalid input InvestigationState"},
            )

        try:
            # 1. Extract and normalize IOCs from state, Threat Hunter, and DFIR findings
            iocs = self._ioc_analyzer.extract_and_normalize(state)

            # 2. Evaluate provider enrichment and consensus
            consensuses = [self._consensus_engine.evaluate_consensus(ioc) for ioc in iocs]

            # 3. Build relationships and threat clusters
            relationships = self._relationship_engine.build_relationships(iocs, state)
            clusters = self._cluster_generator.generate_clusters(iocs, consensuses, state)

            # 4. Formulate conservative attribution assessment
            attribution = self._attribution_engine.evaluate_attribution(consensuses, clusters, state)

            # 5. Generate Findings and Intelligence Gaps
            findings, gaps = self._finding_generator.generate_findings_and_gaps(
                iocs, consensuses, clusters, attribution, state
            )

            # 6. Generate Human-Governed Recommendations
            recommendations = self._recommendation_generator.generate_recommendations(findings, gaps)

            # 7. Memory Integration
            self._short_memory.store(
                f"threat_intel:{state.investigation_id}:consensus",
                [c.model_dump() for c in consensuses],
            )
            if state.case_id:
                self._case_memory.store_for_case(
                    state.case_id,
                    f"threat_intel:{state.investigation_id}:clusters",
                    [cl.model_dump() for cl in clusters],
                )

            # 8. Update InvestigationState risk and confidence scores
            avg_confidence = (
                sum(c.confidence for c in consensuses) / len(consensuses) if consensuses else 0.5
            )
            max_threat_score = (
                max(c.consolidated_threat_score for c in consensuses) if consensuses else 0.0
            )

            state.confidence_score = round(max(state.confidence_score, avg_confidence), 2)
            state.risk_score = round(max(state.risk_score, max_threat_score), 1)

            for rec in recommendations:
                state.add_recommendation(rec.title)

            # 9. Format AgentResult
            exec_time = round((time.time() - start_time) * 1000, 2)
            result = AgentResult(
                agent_name=self.name,
                status=AgentStatus.SUCCESS,
                confidence_score=avg_confidence,
                findings=[f.model_dump() for f in findings],
                evidence=[{"ioc": c.ioc_value, "threat_score": c.consolidated_threat_score} for c in consensuses],
                recommendations=[r.title for r in recommendations],
                execution_time_ms=exec_time,
                metadata={
                    "iocs_count": len(iocs),
                    "consensuses_count": len(consensuses),
                    "clusters": [cl.model_dump() for cl in clusters],
                    "attribution": attribution.model_dump(),
                    "intelligence_gaps": [g.model_dump() for g in gaps],
                    "detailed_recommendations": [r.model_dump() for r in recommendations],
                },
            )

            return result

        except Exception as e:
            exec_time = round((time.time() - start_time) * 1000, 2)
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.FAILURE,
                execution_time_ms=exec_time,
                metadata={"error": str(e)},
            )
