"""
Threat Hunter Agent Implementation.

Autonomous Threat Hunting AI Agent for AegisAI XDR.
Inherits from BaseAgent. Executes deterministic threat hunting workflows over InvestigationState.

STRICT SECURITY GUARANTEE:
- Read-only queries only.
- No shell execution, arbitrary Python, network modifications, process termination, or un-governed playbooks.
- Human approval explicitly enforced for all response recommendations.
"""

import time
from typing import List, Dict, Any, Optional
from app.ai.agents.base import BaseAgent, AgentResult, AgentStatus
from app.ai.orchestrator.state import InvestigationState
from app.ai.tools.registry import ToolRegistry
from app.ai.tools.security_tools import (
    QuerySIEMTool,
    QueryThreatIntelTool,
    QueryMitreTool,
    QueryEvidenceTool,
)
from app.ai.agents.threat_hunter.schemas import (
    ObservableItem,
    ThreatHypothesis,
    ThreatFinding,
    ThreatRecommendation,
)
from app.ai.agents.threat_hunter.analyzers import ObservableAnalyzer
from app.ai.agents.threat_hunter.hypotheses import HypothesisEngine
from app.ai.agents.threat_hunter.investigation import ThreatInvestigationEngine
from app.ai.agents.threat_hunter.recommendations import ThreatRecommendationGenerator
from app.ai.memory.short_term import ShortTermMemory
from app.ai.memory.case_memory import CaseMemory


class ThreatHunterAgent(BaseAgent):
    """Specialized autonomous Threat Hunting AI Agent for AegisAI XDR."""

    def __init__(self, tool_registry: Optional[ToolRegistry] = None):
        self._tool_registry = tool_registry or ToolRegistry()
        # Register default safe read-only tools if not present
        if not self._tool_registry.get("query_siem_logs"):
            self._tool_registry.register(QuerySIEMTool())
        if not self._tool_registry.get("query_threat_intel"):
            self._tool_registry.register(QueryThreatIntelTool())
        if not self._tool_registry.get("query_mitre_attack"):
            self._tool_registry.register(QueryMitreTool())
        if not self._tool_registry.get("query_evidence_metadata"):
            self._tool_registry.register(QueryEvidenceTool())

        self._analyzer = ObservableAnalyzer()
        self._hypothesis_engine = HypothesisEngine()
        self._investigation_engine = ThreatInvestigationEngine()
        self._recommendation_generator = ThreatRecommendationGenerator()
        self._short_memory = ShortTermMemory()
        self._case_memory = CaseMemory()

    @property
    def name(self) -> str:
        return "ThreatHunterAgent"

    @property
    def description(self) -> str:
        return (
            "Autonomous Threat Hunting agent that analyzes security observables, forms threat hypotheses, "
            "correlates behavioral attack patterns, and produces structured security recommendations."
        )

    @property
    def capabilities(self) -> List[str]:
        return [
            "Threat Hunting",
            "Behavioral Analysis",
            "IOC Analysis",
            "Attack Pattern Detection",
            "MITRE ATT&CK Analysis",
            "Hypothesis Generation",
            "Risk Assessment",
        ]

    def validate_input(self, state: InvestigationState) -> bool:
        """Validate state contains required investigation identifier."""
        return state is not None and bool(state.investigation_id)

    def health_check(self) -> bool:
        """Verify agent health."""
        return True

    async def execute(self, state: InvestigationState) -> AgentResult:
        """Execute Threat Hunting investigation pipeline over InvestigationState."""
        start_time = time.time()

        if not self.validate_input(state):
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.FAILURE,
                metadata={"error": "Invalid input InvestigationState"},
            )

        try:
            # 1. Observable Extraction
            observables = self._analyzer.extract_observables(state)

            # 2. Observable Enrichment via safe read-only tools
            analysis_results = await self._analyzer.analyze_observables(observables, self._tool_registry)

            # 3. Hypothesis Generation
            hypotheses = self._hypothesis_engine.generate_hypotheses(observables, state)

            # 4. Correlation & Telemetry Analysis
            correlation = self._investigation_engine.correlate_telemetry(observables, state, hypotheses)

            # 5. Deterministic Confidence & Risk Scoring
            confidence = self._investigation_engine.calculate_confidence(observables, hypotheses, analysis_results)
            risk_score = self._investigation_engine.calculate_risk_score(confidence, hypotheses, state, analysis_results)

            # 6. Generate Findings & Recommendations
            findings, recommendations = self._recommendation_generator.generate_findings_and_recommendations(
                observables, hypotheses, correlation, confidence, risk_score, state
            )

            # 7. Memory Integration
            self._short_memory.store(f"threat_hunter:{state.investigation_id}:hypotheses", [h.model_dump() for h in hypotheses])
            if state.case_id:
                self._case_memory.store_for_case(
                    state.case_id, f"threat_hunter:{state.investigation_id}:findings", [f.model_dump() for f in findings]
                )

            # 8. State Updates
            state.confidence_score = confidence
            state.risk_score = risk_score
            state.hypotheses.extend([h.model_dump() for h in hypotheses])
            for rec in recommendations:
                state.add_recommendation(rec.title)

            # 9. Format AgentResult
            exec_time = round((time.time() - start_time) * 1000, 2)
            result = AgentResult(
                agent_name=self.name,
                status=AgentStatus.SUCCESS,
                confidence_score=confidence,
                findings=[f.model_dump() for f in findings],
                evidence=[{"observable": o.value, "type": o.type.value} for o in observables],
                recommendations=[r.title for r in recommendations],
                execution_time_ms=exec_time,
                metadata={
                    "observables_count": len(observables),
                    "hypotheses_count": len(hypotheses),
                    "findings_count": len(findings),
                    "recommendations_count": len(recommendations),
                    "detailed_recommendations": [r.model_dump() for r in recommendations],
                    "risk_score": risk_score,
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
