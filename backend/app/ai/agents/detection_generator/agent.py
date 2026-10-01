"""
Detection Rule Generator Agent Implementation.

Specialized Detection Engineering AI Agent for AegisAI XDR.
Inherits from BaseAgent. Executes analysis over InvestigationState.

STRICT SAFETY GUARANTEE:
- Generates candidate rules only.
- Does NOT automatically deploy or activate rules in production SIEM/EDR/IDS.
- Uses dry-run testing only via Sprint 8 Detection Engine.
- Human approval explicitly enforced for all deployment recommendations.
"""

import time
from typing import List, Dict, Any, Optional
from app.ai.agents.base import BaseAgent, AgentResult, AgentStatus
from app.ai.orchestrator.state import InvestigationState
from app.ai.tools.registry import ToolRegistry
from app.ai.tools.security_tools import QuerySIEMTool
from app.ai.agents.detection_generator.schemas import (
    DetectionRuleCandidate,
    RuleGenerationResult,
    DetectionRuleRecommendation,
)
from app.ai.agents.detection_generator.evidence_analyzer import DetectionEvidenceAnalyzer
from app.ai.agents.detection_generator.rule_generator import DetectionRuleGenerationEngine
from app.ai.agents.detection_generator.recommendations import DetectionRuleRecommendationGenerator
from app.ai.memory.short_term import ShortTermMemory
from app.ai.memory.case_memory import CaseMemory


class DetectionRuleGeneratorAgent(BaseAgent):
    """Specialized Detection Engineering AI Agent for AegisAI XDR."""

    def __init__(self, tool_registry: Optional[ToolRegistry] = None):
        self._tool_registry = tool_registry or ToolRegistry()
        if not self._tool_registry.get("query_siem_logs"):
            self._tool_registry.register(QuerySIEMTool())

        self._evidence_analyzer = DetectionEvidenceAnalyzer()
        self._generation_engine = DetectionRuleGenerationEngine()
        self._recommendation_generator = DetectionRuleRecommendationGenerator()
        self._short_memory = ShortTermMemory()
        self._case_memory = CaseMemory()

    @property
    def name(self) -> str:
        return "DetectionRuleGeneratorAgent"

    @property
    def description(self) -> str:
        return (
            "Specialized Detection Rule Generator agent that transforms investigation telemetry into "
            "validated Sigma, YARA, Suricata, and Custom detection rules."
        )

    @property
    def capabilities(self) -> List[str]:
        return [
            "Detection Engineering",
            "Sigma Generation",
            "YARA Generation",
            "Suricata Generation",
            "Behavioral Detection",
            "IOC Detection",
            "MITRE-Based Detection",
            "Detection Quality Analysis",
            "Rule Validation",
            "Rule Recommendation",
        ]

    def validate_input(self, state: InvestigationState) -> bool:
        """Validate state contains required investigation identifier."""
        return state is not None and bool(state.investigation_id)

    def health_check(self) -> bool:
        """Verify agent health."""
        return True

    async def execute(self, state: InvestigationState) -> AgentResult:
        """Execute detection rule generation pipeline over InvestigationState."""
        start_time = time.time()

        if not self.validate_input(state):
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.FAILURE,
                metadata={"error": "Invalid input InvestigationState"},
            )

        try:
            # 1. Extract detection-worthy observables & behaviors
            observables = self._evidence_analyzer.analyze_evidence(state)

            # 2. Generate candidate rules, delegate validation/testing to Sprint 8 Detection Engine
            gen_result = self._generation_engine.generate_candidates(observables)

            # 3. Generate Human-Governed Recommendations
            recommendations = self._recommendation_generator.generate_recommendations(gen_result)

            # 4. Memory Integration
            self._short_memory.store(
                f"detection_gen:{state.investigation_id}:candidates",
                [c.model_dump() for c in gen_result.candidates],
            )
            if state.case_id:
                self._case_memory.store_for_case(
                    state.case_id,
                    f"detection_gen:{state.investigation_id}:recommendations",
                    [r.model_dump() for r in recommendations],
                )

            # 5. Update InvestigationState
            for rec in recommendations:
                state.add_recommendation(rec.title)

            # 6. Format AgentResult
            exec_time = round((time.time() - start_time) * 1000, 2)
            avg_confidence = (
                sum(c.confidence for c in gen_result.candidates) / len(gen_result.candidates)
                if gen_result.candidates
                else 0.80
            )

            result = AgentResult(
                agent_name=self.name,
                status=AgentStatus.SUCCESS,
                confidence_score=round(avg_confidence, 2),
                findings=[
                    {
                        "candidate_id": c.candidate_id,
                        "title": c.title,
                        "rule_type": c.rule_type.value,
                        "severity": c.severity.value,
                        "quality": gen_result.quality_scores.get(c.candidate_id, {}),
                    }
                    for c in gen_result.candidates
                ],
                evidence=[{"candidate_id": c.candidate_id, "logic": c.detection_logic} for c in gen_result.candidates],
                recommendations=[r.title for r in recommendations],
                execution_time_ms=exec_time,
                metadata={
                    "generated_count": gen_result.generated_count,
                    "rejected_count": gen_result.rejected_count,
                    "candidates": [c.model_dump() for c in gen_result.candidates],
                    "validation_results": gen_result.validation_results,
                    "dry_run_results": gen_result.dry_run_results,
                    "quality_scores": gen_result.quality_scores,
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
