"""
Incident Commander Agent Implementation.

Master coordination and synthesis AI Security Agent for AegisAI XDR.
Inherits from BaseAgent. Executes multi-agent synthesis over InvestigationState.

STRICT SAFETY GUARANTEE:
- Performs analysis, synthesis, scoring, attack chain reconstruction, and response planning ONLY.
- Does NOT execute destructive security actions or live SOAR operations directly.
- Human approval explicitly enforced for all response recommendations.
"""

import time
from typing import List, Dict, Any, Optional
from app.ai.agents.base import BaseAgent, AgentResult, AgentStatus
from app.ai.orchestrator.state import InvestigationState
from app.ai.tools.registry import ToolRegistry
from app.ai.agents.incident_commander.schemas import (
    IncidentAssessment,
    AttackChainStage,
    CommanderFinding,
    CommanderRecommendation,
    ResponsePlan,
    ExecutiveIncidentSummary,
)
from app.ai.agents.incident_commander.synthesis import IncidentSynthesisEngine
from app.ai.agents.incident_commander.attack_chain import AttackChainAnalyzer
from app.ai.agents.incident_commander.severity import SeverityPriorityEngine
from app.ai.agents.incident_commander.consensus import IncidentConsensusEngine
from app.ai.agents.incident_commander.response_plan import ResponsePlanEngine
from app.ai.agents.incident_commander.executive_summary import ExecutiveSummaryGenerator
from app.ai.memory.short_term import ShortTermMemory
from app.ai.memory.case_memory import CaseMemory


class IncidentCommanderAgent(BaseAgent):
    """Master coordination and synthesis AI Security Agent for AegisAI XDR."""

    def __init__(self, tool_registry: Optional[ToolRegistry] = None):
        self._tool_registry = tool_registry or ToolRegistry()
        self._synthesis_engine = IncidentSynthesisEngine()
        self._attack_chain_analyzer = AttackChainAnalyzer()
        self._severity_engine = SeverityPriorityEngine()
        self._consensus_engine = IncidentConsensusEngine()
        self._response_plan_engine = ResponsePlanEngine()
        self._executive_summary_generator = ExecutiveSummaryGenerator()
        self._short_memory = ShortTermMemory()
        self._case_memory = CaseMemory()

    @property
    def name(self) -> str:
        return "IncidentCommanderAgent"

    @property
    def description(self) -> str:
        return (
            "Master Incident Commander agent providing multi-agent synthesis, attack chain reconstruction, "
            "consensus conflict evaluation, severity scoring, and human-governed response planning."
        )

    @property
    def capabilities(self) -> List[str]:
        return [
            "incident_synthesis",
            "attack_chain_analysis",
            "root_cause_assessment",
            "severity_assessment",
            "consensus_analysis",
            "response_planning",
            "executive_reporting",
            "incident_coordination",
        ]

    def validate_input(self, state: InvestigationState) -> bool:
        """Validate state contains required investigation identifier."""
        return state is not None and bool(state.investigation_id)

    def health_check(self) -> bool:
        """Verify agent health."""
        return True

    async def execute(self, state: InvestigationState) -> AgentResult:
        """Execute Incident Commander synthesis pipeline over InvestigationState."""
        start_time = time.time()

        if not self.validate_input(state):
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.FAILURE,
                metadata={"error": "Invalid input InvestigationState"},
            )

        try:
            # 1. Multi-Agent Synthesis
            confirmed, suspected, gaps, root_cause = self._synthesis_engine.synthesize(state)

            # 2. Attack Chain Reconstruction
            attack_stages = self._attack_chain_analyzer.reconstruct_attack_chain(state)
            current_stage = (
                [s.stage for s in attack_stages if s.status.value == "OBSERVED"][-1]
                if any(s.status.value == "OBSERVED" for s in attack_stages)
                else "INITIAL_ACCESS"
            )

            # 3. Severity & Priority Scoring
            risk_score, confidence_score, severity, priority = self._severity_engine.calculate_scores(state)

            # 4. Consensus & Conflict Evaluation
            agreed_score, conflict_count, ev_support_score, consensus_status, conflicts = (
                self._consensus_engine.evaluate_consensus(state)
            )

            # 5. Response Plan Construction
            response_plan = self._response_plan_engine.build_response_plan(state, severity)

            # 6. Executive Summary Generation
            title = f"Synthesized Incident Assessment ({state.investigation_id})"
            exec_summary = self._executive_summary_generator.generate_summary(
                state=state,
                title=title,
                severity=severity,
                confidence=confidence_score,
                findings=confirmed + suspected,
                likely_root_cause=root_cause,
            )

            # 7. Assemble Master Incident Assessment
            all_recs = (
                response_plan.immediate_actions
                + response_plan.containment_actions
                + response_plan.investigation_actions
            )

            assessment = IncidentAssessment(
                incident_id=state.incident_id,
                investigation_id=state.investigation_id,
                case_id=state.case_id,
                title=title,
                summary=exec_summary.executive_summary,
                severity=severity,
                priority=priority,
                risk_score=risk_score,
                confidence_score=confidence_score,
                attack_stage=current_stage,
                root_cause=root_cause,
                confirmed_findings=confirmed,
                suspected_findings=suspected,
                evidence_gaps=gaps,
                contributing_agents=list(state.agent_results.keys()),
                conflicting_findings=conflicts,
                recommendations=all_recs,
                response_plan=response_plan,
                executive_summary=exec_summary,
                requires_human_review=True,
            )

            # 8. Memory Store Integration
            self._short_memory.store(
                f"incident_cmd:{state.investigation_id}:assessment",
                assessment.model_dump(),
            )
            if state.case_id:
                self._case_memory.store_for_case(
                    state.case_id,
                    f"incident_cmd:{state.investigation_id}:response_plan",
                    response_plan.model_dump(),
                )

            # 9. Update InvestigationState (Preserving existing state & agent_results)
            state.risk_score = risk_score
            state.confidence_score = confidence_score
            state.current_phase = "SYNTHESIS_COMPLETE"

            for rec in all_recs:
                state.add_recommendation(f"{rec.action}: {rec.rationale}")

            # 10. Return AgentResult
            exec_time = round((time.time() - start_time) * 1000, 2)
            result = AgentResult(
                agent_name=self.name,
                status=AgentStatus.SUCCESS,
                confidence_score=confidence_score,
                findings=[
                    {
                        "category": "IncidentCommanderAssessment",
                        "title": assessment.title,
                        "severity": severity,
                        "priority": priority,
                        "risk_score": risk_score,
                        "root_cause": root_cause,
                        "attack_stage": current_stage,
                        "consensus_status": consensus_status,
                    }
                ],
                evidence=[{"assessment_id": assessment.assessment_id, "evidence_gaps": gaps}],
                recommendations=[rec.action for rec in all_recs],
                execution_time_ms=exec_time,
                metadata={
                    "assessment": assessment.model_dump(),
                    "attack_chain": [s.model_dump() for s in attack_stages],
                    "consensus": {
                        "agreement_score": agreed_score,
                        "conflict_count": conflict_count,
                        "evidence_support_score": ev_support_score,
                        "status": consensus_status,
                        "conflicts": conflicts,
                    },
                    "response_plan": response_plan.model_dump(),
                    "executive_summary": exec_summary.model_dump(),
                },
            )

            state.add_agent_result(result)
            return result


        except Exception as e:
            exec_time = round((time.time() - start_time) * 1000, 2)
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.FAILURE,
                execution_time_ms=exec_time,
                metadata={"error": str(e)},
            )
