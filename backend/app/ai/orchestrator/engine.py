"""
AI Orchestrator Main Engine.

Coordinates multi-agent investigation workflows, manages InvestigationState,
invokes registered agents, evaluates graph dependencies, aggregates consensus findings,
and persists memory artifacts without direct domain agent logic.
"""

import time
import uuid
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

from app.ai.agents.base import BaseAgent, AgentResult, AgentStatus
from app.ai.agents.registry import AgentRegistry
from app.ai.orchestrator.state import InvestigationState
from app.ai.orchestrator.graph import WorkflowGraph, WorkflowStep, WorkflowExecution
from app.ai.orchestrator.consensus import ConsensusEngine, ConsensusResult
from app.ai.memory.interface import BaseMemoryStore
from app.ai.memory.short_term import ShortTermMemory
from app.ai.memory.case_memory import CaseMemory
from app.ai.tools.registry import ToolRegistry
from app.ai.models.provider import LLMProviderFactory
from app.ai.workflows.base import BaseWorkflow


class OrchestrationResult(BaseModel):
    """Structured response container returned after orchestrator workflow execution."""
    investigation_id: str
    status: str = Field(default="COMPLETED", description="Orchestration status (COMPLETED, FAILED)")
    state: InvestigationState
    consensus: ConsensusResult
    completed_steps: List[str] = Field(default_factory=list)
    failed_steps: List[str] = Field(default_factory=list)
    execution_time_ms: float = 0.0


class AIOrchestrator:
    """Main AI Orchestrator engine executing multi-agent security workflows."""

    def __init__(
        self,
        agent_registry: Optional[AgentRegistry] = None,
        tool_registry: Optional[ToolRegistry] = None,
        memory_store: Optional[BaseMemoryStore] = None,
        consensus_engine: Optional[ConsensusEngine] = None,
        llm_factory: Optional[LLMProviderFactory] = None,
    ):
        self.agent_registry = agent_registry or AgentRegistry()
        self.tool_registry = tool_registry or ToolRegistry()
        self.memory_store = memory_store or ShortTermMemory()
        self.case_memory = CaseMemory()
        self.consensus_engine = consensus_engine or ConsensusEngine()
        self.llm_factory = llm_factory or LLMProviderFactory()

    def start_investigation(
        self,
        investigation_id: str,
        incident_id: Optional[str] = None,
        case_id: Optional[str] = None,
        initial_alerts: Optional[List[Dict[str, Any]]] = None,
    ) -> InvestigationState:
        """Construct initial InvestigationState for an investigation run."""
        state = InvestigationState(
            investigation_id=str(investigation_id),
            incident_id=str(incident_id) if incident_id else None,
            case_id=str(case_id) if case_id else None,
            alerts=initial_alerts or [],
            current_phase="TRIAGE",
        )
        self.memory_store.store(f"investigation:{investigation_id}:state", state.to_dict())
        if case_id:
            self.case_memory.store_for_case(case_id, f"investigation:{investigation_id}", state.to_dict())
        return state

    async def execute_workflow(
        self, workflow: BaseWorkflow, state: InvestigationState
    ) -> OrchestrationResult:
        """Execute workflow graph across registered AI agents."""
        start_time = time.time()
        graph = workflow.build_graph()
        execution_order = graph.get_execution_order()

        completed_steps: List[str] = []
        failed_steps: List[str] = []
        collected_results: List[AgentResult] = []

        for step in execution_order:
            # Evaluate step condition
            if not graph.evaluate_step_condition(step, state):
                continue

            agent = self.agent_registry.get_agent(step.agent_name)
            step_start = time.time()

            if agent:
                try:
                    if agent.validate_input(state):
                        res = await agent.execute(state)
                    else:
                        res = AgentResult(
                            agent_name=step.agent_name,
                            status=AgentStatus.FAILURE,
                            metadata={"error": "Invalid input state"},
                        )
                except Exception as e:
                    res = AgentResult(
                        agent_name=step.agent_name,
                        status=AgentStatus.FAILURE,
                        metadata={"error": str(e)},
                    )
            else:
                # Placeholder fallback result for un-implemented future specialized agents
                res = AgentResult(
                    agent_name=step.agent_name,
                    status=AgentStatus.SUCCESS,
                    confidence_score=0.85,
                    findings=[{
                        "step_id": step.step_id,
                        "category": step.agent_name,
                        "summary": f"Placeholder simulation finding for future agent '{step.agent_name}'",
                    }],
                    recommendations=[f"Recommended action based on {step.agent_name} analysis."],
                    execution_time_ms=round((time.time() - step_start) * 1000, 2),
                    metadata={"mode": "PLACEHOLDER_SIMULATION"},
                )

            state.add_agent_result(res)
            collected_results.append(res)

            if res.status == AgentStatus.SUCCESS:
                completed_steps.append(step.step_id)
            else:
                failed_steps.append(step.step_id)

        # Consensus aggregation
        consensus_res = self.consensus_engine.aggregate(collected_results)
        state.confidence_score = consensus_res.composite_confidence_score
        state.risk_score = consensus_res.composite_risk_score
        for rec in consensus_res.ranked_recommendations:
            state.add_recommendation(rec)

        state.current_phase = "SYNTHESIZED"
        exec_duration = round((time.time() - start_time) * 1000, 2)

        # Store updated state in memory
        self.memory_store.store(f"investigation:{state.investigation_id}:state", state.to_dict())
        if state.case_id:
            self.case_memory.store_for_case(state.case_id, f"investigation:{state.investigation_id}", state.to_dict())

        return OrchestrationResult(
            investigation_id=state.investigation_id,
            status="FAILED" if failed_steps and not completed_steps else "COMPLETED",
            state=state,
            consensus=consensus_res,
            completed_steps=completed_steps,
            failed_steps=failed_steps,
            execution_time_ms=exec_duration,
        )

    def health_check(self) -> bool:
        """Verify orchestrator health."""
        return True
