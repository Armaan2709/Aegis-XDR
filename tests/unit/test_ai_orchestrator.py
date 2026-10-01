"""
Comprehensive Unit Tests for AI Orchestrator Foundation (Sprint 11).

Verifies Agent Abstractions, AgentRegistry, InvestigationState serialization, LLM Provider Abstractions,
ShortTerm/CaseMemory, Security Tool Abstraction & ToolRegistry, Playbook Safety Boundary,
PromptRegistry, WorkflowGraph DAG validation/cycle detection, ConsensusEngine, AIOrchestrator execution, and API schemas.
"""

import uuid
import pytest
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.models.base import Base
from app.models.investigation import Investigation, InvestigationStatus, InvestigationPriority, InvestigationPhase
from app.domains.investigations.schemas import InvestigationCreate
from app.domains.investigations.repositories import InvestigationRepository

from app.ai.agents.base import BaseAgent, AgentStatus, AgentResult
from app.ai.agents.registry import AgentRegistry
from app.ai.orchestrator.state import InvestigationState
from app.ai.models.base import BaseLLMProvider
from app.ai.models.mock import MockLLMProvider
from app.ai.models.provider import LLMProviderFactory
from app.ai.memory.short_term import ShortTermMemory
from app.ai.memory.case_memory import CaseMemory
from app.ai.tools.base import BaseSecurityTool
from app.ai.tools.security_tools import (
    QuerySIEMTool,
    QueryThreatIntelTool,
    QueryMitreTool,
    QueryEvidenceTool,
    ExecutePlaybookTool,
)
from app.ai.tools.registry import ToolRegistry
from app.ai.prompts.registry import PromptTemplate, PromptRegistry
from app.ai.orchestrator.graph import WorkflowGraph, WorkflowStep, AgentNode
from app.ai.orchestrator.consensus import ConsensusEngine
from app.ai.workflows.investigation import InvestigationWorkflow
from app.ai.orchestrator.engine import AIOrchestrator
from app.core.exceptions import ValidationError as DomainValidationError, NotFoundError, ConflictError


# ==========================================
# Mock Test Agent Implementation
# ==========================================

class SampleTestAgent(BaseAgent):
    """Concrete mock agent for unit testing."""

    def __init__(self, name: str = "TestAgent", confidence: float = 0.9):
        self._name = name
        self._confidence = confidence

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return "Sample agent for testing."

    @property
    def capabilities(self) -> list[str]:
        return ["threat_hunting", "triage"]

    async def execute(self, state: InvestigationState) -> AgentResult:
        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.SUCCESS,
            confidence_score=self._confidence,
            findings=[{"category": "Triage", "verdict": "MALICIOUS", "risk_score": 85.0}],
            recommendations=[f"Isolate compromised host identified by {self.name}"],
        )


# ==========================================
# 1. Agent & Registry Unit Tests
# ==========================================

def test_agent_registry_operations():
    """Verify agent registration, lookup, duplicate rejection, and capability search."""
    registry = AgentRegistry()
    agent = SampleTestAgent(name="TriageAgent")

    registry.register_agent(agent)
    assert registry.get_agent("TriageAgent") == agent
    assert len(registry.list_agents()) == 1
    assert len(registry.find_by_capability("threat_hunting")) == 1

    # Duplicate registration rejection
    with pytest.raises(ConflictError):
        registry.register_agent(agent)

    # Health check
    health = registry.health_check_all()
    assert health["TriageAgent"] is True

    # Unregister
    registry.unregister_agent("TriageAgent")
    assert registry.get_agent("TriageAgent") is None


def test_agent_result_schema_validation():
    """Verify AgentResult schema bounds and defaults."""
    res = AgentResult(
        agent_name="DFIRAgent",
        status=AgentStatus.SUCCESS,
        confidence_score=0.95,
        findings=[{"evidence_id": "EV-001"}],
    )
    assert res.agent_name == "DFIRAgent"
    assert res.confidence_score == 0.95

    with pytest.raises(PydanticValidationError):
        AgentResult(agent_name="BadAgent", confidence_score=1.5)


# ==========================================
# 2. Investigation State Serialization Tests
# ==========================================

def test_investigation_state_serialization():
    """Verify InvestigationState model creation, update, and dictionary round-trip."""
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        incident_id=str(uuid.uuid4()),
        case_id="CASE-2026-0001",
        current_phase="TRIAGE",
    )
    state.add_recommendation("Isolate host WKSTN-01")
    state.add_agent_result(AgentResult(agent_name="MockAgent", confidence_score=0.88))

    dict_repr = state.to_dict()
    assert dict_repr["investigation_id"] == state.investigation_id
    assert "Isolate host WKSTN-01" in dict_repr["recommendations"]

    reconstructed = InvestigationState.from_dict(dict_repr)
    assert reconstructed.investigation_id == state.investigation_id
    assert "MockAgent" in reconstructed.agent_results


# ==========================================
# 3. LLM Provider Tests
# ==========================================

@pytest.mark.anyio
async def test_mock_llm_provider_and_factory():
    """Verify MockLLMProvider response generation and provider factory resolution."""
    factory = LLMProviderFactory()
    provider = factory.get_provider()

    assert provider.health_check() is True
    res = await provider.generate("Perform alert triage on workstation")
    assert "triage completed" in res.lower()

    # Factory duplicate registration check
    mock2 = MockLLMProvider("mock-aegis-llm-v1")
    with pytest.raises(ConflictError):
        factory.register_provider(mock2)


# ==========================================
# 4. Memory Store Unit Tests
# ==========================================

def test_short_term_and_case_memory():
    """Verify ShortTermMemory and CaseMemory operations."""
    st_memory = ShortTermMemory()
    st_memory.store("key1", "value1")
    assert st_memory.retrieve("key1") == "value1"
    assert len(st_memory.search("value")) == 1

    case_mem = CaseMemory()
    case_mem.store_for_case("CASE-100", "findings", {"risk": "HIGH"})
    assert case_mem.retrieve_for_case("CASE-100", "findings") == {"risk": "HIGH"}


# ==========================================
# 5. Security Tools & Tool Registry Tests
# ==========================================

@pytest.mark.anyio
async def test_security_tools_and_tool_registry():
    """Verify tool registration, safe read-only tool execution, and playbook tool safety boundary."""
    registry = ToolRegistry()
    siem_tool = QuerySIEMTool()
    pb_tool = ExecutePlaybookTool()

    registry.register(siem_tool)
    registry.register(pb_tool)

    assert registry.get("query_siem_logs") == siem_tool
    assert len(registry.list()) == 2

    # Safe read-only SIEM tool execution
    siem_res = await siem_tool.execute({"query": "EventID:4624"})
    assert siem_res["status"] == "success"
    assert siem_res["mode"] == "READ_ONLY_SIMULATED"

    # Playbook safety boundary test (Must NOT execute directly or bypass approvals)
    pb_res = await pb_tool.execute({"playbook_id": "PB-001", "case_id": "CASE-100"})
    assert pb_res["status"] == "simulated_request_submitted"
    assert pb_res["approval_required"] is True
    assert pb_res["mode"] == "GOVERNED_SIMULATION"


# ==========================================
# 6. Prompt Registry Unit Tests
# ==========================================

def test_prompt_registry_formatting_and_versioning():
    """Verify PromptTemplate formatting, variable checks, and PromptRegistry versioning."""
    registry = PromptRegistry()
    tpl = PromptTemplate(
        name="TriagePrompt",
        version="1.0.0",
        description="Triage analysis prompt",
        template="Analyze alert {alert_id} on host {hostname}",
        variables=["alert_id", "hostname"],
        is_active=True,
    )
    registry.register(tpl)

    active = registry.get_active_version("TriagePrompt")
    assert active.version == "1.0.0"

    formatted = active.format(alert_id="ALT-99", hostname="WKSTN-01")
    assert formatted == "Analyze alert ALT-99 on host WKSTN-01"

    # Missing variable error
    with pytest.raises(DomainValidationError):
        active.format(alert_id="ALT-99")


# ==========================================
# 7. Workflow Graph & DAG Validation Tests
# ==========================================

def test_workflow_graph_topological_sort_and_cycle_detection():
    """Verify DAG topological sorting and cycle detection in WorkflowGraph."""
    graph = WorkflowGraph(name="test_dag")

    graph.add_step(WorkflowStep(step_id="step1", agent_name="Agent1", dependencies=[]))
    graph.add_step(WorkflowStep(step_id="step2", agent_name="Agent2", dependencies=["step1"]))
    graph.add_step(WorkflowStep(step_id="step3", agent_name="Agent3", dependencies=["step2"]))

    order = graph.get_execution_order()
    assert [s.step_id for s in order] == ["step1", "step2", "step3"]

    # Introduce Cycle
    cycle_graph = WorkflowGraph(name="cycle_dag")
    cycle_graph.add_step(WorkflowStep(step_id="stepA", agent_name="AgentA", dependencies=["stepB"]))
    cycle_graph.add_step(WorkflowStep(step_id="stepB", agent_name="AgentB", dependencies=["stepA"]))

    with pytest.raises(DomainValidationError):
        cycle_graph.get_execution_order()


# ==========================================
# 8. Consensus Engine Unit Tests
# ==========================================

def test_consensus_engine_aggregation():
    """Verify ConsensusEngine aggregation, confidence calculation, and recommendation ranking."""
    engine = ConsensusEngine()

    res1 = AgentResult(
        agent_name="Agent1",
        status=AgentStatus.SUCCESS,
        confidence_score=0.9,
        findings=[{"category": "ThreatIntel", "verdict": "MALICIOUS", "risk_score": 90.0}],
        recommendations=["Isolate IP 198.51.100.50"],
    )
    res2 = AgentResult(
        agent_name="Agent2",
        status=AgentStatus.SUCCESS,
        confidence_score=0.8,
        findings=[{"category": "DFIR", "verdict": "MALICIOUS", "risk_score": 80.0}],
        recommendations=["Isolate IP 198.51.100.50", "Dump memory on host WKSTN-01"],
    )

    consensus = engine.aggregate([res1, res2])
    assert consensus.composite_confidence_score == 0.85
    assert consensus.composite_risk_score == 85.3
    assert len(consensus.ranked_recommendations) == 2
    assert consensus.ranked_recommendations[0] == "Isolate IP 198.51.100.50"


# ==========================================
# 9. AI Orchestrator Execution Integration Tests
# ==========================================

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def async_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.mark.anyio
async def test_ai_orchestrator_full_workflow_run(async_session: AsyncSession):
    """Test full AIOrchestrator execution run with registered agents and InvestigationWorkflow."""
    # 1. Create Investigation database entity
    repo = InvestigationRepository(async_session)
    inv = await repo.create(
        InvestigationCreate(incident_id=uuid.uuid4(), name="APT29 Breach Investigation", status=InvestigationStatus.INITIATED)
    )


    # 2. Setup Orchestrator and register test agent
    agent_reg = AgentRegistry()
    triage_agent = SampleTestAgent(name="TriageAgent")
    agent_reg.register_agent(triage_agent)

    orchestrator = AIOrchestrator(agent_registry=agent_reg)

    # 3. Start investigation state
    state = orchestrator.start_investigation(
        investigation_id=str(inv.id),
        initial_alerts=[{"alert_id": "ALT-001", "severity": "HIGH"}],
    )
    assert state.investigation_id == str(inv.id)

    # 4. Execute standard workflow
    workflow = InvestigationWorkflow()
    result = await orchestrator.execute_workflow(workflow, state)

    assert result.status == "COMPLETED"
    assert len(result.completed_steps) == 6
    assert result.consensus.composite_confidence_score > 0.0
    assert len(result.state.recommendations) >= 1
