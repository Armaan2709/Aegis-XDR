"""
Unit Tests for Incident Commander Agent (Sprint 16).

Verifies IncidentCommanderAgent initialization, registration, state validation, empty/missing agent handling,
multi-agent synthesis, consensus & conflict detection, 12-tactic attack chain reconstruction,
root cause assessment, severity/priority calculation, response planning, human approval enforcement,
executive summary generation, state preservation, deterministic execution, and full multi-agent workflow DAG integration.
"""

import uuid
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.models.base import Base
from app.models.investigation import Investigation, InvestigationStatus
from app.domains.investigations.schemas import InvestigationCreate
from app.domains.investigations.repositories import InvestigationRepository
from app.ai.agents.base import AgentStatus, AgentResult
from app.ai.agents.registry import AgentRegistry
from app.ai.agents.threat_hunter import ThreatHunterAgent
from app.ai.agents.dfir import DFIRInvestigatorAgent
from app.ai.agents.threat_intel import ThreatIntelligenceAnalystAgent
from app.ai.agents.detection_generator import DetectionRuleGeneratorAgent
from app.ai.agents.incident_commander import (
    IncidentCommanderAgent,
    IncidentSynthesisEngine,
    AttackChainAnalyzer,
    SeverityPriorityEngine,
    IncidentConsensusEngine,
    ResponsePlanEngine,
    ExecutiveSummaryGenerator,
)
from app.ai.orchestrator.state import InvestigationState
from app.ai.orchestrator.engine import AIOrchestrator
from app.ai.workflows.investigation import InvestigationWorkflow


# ==========================================
# 1. Agent Initialization & Registration Tests
# ==========================================

def test_incident_commander_initialization():
    """Verify IncidentCommanderAgent capabilities, name, and health check."""
    agent = IncidentCommanderAgent()
    assert agent.name == "IncidentCommanderAgent"
    assert "incident_synthesis" in agent.capabilities
    assert "attack_chain_analysis" in agent.capabilities
    assert "response_planning" in agent.capabilities
    assert agent.health_check() is True

    registry = AgentRegistry()
    registry.register_agent(agent)
    assert registry.get_agent("IncidentCommanderAgent") == agent


def test_incident_commander_input_validation():
    """Verify state validation logic."""
    agent = IncidentCommanderAgent()
    invalid_state = InvestigationState(investigation_id="")
    assert agent.validate_input(invalid_state) is False

    valid_state = InvestigationState(investigation_id=str(uuid.uuid4()))
    assert agent.validate_input(valid_state) is True


# ==========================================
# 2. Synthesis, Evidence Gap, & Root Cause Tests
# ==========================================

def test_incident_synthesis_and_root_cause():
    """Verify multi-agent synthesis, evidence gap detection, and root cause assessment."""
    synthesis = IncidentSynthesisEngine()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        evidence=[{
            "evidence_id": "EV-001",
            "sha256": "a" * 64,
            "file_path": "/tmp/malware.bin",
        }],
        alerts=[{
            "alert_id": "ALT-1",
            "ip": "198.51.100.22",
            "command_line": "powershell.exe -enc DDD==",
        }],
    )

    confirmed, suspected, gaps, root_cause = synthesis.synthesize(state)
    assert len(confirmed) >= 1
    assert any("Missing host memory" in g or "Missing centralized" in g for g in gaps)
    assert "script interpreter abuse" in root_cause or "payload delivery" in root_cause


# ==========================================
# 3. Attack Chain Reconstruction Tests
# ==========================================

def test_attack_chain_reconstruction():
    """Verify 12-tactic attack chain reconstruction across observed and inferred stages."""
    analyzer = AttackChainAnalyzer()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        alerts=[{
            "alert_id": "ALT-10",
            "ip": "203.0.113.5",
            "command_line": "powershell.exe -nop -enc AAA=",
        }],
        mitre_mappings=[{"technique_id": "T1059.001"}, {"technique_id": "T1071.001"}],
    )

    stages = analyzer.reconstruct_attack_chain(state)
    assert len(stages) == 12

    exec_stage = next(s for s in stages if s.stage == "EXECUTION")
    c2_stage = next(s for s in stages if s.stage == "COMMAND_AND_CONTROL")

    assert exec_stage.status.value == "OBSERVED"
    assert c2_stage.status.value == "OBSERVED"


# ==========================================
# 4. Severity, Priority, & Consensus Tests
# ==========================================

def test_severity_priority_and_consensus():
    """Verify deterministic severity/priority scoring and conflict detection."""
    sev_engine = SeverityPriorityEngine()
    consensus_engine = IncidentConsensusEngine()

    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        alerts=[{"severity": "CRITICAL"}, {"severity": "HIGH"}],
        evidence=[{"id": "EV-1"}, {"id": "EV-2"}],
    )

    # Mock agent results with conflicting verdicts
    res1 = AgentResult(agent_name="ThreatHunterAgent", status=AgentStatus.SUCCESS, confidence_score=0.9, findings=[{"category": "Malware", "verdict": "MALICIOUS"}])
    res2 = AgentResult(agent_name="ThreatIntelAgent", status=AgentStatus.SUCCESS, confidence_score=0.8, findings=[{"category": "Malware", "verdict": "BENIGN"}])
    state.add_agent_result(res1)
    state.add_agent_result(res2)

    risk, conf, severity, priority = sev_engine.calculate_scores(state)
    assert risk >= 60.0
    assert severity in ("HIGH", "CRITICAL")

    agreed_score, conflict_count, ev_score, status, conflicts = consensus_engine.evaluate_consensus(state)
    assert conflict_count == 1
    assert status == "PARTIAL_AGREEMENT"


# ==========================================
# 5. Human Approval Enforcement Tests
# ==========================================

@pytest.mark.anyio
async def test_response_plan_human_approval_enforcement():
    """Verify response plan generation enforces requires_human_approval = True for SOAR actions."""
    plan_engine = ResponsePlanEngine()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        case_id="CASE-999",
        alerts=[{"hostname": "WKSTN-01", "ip": "10.0.0.99"}],
    )

    plan = plan_engine.build_response_plan(state, severity="HIGH")
    assert plan.approval_required is True

    for rec in plan.immediate_actions + plan.containment_actions:
        if rec.action in ("ISOLATE_HOST", "BLOCK_IP", "DISABLE_ACCOUNT", "DEPLOY_RULE", "EXECUTE_PLAYBOOK"):
            assert rec.requires_human_approval is True


# ==========================================
# 6. Executive Summary & Determinism Tests
# ==========================================

def test_executive_summary_and_determinism():
    """Verify executive summary generation and deterministic output reproducibility."""
    gen = ExecutiveSummaryGenerator()
    state = InvestigationState(investigation_id="INV-12345", alerts=[{"id": "ALT-1"}])

    summary1 = gen.generate_summary(
        state=state,
        title="Test Summary",
        severity="HIGH",
        confidence=0.90,
        findings=[],
        likely_root_cause="Script execution",
    )
    summary2 = gen.generate_summary(
        state=state,
        title="Test Summary",
        severity="HIGH",
        confidence=0.90,
        findings=[],
        likely_root_cause="Script execution",
    )

    assert summary1.executive_summary == summary2.executive_summary
    assert summary1.business_impact == "Business impact not determined."


# ==========================================
# 7. Full Execution Run & Orchestrator Workflow
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
async def test_incident_commander_agent_execution_run(async_session: AsyncSession):
    """Verify IncidentCommanderAgent execution updates InvestigationState without destroying prior results."""
    agent = IncidentCommanderAgent()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        case_id="CASE-555",
        alerts=[{"alert_id": "ALT-001", "ip": "10.0.0.50", "command_line": "powershell.exe -enc"}],
    )

    # Add prior agent results
    prior_res = AgentResult(agent_name="ThreatHunterAgent", status=AgentStatus.SUCCESS, confidence_score=0.88)
    state.add_agent_result(prior_res)

    result = await agent.execute(state)
    assert result.status == AgentStatus.SUCCESS
    assert result.agent_name == "IncidentCommanderAgent"

    # Verify prior state preserved
    assert "ThreatHunterAgent" in state.agent_results
    assert "IncidentCommanderAgent" in state.agent_results
    assert len(state.recommendations) >= 1


@pytest.mark.anyio
async def test_orchestrator_full_five_agent_workflow(async_session: AsyncSession):
    """Verify AIOrchestrator executes full multi-agent investigation workflow culminating in Incident Commander."""
    repo = InvestigationRepository(async_session)
    inv = await repo.create(
        InvestigationCreate(incident_id=uuid.uuid4(), name="Full Autonomous SOC Investigation", status=InvestigationStatus.INITIATED)
    )

    agent_reg = AgentRegistry()
    hunter_agent = ThreatHunterAgent()
    dfir_agent = DFIRInvestigatorAgent()
    intel_agent = ThreatIntelligenceAnalystAgent()
    detection_agent = DetectionRuleGeneratorAgent()
    commander_agent = IncidentCommanderAgent()

    agent_reg.register_agent(hunter_agent)
    agent_reg.register_agent(dfir_agent)
    agent_reg.register_agent(intel_agent, alias="ThreatIntelAgent")
    agent_reg.register_agent(detection_agent, alias="DetectionAgent")
    agent_reg.register_agent(commander_agent)

    orchestrator = AIOrchestrator(agent_registry=agent_reg)

    state = orchestrator.start_investigation(
        investigation_id=str(inv.id),
        initial_alerts=[{"alert_id": "ALT-9000", "ip": "198.51.100.50", "command_line": "powershell.exe -enc EEEE"}],
    )

    workflow = InvestigationWorkflow()
    orch_result = await orchestrator.execute_workflow(workflow, state)

    assert orch_result.status == "COMPLETED"
    assert "step_threat_hunter" in orch_result.completed_steps
    assert "step_dfir" in orch_result.completed_steps
    assert "step_threat_intel" in orch_result.completed_steps
    assert "step_detection" in orch_result.completed_steps
    assert "step_commander" in orch_result.completed_steps
    assert "IncidentCommanderAgent" in orch_result.state.agent_results
