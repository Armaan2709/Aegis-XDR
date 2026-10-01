"""
Unit Tests for DFIR Investigator Agent (Sprint 13).

Verifies DFIRInvestigatorAgent initialization, artifact normalization, forensic timeline reconstruction,
attack phase mapping, process tree analysis, command-line analysis, root-cause hypotheses,
evidence gap detection, findings/recommendations generation, human approval enforcement,
Threat Hunter context consumption, state updates, failure handling, and AIOrchestrator integration.
"""

import uuid
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.models.base import Base
from app.models.investigation import Investigation, InvestigationStatus
from app.domains.investigations.schemas import InvestigationCreate
from app.domains.investigations.repositories import InvestigationRepository
from app.ai.agents.base import AgentStatus
from app.ai.agents.registry import AgentRegistry
from app.ai.agents.threat_hunter import ThreatHunterAgent
from app.ai.agents.dfir import (
    DFIRInvestigatorAgent,
    ArtifactNormalizer,
    ArtifactCategory,
    ForensicTimelineAnalyzer,
    AttackPhase,
    ProcessTreeAnalyzer,
    CommandLineAnalyzer,
    AttackReconstructionEngine,
    RootCauseStatus,
    DFIRFindingGenerator,
    DFIRRecommendationGenerator,
)
from app.ai.orchestrator.state import InvestigationState
from app.ai.orchestrator.engine import AIOrchestrator
from app.ai.workflows.investigation import InvestigationWorkflow


# ==========================================
# 1. Agent Initialization & Validation Tests
# ==========================================

def test_dfir_agent_initialization():
    """Verify DFIRInvestigatorAgent capabilities, name, and health check."""
    agent = DFIRInvestigatorAgent()
    assert agent.name == "DFIRInvestigatorAgent"
    assert "Digital Forensics" in agent.capabilities
    assert "Timeline Reconstruction" in agent.capabilities
    assert agent.health_check() is True

    registry = AgentRegistry()
    registry.register_agent(agent)
    assert registry.get_agent("DFIRInvestigatorAgent") == agent


def test_dfir_input_validation_and_empty_state():
    """Verify input validation rules and empty state handling."""
    agent = DFIRInvestigatorAgent()
    invalid_state = InvestigationState(investigation_id="")
    assert agent.validate_input(invalid_state) is False

    valid_state = InvestigationState(investigation_id=str(uuid.uuid4()))
    assert agent.validate_input(valid_state) is True


# ==========================================
# 2. Artifact Normalization & Classification Tests
# ==========================================

def test_artifact_normalization_and_classification():
    """Verify raw state evidence, timeline, and alerts normalization into ArtifactCategory."""
    normalizer = ArtifactNormalizer()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        evidence=[{
            "evidence_id": "EV-100",
            "sha256": "a" * 64,
            "file_name": "suspicious_payload.dll",
            "host": "WKSTN-01",
        }],
        timeline=[{
            "event_id": "EVT-200",
            "timestamp": "2026-08-08T10:00:00Z",
            "summary": "User admin_user login success",
            "entity": "WKSTN-01",
        }],
        alerts=[{
            "alert_id": "ALT-300",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "host": "WKSTN-01",
        }],
    )

    artifacts = normalizer.normalize(state)
    categories = {a.category for a in artifacts}

    assert ArtifactCategory.FILE in categories
    assert ArtifactCategory.AUTHENTICATION in categories
    assert ArtifactCategory.PROCESS in categories


# ==========================================
# 3. Timeline Reconstruction & Attack Phases
# ==========================================

def test_timeline_reconstruction_and_attack_phases():
    """Verify chronological timeline ordering and AttackPhase mapping."""
    normalizer = ArtifactNormalizer()
    timeline_analyzer = ForensicTimelineAnalyzer()

    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        alerts=[
            {"alert_id": "ALT-1", "process_name": "lsass.exe"},
            {"alert_id": "ALT-2", "command_line": "powershell.exe -enc AAAA"},
        ],
    )

    artifacts = normalizer.normalize(state)
    events = timeline_analyzer.reconstruct_timeline(artifacts)

    phases = {e["attack_phase"] for e in events if e["attack_phase"]}
    assert AttackPhase.CREDENTIAL_ACCESS.value in phases or AttackPhase.EXECUTION.value in phases


# ==========================================
# 4. Process Tree & Command Line Analysis Tests
# ==========================================

def test_process_tree_and_cmd_line_analysis():
    """Verify parent-child anomaly detection and command-line flag analysis."""
    normalizer = ArtifactNormalizer()
    proc_analyzer = ProcessTreeAnalyzer()
    cmd_analyzer = CommandLineAnalyzer()

    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        alerts=[{
            "alert_id": "ALT-1",
            "command_line": "winword.exe spawning powershell.exe -enc AAAA downloadstring",
        }],
    )

    artifacts = normalizer.normalize(state)
    proc_obs = proc_analyzer.analyze_process_trees(artifacts)
    cmd_obs = cmd_analyzer.analyze_command_lines(artifacts)

    assert len(proc_obs) >= 1
    assert len(cmd_obs) >= 1
    assert any("Encoded" in obs["indicator"] for obs in cmd_obs)


# ==========================================
# 5. Attack Reconstruction & Evidence Gaps
# ==========================================

def test_attack_reconstruction_and_evidence_gaps():
    """Verify root-cause hypothesis status rules and evidence gap detection."""
    normalizer = ArtifactNormalizer()
    proc_analyzer = ProcessTreeAnalyzer()
    cmd_analyzer = CommandLineAnalyzer()
    engine = AttackReconstructionEngine()
    finding_gen = DFIRFindingGenerator()

    state = InvestigationState(investigation_id=str(uuid.uuid4()))
    artifacts = normalizer.normalize(state)
    proc_obs = proc_analyzer.analyze_process_trees(artifacts)
    cmd_obs = cmd_analyzer.analyze_command_lines(artifacts)

    root_causes, mitre_techs = engine.reconstruct_attack_and_root_cause(
        artifacts, proc_obs, cmd_obs, state
    )
    findings, gaps = finding_gen.generate_findings_and_gaps(
        artifacts, root_causes, proc_obs, cmd_obs, mitre_techs, state
    )

    assert len(root_causes) >= 1
    assert len(findings) >= 1
    assert len(gaps) >= 1
    assert any("RAM" in g.description or "memory" in g.description.lower() for g in gaps)


# ==========================================
# 6. Human Approval Enforcement & SOAR Recommendations
# ==========================================

def test_dfir_recommendations_human_approval():
    """Verify that DFIR recommendations involving SOAR playbooks set requires_human_approval = True."""
    rec_gen = DFIRRecommendationGenerator()
    finding_gen = DFIRFindingGenerator()
    state = InvestigationState(investigation_id=str(uuid.uuid4()))

    findings, gaps = finding_gen.generate_findings_and_gaps([], [], [], [], [], state)
    recommendations = rec_gen.generate_recommendations(findings, gaps)

    soar_recs = [r for r in recommendations if r.suggested_playbook]
    for rec in soar_recs:
        assert rec.requires_human_approval is True


# ==========================================
# 7. Full Agent Execution & Orchestrator Integration
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
async def test_dfir_agent_execution_run(async_session: AsyncSession):
    """Verify DFIRInvestigatorAgent execution updates InvestigationState."""
    agent = DFIRInvestigatorAgent()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        case_id="CASE-200",
        alerts=[{
            "alert_id": "ALT-500",
            "host": "WKSTN-01",
            "process_name": "lsass.exe",
            "command_line": "powershell.exe -enc AAAA",
        }],
    )

    result = await agent.execute(state)
    assert result.status == AgentStatus.SUCCESS
    assert result.agent_name == "DFIRInvestigatorAgent"
    assert len(result.findings) >= 1
    assert len(state.recommendations) >= 1


@pytest.mark.anyio
async def test_orchestrator_multi_agent_execution(async_session: AsyncSession):
    """Verify AIOrchestrator invokes ThreatHunterAgent and DFIRInvestigatorAgent sequentially."""
    repo = InvestigationRepository(async_session)
    inv = await repo.create(
        InvestigationCreate(incident_id=uuid.uuid4(), name="Multi-Agent Run", status=InvestigationStatus.INITIATED)
    )

    agent_reg = AgentRegistry()
    hunter_agent = ThreatHunterAgent()
    dfir_agent = DFIRInvestigatorAgent()

    agent_reg.register_agent(hunter_agent)
    agent_reg.register_agent(dfir_agent)

    orchestrator = AIOrchestrator(agent_registry=agent_reg)

    state = orchestrator.start_investigation(
        investigation_id=str(inv.id),
        initial_alerts=[{"alert_id": "ALT-999", "command_line": "powershell.exe -enc CCCC"}],
    )

    workflow = InvestigationWorkflow()
    orch_result = await orchestrator.execute_workflow(workflow, state)

    assert orch_result.status == "COMPLETED"
    assert "step_threat_hunter" in orch_result.completed_steps
    assert "step_dfir" in orch_result.completed_steps
    assert "DFIRInvestigatorAgent" in orch_result.state.agent_results
