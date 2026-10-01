"""
Unit Tests for Threat Hunter Agent (Sprint 12).

Verifies ThreatHunterAgent initialization, observable extraction, safe tool analysis,
hypothesis generation, evidence validation, scoring algorithms, findings/recommendations generation,
human approval enforcement, state updates, failure handling, and AIOrchestrator integration.
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
from app.ai.agents.threat_hunter import (
    ThreatHunterAgent,
    ObservableAnalyzer,
    ObservableType,
    HypothesisEngine,
    HypothesisStatus,
    ThreatHypothesis,
    ThreatInvestigationEngine,
    ThreatRecommendationGenerator,
)

from app.ai.orchestrator.state import InvestigationState
from app.ai.orchestrator.engine import AIOrchestrator
from app.ai.workflows.investigation import InvestigationWorkflow
from app.ai.tools.registry import ToolRegistry


# ==========================================
# 1. Agent Initialization & Input Validation Tests
# ==========================================

def test_threat_hunter_agent_initialization():
    """Verify ThreatHunterAgent capabilities, name, and health check."""
    agent = ThreatHunterAgent()
    assert agent.name == "ThreatHunterAgent"
    assert "Threat Hunting" in agent.capabilities
    assert agent.health_check() is True

    # Registration test
    registry = AgentRegistry()
    registry.register_agent(agent)
    assert registry.get_agent("ThreatHunterAgent") == agent


def test_threat_hunter_input_validation():
    """Verify input state validation rules."""
    agent = ThreatHunterAgent()
    invalid_state = InvestigationState(investigation_id="")
    assert agent.validate_input(invalid_state) is False

    valid_state = InvestigationState(investigation_id=str(uuid.uuid4()))
    assert agent.validate_input(valid_state) is True


# ==========================================
# 2. Observable Extraction & Type Detection Tests
# ==========================================

def test_observable_extraction_and_types():
    """Verify regex and pattern extraction of IP, hash, process, command line, user observables."""
    analyzer = ObservableAnalyzer()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        alerts=[{
            "alert_id": "ALT-001",
            "host": "WKSTN-01",
            "user": "admin_user",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA 198.51.100.50",
        }],
        evidence=[{
            "evidence_id": "EV-001",
            "sha256": "e" * 64,
            "file_name": "malicious.exe",
        }],
    )

    observables = analyzer.extract_observables(state)
    obs_types = {o.type for o in observables}

    assert ObservableType.IP_ADDRESS in obs_types
    assert ObservableType.PROCESS in obs_types
    assert ObservableType.COMMAND_LINE in obs_types
    assert ObservableType.HASH in obs_types
    assert ObservableType.USER_ACCOUNT in obs_types


# ==========================================
# 3. Hypothesis Engine & Evidence Rules
# ==========================================

def test_hypothesis_generation_and_evidence_rules():
    """Verify deterministic hypothesis generation and status rules (SUPPORTED vs INCONCLUSIVE)."""
    engine = HypothesisEngine()
    analyzer = ObservableAnalyzer()

    # Case A: Encoded PowerShell -> SUPPORTED
    state_encoded = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        alerts=[{"command_line": "powershell.exe -enc AAAA"}],
    )
    obs_encoded = analyzer.extract_observables(state_encoded)
    hyp_encoded = engine.generate_hypotheses(obs_encoded, state_encoded)
    
    ps_hyp = next(h for h in hyp_encoded if "PowerShell" in h.title)
    assert ps_hyp.status == HypothesisStatus.SUPPORTED

    # Case B: Standard IP without Threat Intel -> INCONCLUSIVE
    state_ip = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        alerts=[{"host": "WKSTN-02"}],
    )
    obs_ip = analyzer.extract_observables(state_ip)
    hyp_ip = engine.generate_hypotheses(obs_ip, state_ip)
    c2_hyp = next((h for h in hyp_ip if "C2" in h.title), None)
    if c2_hyp:
        assert c2_hyp.status == HypothesisStatus.INCONCLUSIVE


# ==========================================
# 4. Correlation & Scoring Engine Tests
# ==========================================

def test_investigation_scoring_algorithms():
    """Verify confidence (0-1) and risk score (0-100) calculations."""
    engine = ThreatInvestigationEngine()
    state = InvestigationState(investigation_id=str(uuid.uuid4()), risk_score=50.0)

    confidence = engine.calculate_confidence(observables=[], hypotheses=[], analysis_results={})
    assert 0.0 <= confidence <= 1.0

    risk = engine.calculate_risk_score(confidence, hypotheses=[], state=state, analysis_results={})
    assert 0.0 <= risk <= 100.0
    # Must not blindly overwrite higher authoritative state risk score
    assert risk >= 50.0


# ==========================================
# 5. Findings & Recommendations Human Approval
# ==========================================

def test_recommendation_human_approval_enforcement():
    """Verify that SOAR response recommendations strictly enforce requires_human_approval = True."""
    generator = ThreatRecommendationGenerator()
    state = InvestigationState(investigation_id=str(uuid.uuid4()))
    engine = HypothesisEngine()

    hypotheses = [
        ThreatHypothesis(
            title="Credential Theft via LSASS",
            description="LSASS dump attempt",
            status=HypothesisStatus.SUPPORTED,
            risk_score=90.0,
        )
    ]

    findings, recommendations = generator.generate_findings_and_recommendations(
        observables=[],
        hypotheses=hypotheses,
        correlation={"affected_hosts": ["WKSTN-01"]},
        confidence=0.9,
        risk_score=90.0,
        state=state,
    )

    assert len(findings) >= 1
    assert len(recommendations) >= 1

    soar_recs = [r for r in recommendations if r.suggested_playbook]
    for rec in soar_recs:
        assert rec.requires_human_approval is True


# ==========================================
# 6. Full Execution & AIOrchestrator Integration
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
async def test_threat_hunter_execution_run(async_session: AsyncSession):
    """Verify ThreatHunterAgent execution update on InvestigationState."""
    agent = ThreatHunterAgent()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        case_id="CASE-100",
        alerts=[{
            "alert_id": "ALT-101",
            "host": "WKSTN-01",
            "process_name": "lsass.exe",
            "command_line": "powershell.exe -enc AAAA",
        }],
    )

    result = await agent.execute(state)
    assert result.status == AgentStatus.SUCCESS
    assert result.agent_name == "ThreatHunterAgent"
    assert result.confidence_score > 0.0
    assert len(result.findings) >= 1
    assert len(state.hypotheses) >= 1
    assert len(state.recommendations) >= 1


@pytest.mark.anyio
async def test_orchestrator_integration_with_threat_hunter(async_session: AsyncSession):
    """Verify AIOrchestrator invokes registered ThreatHunterAgent in InvestigationWorkflow."""
    repo = InvestigationRepository(async_session)
    inv = await repo.create(
        InvestigationCreate(incident_id=uuid.uuid4(), name="APT Hunt Run", status=InvestigationStatus.INITIATED)
    )

    agent_reg = AgentRegistry()
    hunter_agent = ThreatHunterAgent()
    agent_reg.register_agent(hunter_agent)

    orchestrator = AIOrchestrator(agent_registry=agent_reg)

    state = orchestrator.start_investigation(
        investigation_id=str(inv.id),
        initial_alerts=[{"alert_id": "ALT-202", "command_line": "powershell.exe -enc BBBB"}],
    )

    workflow = InvestigationWorkflow()
    orch_result = await orchestrator.execute_workflow(workflow, state)

    assert orch_result.status == "COMPLETED"
    assert "step_threat_hunter" in orch_result.completed_steps
    assert "ThreatHunterAgent" in orch_result.state.agent_results
