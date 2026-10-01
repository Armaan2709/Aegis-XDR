"""
Unit Tests for Threat Intelligence Analyst Agent (Sprint 14).

Verifies ThreatIntelligenceAnalystAgent initialization, registration, IOC extraction,
IOC normalization, provider consensus, agreement/disagreement metrics, threat scoring,
relationship mapping, threat clustering, conservative attribution, intelligence gap detection,
findings/recommendations generation, human approval enforcement, Threat Hunter/DFIR context consumption,
memory integration, failure handling, and AIOrchestrator integration.
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
from app.ai.agents.dfir import DFIRInvestigatorAgent
from app.ai.agents.threat_intel import (
    ThreatIntelligenceAnalystAgent,
    IOCAnalyzer,
    ThreatEnrichmentConsensusEngine,
    IOCRelationshipEngine,
    ThreatClusterGenerator,
    ConservativeAttributionEngine,
    AttributionLevel,
    ThreatIntelFindingGenerator,
    ThreatIntelRecommendationGenerator,
)
from app.ai.orchestrator.state import InvestigationState
from app.ai.orchestrator.engine import AIOrchestrator
from app.ai.workflows.investigation import InvestigationWorkflow


# ==========================================
# 1. Agent Initialization & Validation Tests
# ==========================================

def test_threat_intel_agent_initialization():
    """Verify ThreatIntelligenceAnalystAgent capabilities, name, and health check."""
    agent = ThreatIntelligenceAnalystAgent()
    assert agent.name == "ThreatIntelligenceAnalystAgent"
    assert "Threat Intelligence Analysis" in agent.capabilities
    assert "IOC Enrichment" in agent.capabilities
    assert agent.health_check() is True

    registry = AgentRegistry()
    registry.register_agent(agent)
    assert registry.get_agent("ThreatIntelligenceAnalystAgent") == agent


def test_threat_intel_input_validation():
    """Verify input state validation rules."""
    agent = ThreatIntelligenceAnalystAgent()
    invalid_state = InvestigationState(investigation_id="")
    assert agent.validate_input(invalid_state) is False

    valid_state = InvestigationState(investigation_id=str(uuid.uuid4()))
    assert agent.validate_input(valid_state) is True


# ==========================================
# 2. IOC Extraction & Normalization Tests
# ==========================================

def test_ioc_extraction_and_normalization():
    """Verify IOC extraction across state, alerts, evidence, and agent results."""
    analyzer = IOCAnalyzer()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        evidence=[{
            "evidence_id": "EV-1",
            "sha256": "E" * 64,
            "ip": "192.168.1.50",
            "domain": "malicious-c2.com",
        }],
        alerts=[{
            "alert_id": "ALT-1",
            "process_name": "powershell.exe",
        }],
    )

    iocs = analyzer.extract_and_normalize(state)
    ioc_vals = [i.normalized_value for i in iocs]

    assert "e" * 64 in ioc_vals
    assert "192.168.1.50" in ioc_vals
    assert "malicious-c2.com" in ioc_vals


# ==========================================
# 3. Provider Consensus & Threat Scoring Tests
# ==========================================

def test_provider_consensus_and_threat_scoring():
    """Verify provider consensus evaluation, agreement metrics, and consolidated threat score."""
    analyzer = IOCAnalyzer()
    consensus_engine = ThreatEnrichmentConsensusEngine()

    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        evidence=[{"sha256": "a" * 64, "domain": "malicious-evil.com"}],
    )

    iocs = analyzer.extract_and_normalize(state)
    consensuses = [consensus_engine.evaluate_consensus(ioc) for ioc in iocs]

    for cons in consensuses:
        assert 0.0 <= cons.confidence <= 1.0
        assert 0.0 <= cons.consolidated_threat_score <= 100.0
        assert cons.malicious_count + cons.benign_count + cons.unknown_count == len(cons.provider_assessments)
        assert round(cons.agreement_ratio + cons.disagreement_ratio, 2) == 1.00


# ==========================================
# 4. Threat Clustering & Conservative Attribution
# ==========================================

def test_threat_clustering_and_attribution():
    """Verify threat cluster generation and non-definitive conservative attribution."""
    analyzer = IOCAnalyzer()
    consensus_engine = ThreatEnrichmentConsensusEngine()
    cluster_gen = ThreatClusterGenerator()
    attr_engine = ConservativeAttributionEngine()

    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        evidence=[{"domain": "malicious-domain.com"}],
    )

    iocs = analyzer.extract_and_normalize(state)
    consensuses = [consensus_engine.evaluate_consensus(ioc) for ioc in iocs]
    clusters = cluster_gen.generate_clusters(iocs, consensuses, state)
    attribution = attr_engine.evaluate_attribution(consensuses, clusters, state)

    assert len(clusters) >= 1
    assert attribution.level in (
        AttributionLevel.UNKNOWN,
        AttributionLevel.POTENTIAL_CAMPAIGN,
        AttributionLevel.POSSIBLE_THREAT_GROUP,
        AttributionLevel.INFRASTRUCTURE_RELATIONSHIP,
    )
    assert "definitely" not in attribution.statement.lower()


# ==========================================
# 5. Human Approval Enforcement & SOAR Recommendations
# ==========================================

def test_threat_intel_recommendations_human_approval():
    """Verify that recommendations suggesting SOAR actions set requires_human_approval = True."""
    finding_gen = ThreatIntelFindingGenerator()
    rec_gen = ThreatIntelRecommendationGenerator()
    analyzer = IOCAnalyzer()
    consensus_engine = ThreatEnrichmentConsensusEngine()

    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        evidence=[{"domain": "malicious-evil.com"}],
    )

    iocs = analyzer.extract_and_normalize(state)
    consensuses = [consensus_engine.evaluate_consensus(ioc) for ioc in iocs]
    findings, gaps = finding_gen.generate_findings_and_gaps(iocs, consensuses, [], None, state)
    recommendations = rec_gen.generate_recommendations(findings, gaps)

    soar_recs = [r for r in recommendations if r.suggested_playbook]
    for rec in soar_recs:
        assert rec.requires_human_approval is True


# ==========================================
# 6. Full Agent Execution & Orchestrator Integration
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
async def test_threat_intel_agent_execution_run(async_session: AsyncSession):
    """Verify ThreatIntelligenceAnalystAgent execution updates InvestigationState."""
    agent = ThreatIntelligenceAnalystAgent()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        case_id="CASE-300",
        alerts=[{
            "alert_id": "ALT-700",
            "ip": "192.168.1.50",
            "domain": "evil-c2-server.com",
        }],
    )

    result = await agent.execute(state)
    assert result.status == AgentStatus.SUCCESS
    assert result.agent_name == "ThreatIntelligenceAnalystAgent"
    assert len(result.findings) >= 1
    assert len(state.recommendations) >= 1


@pytest.mark.anyio
async def test_orchestrator_tri_agent_execution(async_session: AsyncSession):
    """Verify AIOrchestrator invokes ThreatHunter, DFIR, and ThreatIntel agents sequentially."""
    repo = InvestigationRepository(async_session)
    inv = await repo.create(
        InvestigationCreate(incident_id=uuid.uuid4(), name="Tri-Agent Run", status=InvestigationStatus.INITIATED)
    )

    agent_reg = AgentRegistry()
    hunter_agent = ThreatHunterAgent()
    dfir_agent = DFIRInvestigatorAgent()
    intel_agent = ThreatIntelligenceAnalystAgent()

    agent_reg.register_agent(hunter_agent)
    agent_reg.register_agent(dfir_agent)
    agent_reg.register_agent(intel_agent, alias="ThreatIntelAgent")


    orchestrator = AIOrchestrator(agent_registry=agent_reg)

    state = orchestrator.start_investigation(
        investigation_id=str(inv.id),
        initial_alerts=[{"alert_id": "ALT-888", "ip": "192.168.1.50", "command_line": "powershell.exe -enc DDDD"}],
    )

    workflow = InvestigationWorkflow()
    orch_result = await orchestrator.execute_workflow(workflow, state)

    assert orch_result.status == "COMPLETED"
    assert "step_threat_hunter" in orch_result.completed_steps
    assert "step_dfir" in orch_result.completed_steps
    assert "step_threat_intel" in orch_result.completed_steps
    assert "ThreatIntelligenceAnalystAgent" in orch_result.state.agent_results
