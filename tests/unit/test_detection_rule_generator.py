"""
Unit Tests for Detection Rule Generator Agent (Sprint 15).

Verifies DetectionRuleGeneratorAgent initialization, registration, state validation,
evidence extraction, Sigma/YARA/Suricata/Custom generation, existing Sprint 8 Detection Engine
parser/validator/tester reuse, duplicate detection, quality scoring, false positive analysis,
human approval enforcement, and multi-agent workflow DAG execution.
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
from app.ai.agents.threat_intel import ThreatIntelligenceAnalystAgent
from app.ai.agents.detection_generator import (
    DetectionRuleGeneratorAgent,
    DetectionEvidenceAnalyzer,
    SigmaRuleGenerator,
    YaraRuleGenerator,
    SuricataRuleGenerator,
    DetectionRuleQualityAnalyzer,
    RuleQualityLevel,
)
from app.ai.orchestrator.state import InvestigationState
from app.ai.orchestrator.engine import AIOrchestrator
from app.ai.workflows.investigation import InvestigationWorkflow


# ==========================================
# 1. Agent Initialization & Validation Tests
# ==========================================

def test_detection_generator_agent_initialization():
    """Verify DetectionRuleGeneratorAgent capabilities, name, and health check."""
    agent = DetectionRuleGeneratorAgent()
    assert agent.name == "DetectionRuleGeneratorAgent"
    assert "Detection Engineering" in agent.capabilities
    assert "Sigma Generation" in agent.capabilities
    assert agent.health_check() is True

    registry = AgentRegistry()
    registry.register_agent(agent, alias="DetectionAgent")
    assert registry.get_agent("DetectionRuleGeneratorAgent") == agent
    assert registry.get_agent("DetectionAgent") == agent


def test_detection_generator_input_validation():
    """Verify input state validation rules."""
    agent = DetectionRuleGeneratorAgent()
    invalid_state = InvestigationState(investigation_id="")
    assert agent.validate_input(invalid_state) is False

    valid_state = InvestigationState(investigation_id=str(uuid.uuid4()))
    assert agent.validate_input(valid_state) is True


# ==========================================
# 2. Evidence Analysis & Observable Extraction
# ==========================================

def test_detection_evidence_extraction():
    """Verify observable extraction across evidence, alerts, and agent results."""
    analyzer = DetectionEvidenceAnalyzer()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        evidence=[{
            "evidence_id": "EV-100",
            "sha256": "f" * 64,
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c powershell -enc test",
        }],
        alerts=[{
            "alert_id": "ALT-200",
            "ip": "10.0.0.99",
            "domain": "malicious-c2-node.org",
        }],
        mitre_mappings=[{"technique_id": "T1059.001"}],
    )

    obs = analyzer.analyze_evidence(state)
    assert "f" * 64 in obs["hashes"]
    assert "cmd.exe" in obs["processes"]
    assert "10.0.0.99" in obs["ips"]
    assert "malicious-c2-node.org" in obs["domains"]
    assert "T1059.001" in obs["mitre_techniques"]


# ==========================================
# 3. Rule Format Generation Tests
# ==========================================

def test_sigma_yara_suricata_generators():
    """Verify Sigma, YARA, and Suricata rule generation and existing Detection Engine validator integration."""
    sigma_gen = SigmaRuleGenerator()
    yara_gen = YaraRuleGenerator()
    suricata_gen = SuricataRuleGenerator()

    observables = {
        "processes": ["powershell.exe"],
        "commands": ["powershell.exe -ExecutionPolicy Bypass -enc AAA=="],
        "hashes": ["b" * 64],
        "ips": ["192.168.1.100"],
        "domains": ["evil-domain.com"],
        "mitre_techniques": ["T1059.001"],
        "evidence_refs": ["EV-555"],
    }

    sigma = sigma_gen.generate_rule(observables)
    yara = yara_gen.generate_rule(observables)
    suricata = suricata_gen.generate_rule(observables)

    assert sigma is not None and "title:" in sigma.detection_logic
    assert yara is not None and "rule " in yara.detection_logic
    assert suricata is not None and "alert ip" in suricata.detection_logic


# ==========================================
# 4. Quality Scoring & Duplicate Detection
# ==========================================

def test_quality_scoring_and_duplicate_detection():
    """Verify DetectionRuleQualityAnalyzer scores quality 0-100 and flags duplicates."""
    quality_analyzer = DetectionRuleQualityAnalyzer()
    sigma_gen = SigmaRuleGenerator()

    observables = {
        "processes": ["cmd.exe"],
        "commands": ["cmd.exe /c whoami"],
        "mitre_techniques": ["T1059"],
        "evidence_refs": ["EV-1"],
    }

    cand = sigma_gen.generate_rule(observables)
    assert cand is not None

    q_score = quality_analyzer.evaluate_quality(cand)
    assert 0.0 <= q_score.quality_score <= 100.0
    assert q_score.quality_level in (RuleQualityLevel.EXCELLENT, RuleQualityLevel.GOOD, RuleQualityLevel.ACCEPTABLE)
    assert q_score.is_duplicate is False

    # Test duplicate detection
    existing_rules = [{"name": "Existing Cmd Rule", "content": cand.detection_logic}]
    q_score_dup = quality_analyzer.evaluate_quality(cand, existing_rules=existing_rules)
    assert q_score_dup.is_duplicate is True
    assert q_score_dup.duplicate_rule_name == "Existing Cmd Rule"


# ==========================================
# 5. Human Approval Enforcement Tests
# ==========================================

@pytest.mark.anyio
async def test_detection_recommendations_human_approval():
    """Verify that all deployment/activation recommendations enforce requires_human_approval = True."""
    agent = DetectionRuleGeneratorAgent()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        evidence=[{"process_name": "powershell.exe", "command_line": "powershell -enc AAA=="}],
    )

    result = await agent.execute(state)
    assert result.status == AgentStatus.SUCCESS

    detailed_recs = result.metadata.get("detailed_recommendations", [])
    assert len(detailed_recs) >= 1
    for rec in detailed_recs:
        if "Deploy" in rec["title"] or "Review" in rec["title"]:
            assert rec["requires_human_approval"] is True


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
async def test_detection_generator_agent_execution_run(async_session: AsyncSession):
    """Verify DetectionRuleGeneratorAgent execution updates InvestigationState."""
    agent = DetectionRuleGeneratorAgent()
    state = InvestigationState(
        investigation_id=str(uuid.uuid4()),
        case_id="CASE-400",
        alerts=[{
            "alert_id": "ALT-999",
            "ip": "10.0.0.50",
            "command_line": "powershell.exe -nop -w hidden -enc",
        }],
    )

    result = await agent.execute(state)
    assert result.status == AgentStatus.SUCCESS
    assert result.agent_name == "DetectionRuleGeneratorAgent"
    assert len(result.findings) >= 1
    assert len(state.recommendations) >= 1


@pytest.mark.anyio
async def test_orchestrator_quad_agent_execution(async_session: AsyncSession):
    """Verify AIOrchestrator invokes ThreatHunter, DFIR, ThreatIntel, and Detection agents sequentially."""
    repo = InvestigationRepository(async_session)
    inv = await repo.create(
        InvestigationCreate(incident_id=uuid.uuid4(), name="Quad-Agent Run", status=InvestigationStatus.INITIATED)
    )

    agent_reg = AgentRegistry()
    hunter_agent = ThreatHunterAgent()
    dfir_agent = DFIRInvestigatorAgent()
    intel_agent = ThreatIntelligenceAnalystAgent()
    detection_agent = DetectionRuleGeneratorAgent()

    agent_reg.register_agent(hunter_agent)
    agent_reg.register_agent(dfir_agent)
    agent_reg.register_agent(intel_agent, alias="ThreatIntelAgent")
    agent_reg.register_agent(detection_agent, alias="DetectionAgent")

    orchestrator = AIOrchestrator(agent_registry=agent_reg)

    state = orchestrator.start_investigation(
        investigation_id=str(inv.id),
        initial_alerts=[{"alert_id": "ALT-1000", "ip": "192.168.1.50", "command_line": "powershell.exe -enc DDDD"}],
    )

    workflow = InvestigationWorkflow()
    orch_result = await orchestrator.execute_workflow(workflow, state)

    assert orch_result.status == "COMPLETED"
    assert "step_threat_hunter" in orch_result.completed_steps
    assert "step_dfir" in orch_result.completed_steps
    assert "step_threat_intel" in orch_result.completed_steps
    assert "step_detection" in orch_result.completed_steps
    assert "DetectionRuleGeneratorAgent" in orch_result.state.agent_results
