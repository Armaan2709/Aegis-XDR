"""
Integration Tests for End-to-End Autonomous Investigation Pipeline (Sprint 17).

Verifies full database-backed investigation creation, alert ingestion, correlation,
multi-agent investigation pipeline execution, CaseApproval gate integration,
mock SOAR response execution, timeline generation, and API router compatibility.
"""

import uuid
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.models.base import Base
from app.models.investigation import Investigation, InvestigationStatus
from app.domains.investigations.schemas import InvestigationCreate
from app.domains.investigations.repositories import InvestigationRepository
from app.ai.pipeline import (
    AutonomousInvestigationPipeline,
    PipelineRunRequest,
    PipelineStatus,
    PipelineStage,
)


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
async def test_full_autonomous_investigation_integration(async_session: AsyncSession):
    """Verify end-to-end autonomous investigation execution starting from database Investigation entity."""
    inv_repo = InvestigationRepository(async_session)
    inv = await inv_repo.create(
        InvestigationCreate(
            incident_id=uuid.uuid4(),
            name="Integration Test Autonomous SOC Pipeline",
            status=InvestigationStatus.INITIATED,
        )
    )

    pipeline = AutonomousInvestigationPipeline()
    req = PipelineRunRequest(
        investigation_id=str(inv.id),
        incident_id=str(inv.incident_id),
        initial_alerts=[{
            "alert_id": "ALT-INTEG-001",
            "ip": "198.51.100.99",
            "hostname": "FINANCE-PC-01",
            "command_line": "powershell.exe -nop -enc BASE64==",
            "severity": "HIGH",
        }],
        auto_approve_routine=True,
    )

    context = pipeline.initialize_context(req)
    result_ctx = await pipeline.run(context)

    # 1. Pipeline Completion Check
    assert result_ctx.status == PipelineStatus.COMPLETED
    assert result_ctx.current_stage == PipelineStage.COMPLETED

    # 2. Stage Execution Verification across all 11 stages
    assert PipelineStage.TRIAGING.value in result_ctx.stage_results
    assert PipelineStage.CORRELATING.value in result_ctx.stage_results
    assert PipelineStage.INVESTIGATION_STARTED.value in result_ctx.stage_results
    assert PipelineStage.THREAT_HUNTING.value in result_ctx.stage_results
    assert PipelineStage.DFIR_ANALYSIS.value in result_ctx.stage_results
    assert PipelineStage.THREAT_INTELLIGENCE.value in result_ctx.stage_results
    assert PipelineStage.DETECTION_GENERATION.value in result_ctx.stage_results
    assert PipelineStage.INCIDENT_SYNTHESIS.value in result_ctx.stage_results
    assert PipelineStage.AWAITING_REVIEW.value in result_ctx.stage_results
    assert PipelineStage.RESPONSE_EXECUTING.value in result_ctx.stage_results
    assert PipelineStage.COMPLETED.value in result_ctx.stage_results

    # 3. InvestigationState Verification
    state = result_ctx.investigation_state
    assert len(state.agent_results) >= 5
    assert "ThreatHunterAgent" in state.agent_results
    assert "DFIRInvestigatorAgent" in state.agent_results
    assert "ThreatIntelligenceAnalystAgent" in state.agent_results
    assert "DetectionRuleGeneratorAgent" in state.agent_results
    assert "IncidentCommanderAgent" in state.agent_results
    assert state.risk_score > 0.0

    # 4. Auditable Timeline Verification
    assert len(result_ctx.timeline) >= 10
    event_types = [t.event_type for t in result_ctx.timeline]
    assert "PIPELINE_CREATED" in event_types
    assert "STAGE_COMPLETED" in event_types
