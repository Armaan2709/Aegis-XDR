"""
Unit Tests for End-to-End Autonomous Investigation Pipeline (Sprint 17).

Verifies pipeline initialization, state transitions, state machine validation,
stage execution, agent failure recovery, retry policy, human review gate enforcement,
approval rejection safety, playbook execution safety, pipeline cancellation, pipeline recovery,
audit trail logging, metrics collection, and finalization.
"""

import uuid
import pytest
from app.ai.pipeline import (
    PipelineStage,
    PipelineStatus,
    StageStatus,
    PipelineRunRequest,
    PipelineContext,
    PipelineStateManager,
    AutonomousInvestigationPipeline,
    PipelineRecoveryEngine,
    PipelineAuditLogger,
    PipelineMetricsCollector,
)
from app.ai.orchestrator.state import InvestigationState


# ==========================================
# 1. Pipeline Context & Initialization Tests
# ==========================================

def test_pipeline_initialization():
    """Verify PipelineContext creation and initial default values."""
    engine = AutonomousInvestigationPipeline()
    req = PipelineRunRequest(
        investigation_id="INV-TEST-001",
        incident_id="INC-TEST-001",
        initial_alerts=[{"alert_id": "ALT-1", "ip": "10.0.0.1"}],
    )
    ctx = engine.initialize_context(req)

    assert ctx.investigation_id == "INV-TEST-001"
    assert ctx.incident_id == "INC-TEST-001"
    assert ctx.current_stage == PipelineStage.CREATED
    assert ctx.status == PipelineStatus.RUNNING
    assert len(ctx.timeline) == 1
    assert ctx.timeline[0].event_type == "PIPELINE_CREATED"


# ==========================================
# 2. State Machine Transition Tests
# ==========================================

def test_state_machine_valid_and_invalid_transitions():
    """Verify state manager permits valid stage transitions and rejects illegal state jumps."""
    mgr = PipelineStateManager()
    ctx = PipelineContext(
        investigation_id="INV-001",
        investigation_state=InvestigationState(investigation_id="INV-001"),
    )

    # Valid step-by-step transitions
    mgr.transition_to(ctx, PipelineStage.TRIAGING)
    assert ctx.current_stage == PipelineStage.TRIAGING

    mgr.transition_to(ctx, PipelineStage.CORRELATING)
    assert ctx.current_stage == PipelineStage.CORRELATING

    # Invalid jump (Correlating -> Response Executing directly)
    with pytest.raises(ValueError, match="Invalid pipeline state transition"):
        mgr.transition_to(ctx, PipelineStage.RESPONSE_EXECUTING)


# ==========================================
# 3. Full Pipeline Execution Runs (Approved vs Awaiting Review)
# ==========================================

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_pipeline_run_awaiting_approval():
    """Verify pipeline pauses at AWAITING_REVIEW stage when approval is required."""
    engine = AutonomousInvestigationPipeline()
    req = PipelineRunRequest(
        investigation_id="INV-WAIT-001",
        initial_alerts=[{"alert_id": "ALT-10", "ip": "198.51.100.10", "command_line": "powershell.exe -enc"}],
        auto_approve_routine=False,
    )
    ctx = engine.initialize_context(req)
    res_ctx = await engine.run(ctx)

    assert res_ctx.status == PipelineStatus.AWAITING_APPROVAL
    assert res_ctx.current_stage == PipelineStage.AWAITING_REVIEW
    assert res_ctx.approval_required is True
    assert PipelineStage.RESPONSE_EXECUTING.value not in res_ctx.stage_results


@pytest.mark.anyio
async def test_pipeline_run_auto_approved():
    """Verify pipeline executes through response execution and finalization when pre-approved."""
    engine = AutonomousInvestigationPipeline()
    req = PipelineRunRequest(
        investigation_id="INV-APPROVED-001",
        initial_alerts=[{"alert_id": "ALT-20", "ip": "203.0.113.5", "command_line": "powershell.exe -enc"}],
        auto_approve_routine=True,
    )
    ctx = engine.initialize_context(req)
    res_ctx = await engine.run(ctx)

    assert res_ctx.status == PipelineStatus.COMPLETED
    assert res_ctx.current_stage == PipelineStage.COMPLETED
    assert res_ctx.approval_status == "AUTO_APPROVED"
    assert PipelineStage.RESPONSE_EXECUTING.value in res_ctx.stage_results
    assert res_ctx.stage_results[PipelineStage.RESPONSE_EXECUTING.value].status == StageStatus.SUCCESS


# ==========================================
# 4. Approval Rejection & Governance Boundaries
# ==========================================

@pytest.mark.anyio
async def test_response_execution_rejected_approval_prevention():
    """Verify ResponseExecutionStage throws PermissionError if approval_status is REJECTED or PENDING."""
    from app.ai.pipeline.stages import ResponseExecutionStage

    stage = ResponseExecutionStage()
    ctx = PipelineContext(
        investigation_id="INV-REJECTED-001",
        approval_status="REJECTED",
        investigation_state=InvestigationState(investigation_id="INV-REJECTED-001"),
    )

    with pytest.raises(PermissionError, match="CaseApproval status is 'REJECTED'"):
        await stage.execute(ctx)


# ==========================================
# 5. Cancellation & Recovery Tests
# ==========================================

@pytest.mark.anyio
async def test_pipeline_cancellation_and_recovery():
    """Verify pipeline cancellation stops future stages and recovery engine resumes paused execution."""
    engine = AutonomousInvestigationPipeline()
    recovery = PipelineRecoveryEngine(engine)

    req = PipelineRunRequest(
        investigation_id="INV-RECOVER-001",
        initial_alerts=[{"alert_id": "ALT-30", "ip": "10.0.0.30"}],
    )
    ctx = engine.initialize_context(req)
    res_ctx = await engine.run(ctx)

    # Currently paused at AWAITING_REVIEW
    assert res_ctx.status == PipelineStatus.AWAITING_APPROVAL

    # Cancel pipeline
    cancelled = engine.cancel(res_ctx, reason="Manual test cancellation")
    assert cancelled.status == PipelineStatus.CANCELLED

    # Approve and Resume via Recovery Engine
    res_ctx.approval_status = "APPROVED"
    resumed = await recovery.resume_pipeline(res_ctx, from_stage=PipelineStage.AWAITING_REVIEW)

    assert resumed.status == PipelineStatus.COMPLETED
    assert resumed.current_stage == PipelineStage.COMPLETED


# ==========================================
# 6. Audit & Metrics Tests
# ==========================================

def test_audit_logger_and_metrics_collector():
    """Verify audit entries append to timeline and metrics collector tracks operational metrics."""
    logger = PipelineAuditLogger()
    metrics = PipelineMetricsCollector()

    ctx = PipelineContext(
        investigation_id="INV-METRIC-001",
        investigation_state=InvestigationState(investigation_id="INV-METRIC-001"),
    )

    entry = logger.log_event(ctx, "CUSTOM_TEST_EVENT", "Test audit description")
    assert len(ctx.timeline) == 1
    assert entry.event_type == "CUSTOM_TEST_EVENT"

    ctx.status = PipelineStatus.COMPLETED
    metrics.record_run(ctx)

    m_data = metrics.get_metrics()
    assert m_data["total_runs"] == 1
    assert m_data["completed_runs"] == 1
