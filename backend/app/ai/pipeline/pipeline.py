"""
Master Autonomous Investigation Pipeline Coordinator Engine.

Orchestrates deterministic 11-stage autonomous security investigation lifecycle.
Handles retries, stage execution, state transitions, human review gates, cancellation, and metrics.
"""

from typing import Optional, Dict, Any, List
from app.ai.orchestrator.state import InvestigationState
from app.ai.pipeline.schemas import (
    PipelineStage,
    PipelineStatus,
    StageStatus,
    PipelineContext,
    StageResult,
    PipelineRunRequest,
)
from app.ai.pipeline.state_manager import PipelineStateManager
from app.ai.pipeline.stages import (
    AlertTriageStage,
    CorrelationStage,
    InvestigationInitializationStage,
    ThreatHuntingStage,
    DFIRAnalysisStage,
    ThreatIntelligenceStage,
    DetectionGenerationStage,
    IncidentSynthesisStage,
    HumanReviewGateStage,
    ResponseExecutionStage,
    FinalizationStage,
)
from app.ai.pipeline.audit import PipelineAuditLogger
from app.ai.pipeline.metrics import PipelineMetricsCollector


class AutonomousInvestigationPipeline:
    """Master pipeline coordinator executing end-to-end security investigations."""

    def __init__(self, max_retries: int = 2):
        self._state_manager = PipelineStateManager()
        self._audit_logger = PipelineAuditLogger()
        self._metrics_collector = PipelineMetricsCollector()
        self.max_retries = max_retries

        self._stages = {
            PipelineStage.TRIAGING: AlertTriageStage(),
            PipelineStage.CORRELATING: CorrelationStage(),
            PipelineStage.INVESTIGATION_STARTED: InvestigationInitializationStage(),
            PipelineStage.THREAT_HUNTING: ThreatHuntingStage(),
            PipelineStage.DFIR_ANALYSIS: DFIRAnalysisStage(),
            PipelineStage.THREAT_INTELLIGENCE: ThreatIntelligenceStage(),
            PipelineStage.DETECTION_GENERATION: DetectionGenerationStage(),
            PipelineStage.INCIDENT_SYNTHESIS: IncidentSynthesisStage(),
            PipelineStage.AWAITING_REVIEW: HumanReviewGateStage(),
            PipelineStage.RESPONSE_EXECUTING: ResponseExecutionStage(),
            PipelineStage.COMPLETED: FinalizationStage(),
        }

    def initialize_context(self, req: PipelineRunRequest) -> PipelineContext:
        """Initialize PipelineContext from PipelineRunRequest."""
        inv_state = InvestigationState(
            investigation_id=req.investigation_id,
            incident_id=req.incident_id,
            alerts=req.initial_alerts,
        )
        context = PipelineContext(
            investigation_id=req.investigation_id,
            incident_id=req.incident_id,
            investigation_state=inv_state,
        )
        if req.auto_approve_routine:
            context.approval_status = "AUTO_APPROVED"

        self._audit_logger.log_event(context, "PIPELINE_CREATED", "Initialized pipeline context.")

        return context

    async def run(self, context: PipelineContext) -> PipelineContext:
        """Run pipeline from current stage to completion or approval pause."""
        stage_sequence = [
            PipelineStage.TRIAGING,
            PipelineStage.CORRELATING,
            PipelineStage.INVESTIGATION_STARTED,
            PipelineStage.THREAT_HUNTING,
            PipelineStage.DFIR_ANALYSIS,
            PipelineStage.THREAT_INTELLIGENCE,
            PipelineStage.DETECTION_GENERATION,
            PipelineStage.INCIDENT_SYNTHESIS,
            PipelineStage.AWAITING_REVIEW,
        ]

        # Find starting index based on current_stage
        start_idx = 0
        if context.current_stage != PipelineStage.CREATED:
            try:
                start_idx = stage_sequence.index(context.current_stage)
            except ValueError:
                start_idx = 0

        for stage_enum in stage_sequence[start_idx:]:
            if context.status in (PipelineStatus.CANCELLED, PipelineStatus.FAILED, PipelineStatus.PAUSED):
                break

            # Transition state
            if context.current_stage != stage_enum:
                self._state_manager.transition_to(
                    context, stage_enum, f"Executing stage {stage_enum.value}"
                )

            # Execute Stage with Retries
            stage_impl = self._stages[stage_enum]
            res = await self._run_stage_with_retries(context, stage_impl)
            context.stage_results[stage_enum.value] = res

            if res.status == StageStatus.FAILURE:
                context.errors.append(f"Stage {stage_enum.value} failed: {res.error}")
                self._state_manager.transition_to(context, PipelineStage.FAILED, f"Stage {stage_enum.value} failed.")
                break

            # Handle Human Review Gate
            if stage_enum == PipelineStage.AWAITING_REVIEW:
                if context.approval_status in ("APPROVED", "AUTO_APPROVED"):
                    # Approved: Proceed to response execution
                    self._state_manager.transition_to(
                        context, PipelineStage.RESPONSE_APPROVED, "Approval granted."
                    )
                    self._state_manager.transition_to(
                        context, PipelineStage.RESPONSE_EXECUTING, "Executing response actions."
                    )
                    resp_res = await self._run_stage_with_retries(context, self._stages[PipelineStage.RESPONSE_EXECUTING])
                    context.stage_results[PipelineStage.RESPONSE_EXECUTING.value] = resp_res
                    self._state_manager.transition_to(
                        context, PipelineStage.RESPONSE_COMPLETED, "Response execution completed."
                    )
                    self._state_manager.transition_to(
                        context, PipelineStage.COMPLETED, "Finalizing investigation."
                    )
                    fin_res = await self._stages[PipelineStage.COMPLETED].execute(context)
                    context.stage_results[PipelineStage.COMPLETED.value] = fin_res
                else:
                    # Pending Approval: Pause pipeline
                    context.status = PipelineStatus.AWAITING_APPROVAL
                    self._audit_logger.log_event(context, "APPROVAL_PAUSE", "Pipeline paused awaiting CaseApproval decision.")
                break

        self._metrics_collector.record_run(context)
        return context

    async def _run_stage_with_retries(self, context: PipelineContext, stage: Any) -> StageResult:
        """Run single stage with retry handling."""
        stage_enum = stage.stage
        retries = 0

        self._audit_logger.log_event(context, "STAGE_STARTED", f"Started stage {stage_enum.value}")

        while retries <= self.max_retries:
            try:
                res = await stage.execute(context)
                res.retry_count = retries
                self._audit_logger.log_event(context, "STAGE_COMPLETED", f"Completed stage {stage_enum.value}")
                return res
            except Exception as e:
                retries += 1
                context.retries[stage_enum.value] = retries
                if retries > self.max_retries:
                    self._audit_logger.log_event(context, "STAGE_FAILED", f"Failed stage {stage_enum.value}: {str(e)}")
                    return StageResult(
                        stage=stage_enum,
                        status=StageStatus.FAILURE,
                        error=str(e),
                        retry_count=retries - 1,
                    )

        return StageResult(stage=stage_enum, status=StageStatus.FAILURE, error="Max retries exceeded")

    def cancel(self, context: PipelineContext, reason: str = "User cancelled pipeline") -> PipelineContext:
        """Safely cancel running pipeline."""
        if context.status in (PipelineStatus.COMPLETED, PipelineStatus.FAILED, PipelineStatus.CANCELLED):
            return context

        self._state_manager.transition_to(context, PipelineStage.CANCELLED, reason)
        context.errors.append(f"Pipeline cancelled: {reason}")
        self._audit_logger.log_event(context, "PIPELINE_CANCELLED", reason)
        return context
