"""
Pipeline State Manager.

Enforces valid state machine transitions, maintains historical stage progression,
and manages pipeline status serialization and state validation.
"""

from typing import Dict, Set, List
from app.ai.pipeline.schemas import PipelineStage, PipelineStatus, PipelineContext, PipelineTimelineEntry


class PipelineStateManager:
    """State Machine manager enforcing valid pipeline stage transitions."""

    ALLOWED_TRANSITIONS: Dict[PipelineStage, Set[PipelineStage]] = {
        PipelineStage.CREATED: {PipelineStage.TRIAGING, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.TRIAGING: {PipelineStage.CORRELATING, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.CORRELATING: {PipelineStage.INVESTIGATION_STARTED, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.INVESTIGATION_STARTED: {PipelineStage.THREAT_HUNTING, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.THREAT_HUNTING: {PipelineStage.DFIR_ANALYSIS, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.DFIR_ANALYSIS: {PipelineStage.THREAT_INTELLIGENCE, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.THREAT_INTELLIGENCE: {PipelineStage.DETECTION_GENERATION, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.DETECTION_GENERATION: {PipelineStage.INCIDENT_SYNTHESIS, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.INCIDENT_SYNTHESIS: {PipelineStage.AWAITING_REVIEW, PipelineStage.COMPLETED, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.AWAITING_REVIEW: {PipelineStage.RESPONSE_APPROVED, PipelineStage.COMPLETED, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.RESPONSE_APPROVED: {PipelineStage.RESPONSE_EXECUTING, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.RESPONSE_EXECUTING: {PipelineStage.RESPONSE_COMPLETED, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.RESPONSE_COMPLETED: {PipelineStage.COMPLETED, PipelineStage.FAILED, PipelineStage.CANCELLED},
        PipelineStage.COMPLETED: set(),
        PipelineStage.FAILED: set(),
        PipelineStage.CANCELLED: set(),
    }

    def validate_transition(self, current_stage: PipelineStage, target_stage: PipelineStage) -> bool:
        """Verify if transition from current_stage to target_stage is valid."""
        allowed = self.ALLOWED_TRANSITIONS.get(current_stage, set())
        return target_stage in allowed

    def transition_to(
        self, context: PipelineContext, target_stage: PipelineStage, event_desc: str = ""
    ) -> None:
        """
        Transition pipeline context to target_stage if valid.

        Raises:
            ValueError: If transition violates state machine rules.
        """
        if not self.validate_transition(context.current_stage, target_stage):
            raise ValueError(
                f"Invalid pipeline state transition from '{context.current_stage.value}' to '{target_stage.value}'."
            )

        context.previous_stage = context.current_stage
        context.current_stage = target_stage

        if target_stage == PipelineStage.COMPLETED:
            context.status = PipelineStatus.COMPLETED
        elif target_stage == PipelineStage.FAILED:
            context.status = PipelineStatus.FAILED
        elif target_stage == PipelineStage.CANCELLED:
            context.status = PipelineStatus.CANCELLED
        elif target_stage == PipelineStage.AWAITING_REVIEW:
            context.status = PipelineStatus.AWAITING_APPROVAL
        else:
            context.status = PipelineStatus.RUNNING

        context.timeline.append(
            PipelineTimelineEntry(
                stage=target_stage,
                event_type="STAGE_TRANSITION",
                description=event_desc or f"Transitioned to stage {target_stage.value}",
            )
        )
