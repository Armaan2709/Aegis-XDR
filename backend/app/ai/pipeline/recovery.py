"""
Pipeline Recovery Engine.

Enables safe resumption of paused or failed pipelines from specific stages
without re-running previously successful stages.
"""

from typing import Optional
from app.ai.pipeline.schemas import PipelineStage, PipelineStatus, PipelineContext
from app.ai.pipeline.pipeline import AutonomousInvestigationPipeline


class PipelineRecoveryEngine:
    """Recovery engine for resuming failed or paused investigation pipelines."""

    def __init__(self, pipeline: Optional[AutonomousInvestigationPipeline] = None):
        self._pipeline = pipeline or AutonomousInvestigationPipeline()

    async def resume_pipeline(
        self, context: PipelineContext, from_stage: Optional[PipelineStage] = None
    ) -> PipelineContext:
        """
        Resume pipeline execution from specified stage or last uncompleted stage.

        Returns:
            Updated PipelineContext after resumed execution run.
        """
        if context.status == PipelineStatus.COMPLETED:
            return context

        target_stage = from_stage
        if not target_stage:
            # Find first failed or uncompleted stage
            for stage_key, res in context.stage_results.items():
                if getattr(res, "status", None) == "FAILURE":
                    try:
                        target_stage = PipelineStage(stage_key)
                        break
                    except ValueError:
                        pass

        if target_stage:
            context.current_stage = target_stage
            context.status = PipelineStatus.RUNNING
            context.errors.clear()

        # Execute resumed run
        return await self._pipeline.run(context)
