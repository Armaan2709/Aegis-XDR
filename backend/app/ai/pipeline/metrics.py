"""
Pipeline Metrics Collector.

Tracks operational pipeline execution metrics, stage durations, retry counts, and MTTR approximations.
"""

from typing import Dict, Any, List
from app.ai.pipeline.schemas import PipelineContext, PipelineStatus


class PipelineMetricsCollector:
    """Collector recording pipeline performance and operational metrics."""

    def __init__(self):
        self._total_runs = 0
        self._completed_runs = 0
        self._failed_runs = 0
        self._total_duration_ms = 0.0
        self._total_retries = 0

    def record_run(self, context: PipelineContext) -> None:
        """Record completed or failed pipeline execution run metrics."""
        self._total_runs += 1
        if context.status == PipelineStatus.COMPLETED:
            self._completed_runs += 1
        elif context.status == PipelineStatus.FAILED:
            self._failed_runs += 1

        run_ms = sum(
            res.execution_time_ms for res in context.stage_results.values() if hasattr(res, "execution_time_ms")
        )
        self._total_duration_ms += run_ms
        self._total_retries += sum(context.retries.values())

    def get_metrics(self) -> Dict[str, Any]:
        """Retrieve aggregated operational metrics dictionary."""
        avg_dur = round(self._total_duration_ms / self._total_runs, 2) if self._total_runs > 0 else 0.0
        return {
            "total_runs": self._total_runs,
            "completed_runs": self._completed_runs,
            "failed_runs": self._failed_runs,
            "total_retries": self._total_retries,
            "avg_duration_ms": avg_dur,
            "mttr_ms_approximation": avg_dur,
        }
