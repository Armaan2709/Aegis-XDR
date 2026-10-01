"""
SOAR Playbook Engine Execution Tracker.

Maintains execution context state, tracks current step progress, records outputs,
propagates context variables between sequential steps, and logs retries/errors.
"""

from typing import Dict, Any, Optional
import uuid
from datetime import datetime, timezone

from app.playbooks.models import (
    PlaybookExecution,
    PlaybookStepExecution,
    ExecutionStatus,
    StepExecutionStatus,
)


class ExecutionTracker:
    """State and context tracking manager for playbook executions."""

    def __init__(self, execution: PlaybookExecution):
        self.execution = execution
        self.context: Dict[str, Any] = dict(execution.execution_context or {})
        self.results: Dict[str, Any] = dict(execution.results or {})

    def update_context(self, key: str, value: Any) -> None:
        """Inject or update a context variable available to subsequent steps."""
        self.context[key] = value
        self.execution.execution_context = dict(self.context)

    def record_step_result(
        self, step_name: str, step_order: int, output_data: Dict[str, Any]
    ) -> None:
        """Store step output dictionary in execution results."""
        self.results[f"step_{step_order}_{step_name}"] = output_data
        self.execution.results = dict(self.results)
        self.execution.current_step_order = step_order + 1

    def mark_completed(self) -> None:
        """Set execution state to COMPLETED."""
        self.execution.status = ExecutionStatus.COMPLETED
        self.execution.completed_at = datetime.now(timezone.utc)

    def mark_partially_completed(self, reason: str) -> None:
        """Set execution state to PARTIALLY_COMPLETED."""
        self.execution.status = ExecutionStatus.PARTIALLY_COMPLETED
        self.execution.error_details = reason
        self.execution.completed_at = datetime.now(timezone.utc)

    def mark_failed(self, error_message: str) -> None:
        """Set execution state to FAILED."""
        self.execution.status = ExecutionStatus.FAILED
        self.execution.error_details = error_message
        self.execution.completed_at = datetime.now(timezone.utc)

    def mark_waiting_approval(self, approval_id: uuid.UUID) -> None:
        """Set execution state to WAITING_APPROVAL."""
        self.execution.status = ExecutionStatus.WAITING_APPROVAL
        self.execution.approval_id = approval_id

    def mark_cancelled(self, reason: str = "Execution cancelled by user") -> None:
        """Set execution state to CANCELLED."""
        self.execution.status = ExecutionStatus.CANCELLED
        self.execution.error_details = reason
        self.execution.completed_at = datetime.now(timezone.utc)
