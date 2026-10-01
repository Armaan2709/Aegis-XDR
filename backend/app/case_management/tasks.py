"""
Case Management Task Submodule Logic.

Provides state transition validation and task lifecycle helpers for Case Tasks.
"""

from typing import Set, Tuple
from app.case_management.models import TaskStatus
from app.core.exceptions import ValidationError


class TaskStateEngine:
    """State transition validator for Case Tasks."""

    ALLOWED_TRANSITIONS: Set[Tuple[TaskStatus, TaskStatus]] = {
        (TaskStatus.PENDING, TaskStatus.IN_PROGRESS),
        (TaskStatus.PENDING, TaskStatus.COMPLETED),
        (TaskStatus.PENDING, TaskStatus.CANCELLED),
        (TaskStatus.IN_PROGRESS, TaskStatus.COMPLETED),
        (TaskStatus.IN_PROGRESS, TaskStatus.CANCELLED),
        (TaskStatus.IN_PROGRESS, TaskStatus.PENDING),
        (TaskStatus.COMPLETED, TaskStatus.IN_PROGRESS),
        (TaskStatus.CANCELLED, TaskStatus.PENDING),
    }

    @classmethod
    def validate_transition(cls, current_status: TaskStatus, new_status: TaskStatus) -> None:
        """Enforce strict task state transition validation."""
        if current_status == new_status:
            return  # No state change

        transition = (current_status, new_status)
        if transition not in cls.ALLOWED_TRANSITIONS:
            raise ValidationError(
                f"Invalid task status transition from '{current_status.value}' to '{new_status.value}'"
            )
