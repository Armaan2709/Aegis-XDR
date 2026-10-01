"""
SOAR Playbook Engine Validation Engine.

Provides PlaybookValidator for verifying playbook structure, step ordering,
action types, configurations, timeouts, retries, conditions, and status transitions.
"""

from typing import List, Optional, Set
import uuid

from app.playbooks.models import Playbook, PlaybookStep, ActionType, PlaybookStatus
from app.playbooks.schemas import PlaybookValidationResult, PlaybookCreate, PlaybookStepCreate


class PlaybookValidator:
    """Validator engine for playbook definitions and steps."""

    VALID_TRANSITIONS = {
        PlaybookStatus.DRAFT: {PlaybookStatus.TESTING, PlaybookStatus.ACTIVE, PlaybookStatus.ARCHIVED},
        PlaybookStatus.TESTING: {PlaybookStatus.ACTIVE, PlaybookStatus.DRAFT, PlaybookStatus.DISABLED},
        PlaybookStatus.ACTIVE: {PlaybookStatus.DISABLED, PlaybookStatus.TESTING, PlaybookStatus.ARCHIVED},
        PlaybookStatus.DISABLED: {PlaybookStatus.ACTIVE, PlaybookStatus.ARCHIVED, PlaybookStatus.DRAFT},
        PlaybookStatus.ARCHIVED: {PlaybookStatus.DRAFT},
    }

    @classmethod
    def validate_playbook(cls, playbook: Playbook) -> PlaybookValidationResult:
        """Validate an existing Playbook entity and its steps."""
        errors: List[str] = []
        warnings: List[str] = []

        if not playbook.name or len(playbook.name.strip()) < 3:
            errors.append("Playbook name must be at least 3 characters long.")

        if not playbook.steps or len(playbook.steps) == 0:
            warnings.append("Playbook has no steps configured.")

        # Check step ordering & duplicates
        step_orders: Set[int] = set()
        step_names: Set[str] = set()

        for step in (playbook.steps or []):
            # Duplicate order
            if step.step_order in step_orders:
                errors.append(f"Duplicate step order found: {step.step_order} on step '{step.name}'.")
            step_orders.add(step.step_order)

            # Duplicate name
            if step.name in step_names:
                warnings.append(f"Duplicate step name found: '{step.name}'.")
            step_names.add(step.name)

            # ActionType check
            if not isinstance(step.action_type, ActionType):
                errors.append(f"Step '{step.name}' has invalid ActionType: {step.action_type}.")

            # Timeout check
            if step.timeout_seconds <= 0:
                errors.append(f"Step '{step.name}' has invalid timeout: {step.timeout_seconds}s. Must be > 0.")

            # Retry count check
            if step.retry_count < 0 or step.retry_count > 10:
                errors.append(f"Step '{step.name}' has invalid retry_count: {step.retry_count}. Must be between 0 and 10.")

            # Required configuration check
            if step.action_type == ActionType.BLOCK_IP and not step.configuration:
                warnings.append(f"Step '{step.name}' (BLOCK_IP) has empty configuration dictionary.")

        is_valid = len(errors) == 0
        return PlaybookValidationResult(
            is_valid=is_valid,
            playbook_id=playbook.id,
            errors=errors,
            warnings=warnings,
        )

    @classmethod
    def validate_create_schema(cls, playbook_in: PlaybookCreate) -> PlaybookValidationResult:
        """Validate PlaybookCreate DTO before persistence."""
        errors: List[str] = []
        warnings: List[str] = []

        if not playbook_in.name or len(playbook_in.name.strip()) < 3:
            errors.append("Playbook name must be at least 3 characters long.")

        step_orders: Set[int] = set()
        for step in playbook_in.steps:
            if step.step_order in step_orders:
                errors.append(f"Duplicate step order found: {step.step_order} on step '{step.name}'.")
            step_orders.add(step.step_order)

            if step.timeout_seconds <= 0:
                errors.append(f"Step '{step.name}' has invalid timeout: {step.timeout_seconds}s.")

            if step.retry_count < 0 or step.retry_count > 10:
                errors.append(f"Step '{step.name}' has invalid retry_count: {step.retry_count}.")

        is_valid = len(errors) == 0
        return PlaybookValidationResult(
            is_valid=is_valid,
            playbook_id=None,
            errors=errors,
            warnings=warnings,
        )

    @classmethod
    def validate_status_transition(cls, current_status: PlaybookStatus, new_status: PlaybookStatus) -> bool:
        """Validate if a status transition is permitted."""
        if current_status == new_status:
            return True
        allowed = cls.VALID_TRANSITIONS.get(current_status, set())
        return new_status in allowed
