"""
SOAR Playbook Engine Domain Service.

Orchestrates business logic for Playbooks, Steps, Executions, Validation,
Registration, Approval Resumptions, and Cancellation.
"""

import uuid
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ValidationError, ConflictError
from app.playbooks.models import (
    Playbook,
    PlaybookStep,
    PlaybookExecution,
    PlaybookStatus,
    ExecutionStatus,
)
from app.playbooks.schemas import (
    PlaybookCreate,
    PlaybookUpdate,
    PlaybookStepCreate,
    PlaybookStepUpdate,
    PlaybookFilterParams,
    PlaybookExecutionCreate,
    PlaybookValidationResult,
)
from app.playbooks.repositories import (
    PlaybookRepository,
    PlaybookStepRepository,
    PlaybookExecutionRepository,
    PlaybookStepExecutionRepository,
)
from app.playbooks.validators import PlaybookValidator
from app.playbooks.registry import PlaybookRegistry
from app.playbooks.engine import PlaybookEngine


class PlaybookService:
    """Core domain service for SOAR Playbook Engine."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.playbook_repo = PlaybookRepository(session)
        self.step_repo = PlaybookStepRepository(session)
        self.execution_repo = PlaybookExecutionRepository(session)
        self.step_exec_repo = PlaybookStepExecutionRepository(session)
        self.registry = PlaybookRegistry()

    async def create_playbook(
        self, playbook_in: PlaybookCreate, created_by_id: Optional[uuid.UUID] = None
    ) -> Playbook:
        """Create a new playbook definition after name uniqueness and structure validation."""
        existing = await self.playbook_repo.get_by_name(playbook_in.name)
        if existing:
            raise ConflictError(f"A playbook with name '{playbook_in.name}' already exists")

        # Validate schema DTO
        val_result = PlaybookValidator.validate_create_schema(playbook_in)
        if not val_result.is_valid:
            raise ValidationError(f"Playbook creation validation failed: {'; '.join(val_result.errors)}")

        playbook = await self.playbook_repo.create(playbook_in, created_by_id=created_by_id)
        self.registry.register(playbook)
        return playbook

    async def get_playbook(self, playbook_id: uuid.UUID) -> Playbook:
        """Retrieve playbook by UUID or raise NotFoundError."""
        playbook = await self.playbook_repo.get_by_id(playbook_id)
        if not playbook:
            raise NotFoundError(f"Playbook with ID '{playbook_id}' not found")
        return playbook

    async def list_playbooks(
        self, params: PlaybookFilterParams
    ) -> Tuple[List[Playbook], int]:
        """List, search, filter, and paginate playbooks."""
        return await self.playbook_repo.list_filtered(params)

    async def update_playbook(
        self,
        playbook_id: uuid.UUID,
        update_in: PlaybookUpdate,
        updated_by_id: Optional[uuid.UUID] = None,
    ) -> Playbook:
        """Update playbook fields and check status transition validity."""
        playbook = await self.get_playbook(playbook_id)
        update_dict = update_in.model_dump(exclude_unset=True)

        if "status" in update_dict:
            new_status = update_dict["status"]
            if not PlaybookValidator.validate_status_transition(playbook.status, new_status):
                raise ValidationError(
                    f"Invalid status transition from '{playbook.status.value}' to '{new_status.value}'"
                )

        if updated_by_id:
            update_dict["updated_by_id"] = updated_by_id

        updated = await self.playbook_repo.update(playbook, update_dict)
        self.registry.register(updated)
        return updated

    async def delete_playbook(self, playbook_id: uuid.UUID) -> bool:
        """Delete playbook by UUID."""
        playbook = await self.get_playbook(playbook_id)
        return await self.playbook_repo.delete(playbook)

    # ==========================================
    # Step Operations
    # ==========================================

    async def add_step(
        self, playbook_id: uuid.UUID, step_in: PlaybookStepCreate
    ) -> PlaybookStep:
        """Add a new step to an existing playbook."""
        await self.get_playbook(playbook_id)
        return await self.step_repo.create(step_in, playbook_id=playbook_id)

    async def update_step(
        self, playbook_id: uuid.UUID, step_id: uuid.UUID, update_in: PlaybookStepUpdate
    ) -> PlaybookStep:
        """Update a step configuration or order."""
        await self.get_playbook(playbook_id)
        step = await self.step_repo.get_by_id(step_id)
        if not step or step.playbook_id != playbook_id:
            raise NotFoundError(f"Step '{step_id}' not found in playbook '{playbook_id}'")

        update_dict = update_in.model_dump(exclude_unset=True)
        return await self.step_repo.update(step, update_dict)

    async def delete_step(self, playbook_id: uuid.UUID, step_id: uuid.UUID) -> bool:
        """Delete a step from a playbook."""
        await self.get_playbook(playbook_id)
        step = await self.step_repo.get_by_id(step_id)
        if not step or step.playbook_id != playbook_id:
            raise NotFoundError(f"Step '{step_id}' not found in playbook '{playbook_id}'")
        return await self.step_repo.delete(step)

    # ==========================================
    # Validation & Execution Operations
    # ==========================================

    async def validate_playbook(self, playbook_id: uuid.UUID) -> PlaybookValidationResult:
        """Validate structure and step configuration of a playbook."""
        playbook = await self.get_playbook(playbook_id)
        return PlaybookValidator.validate_playbook(playbook)

    async def execute_playbook(
        self, exec_in: PlaybookExecutionCreate, executed_by_id: Optional[uuid.UUID] = None
    ) -> PlaybookExecution:
        """Trigger execution of a playbook."""
        engine = PlaybookEngine(self.session)
        return await engine.execute_playbook(
            playbook_id=exec_in.playbook_id,
            initial_context=exec_in.initial_context,
            trigger_source=exec_in.trigger_source,
            incident_id=exec_in.incident_id,
            case_id=exec_in.case_id,
            investigation_id=exec_in.investigation_id,
            executed_by_id=executed_by_id,
        )

    async def resume_execution(
        self, execution_id: uuid.UUID, actor_id: Optional[uuid.UUID] = None
    ) -> PlaybookExecution:
        """Resume a paused playbook execution."""
        engine = PlaybookEngine(self.session)
        return await engine.resume_execution_after_approval(execution_id, actor_id=actor_id)

    async def cancel_execution(
        self, execution_id: uuid.UUID, reason: str = "Execution cancelled by user"
    ) -> PlaybookExecution:
        """Cancel a running or queued playbook execution."""
        engine = PlaybookEngine(self.session)
        return await engine.cancel_execution(execution_id, reason=reason)

    async def get_execution(self, execution_id: uuid.UUID) -> PlaybookExecution:
        """Retrieve execution run details by UUID."""
        execution = await self.execution_repo.get_by_id(execution_id)
        if not execution:
            raise NotFoundError(f"Execution with ID '{execution_id}' not found")
        return execution

    async def list_executions(
        self,
        page: int = 1,
        page_size: int = 20,
        playbook_id: Optional[uuid.UUID] = None,
        status: Optional[ExecutionStatus] = None,
    ) -> Tuple[List[PlaybookExecution], int]:
        """List and filter playbook execution runs."""
        return await self.execution_repo.list_filtered(
            page=page, page_size=page_size, playbook_id=playbook_id, status=status
        )
