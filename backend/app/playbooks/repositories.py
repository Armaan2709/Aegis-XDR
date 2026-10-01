"""
SOAR Playbook Engine Domain Async Database Repositories.

Provides asynchronous SQLAlchemy 2.0 CRUD data access, dynamic filtering,
pagination, and status execution logging for Playbooks, Steps, Executions, and Step Executions.
"""

import uuid
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, func, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.playbooks.models import (
    Playbook,
    PlaybookStep,
    PlaybookExecution,
    PlaybookStepExecution,
    PlaybookStatus,
    PlaybookCategory,
    PlaybookSeverity,
    ActionType,
    ExecutionStatus,
    StepExecutionStatus,
)
from app.playbooks.schemas import (
    PlaybookCreate,
    PlaybookStepCreate,
    PlaybookFilterParams,
)


class PlaybookRepository:
    """Async repository for Playbook entity persistence."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self, playbook_in: PlaybookCreate, created_by_id: Optional[uuid.UUID] = None
    ) -> Playbook:
        """Create a new Playbook with steps."""
        playbook = Playbook(
            name=playbook_in.name,
            description=playbook_in.description,
            version=playbook_in.version,
            status=playbook_in.status,
            category=playbook_in.category,
            severity_trigger=playbook_in.severity_trigger,
            author=playbook_in.author,
            created_by_id=created_by_id,
            is_active=playbook_in.is_active,
            requires_approval=playbook_in.requires_approval,
            tags=playbook_in.tags,
            playbook_metadata=playbook_in.playbook_metadata,
        )
        self.session.add(playbook)
        await self.session.flush()

        # Add initial steps if provided
        for step_data in playbook_in.steps:
            step = PlaybookStep(
                playbook_id=playbook.id,
                name=step_data.name,
                description=step_data.description,
                step_order=step_data.step_order,
                action_type=step_data.action_type,
                configuration=step_data.configuration,
                conditions=step_data.conditions,
                timeout_seconds=step_data.timeout_seconds,
                retry_count=step_data.retry_count,
                continue_on_failure=step_data.continue_on_failure,
                requires_approval=step_data.requires_approval,
            )
            self.session.add(step)

        await self.session.commit()
        return await self.get_by_id(playbook.id)  # Load eagerly

    async def get_by_id(self, playbook_id: uuid.UUID) -> Optional[Playbook]:
        """Fetch playbook by UUID with steps ordered by step_order."""
        stmt = (
            select(Playbook)
            .where(Playbook.id == playbook_id)
        )
        res = await self.session.execute(stmt)
        playbook = res.scalar_one_or_none()
        if playbook:
            # Load steps explicitly sorted
            step_stmt = (
                select(PlaybookStep)
                .where(PlaybookStep.playbook_id == playbook_id)
                .order_by(PlaybookStep.step_order.asc())
            )
            step_res = await self.session.execute(step_stmt)
            playbook.steps = list(step_res.scalars().all())
        return playbook

    async def get_by_name(self, name: str) -> Optional[Playbook]:
        """Fetch playbook by unique name."""
        stmt = select(Playbook).where(Playbook.name == name)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_filtered(
        self, params: PlaybookFilterParams
    ) -> Tuple[List[Playbook], int]:
        """Search, filter, and paginate playbooks."""
        query = select(Playbook)

        if params.query:
            pattern = f"%{params.query}%"
            query = query.where(
                or_(
                    Playbook.name.ilike(pattern),
                    Playbook.description.ilike(pattern),
                    Playbook.author.ilike(pattern),
                )
            )

        if params.status:
            query = query.where(Playbook.status == params.status)

        if params.category:
            query = query.where(Playbook.category == params.category)

        if params.severity_trigger:
            query = query.where(Playbook.severity_trigger == params.severity_trigger)

        if params.is_active is not None:
            query = query.where(Playbook.is_active.is_(params.is_active))

        # Total count
        count_stmt = select(func.count()).select_from(query.subquery())
        total = (await self.session.execute(count_stmt)).scalar_one()

        # Sorting
        sort_attr = getattr(Playbook, params.sort_by, Playbook.created_at)
        if params.sort_order.lower() == "asc":
            query = query.order_by(sort_attr.asc())
        else:
            query = query.order_by(sort_attr.desc())

        # Pagination
        offset = (params.page - 1) * params.page_size
        query = query.offset(offset).limit(params.page_size)

        res = await self.session.execute(query)
        playbooks = list(res.scalars().all())

        # Populate steps for each playbook
        for pb in playbooks:
            step_stmt = (
                select(PlaybookStep)
                .where(PlaybookStep.playbook_id == pb.id)
                .order_by(PlaybookStep.step_order.asc())
            )
            step_res = await self.session.execute(step_stmt)
            pb.steps = list(step_res.scalars().all())

        return playbooks, total

    async def update(self, playbook: Playbook, update_data: Dict[str, Any]) -> Playbook:
        """Update Playbook attributes."""
        for key, value in update_data.items():
            if hasattr(playbook, key) and value is not None:
                setattr(playbook, key, value)
        await self.session.commit()
        return await self.get_by_id(playbook.id)

    async def delete(self, playbook: Playbook) -> bool:
        """Delete Playbook record."""
        await self.session.delete(playbook)
        await self.session.commit()
        return True


class PlaybookStepRepository:
    """Async repository for PlaybookStep persistence."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self, step_in: PlaybookStepCreate, playbook_id: uuid.UUID
    ) -> PlaybookStep:
        """Create a new step for a playbook."""
        step = PlaybookStep(
            playbook_id=playbook_id,
            name=step_in.name,
            description=step_in.description,
            step_order=step_in.step_order,
            action_type=step_in.action_type,
            configuration=step_in.configuration,
            conditions=step_in.conditions,
            timeout_seconds=step_in.timeout_seconds,
            retry_count=step_in.retry_count,
            continue_on_failure=step_in.continue_on_failure,
            requires_approval=step_in.requires_approval,
        )
        self.session.add(step)
        await self.session.commit()
        await self.session.refresh(step)
        return step

    async def get_by_id(self, step_id: uuid.UUID) -> Optional[PlaybookStep]:
        """Fetch step by UUID."""
        stmt = select(PlaybookStep).where(PlaybookStep.id == step_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_by_playbook(self, playbook_id: uuid.UUID) -> List[PlaybookStep]:
        """Fetch all steps for a playbook ordered by step_order."""
        stmt = (
            select(PlaybookStep)
            .where(PlaybookStep.playbook_id == playbook_id)
            .order_by(PlaybookStep.step_order.asc())
        )
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def update(self, step: PlaybookStep, update_data: Dict[str, Any]) -> PlaybookStep:
        """Update step attributes."""
        for key, value in update_data.items():
            if hasattr(step, key) and value is not None:
                setattr(step, key, value)
        await self.session.commit()
        await self.session.refresh(step)
        return step

    async def delete(self, step: PlaybookStep) -> bool:
        """Delete step record."""
        await self.session.delete(step)
        await self.session.commit()
        return True


class PlaybookExecutionRepository:
    """Async repository for PlaybookExecution tracking."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        playbook_id: uuid.UUID,
        trigger_source: str = "MANUAL",
        initial_context: Optional[Dict[str, Any]] = None,
        incident_id: Optional[uuid.UUID] = None,
        case_id: Optional[uuid.UUID] = None,
        investigation_id: Optional[uuid.UUID] = None,
        executed_by_id: Optional[uuid.UUID] = None,
    ) -> PlaybookExecution:
        """Create a new execution run record."""
        execution = PlaybookExecution(
            playbook_id=playbook_id,
            incident_id=incident_id,
            case_id=case_id,
            investigation_id=investigation_id,
            trigger_source=trigger_source,
            execution_context=initial_context or {},
            executed_by_id=executed_by_id,
            status=ExecutionStatus.QUEUED,
            current_step_order=1,
            results={},
        )
        self.session.add(execution)
        await self.session.commit()
        return await self.get_by_id(execution.id)

    async def get_by_id(self, execution_id: uuid.UUID) -> Optional[PlaybookExecution]:
        """Fetch execution run by UUID with step executions."""
        stmt = select(PlaybookExecution).where(PlaybookExecution.id == execution_id)
        res = await self.session.execute(stmt)
        execution = res.scalar_one_or_none()
        if execution:
            step_exec_stmt = (
                select(PlaybookStepExecution)
                .where(PlaybookStepExecution.execution_id == execution_id)
                .order_by(PlaybookStepExecution.started_at.asc())
            )
            step_exec_res = await self.session.execute(step_exec_stmt)
            execution.step_executions = list(step_exec_res.scalars().all())
        return execution

    async def list_filtered(
        self,
        page: int = 1,
        page_size: int = 20,
        playbook_id: Optional[uuid.UUID] = None,
        status: Optional[ExecutionStatus] = None,
    ) -> Tuple[List[PlaybookExecution], int]:
        """Filter and paginate playbook executions."""
        query = select(PlaybookExecution)

        if playbook_id:
            query = query.where(PlaybookExecution.playbook_id == playbook_id)

        if status:
            query = query.where(PlaybookExecution.status == status)

        count_stmt = select(func.count()).select_from(query.subquery())
        total = (await self.session.execute(count_stmt)).scalar_one()

        offset = (page - 1) * page_size
        query = query.order_by(PlaybookExecution.started_at.desc()).offset(offset).limit(page_size)

        res = await self.session.execute(query)
        executions = list(res.scalars().all())

        for exc in executions:
            step_exec_stmt = (
                select(PlaybookStepExecution)
                .where(PlaybookStepExecution.execution_id == exc.id)
                .order_by(PlaybookStepExecution.started_at.asc())
            )
            step_exec_res = await self.session.execute(step_exec_stmt)
            exc.step_executions = list(step_exec_res.scalars().all())

        return executions, total

    async def update(
        self, execution: PlaybookExecution, update_data: Dict[str, Any]
    ) -> PlaybookExecution:
        """Update execution record attributes."""
        for key, value in update_data.items():
            if hasattr(execution, key) and value is not None:
                setattr(execution, key, value)
        await self.session.commit()
        return await self.get_by_id(execution.id)


class PlaybookStepExecutionRepository:
    """Async repository for PlaybookStepExecution tracking."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        execution_id: uuid.UUID,
        step_id: uuid.UUID,
        step_name: str,
        action_type: ActionType,
        input_parameters: Optional[Dict[str, Any]] = None,
    ) -> PlaybookStepExecution:
        """Create step execution log entry."""
        step_exec = PlaybookStepExecution(
            execution_id=execution_id,
            step_id=step_id,
            step_name=step_name,
            action_type=action_type,
            status=StepExecutionStatus.PENDING,
            input_parameters=input_parameters or {},
            output_data={},
        )
        self.session.add(step_exec)
        await self.session.commit()
        await self.session.refresh(step_exec)
        return step_exec

    async def get_by_id(self, step_exec_id: uuid.UUID) -> Optional[PlaybookStepExecution]:
        """Fetch step execution by UUID."""
        stmt = select(PlaybookStepExecution).where(PlaybookStepExecution.id == step_exec_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_by_execution(
        self, execution_id: uuid.UUID
    ) -> List[PlaybookStepExecution]:
        """List step executions for a playbook run."""
        stmt = (
            select(PlaybookStepExecution)
            .where(PlaybookStepExecution.execution_id == execution_id)
            .order_by(PlaybookStepExecution.started_at.asc())
        )
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def update(
        self, step_exec: PlaybookStepExecution, update_data: Dict[str, Any]
    ) -> PlaybookStepExecution:
        """Update step execution entry."""
        for key, value in update_data.items():
            if hasattr(step_exec, key) and value is not None:
                setattr(step_exec, key, value)
        await self.session.commit()
        await self.session.refresh(step_exec)
        return step_exec
