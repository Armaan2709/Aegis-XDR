"""
SOAR Playbook Engine REST API Router.

Exposes endpoints for Playbook CRUD, Step management, Playbook validation,
Execution triggering, Execution listing, Execution cancellation, and Approval resumption.
Mounted under /api/v1/playbooks.
"""

import math
import uuid
from typing import Annotated, List
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.users.router import get_current_user
from app.models.user import User
from app.playbooks.models import PlaybookStatus, PlaybookCategory, PlaybookSeverity, ExecutionStatus
from app.playbooks.schemas import (
    PlaybookCreate,
    PlaybookUpdate,
    PlaybookResponse,
    PlaybookFilterParams,
    PlaybookStepCreate,
    PlaybookStepUpdate,
    PlaybookStepResponse,
    PlaybookExecutionCreate,
    PlaybookExecutionResponse,
    PlaybookValidationResult,
)
from app.playbooks.services import PlaybookService
from app.schemas.response import APIResponse, PaginatedResponse, PaginationMeta

router = APIRouter(prefix="/playbooks", tags=["SOAR Playbook Engine Domain"])


@router.post("/", response_model=APIResponse[PlaybookResponse], status_code=status.HTTP_201_CREATED)
async def create_playbook(
    playbook_in: PlaybookCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[PlaybookResponse]:
    """Create a new SOAR playbook definition with initial steps."""
    service = PlaybookService(db)
    playbook = await service.create_playbook(playbook_in, created_by_id=current_user.id)
    return APIResponse(
        message=f"Playbook '{playbook.name}' created successfully",
        data=PlaybookResponse.model_validate(playbook),
    )


@router.get("/", response_model=PaginatedResponse[PlaybookResponse])
async def list_playbooks(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    query: Annotated[str | None, Query(description="Search term across name, description, author")] = None,
    status: Annotated[PlaybookStatus | None, Query(description="Filter by status")] = None,
    category: Annotated[PlaybookCategory | None, Query(description="Filter by category")] = None,
    severity_trigger: Annotated[PlaybookSeverity | None, Query(description="Filter by severity trigger")] = None,
    is_active: Annotated[bool | None, Query(description="Filter active playbooks")] = None,
    sort_by: Annotated[str, Query(description="Sort attribute")] = "created_at",
    sort_order: Annotated[str, Query(description="Sort direction (asc, desc)")] = "desc",
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Page size")] = 20,
) -> PaginatedResponse[PlaybookResponse]:
    """List, search, filter, and paginate playbooks."""
    params = PlaybookFilterParams(
        query=query,
        status=status,
        category=category,
        severity_trigger=severity_trigger,
        is_active=is_active,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )
    service = PlaybookService(db)
    playbooks, total_items = await service.list_playbooks(params)
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 0

    return PaginatedResponse(
        data=[PlaybookResponse.model_validate(pb) for pb in playbooks],
        meta=PaginationMeta(
            page=page,
            page_size=page_size,
            total_items=total_items,
            total_pages=total_pages,
        ),
    )


# Static execution routes placed BEFORE /{playbook_id} to avoid UUID route conflicts

@router.get("/executions", response_model=PaginatedResponse[PlaybookExecutionResponse])
async def list_executions(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    playbook_id: Annotated[uuid.UUID | None, Query(description="Filter by playbook UUID")] = None,
    status: Annotated[ExecutionStatus | None, Query(description="Filter by execution status")] = None,
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[PlaybookExecutionResponse]:
    """List and filter playbook execution runs."""
    service = PlaybookService(db)
    executions, total_items = await service.list_executions(
        page=page, page_size=page_size, playbook_id=playbook_id, status=status
    )
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 0

    return PaginatedResponse(
        data=[PlaybookExecutionResponse.model_validate(ex) for ex in executions],
        meta=PaginationMeta(
            page=page,
            page_size=page_size,
            total_items=total_items,
            total_pages=total_pages,
        ),
    )


@router.get("/executions/{execution_id}", response_model=APIResponse[PlaybookExecutionResponse])
async def get_execution(
    execution_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[PlaybookExecutionResponse]:
    """Retrieve detailed execution run record by UUID."""
    service = PlaybookService(db)
    execution = await service.get_execution(execution_id)
    return APIResponse(
        message="Playbook execution details retrieved successfully",
        data=PlaybookExecutionResponse.model_validate(execution),
    )


@router.post("/executions/{execution_id}/cancel", response_model=APIResponse[PlaybookExecutionResponse])
async def cancel_execution(
    execution_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[PlaybookExecutionResponse]:
    """Cancel a running or queued playbook execution."""
    service = PlaybookService(db)
    execution = await service.cancel_execution(execution_id, reason="Cancelled via REST API request")
    return APIResponse(
        message="Playbook execution cancelled successfully",
        data=PlaybookExecutionResponse.model_validate(execution),
    )


# Dynamic /{playbook_id} parameter routes

@router.get("/{playbook_id}", response_model=APIResponse[PlaybookResponse])
async def get_playbook(
    playbook_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[PlaybookResponse]:
    """Retrieve detailed playbook definition by UUID."""
    service = PlaybookService(db)
    playbook = await service.get_playbook(playbook_id)
    return APIResponse(
        message="Playbook details retrieved successfully",
        data=PlaybookResponse.model_validate(playbook),
    )


@router.patch("/{playbook_id}", response_model=APIResponse[PlaybookResponse])
async def update_playbook(
    playbook_id: uuid.UUID,
    update_in: PlaybookUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[PlaybookResponse]:
    """Update playbook metadata or lifecycle status."""
    service = PlaybookService(db)
    playbook = await service.update_playbook(playbook_id, update_in, updated_by_id=current_user.id)
    return APIResponse(
        message="Playbook updated successfully",
        data=PlaybookResponse.model_validate(playbook),
    )


@router.delete("/{playbook_id}", response_model=APIResponse[bool])
async def delete_playbook(
    playbook_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[bool]:
    """Delete playbook by UUID."""
    service = PlaybookService(db)
    success = await service.delete_playbook(playbook_id)
    return APIResponse(
        message="Playbook deleted successfully",
        data=success,
    )


@router.post("/{playbook_id}/steps", response_model=APIResponse[PlaybookStepResponse], status_code=status.HTTP_201_CREATED)
async def add_step(
    playbook_id: uuid.UUID,
    step_in: PlaybookStepCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[PlaybookStepResponse]:
    """Add a new execution step to a playbook."""
    service = PlaybookService(db)
    step = await service.add_step(playbook_id, step_in)
    return APIResponse(
        message=f"Step '{step.name}' added to playbook successfully",
        data=PlaybookStepResponse.model_validate(step),
    )


@router.patch("/{playbook_id}/steps/{step_id}", response_model=APIResponse[PlaybookStepResponse])
async def update_step(
    playbook_id: uuid.UUID,
    step_id: uuid.UUID,
    update_in: PlaybookStepUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[PlaybookStepResponse]:
    """Update step properties or configuration."""
    service = PlaybookService(db)
    step = await service.update_step(playbook_id, step_id, update_in)
    return APIResponse(
        message="Playbook step updated successfully",
        data=PlaybookStepResponse.model_validate(step),
    )


@router.delete("/{playbook_id}/steps/{step_id}", response_model=APIResponse[bool])
async def delete_step(
    playbook_id: uuid.UUID,
    step_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[bool]:
    """Delete a step from a playbook."""
    service = PlaybookService(db)
    success = await service.delete_step(playbook_id, step_id)
    return APIResponse(
        message="Playbook step deleted successfully",
        data=success,
    )


@router.post("/{playbook_id}/validate", response_model=APIResponse[PlaybookValidationResult])
async def validate_playbook(
    playbook_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[PlaybookValidationResult]:
    """Validate structure and step configuration of a playbook."""
    service = PlaybookService(db)
    result = await service.validate_playbook(playbook_id)
    return APIResponse(
        message="Playbook validation completed",
        data=result,
    )


from app.core.authorization import require_role, RoleEnum


@router.post("/{playbook_id}/execute", response_model=APIResponse[PlaybookExecutionResponse], status_code=status.HTTP_201_CREATED)
async def execute_playbook(
    playbook_id: uuid.UUID,
    exec_in: PlaybookExecutionCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_role([RoleEnum.SENIOR_ANALYST, RoleEnum.SOC_MANAGER, RoleEnum.ADMIN]))],
) -> APIResponse[PlaybookExecutionResponse]:
    """Trigger playbook execution."""
    exec_in.playbook_id = playbook_id
    service = PlaybookService(db)
    execution = await service.execute_playbook(exec_in, executed_by_id=current_user.id)
    return APIResponse(
        message=f"Playbook execution triggered (Status: {execution.status.value})",
        data=PlaybookExecutionResponse.model_validate(execution),
    )
