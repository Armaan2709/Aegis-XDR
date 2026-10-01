"""
Case Management REST API Router.

Exposes REST API endpoints for Case CRUD, filtering, pagination, search, assignments,
domain entity linking, threaded comments, attachment metadata, tasks, approvals,
activity audit timelines, and aggregated statistics.
"""

import math
import uuid
from typing import Annotated, List
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.users.router import get_current_user
from app.models.user import User
from app.case_management.models import CaseStatus, CaseSeverity, CasePriority
from app.case_management.schemas import (
    CaseCreate,
    CaseUpdate,
    CaseClose,
    CaseLinkUpdate,
    CaseResponse,
    CaseFilterParams,
    CaseCommentCreate,
    CaseCommentUpdate,
    CaseCommentResponse,
    CaseAttachmentCreate,
    CaseAttachmentResponse,
    CaseTaskCreate,
    CaseTaskUpdate,
    CaseTaskResponse,
    CaseApprovalCreate,
    CaseApprovalDecision,
    CaseApprovalResponse,
    CaseActivityResponse,
    CaseAssignmentCreate,
    CaseAssignmentResponse,
    CaseSummaryStats,
)
from app.case_management.services import CaseService
from app.schemas.response import APIResponse, PaginatedResponse, PaginationMeta

router = APIRouter(prefix="/cases", tags=["Case Management Domain"])


@router.post("/", response_model=APIResponse[CaseResponse], status_code=status.HTTP_201_CREATED)
async def create_case(
    case_in: CaseCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseResponse]:
    """Create a new security case workspace."""
    service = CaseService(db)
    case = await service.create_case(case_in, created_by_id=current_user.id)
    return APIResponse(
        message=f"Case '{case.case_number}' created successfully",
        data=CaseResponse.model_validate(case),
    )


@router.get("/", response_model=PaginatedResponse[CaseResponse])
async def list_cases(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    query: Annotated[str | None, Query(description="Search title, description, or case number")] = None,
    status: Annotated[CaseStatus | None, Query(description="Filter by case status")] = None,
    severity: Annotated[CaseSeverity | None, Query(description="Filter by severity level")] = None,
    priority: Annotated[CasePriority | None, Query(description="Filter by priority level")] = None,
    owner_id: Annotated[uuid.UUID | None, Query(description="Filter owner analyst UUID")] = None,
    assigned_user_id: Annotated[uuid.UUID | None, Query(description="Filter assigned analyst UUID")] = None,
    sla_breached: Annotated[bool | None, Query(description="Filter SLA breach state")] = None,
    sort_by: Annotated[str, Query(description="Sort field (created_at, priority, severity)")] = "created_at",
    sort_order: Annotated[str, Query(description="Sort direction (asc, desc)")] = "desc",
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[CaseResponse]:
    """Search, filter, sort, and paginate cases."""
    params = CaseFilterParams(
        query=query,
        status=status,
        severity=severity,
        priority=priority,
        owner_id=owner_id,
        assigned_user_id=assigned_user_id,
        sla_breached=sla_breached,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )
    service = CaseService(db)
    cases, total_items = await service.list_cases(params)
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 0

    return PaginatedResponse(
        data=[CaseResponse.model_validate(c) for c in cases],
        meta=PaginationMeta(
            page=page,
            page_size=page_size,
            total_items=total_items,
            total_pages=total_pages,
        ),
    )


@router.get("/statistics", response_model=APIResponse[CaseSummaryStats])
async def get_case_statistics(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseSummaryStats]:
    """Retrieve aggregated case workspace operational metrics."""
    service = CaseService(db)
    stats = await service.get_case_statistics()
    return APIResponse(
        message="Case summary statistics retrieved successfully",
        data=stats,
    )


@router.get("/pending-approvals", response_model=APIResponse[List[CaseApprovalResponse]])
async def list_all_pending_approvals(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[CaseApprovalResponse]]:
    """List all pending governance approval requests across all cases."""
    service = CaseService(db)
    approvals = await service.list_all_pending_approvals()
    return APIResponse(
        message="All pending case approvals retrieved successfully",
        data=[CaseApprovalResponse.model_validate(a) for a in approvals],
    )


@router.get("/{case_id}", response_model=APIResponse[CaseResponse])
async def get_case_detail(
    case_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseResponse]:
    """Retrieve detailed case workspace information by UUID."""
    service = CaseService(db)
    case = await service.get_case(case_id)
    return APIResponse(
        message="Case details retrieved successfully",
        data=CaseResponse.model_validate(case),
    )


@router.patch("/{case_id}", response_model=APIResponse[CaseResponse])
async def update_case(
    case_id: uuid.UUID,
    update_in: CaseUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseResponse]:
    """Partially update case properties."""
    service = CaseService(db)
    case = await service.update_case(case_id, update_in, actor_id=current_user.id)
    return APIResponse(
        message="Case updated successfully",
        data=CaseResponse.model_validate(case),
    )


@router.post("/{case_id}/close", response_model=APIResponse[CaseResponse])
async def close_case(
    case_id: uuid.UUID,
    close_in: CaseClose,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseResponse]:
    """Close case with mandatory closure summary notes."""
    service = CaseService(db)
    case = await service.close_case(case_id, close_in, actor_id=current_user.id)
    return APIResponse(
        message=f"Case '{case.case_number}' closed successfully",
        data=CaseResponse.model_validate(case),
    )


# ==========================================
# Analyst Assignments
# ==========================================

@router.post("/{case_id}/assignments", response_model=APIResponse[CaseAssignmentResponse], status_code=status.HTTP_201_CREATED)
async def assign_analyst(
    case_id: uuid.UUID,
    assign_in: CaseAssignmentCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseAssignmentResponse]:
    """Assign an analyst to a case."""
    service = CaseService(db)
    assignment = await service.assign_analyst(case_id, assign_in, assigned_by_id=current_user.id)
    return APIResponse(
        message="Analyst assigned successfully",
        data=CaseAssignmentResponse.model_validate(assignment),
    )


@router.delete("/{case_id}/assignments/{user_id}", response_model=APIResponse[bool])
async def remove_analyst(
    case_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[bool]:
    """Remove an analyst assignment from a case."""
    service = CaseService(db)
    success = await service.remove_analyst(case_id, user_id, actor_id=current_user.id)
    return APIResponse(
        message="Analyst assignment removed successfully",
        data=success,
    )


# ==========================================
# Domain Entity Links
# ==========================================

@router.post("/{case_id}/links", response_model=APIResponse[CaseResponse])
async def link_entity(
    case_id: uuid.UUID,
    link_in: CaseLinkUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseResponse]:
    """Link an incident, investigation, evidence, timeline, MITRE technique, or threat indicator to case."""
    service = CaseService(db)
    case = await service.link_entity(case_id, link_in, actor_id=current_user.id)
    return APIResponse(
        message=f"Entity '{link_in.entity_id}' linked to case successfully",
        data=CaseResponse.model_validate(case),
    )


# ==========================================
# Comments
# ==========================================

@router.get("/{case_id}/comments", response_model=APIResponse[List[CaseCommentResponse]])
async def list_comments(
    case_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[CaseCommentResponse]]:
    """List comments for a case."""
    service = CaseService(db)
    comments = await service.list_comments(case_id)
    return APIResponse(
        message="Case comments retrieved successfully",
        data=[CaseCommentResponse.model_validate(c) for c in comments],
    )


@router.post("/{case_id}/comments", response_model=APIResponse[CaseCommentResponse], status_code=status.HTTP_201_CREATED)
async def add_comment(
    case_id: uuid.UUID,
    comment_in: CaseCommentCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseCommentResponse]:
    """Add a Markdown comment or threaded reply to case."""
    service = CaseService(db)
    author_name = current_user.full_name or current_user.email
    comment = await service.add_comment(
        case_id, comment_in, author_id=current_user.id, author_name=author_name
    )
    return APIResponse(
        message="Comment added successfully",
        data=CaseCommentResponse.model_validate(comment),
    )


@router.patch("/{case_id}/comments/{comment_id}", response_model=APIResponse[CaseCommentResponse])
async def edit_comment(
    case_id: uuid.UUID,
    comment_id: uuid.UUID,
    update_in: CaseCommentUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseCommentResponse]:
    """Edit comment content."""
    service = CaseService(db)
    comment = await service.edit_comment(case_id, comment_id, update_in, actor_id=current_user.id)
    return APIResponse(
        message="Comment updated successfully",
        data=CaseCommentResponse.model_validate(comment),
    )


@router.delete("/{case_id}/comments/{comment_id}", response_model=APIResponse[CaseCommentResponse])
async def delete_comment(
    case_id: uuid.UUID,
    comment_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseCommentResponse]:
    """Soft delete comment."""
    service = CaseService(db)
    comment = await service.delete_comment(case_id, comment_id, actor_id=current_user.id)
    return APIResponse(
        message="Comment deleted successfully",
        data=CaseCommentResponse.model_validate(comment),
    )


# ==========================================
# Attachments Metadata
# ==========================================

@router.get("/{case_id}/attachments", response_model=APIResponse[List[CaseAttachmentResponse]])
async def list_attachments(
    case_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[CaseAttachmentResponse]]:
    """List attachment metadata records for a case."""
    service = CaseService(db)
    attachments = await service.list_attachments(case_id)
    return APIResponse(
        message="Attachments metadata retrieved successfully",
        data=[CaseAttachmentResponse.model_validate(a) for a in attachments],
    )


@router.post("/{case_id}/attachments", response_model=APIResponse[CaseAttachmentResponse], status_code=status.HTTP_201_CREATED)
async def add_attachment_metadata(
    case_id: uuid.UUID,
    attachment_in: CaseAttachmentCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseAttachmentResponse]:
    """Add attachment metadata to a case."""
    service = CaseService(db)
    attachment = await service.add_attachment_metadata(
        case_id, attachment_in, uploaded_by_id=current_user.id
    )
    return APIResponse(
        message="Attachment metadata added successfully",
        data=CaseAttachmentResponse.model_validate(attachment),
    )


# ==========================================
# Tasks
# ==========================================

@router.get("/{case_id}/tasks", response_model=APIResponse[List[CaseTaskResponse]])
async def list_tasks(
    case_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[CaseTaskResponse]]:
    """List operational tasks for a case."""
    service = CaseService(db)
    tasks = await service.list_tasks(case_id)
    return APIResponse(
        message="Case tasks retrieved successfully",
        data=[CaseTaskResponse.model_validate(t) for t in tasks],
    )


@router.post("/{case_id}/tasks", response_model=APIResponse[CaseTaskResponse], status_code=status.HTTP_201_CREATED)
async def create_task(
    case_id: uuid.UUID,
    task_in: CaseTaskCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseTaskResponse]:
    """Create a task for a case."""
    service = CaseService(db)
    task = await service.create_task(case_id, task_in, actor_id=current_user.id)
    return APIResponse(
        message="Case task created successfully",
        data=CaseTaskResponse.model_validate(task),
    )


@router.patch("/{case_id}/tasks/{task_id}", response_model=APIResponse[CaseTaskResponse])
async def update_task_status(
    case_id: uuid.UUID,
    task_id: uuid.UUID,
    update_in: CaseTaskUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseTaskResponse]:
    """Update task status or assignment."""
    service = CaseService(db)
    task = await service.update_task_status(case_id, task_id, update_in, actor_id=current_user.id)
    return APIResponse(
        message="Case task updated successfully",
        data=CaseTaskResponse.model_validate(task),
    )


# ==========================================
# Approvals
# ==========================================


@router.get("/{case_id}/approvals", response_model=APIResponse[List[CaseApprovalResponse]])

async def list_approvals(
    case_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[CaseApprovalResponse]]:
    """List governance approval requests for a case."""
    service = CaseService(db)
    approvals = await service.list_approvals(case_id)
    return APIResponse(
        message="Case approvals retrieved successfully",
        data=[CaseApprovalResponse.model_validate(a) for a in approvals],
    )


@router.post("/{case_id}/approvals", response_model=APIResponse[CaseApprovalResponse], status_code=status.HTTP_201_CREATED)
async def request_approval(
    case_id: uuid.UUID,
    approval_in: CaseApprovalCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CaseApprovalResponse]:
    """Submit approval request with auto-approval policy evaluation."""
    service = CaseService(db)
    approval = await service.request_approval(case_id, approval_in, actor_id=current_user.id)
    return APIResponse(
        message=f"Approval request submitted (Status: {approval.status.value})",
        data=CaseApprovalResponse.model_validate(approval),
    )


from app.core.authorization import require_role, RoleEnum


@router.post("/{case_id}/approvals/{approval_id}/decision", response_model=APIResponse[CaseApprovalResponse])
async def process_approval(
    case_id: uuid.UUID,
    approval_id: uuid.UUID,
    decision_in: CaseApprovalDecision,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_role([RoleEnum.SENIOR_ANALYST, RoleEnum.SOC_MANAGER, RoleEnum.ADMIN]))],
) -> APIResponse[CaseApprovalResponse]:
    """Record manual decision on approval request."""
    service = CaseService(db)
    approval = await service.process_approval(case_id, approval_id, decision_in, approver_id=current_user.id)
    return APIResponse(
        message=f"Approval decision recorded as {approval.status.value}",
        data=CaseApprovalResponse.model_validate(approval),
    )


# ==========================================
# Activity Audit Log
# ==========================================

@router.get("/{case_id}/activity", response_model=APIResponse[List[CaseActivityResponse]])
async def get_case_activity(
    case_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[CaseActivityResponse]]:
    """Retrieve audit timeline events for a case."""
    service = CaseService(db)
    activities = await service.get_case_activity(case_id)
    return APIResponse(
        message="Case activity audit log retrieved successfully",
        data=[CaseActivityResponse.model_validate(act) for act in activities],
    )
