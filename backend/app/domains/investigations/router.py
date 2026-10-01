"""
Investigations Domain REST API Endpoints Router.

Exposes endpoints for starting, updating, assigning, phase managing, findings recording,
and closing security investigation sessions.
"""

import math
import uuid
from typing import Annotated, List
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.users.router import get_current_user
from app.models.user import User
from app.models.investigation import (
    InvestigationStatus,
    InvestigationPriority,
    InvestigationPhase,
)
from app.domains.investigations.schemas import (
    InvestigationCreate,
    InvestigationUpdate,
    InvestigationStatusUpdate,
    InvestigationPriorityUpdate,
    InvestigationAssignmentUpdate,
    InvestigationNotesUpdate,
    InvestigationFindingsUpdate,
    InvestigationRecommendationsUpdate,
    InvestigationRead,
    InvestigationFilterParams,
    InvestigationSummaryStats,
)
from app.domains.investigations.services import InvestigationService
from app.schemas.response import APIResponse, PaginatedResponse, PaginationMeta

router = APIRouter(prefix="/investigations", tags=["Investigations Domain"])


@router.post("/", response_model=APIResponse[InvestigationRead], status_code=status.HTTP_201_CREATED)
async def start_investigation(
    investigation_in: InvestigationCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[InvestigationRead]:
    """Start a new investigation session for a security incident."""
    service = InvestigationService(db)
    investigation = await service.start_investigation(investigation_in, created_by_user_id=current_user.id)
    return APIResponse(
        message=f"Investigation '{investigation.name}' initiated successfully",
        data=InvestigationRead.model_validate(investigation),
    )


@router.get("/", response_model=PaginatedResponse[InvestigationRead])
async def list_investigations(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    query: Annotated[str | None, Query(description="Search name, description, or summary")] = None,
    incident_id: Annotated[uuid.UUID | None, Query(description="Filter by incident UUID")] = None,
    status: Annotated[InvestigationStatus | None, Query(description="Filter lifecycle status")] = None,
    priority: Annotated[InvestigationPriority | None, Query(description="Filter priority level")] = None,
    phase: Annotated[InvestigationPhase | None, Query(description="Filter operational phase")] = None,
    assigned_investigator_id: Annotated[uuid.UUID | None, Query(description="Filter assigned investigator")] = None,
    min_risk_score: Annotated[float | None, Query(ge=0.0, le=100.0, description="Minimum risk score")] = None,
    sort_by: Annotated[str, Query(description="Field to sort by (started_at, risk_score, priority)")] = "started_at",
    sort_order: Annotated[str, Query(description="Sort direction (asc or desc)")] = "desc",
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[InvestigationRead]:
    """Search, filter, and paginate security investigations."""
    params = InvestigationFilterParams(
        query=query,
        incident_id=incident_id,
        status=status,
        priority=priority,
        phase=phase,
        assigned_investigator_id=assigned_investigator_id,
        min_risk_score=min_risk_score,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )
    service = InvestigationService(db)
    investigations, total_items = await service.list_investigations(params)
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 0

    return PaginatedResponse(
        data=[InvestigationRead.model_validate(inv) for inv in investigations],
        meta=PaginationMeta(
            page=page,
            page_size=page_size,
            total_items=total_items,
            total_pages=total_pages,
        ),
    )


@router.get("/summary", response_model=APIResponse[InvestigationSummaryStats])
async def get_investigations_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[InvestigationSummaryStats]:
    """Retrieve aggregated summary statistics across active investigations."""
    service = InvestigationService(db)
    stats = await service.get_summary_stats()
    return APIResponse(
        message="Investigation summary metrics retrieved",
        data=stats,
    )


@router.get("/incident/{incident_id}", response_model=APIResponse[List[InvestigationRead]])
async def list_by_incident(
    incident_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[InvestigationRead]]:
    """Retrieve all active investigation sessions for a specific Incident."""
    service = InvestigationService(db)
    investigations = await service.list_by_incident(incident_id)
    return APIResponse(
        message=f"Retrieved {len(investigations)} investigations for incident",
        data=[InvestigationRead.model_validate(inv) for inv in investigations],
    )


@router.get("/{investigation_id}", response_model=APIResponse[InvestigationRead])
async def get_investigation_detail(
    investigation_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[InvestigationRead]:
    """Retrieve detailed information for a specific investigation by UUID."""
    service = InvestigationService(db)
    investigation = await service.get_investigation(investigation_id)
    return APIResponse(
        message="Investigation details retrieved",
        data=InvestigationRead.model_validate(investigation),
    )


@router.patch("/{investigation_id}", response_model=APIResponse[InvestigationRead])
async def update_investigation(
    investigation_id: uuid.UUID,
    update_in: InvestigationUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[InvestigationRead]:
    """Partially update investigation properties or settings."""
    service = InvestigationService(db)
    investigation = await service.update_investigation(investigation_id, update_in)
    return APIResponse(
        message="Investigation updated successfully",
        data=InvestigationRead.model_validate(investigation),
    )


@router.post("/{investigation_id}/assign", response_model=APIResponse[InvestigationRead])
async def assign_investigator(
    investigation_id: uuid.UUID,
    assignment_in: InvestigationAssignmentUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[InvestigationRead]:
    """Assign an investigator user to the session."""
    service = InvestigationService(db)
    investigation = await service.assign_investigator(investigation_id, assignment_in)
    return APIResponse(
        message="Investigator assigned successfully",
        data=InvestigationRead.model_validate(investigation),
    )


@router.post("/{investigation_id}/notes", response_model=APIResponse[InvestigationRead])
async def add_notes(
    investigation_id: uuid.UUID,
    notes_in: InvestigationNotesUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[InvestigationRead]:
    """Append investigation summary notes."""
    service = InvestigationService(db)
    investigation = await service.add_notes(investigation_id, notes_in)
    return APIResponse(
        message="Notes appended to investigation",
        data=InvestigationRead.model_validate(investigation),
    )


@router.put("/{investigation_id}/findings", response_model=APIResponse[InvestigationRead])
async def update_findings(
    investigation_id: uuid.UUID,
    findings_in: InvestigationFindingsUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[InvestigationRead]:
    """Update investigation findings dictionary and confidence score."""
    service = InvestigationService(db)
    investigation = await service.update_findings(investigation_id, findings_in)
    return APIResponse(
        message="Investigation findings updated",
        data=InvestigationRead.model_validate(investigation),
    )


@router.put("/{investigation_id}/recommendations", response_model=APIResponse[InvestigationRead])
async def update_recommendations(
    investigation_id: uuid.UUID,
    recs_in: InvestigationRecommendationsUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[InvestigationRead]:
    """Update actionable response recommendations list."""
    service = InvestigationService(db)
    investigation = await service.update_recommendations(investigation_id, recs_in)
    return APIResponse(
        message="Investigation recommendations updated",
        data=InvestigationRead.model_validate(investigation),
    )


@router.patch("/{investigation_id}/status", response_model=APIResponse[InvestigationRead])
async def update_investigation_status(
    investigation_id: uuid.UUID,
    status_in: InvestigationStatusUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[InvestigationRead]:
    """Transition investigation state machine lifecycle status."""
    service = InvestigationService(db)
    investigation = await service.update_status(investigation_id, status_in)
    return APIResponse(
        message=f"Investigation status updated to {status_in.status.value}",
        data=InvestigationRead.model_validate(investigation),
    )


@router.patch("/{investigation_id}/priority", response_model=APIResponse[InvestigationRead])
async def update_investigation_priority(
    investigation_id: uuid.UUID,
    priority_in: InvestigationPriorityUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[InvestigationRead]:
    """Update investigation priority rating."""
    service = InvestigationService(db)
    investigation = await service.update_priority(investigation_id, priority_in)
    return APIResponse(
        message=f"Investigation priority updated to {priority_in.priority.value}",
        data=InvestigationRead.model_validate(investigation),
    )


@router.post("/{investigation_id}/close", response_model=APIResponse[InvestigationRead])
async def close_investigation(
    investigation_id: uuid.UUID,
    summary: Annotated[str | None, Query(description="Resolution summary")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> APIResponse[InvestigationRead]:
    """Conclude investigation session."""
    service = InvestigationService(db)
    investigation = await service.close_investigation(investigation_id, summary)
    return APIResponse(
        message="Investigation completed and closed",
        data=InvestigationRead.model_validate(investigation),
    )


@router.delete("/{investigation_id}", response_model=APIResponse[dict])
async def delete_investigation(
    investigation_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Soft delete investigation session."""
    service = InvestigationService(db)
    success = await service.soft_delete_investigation(investigation_id)
    return APIResponse(
        message="Investigation soft deleted successfully",
        data={"investigation_id": str(investigation_id), "deleted": success},
    )
