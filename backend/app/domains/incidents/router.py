"""
Incidents Domain REST API Endpoints Router.

Exposes production-ready REST API endpoints for security incident correlation,
lifecycle triage, assignment, severity updates, search/filtering, and case closure.
"""

import math
import uuid
from typing import Annotated
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.users.router import get_current_user
from app.models.user import User
from app.models.incident import (
    IncidentSeverity,
    IncidentPriority,
    IncidentStatus,
    IncidentCategory,
)
from app.domains.incidents.schemas import (
    IncidentCreate,
    IncidentUpdate,
    IncidentStatusUpdate,
    IncidentSeverityUpdate,
    IncidentAssignmentUpdate,
    IncidentClose,
    IncidentRead,
    IncidentFilterParams,
    IncidentSummaryStats,
)
from app.domains.incidents.services import IncidentService
from app.schemas.response import APIResponse, PaginatedResponse, PaginationMeta

router = APIRouter(prefix="/incidents", tags=["Incidents Domain"])


@router.post("/", response_model=APIResponse[IncidentRead], status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_in: IncidentCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[IncidentRead]:
    """Create a new security incident or aggregate correlated alerts into an investigation case."""
    service = IncidentService(db)
    incident = await service.create_incident(incident_in, created_by_user_id=current_user.id)
    return APIResponse(
        message=f"Incident '{incident.incident_code}' created successfully",
        data=IncidentRead.model_validate(incident),
    )


@router.get("/", response_model=PaginatedResponse[IncidentRead])
async def list_incidents(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    query: Annotated[str | None, Query(description="Search title, description, or incident code")] = None,
    category: Annotated[IncidentCategory | None, Query(description="Filter by security category")] = None,
    severity: Annotated[IncidentSeverity | None, Query(description="Filter severity level")] = None,
    priority: Annotated[IncidentPriority | None, Query(description="Filter priority level")] = None,
    status: Annotated[IncidentStatus | None, Query(description="Filter lifecycle status")] = None,
    assigned_to_user_id: Annotated[uuid.UUID | None, Query(description="Filter assigned analyst")] = None,
    min_risk_score: Annotated[float | None, Query(ge=0.0, le=100.0, description="Minimum risk score")] = None,
    sort_by: Annotated[str, Query(description="Field to sort by (created_at, risk_score, severity, priority)")] = "created_at",
    sort_order: Annotated[str, Query(description="Sort direction (asc or desc)")] = "desc",
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[IncidentRead]:
    """Query, search, filter, and sort security incidents with pagination."""
    params = IncidentFilterParams(
        query=query,
        category=category,
        severity=severity,
        priority=priority,
        status=status,
        assigned_to_user_id=assigned_to_user_id,
        min_risk_score=min_risk_score,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )
    service = IncidentService(db)
    incidents, total_items = await service.list_incidents(params)
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 0

    return PaginatedResponse(
        data=[IncidentRead.model_validate(inc) for inc in incidents],
        meta=PaginationMeta(
            page=page,
            page_size=page_size,
            total_items=total_items,
            total_pages=total_pages,
        ),
    )


@router.get("/summary", response_model=APIResponse[IncidentSummaryStats])
async def get_incidents_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[IncidentSummaryStats]:
    """Retrieve aggregated summary statistics and metrics across all incidents."""
    service = IncidentService(db)
    stats = await service.get_summary_stats()
    return APIResponse(
        message="Incident summary statistics retrieved",
        data=stats,
    )


@router.get("/{incident_id}", response_model=APIResponse[IncidentRead])
async def get_incident_detail(
    incident_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[IncidentRead]:
    """Retrieve detailed information for a specific incident by UUID."""
    service = IncidentService(db)
    incident = await service.get_incident(incident_id)
    return APIResponse(
        message="Incident details retrieved",
        data=IncidentRead.model_validate(incident),
    )


@router.patch("/{incident_id}", response_model=APIResponse[IncidentRead])
async def update_incident(
    incident_id: uuid.UUID,
    update_in: IncidentUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[IncidentRead]:
    """Partially update incident fields, investigation findings, or containment status."""
    service = IncidentService(db)
    incident = await service.update_incident(incident_id, update_in)
    return APIResponse(
        message="Incident updated successfully",
        data=IncidentRead.model_validate(incident),
    )


@router.post("/{incident_id}/assign", response_model=APIResponse[IncidentRead])
async def assign_incident(
    incident_id: uuid.UUID,
    assignment_in: IncidentAssignmentUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[IncidentRead]:
    """Assign incident to an analyst and transition status from OPEN to TRIAGED."""
    service = IncidentService(db)
    incident = await service.assign_incident(incident_id, assignment_in)
    return APIResponse(
        message="Incident assigned successfully",
        data=IncidentRead.model_validate(incident),
    )


@router.patch("/{incident_id}/status", response_model=APIResponse[IncidentRead])
async def update_incident_status(
    incident_id: uuid.UUID,
    status_in: IncidentStatusUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[IncidentRead]:
    """Transition incident state machine lifecycle status."""
    service = IncidentService(db)
    incident = await service.update_status(incident_id, status_in)
    return APIResponse(
        message=f"Incident status updated to {status_in.status.value}",
        data=IncidentRead.model_validate(incident),
    )


@router.patch("/{incident_id}/severity", response_model=APIResponse[IncidentRead])
async def update_incident_severity(
    incident_id: uuid.UUID,
    severity_in: IncidentSeverityUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[IncidentRead]:
    """Update incident severity classification and re-evaluate operational priority."""
    service = IncidentService(db)
    incident = await service.update_severity(incident_id, severity_in)
    return APIResponse(
        message=f"Incident severity updated to {severity_in.severity.value}",
        data=IncidentRead.model_validate(incident),
    )


@router.post("/{incident_id}/close", response_model=APIResponse[IncidentRead])
async def close_incident(
    incident_id: uuid.UUID,
    close_in: IncidentClose,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[IncidentRead]:
    """Formally close incident case with mandatory root cause analysis and resolution summary."""
    service = IncidentService(db)
    incident = await service.close_incident(incident_id, close_in)
    return APIResponse(
        message=f"Incident '{incident.incident_code}' closed successfully",
        data=IncidentRead.model_validate(incident),
    )
