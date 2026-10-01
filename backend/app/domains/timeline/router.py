"""
Timeline Domain REST API Endpoints Router.

Exposes REST API routes for chronological event ingestion, search, multi-field filtering,
investigation timeline assembly, updating, and soft deletion.
"""

import math
import uuid
from datetime import datetime
from typing import Annotated, List
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.users.router import get_current_user
from app.models.user import User
from app.models.timeline import TimelineEventType, TimelineEventCategory, TimelineEventSeverity
from app.domains.timeline.schemas import (
    TimelineEventCreate,
    TimelineEventUpdate,
    TimelineEventRead,
    TimelineFilterParams,
    TimelineSummaryStats,
)
from app.domains.timeline.services import TimelineService
from app.schemas.response import APIResponse, PaginatedResponse, PaginationMeta

router = APIRouter(prefix="/timeline", tags=["Timeline Domain"])


@router.post("/", response_model=APIResponse[TimelineEventRead], status_code=status.HTTP_201_CREATED)
async def create_timeline_event(
    event_in: TimelineEventCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[TimelineEventRead]:
    """Ingest a new chronological security event into the investigation timeline."""
    service = TimelineService(db)
    event = await service.create_event(event_in)
    return APIResponse(
        message="Timeline event recorded successfully",
        data=TimelineEventRead.model_validate(event),
    )


@router.get("/", response_model=PaginatedResponse[TimelineEventRead])
async def list_timeline_events(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    query: Annotated[str | None, Query(description="Search term matching description, host, user, process, file, or network")] = None,
    investigation_id: Annotated[uuid.UUID | None, Query(description="Filter by Investigation UUID")] = None,
    incident_id: Annotated[uuid.UUID | None, Query(description="Filter by Incident UUID")] = None,
    evidence_id: Annotated[uuid.UUID | None, Query(description="Filter by Evidence artifact UUID")] = None,
    event_type: Annotated[TimelineEventType | None, Query(description="Filter by event type")] = None,
    event_category: Annotated[TimelineEventCategory | None, Query(description="Filter by event category")] = None,
    severity: Annotated[TimelineEventSeverity | None, Query(description="Filter by severity rating")] = None,
    hostname: Annotated[str | None, Query(description="Filter by hostname")] = None,
    username: Annotated[str | None, Query(description="Filter by username")] = None,
    start_time: Annotated[datetime | None, Query(description="Filter events starting at timestamp")] = None,
    end_time: Annotated[datetime | None, Query(description="Filter events ending at timestamp")] = None,
    sort_by: Annotated[str, Query(description="Field to sort by (timestamp, created_at, severity)")] = "timestamp",
    sort_order: Annotated[str, Query(description="Sort direction (asc or desc)")] = "asc",
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[TimelineEventRead]:
    """Search, filter, sort, and paginate chronological security timeline events."""
    params = TimelineFilterParams(
        query=query,
        investigation_id=investigation_id,
        incident_id=incident_id,
        evidence_id=evidence_id,
        event_type=event_type,
        event_category=event_category,
        severity=severity,
        hostname=hostname,
        username=username,
        start_time=start_time,
        end_time=end_time,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )
    service = TimelineService(db)
    events, total_items = await service.list_events(params)
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 0

    return PaginatedResponse(
        data=[TimelineEventRead.model_validate(ev) for ev in events],
        meta=PaginationMeta(
            page=page,
            page_size=page_size,
            total_items=total_items,
            total_pages=total_pages,
        ),
    )


@router.get("/summary", response_model=APIResponse[TimelineSummaryStats])
async def get_timeline_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[TimelineSummaryStats]:
    """Retrieve aggregate timeline metrics and categorization statistics."""
    service = TimelineService(db)
    stats = await service.get_summary_stats()
    return APIResponse(
        message="Timeline summary statistics retrieved",
        data=stats,
    )


@router.get("/investigation/{investigation_id}", response_model=APIResponse[List[TimelineEventRead]])
async def list_by_investigation(
    investigation_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[TimelineEventRead]]:
    """Retrieve all chronological timeline events for a specific Investigation."""
    service = TimelineService(db)
    events = await service.list_by_investigation(investigation_id)
    return APIResponse(
        message=f"Retrieved {len(events)} timeline events for investigation",
        data=[TimelineEventRead.model_validate(ev) for ev in events],
    )


@router.get("/incident/{incident_id}", response_model=APIResponse[List[TimelineEventRead]])
async def list_by_incident(
    incident_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[TimelineEventRead]]:
    """Retrieve all chronological timeline events for a specific Incident."""
    service = TimelineService(db)
    events = await service.list_by_incident(incident_id)
    return APIResponse(
        message=f"Retrieved {len(events)} timeline events for incident",
        data=[TimelineEventRead.model_validate(ev) for ev in events],
    )


@router.get("/{event_id}", response_model=APIResponse[TimelineEventRead])
async def get_timeline_event(
    event_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[TimelineEventRead]:
    """Retrieve details for a specific timeline event by UUID."""
    service = TimelineService(db)
    event = await service.get_event(event_id)
    return APIResponse(
        message="Timeline event details retrieved",
        data=TimelineEventRead.model_validate(event),
    )


@router.put("/{event_id}", response_model=APIResponse[TimelineEventRead])
async def update_timeline_event(
    event_id: uuid.UUID,
    update_in: TimelineEventUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[TimelineEventRead]:
    """Update details of a timeline event."""
    service = TimelineService(db)
    event = await service.update_event(event_id, update_in)
    return APIResponse(
        message="Timeline event updated successfully",
        data=TimelineEventRead.model_validate(event),
    )


@router.delete("/{event_id}", response_model=APIResponse[dict])
async def delete_timeline_event(
    event_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Soft delete a security timeline event."""
    service = TimelineService(db)
    success = await service.delete_event(event_id)
    return APIResponse(
        message="Timeline event deleted successfully",
        data={"event_id": str(event_id), "deleted": success},
    )
