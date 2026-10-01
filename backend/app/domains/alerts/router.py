"""
Alerts Domain REST API Endpoints Router.

Exposes REST endpoints for ingesting, querying, updating, and triaging security alerts.
"""

import math
import uuid
from typing import Annotated
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.users.router import get_current_user
from app.models.user import User
from app.models.alert import AlertSeverity, AlertStatus
from app.domains.alerts.schemas import (
    AlertCreate,
    AlertUpdate,
    AlertRead,
    AlertFilterParams,
    AlertSummaryStats,
    AlertStatusUpdate,
    BulkAlertStatusUpdate,
)
from app.domains.alerts.services import AlertService
from app.schemas.response import APIResponse, PaginatedResponse, PaginationMeta

router = APIRouter(prefix="/alerts", tags=["Alerts Domain"])


@router.post("/", response_model=APIResponse[AlertRead], status_code=status.HTTP_201_CREATED)
async def ingest_alert(
    alert_in: AlertCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[AlertRead]:
    """Ingest a new security detection alert from SIEM/EDR log streams."""
    service = AlertService(db)
    alert = await service.ingest_alert(alert_in)
    return APIResponse(
        message="Security alert ingested successfully",
        data=AlertRead.model_validate(alert),
    )


@router.get("/", response_model=PaginatedResponse[AlertRead])
async def list_alerts(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    query: Annotated[str | None, Query(description="Search title/description")] = None,
    source: Annotated[str | None, Query(description="Filter log source")] = None,
    severity: Annotated[AlertSeverity | None, Query(description="Filter severity level")] = None,
    status: Annotated[AlertStatus | None, Query(description="Filter lifecycle status")] = None,
    assigned_user_id: Annotated[uuid.UUID | None, Query(description="Filter assigned analyst")] = None,
    incident_id: Annotated[uuid.UUID | None, Query(description="Filter associated incident")] = None,
    min_risk_score: Annotated[float | None, Query(ge=0.0, le=100.0, description="Minimum risk score")] = None,
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[AlertRead]:
    """Query, search, and filter security alerts with pagination."""
    params = AlertFilterParams(
        query=query,
        source=source,
        severity=severity,
        status=status,
        assigned_user_id=assigned_user_id,
        incident_id=incident_id,
        min_risk_score=min_risk_score,
        page=page,
        page_size=page_size,
    )
    service = AlertService(db)
    alerts, total_items = await service.list_alerts(params)
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 0

    return PaginatedResponse(
        data=[AlertRead.model_validate(a) for a in alerts],
        meta=PaginationMeta(
            page=page,
            page_size=page_size,
            total_items=total_items,
            total_pages=total_pages,
        ),
    )


@router.get("/summary", response_model=APIResponse[AlertSummaryStats])
async def get_alerts_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[AlertSummaryStats]:
    """Retrieve aggregated summary metrics and statistics across all alerts."""
    service = AlertService(db)
    stats = await service.get_summary_stats()
    return APIResponse(
        message="Alert summary metrics retrieved",
        data=stats,
    )


@router.get("/{alert_id}", response_model=APIResponse[AlertRead])
async def get_alert_detail(
    alert_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[AlertRead]:
    """Retrieve detailed information for a specific alert by UUID."""
    service = AlertService(db)
    alert = await service.get_alert(alert_id)
    return APIResponse(
        message="Alert details retrieved",
        data=AlertRead.model_validate(alert),
    )


@router.patch("/{alert_id}", response_model=APIResponse[AlertRead])
async def update_alert(
    alert_id: uuid.UUID,
    update_in: AlertUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[AlertRead]:
    """Partially update alert details, severity rating, assignment, or IOC attributes."""
    service = AlertService(db)
    alert = await service.update_alert(alert_id, update_in)
    return APIResponse(
        message="Alert updated successfully",
        data=AlertRead.model_validate(alert),
    )


@router.patch("/{alert_id}/status", response_model=APIResponse[AlertRead])
async def update_alert_status(
    alert_id: uuid.UUID,
    status_in: AlertStatusUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[AlertRead]:
    """Transition alert triage lifecycle state (NEW, IN_PROGRESS, TRIAGED, RESOLVED, FALSE_POSITIVE)."""
    service = AlertService(db)
    alert = await service.update_status(alert_id, status_in)
    return APIResponse(
        message=f"Alert status updated to {status_in.status.value}",
        data=AlertRead.model_validate(alert),
    )


@router.post("/bulk-status", response_model=APIResponse[dict])
async def bulk_update_status(
    bulk_in: BulkAlertStatusUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Bulk update triage status across multiple security alerts."""
    service = AlertService(db)
    updated_count = await service.bulk_update_status(bulk_in)
    return APIResponse(
        message=f"Bulk updated status for {updated_count} alerts",
        data={"updated_count": updated_count, "new_status": bulk_in.status.value},
    )
