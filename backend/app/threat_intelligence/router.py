"""
Threat Intelligence Domain REST API Router.

Exposes REST endpoints for IOC management, lookup, multi-provider enrichment,
feeds, relationships, and threat statistics.
"""

import uuid
from typing import Annotated, List
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.users.router import get_current_user
from app.models.user import User
from app.threat_intelligence.models import IOCType, ThreatReputationLevel
from app.threat_intelligence.schemas import (
    IOCCreate,
    IOCUpdate,
    IOCRead,
    IOCFilterParams,
    ThreatFeedCreate,
    ThreatFeedRead,
    IOCEnrichmentRequest,
    IOCRelationshipCreate,
    IOCRelationshipRead,
    ThreatIntelStatisticsRead,
)
from app.threat_intelligence.enrichment import EnrichmentSummary
from app.threat_intelligence.services import ThreatIntelService
from app.schemas.response import APIResponse, PaginatedResponse

router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence Engine"])


@router.get("/iocs", response_model=PaginatedResponse[IOCRead])
async def list_iocs(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    query: Annotated[str | None, Query(description="Search keyword")] = None,
    ioc_type: Annotated[IOCType | None, Query(description="Filter by IOC type")] = None,
    reputation: Annotated[ThreatReputationLevel | None, Query(description="Filter by reputation")] = None,
    is_active: Annotated[bool | None, Query(description="Filter active status")] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> PaginatedResponse[IOCRead]:
    """Search and filter IOCs with pagination."""
    service = ThreatIntelService(db)
    params = IOCFilterParams(
        query=query,
        ioc_type=ioc_type,
        reputation=reputation,
        is_active=is_active,
        page=page,
        page_size=page_size,
    )
    items, total = await service.list_iocs(params)
    return PaginatedResponse.create(items=items, total=total, page=page, page_size=page_size)


@router.post("/iocs", response_model=APIResponse[IOCRead], status_code=status.HTTP_201_CREATED)
async def create_ioc(
    data: IOCCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[IOCRead]:
    """Create a new Indicator of Compromise (IOC)."""
    service = ThreatIntelService(db)
    ioc = await service.create_ioc(data)
    return APIResponse(message=f"IOC '{ioc.value}' registered successfully", data=ioc)


@router.get("/iocs/{ioc_id}", response_model=APIResponse[IOCRead])
async def get_ioc(
    ioc_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[IOCRead]:
    """Retrieve details for a specific IOC."""
    service = ThreatIntelService(db)
    ioc = await service.get_ioc(ioc_id)
    return APIResponse(message="IOC details retrieved", data=ioc)


@router.put("/iocs/{ioc_id}", response_model=APIResponse[IOCRead])
async def update_ioc(
    ioc_id: uuid.UUID,
    data: IOCUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[IOCRead]:
    """Update an existing IOC."""
    service = ThreatIntelService(db)
    ioc = await service.update_ioc(ioc_id, data)
    return APIResponse(message="IOC updated successfully", data=ioc)


@router.delete("/iocs/{ioc_id}", response_model=APIResponse[dict])
async def delete_ioc(
    ioc_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Delete an IOC."""
    service = ThreatIntelService(db)
    await service.delete_ioc(ioc_id)
    return APIResponse(message="IOC deleted successfully", data={"success": True})


@router.get("/lookup", response_model=APIResponse[dict])
async def lookup_ioc(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    value: Annotated[str, Query(description="IOC value string to lookup")],
) -> APIResponse[dict]:
    """Perform instant lookup and enrichment for an IOC string value."""
    service = ThreatIntelService(db)
    ioc, enrichment = await service.lookup_ioc(value)
    return APIResponse(
        message=f"Threat intelligence lookup completed for '{value}'",
        data={"ioc": ioc.model_dump(), "enrichment": enrichment.model_dump()},
    )


@router.post("/enrich", response_model=APIResponse[EnrichmentSummary])
async def enrich_ioc(
    request: IOCEnrichmentRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[EnrichmentSummary]:
    """Request multi-provider threat intelligence enrichment for an IOC."""
    service = ThreatIntelService(db)
    summary = await service.enrich_ioc(request)
    return APIResponse(message=f"IOC '{request.ioc_value}' enriched successfully", data=summary)


@router.get("/feeds", response_model=APIResponse[List[ThreatFeedRead]])
async def list_feeds(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[ThreatFeedRead]]:
    """List registered threat intelligence feeds."""
    service = ThreatIntelService(db)
    feeds = await service.list_feeds()
    return APIResponse(message="Threat feeds retrieved", data=feeds)


@router.post("/feeds", response_model=APIResponse[ThreatFeedRead], status_code=status.HTTP_201_CREATED)
async def create_feed(
    data: ThreatFeedCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[ThreatFeedRead]:
    """Register a new threat feed."""
    service = ThreatIntelService(db)
    feed = await service.create_feed(data)
    return APIResponse(message=f"Threat feed '{feed.name}' created", data=feed)


@router.post("/relationships", response_model=APIResponse[IOCRelationshipRead], status_code=status.HTTP_201_CREATED)
async def create_relationship(
    data: IOCRelationshipCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[IOCRelationshipRead]:
    """Create a relationship mapping between two IOCs."""
    service = ThreatIntelService(db)
    rel = await service.create_relationship(data)
    return APIResponse(message="IOC relationship created", data=rel)


@router.get("/statistics", response_model=APIResponse[ThreatIntelStatisticsRead])
async def get_statistics(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[ThreatIntelStatisticsRead]:
    """Retrieve Threat Intelligence metrics and statistics."""
    service = ThreatIntelService(db)
    stats = await service.get_statistics()
    return APIResponse(message="Threat intelligence statistics generated", data=stats)
