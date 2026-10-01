"""
Threat Intelligence Domain Service Layer.

Orchestrates IOC lifecycle management, auto-type detection, normalization,
multi-provider enrichment evaluation, feeds, relationships, and stats.
"""

import uuid
from typing import List, Tuple, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.threat_intelligence.repositories import ThreatIntelRepository
from app.threat_intelligence.ioc import IOCValidator
from app.threat_intelligence.enrichment import ThreatEnrichmentEngine, EnrichmentSummary
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
from app.core.exceptions import NotFoundError, ConflictError
from app.core.logging import get_logger

logger = get_logger("domain.threat_intelligence")


class ThreatIntelService:
    """Application service for Threat Intelligence capabilities."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = ThreatIntelRepository(session)
        self.enrichment_engine = ThreatEnrichmentEngine()

    async def create_ioc(self, data: IOCCreate) -> IOCRead:
        """
        Create a new IOC entity with automatic type detection and normalization.
        """
        detected_type, normalized_val = IOCValidator.detect_and_normalize(data.value, explicit_type=data.ioc_type)

        existing = await self.repo.get_ioc_by_value(normalized_val)
        if existing:
            raise ConflictError(f"IOC with value '{data.value}' already exists.")

        ioc = await self.repo.create_ioc(data, normalized_val=normalized_val, detected_type=detected_type)
        logger.info("IOC created", ioc_id=str(ioc.id), type=ioc.ioc_type, value=ioc.value)
        return IOCRead.model_validate(ioc)

    async def get_ioc(self, ioc_id: uuid.UUID) -> IOCRead:
        """Retrieve an IOC by ID."""
        ioc = await self.repo.get_ioc_by_id(ioc_id)
        if not ioc:
            raise NotFoundError(f"IOC with ID '{ioc_id}' was not found.")
        return IOCRead.model_validate(ioc)

    async def lookup_ioc(self, raw_value: str) -> Tuple[IOCRead, EnrichmentSummary]:
        """
        Lookup an IOC by string value, auto-create and enrich if missing.
        """
        detected_type, normalized_val = IOCValidator.detect_and_normalize(raw_value)
        ioc = await self.repo.get_ioc_by_value(normalized_val)

        if not ioc:
            create_dto = IOCCreate(value=raw_value, ioc_type=detected_type)
            ioc = await self.repo.create_ioc(create_dto, normalized_val=normalized_val, detected_type=detected_type)

        enrichment = await self.enrichment_engine.enrich_ioc(ioc.ioc_type, ioc.value)

        # Update IOC with enriched scores
        update_dto = IOCUpdate(
            reputation=enrichment.reputation_level,
            threat_score=enrichment.consolidated_threat_score,
            tags=enrichment.aggregated_tags,
        )
        updated_ioc = await self.repo.update_ioc(ioc.id, update_dto)
        return IOCRead.model_validate(updated_ioc or ioc), enrichment

    async def list_iocs(self, params: IOCFilterParams) -> Tuple[List[IOCRead], int]:
        """List IOCs with filtering and pagination."""
        iocs, total = await self.repo.list_iocs(params)
        dtos = [IOCRead.model_validate(i) for i in iocs]
        return dtos, total

    async def update_ioc(self, ioc_id: uuid.UUID, data: IOCUpdate) -> IOCRead:
        """Update an existing IOC."""
        ioc = await self.repo.update_ioc(ioc_id, data)
        if not ioc:
            raise NotFoundError(f"IOC with ID '{ioc_id}' was not found.")
        return IOCRead.model_validate(ioc)

    async def delete_ioc(self, ioc_id: uuid.UUID) -> bool:
        """Delete an IOC."""
        success = await self.repo.delete_ioc(ioc_id)
        if not success:
            raise NotFoundError(f"IOC with ID '{ioc_id}' was not found.")
        return True

    async def enrich_ioc(self, req: IOCEnrichmentRequest) -> EnrichmentSummary:
        """Perform on-demand multi-provider enrichment for an IOC."""
        detected_type, normalized_val = IOCValidator.detect_and_normalize(req.ioc_value, explicit_type=req.ioc_type)
        summary = await self.enrichment_engine.enrich_ioc(detected_type, req.ioc_value)

        ioc = await self.repo.get_ioc_by_value(normalized_val)
        if ioc:
            update_dto = IOCUpdate(
                reputation=summary.reputation_level,
                threat_score=summary.consolidated_threat_score,
                tags=summary.aggregated_tags,
            )
            await self.repo.update_ioc(ioc.id, update_dto)

        return summary

    async def create_feed(self, data: ThreatFeedCreate) -> ThreatFeedRead:
        """Register a new threat feed."""
        feed = await self.repo.create_feed(data)
        return ThreatFeedRead.model_validate(feed)

    async def list_feeds(self) -> List[ThreatFeedRead]:
        """List registered threat feeds."""
        feeds = await self.repo.list_feeds()
        return [ThreatFeedRead.model_validate(f) for f in feeds]

    async def create_relationship(self, data: IOCRelationshipCreate) -> IOCRelationshipRead:
        """Create a relationship between two IOCs."""
        rel = await self.repo.create_relationship(data)
        return IOCRelationshipRead.model_validate(rel)

    async def get_statistics(self) -> ThreatIntelStatisticsRead:
        """Fetch dashboard metrics for Threat Intelligence."""
        raw_stats = await self.repo.get_statistics_metrics()
        return ThreatIntelStatisticsRead.model_validate(raw_stats)
