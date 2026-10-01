"""
Threat Intelligence Domain Repository Layer.

Encapsulates Async SQLAlchemy 2.0 database queries for IOCs, Threat Feeds,
Enrichment payloads, and IOC entity relationships.
"""

import uuid
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, update, delete, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.threat_intelligence.models import (
    IOC,
    ThreatFeed,
    ThreatEnrichment,
    IOCRelationship,
    IOCType,
    ThreatReputationLevel,
)
from app.threat_intelligence.schemas import (
    IOCCreate,
    IOCUpdate,
    IOCFilterParams,
    ThreatFeedCreate,
    IOCRelationshipCreate,
)


class ThreatIntelRepository:
    """Repository handling persistence for Threat Intelligence entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_ioc(self, data: IOCCreate, normalized_val: str, detected_type: IOCType) -> IOC:
        """Persist a new IOC entity."""
        ioc = IOC(
            ioc_type=detected_type,
            value=data.value,
            normalized_value=normalized_val,
            reputation=data.reputation,
            confidence_score=data.confidence_score,
            threat_score=data.threat_score,
            tags=data.tags,
            sources=data.sources,
            metadata_info=data.metadata_info,
        )
        self.session.add(ioc)
        await self.session.commit()
        await self.session.refresh(ioc)
        return ioc

    async def get_ioc_by_id(self, ioc_id: uuid.UUID) -> Optional[IOC]:
        """Fetch an IOC by primary key UUID."""
        stmt = select(IOC).where(IOC.id == ioc_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_ioc_by_value(self, normalized_val: str) -> Optional[IOC]:
        """Fetch an IOC by normalized value string."""
        stmt = select(IOC).where(IOC.normalized_value == normalized_val)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_iocs(self, params: IOCFilterParams) -> Tuple[List[IOC], int]:
        """List IOCs with filtering, searching, and pagination."""
        stmt = select(IOC)

        if params.ioc_type:
            stmt = stmt.where(IOC.ioc_type == params.ioc_type)

        if params.reputation:
            stmt = stmt.where(IOC.reputation == params.reputation)

        if params.is_active is not None:
            stmt = stmt.where(IOC.is_active == params.is_active)

        if params.query:
            term = f"%{params.query}%"
            stmt = stmt.where(
                or_(
                    IOC.value.ilike(term),
                    IOC.normalized_value.ilike(term),
                )
            )

        count_stmt = select(IOC.id).select_from(stmt.subquery())
        count_res = await self.session.execute(count_stmt)
        total_count = len(count_res.scalars().all())

        stmt = stmt.order_by(IOC.created_at.desc())
        stmt = stmt.offset((params.page - 1) * params.page_size).limit(params.page_size)

        result = await self.session.execute(stmt)
        return list(result.scalars().all()), total_count

    async def update_ioc(self, ioc_id: uuid.UUID, data: IOCUpdate) -> Optional[IOC]:
        """Update an existing IOC."""
        ioc = await self.get_ioc_by_id(ioc_id)
        if not ioc:
            return None

        update_data = data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(ioc, field, value)

        await self.session.commit()
        await self.session.refresh(ioc)
        return ioc

    async def delete_ioc(self, ioc_id: uuid.UUID) -> bool:
        """Delete an IOC entity."""
        ioc = await self.get_ioc_by_id(ioc_id)
        if not ioc:
            return False

        await self.session.delete(ioc)
        await self.session.commit()
        return True

    async def create_enrichment(
        self, ioc_id: uuid.UUID, provider_name: str, score: float, raw: Dict[str, Any], enrichment: Dict[str, Any]
    ) -> ThreatEnrichment:
        """Persist a provider enrichment payload."""
        record = ThreatEnrichment(
            ioc_id=ioc_id,
            provider_name=provider_name,
            reputation_score=score,
            raw_response=raw,
            enrichment_data=enrichment,
        )
        self.session.add(record)
        await self.session.commit()
        await self.session.refresh(record)
        return record

    async def create_feed(self, data: ThreatFeedCreate) -> ThreatFeed:
        """Persist a threat feed registry entry."""
        feed = ThreatFeed(
            name=data.name,
            feed_url=data.feed_url,
            format_type=data.format_type,
            is_enabled=data.is_enabled,
        )
        self.session.add(feed)
        await self.session.commit()
        await self.session.refresh(feed)
        return feed

    async def list_feeds(self) -> List[ThreatFeed]:
        """Fetch all threat feed definitions."""
        stmt = select(ThreatFeed).order_by(ThreatFeed.name.asc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create_relationship(self, data: IOCRelationshipCreate) -> IOCRelationship:
        """Create a directional relationship between two IOCs."""
        rel = IOCRelationship(
            source_ioc_id=data.source_ioc_id,
            target_ioc_id=data.target_ioc_id,
            relationship_type=data.relationship_type,
        )
        self.session.add(rel)
        await self.session.commit()
        await self.session.refresh(rel)
        return rel

    async def get_statistics_metrics(self) -> Dict[str, Any]:
        """Aggregate statistical totals for Threat Intelligence dashboard."""
        total_stmt = select(func.count(IOC.id))
        total_res = await self.session.execute(total_stmt)
        total_iocs = total_res.scalar() or 0

        active_stmt = select(func.count(IOC.id)).where(IOC.is_active.is_(True))
        active_res = await self.session.execute(active_stmt)
        active_iocs = active_res.scalar() or 0

        malicious_stmt = select(func.count(IOC.id)).where(
            IOC.reputation.in_([ThreatReputationLevel.MALICIOUS, ThreatReputationLevel.CRITICAL, ThreatReputationLevel.HIGH])
        )
        malicious_res = await self.session.execute(malicious_stmt)
        malicious_iocs = malicious_res.scalar() or 0

        feeds_stmt = select(func.count(ThreatFeed.id)).where(ThreatFeed.is_enabled.is_(True))
        feeds_res = await self.session.execute(feeds_stmt)
        active_feeds = feeds_res.scalar() or 0

        return {
            "total_iocs_count": total_iocs,
            "active_iocs_count": active_iocs,
            "malicious_iocs_count": malicious_iocs,
            "active_feeds_count": active_feeds,
        }
