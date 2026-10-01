"""
Timeline Domain Repository.

Provides database access routines and query execution for TimelineEvent entities using Async SQLAlchemy 2.0.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, func, or_, and_, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.timeline import (
    TimelineEvent,
    TimelineEventType,
    TimelineEventCategory,
    TimelineEventSeverity,
)
from app.domains.timeline.schemas import (
    TimelineEventCreate,
    TimelineFilterParams,
    TimelineSummaryStats,
)


class TimelineRepository:
    """Repository handling persistence operations for TimelineEvent entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, event_in: TimelineEventCreate) -> TimelineEvent:
        """Persist a new TimelineEvent entity."""
        event_timestamp = event_in.timestamp or datetime.now(timezone.utc)

        event = TimelineEvent(
            investigation_id=event_in.investigation_id,
            incident_id=event_in.incident_id,
            evidence_id=event_in.evidence_id,
            timestamp=event_timestamp,
            event_type=event_in.event_type,
            event_category=event_in.event_category,
            source=event_in.source,
            hostname=event_in.hostname,
            username=event_in.username,
            process_name=event_in.process_name,
            process_id=event_in.process_id,
            parent_process_id=event_in.parent_process_id,
            file_path=event_in.file_path,
            registry_key=event_in.registry_key,
            network_address=event_in.network_address,
            description=event_in.description,
            severity=event_in.severity,
            confidence_score=event_in.confidence_score,
            tags=event_in.tags,
            metadata_info=event_in.metadata_info,
        )
        self.session.add(event)
        await self.session.commit()
        await self.session.refresh(event)
        return event

    async def get_by_id(self, event_id: uuid.UUID, include_deleted: bool = False) -> Optional[TimelineEvent]:
        """Fetch TimelineEvent entity by primary key UUID."""
        stmt = select(TimelineEvent).where(TimelineEvent.id == event_id)
        if not include_deleted:
            stmt = stmt.where(TimelineEvent.is_deleted.is_(False))
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_investigation(self, investigation_id: uuid.UUID) -> List[TimelineEvent]:
        """Fetch all active timeline events for an Investigation in chronological order."""
        stmt = (
            select(TimelineEvent)
            .where(TimelineEvent.investigation_id == investigation_id, TimelineEvent.is_deleted.is_(False))
            .order_by(TimelineEvent.timestamp.asc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_by_incident(self, incident_id: uuid.UUID) -> List[TimelineEvent]:
        """Fetch all active timeline events for an Incident in chronological order."""
        stmt = (
            select(TimelineEvent)
            .where(TimelineEvent.incident_id == incident_id, TimelineEvent.is_deleted.is_(False))
            .order_by(TimelineEvent.timestamp.asc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_filtered(self, params: TimelineFilterParams) -> Tuple[List[TimelineEvent], int]:
        """List timeline events matching filters with pagination and dynamic sorting."""
        stmt = select(TimelineEvent).where(TimelineEvent.is_deleted.is_(False))
        count_stmt = select(func.count(TimelineEvent.id)).where(TimelineEvent.is_deleted.is_(False))
        conditions = []

        if params.query:
            pattern = f"%{params.query}%"
            conditions.append(
                or_(
                    TimelineEvent.description.ilike(pattern),
                    TimelineEvent.hostname.ilike(pattern),
                    TimelineEvent.username.ilike(pattern),
                    TimelineEvent.process_name.ilike(pattern),
                    TimelineEvent.file_path.ilike(pattern),
                    TimelineEvent.network_address.ilike(pattern),
                    TimelineEvent.registry_key.ilike(pattern),
                    TimelineEvent.source.ilike(pattern),
                )
            )

        if params.investigation_id:
            conditions.append(TimelineEvent.investigation_id == params.investigation_id)

        if params.incident_id:
            conditions.append(TimelineEvent.incident_id == params.incident_id)

        if params.evidence_id:
            conditions.append(TimelineEvent.evidence_id == params.evidence_id)

        if params.event_type:
            conditions.append(TimelineEvent.event_type == params.event_type)

        if params.event_category:
            conditions.append(TimelineEvent.event_category == params.event_category)

        if params.severity:
            conditions.append(TimelineEvent.severity == params.severity)

        if params.hostname:
            conditions.append(TimelineEvent.hostname.ilike(f"%{params.hostname}%"))

        if params.username:
            conditions.append(TimelineEvent.username.ilike(f"%{params.username}%"))

        if params.start_time:
            conditions.append(TimelineEvent.timestamp >= params.start_time)

        if params.end_time:
            conditions.append(TimelineEvent.timestamp <= params.end_time)

        if conditions:
            stmt = stmt.where(and_(*conditions))
            count_stmt = count_stmt.where(and_(*conditions))

        total_result = await self.session.execute(count_stmt)
        total_count = total_result.scalar_one()

        # Dynamic Sorting
        sort_attr = getattr(TimelineEvent, params.sort_by, TimelineEvent.timestamp)
        sort_fn = desc if params.sort_order.lower() == "desc" else asc
        stmt = stmt.order_by(sort_fn(sort_attr))

        # Pagination
        offset = (params.page - 1) * params.page_size
        stmt = stmt.offset(offset).limit(params.page_size)

        result = await self.session.execute(stmt)
        events = list(result.scalars().all())

        return events, total_count

    async def update(self, event: TimelineEvent, update_data: Dict[str, Any]) -> TimelineEvent:
        """Update existing TimelineEvent attributes."""
        for field, value in update_data.items():
            if value is not None and hasattr(event, field):
                setattr(event, field, value)

        self.session.add(event)
        await self.session.commit()
        await self.session.refresh(event)
        return event

    async def soft_delete(self, event_id: uuid.UUID) -> bool:
        """Soft delete a timeline event entity."""
        event = await self.get_by_id(event_id)
        if not event:
            return False
        event.is_deleted = True
        self.session.add(event)
        await self.session.commit()
        return True

    async def count_by_investigation(self, investigation_id: uuid.UUID) -> int:
        """Count active timeline events for an investigation."""
        stmt = select(func.count(TimelineEvent.id)).where(
            TimelineEvent.investigation_id == investigation_id, TimelineEvent.is_deleted.is_(False)
        )
        return (await self.session.execute(stmt)).scalar_one()

    async def get_summary_stats(self) -> TimelineSummaryStats:
        """Calculate summary metrics across all timeline events."""
        base_cond = TimelineEvent.is_deleted.is_(False)

        total_stmt = select(func.count(TimelineEvent.id)).where(base_cond)
        total = (await self.session.execute(total_stmt)).scalar_one()

        type_stmt = select(TimelineEvent.event_type, func.count(TimelineEvent.id)).where(base_cond).group_by(TimelineEvent.event_type)
        type_res = await self.session.execute(type_stmt)
        by_type = {t.value if hasattr(t, 'value') else str(t): count for t, count in type_res.all()}

        cat_stmt = select(TimelineEvent.event_category, func.count(TimelineEvent.id)).where(base_cond).group_by(TimelineEvent.event_category)
        cat_res = await self.session.execute(cat_stmt)
        by_category = {c.value if hasattr(c, 'value') else str(c): count for c, count in cat_res.all()}

        sev_stmt = select(TimelineEvent.severity, func.count(TimelineEvent.id)).where(base_cond).group_by(TimelineEvent.severity)
        sev_res = await self.session.execute(sev_stmt)
        by_severity = {s.value if hasattr(s, 'value') else str(s): count for s, count in sev_res.all()}

        time_range_stmt = select(
            func.min(TimelineEvent.timestamp),
            func.max(TimelineEvent.timestamp),
        ).where(base_cond)
        time_res = await self.session.execute(time_range_stmt)
        first_event, last_event = time_res.one_or_none() or (None, None)

        return TimelineSummaryStats(
            total_events=total,
            by_type=by_type,
            by_category=by_category,
            by_severity=by_severity,
            first_event_at=first_event,
            last_event_at=last_event,
        )
