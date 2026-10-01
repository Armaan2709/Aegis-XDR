"""
Investigations Domain Repository.

Provides data access logic and queries for Investigation entities using Async SQLAlchemy 2.0.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, func, or_, and_, update, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.investigation import (
    Investigation,
    InvestigationStatus,
    InvestigationPriority,
    InvestigationPhase,
)
from app.domains.investigations.schemas import InvestigationCreate, InvestigationFilterParams, InvestigationSummaryStats


class InvestigationRepository:
    """Repository handling database routines for Investigation entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, investigation_in: InvestigationCreate, created_by_user_id: Optional[uuid.UUID] = None) -> Investigation:
        """Persist a new Investigation entity."""
        investigation = Investigation(
            incident_id=investigation_in.incident_id,
            name=investigation_in.name,
            description=investigation_in.description,
            status=investigation_in.status,
            priority=investigation_in.priority,
            phase=investigation_in.phase,
            assigned_investigator_id=investigation_in.assigned_investigator_id,
            created_by_user_id=created_by_user_id,
            summary=investigation_in.summary,
            findings=investigation_in.findings,
            recommendations=investigation_in.recommendations,
            confidence_score=investigation_in.confidence_score,
            risk_score=investigation_in.risk_score,
            ai_investigation_enabled=investigation_in.ai_investigation_enabled,
            human_review_required=investigation_in.human_review_required,
            tags=investigation_in.tags,
            investigation_metadata=investigation_in.investigation_metadata,
        )
        self.session.add(investigation)
        await self.session.commit()
        await self.session.refresh(investigation)
        return investigation

    async def get_by_id(self, investigation_id: uuid.UUID, include_deleted: bool = False) -> Optional[Investigation]:
        """Fetch Investigation by primary key UUID."""
        stmt = select(Investigation).where(Investigation.id == investigation_id)
        if not include_deleted:
            stmt = stmt.where(Investigation.is_deleted.is_(False))
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_incident(self, incident_id: uuid.UUID) -> List[Investigation]:
        """Fetch all active investigations for a given Incident."""
        stmt = (
            select(Investigation)
            .where(Investigation.incident_id == incident_id, Investigation.is_deleted.is_(False))
            .order_by(Investigation.started_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_filtered(self, params: InvestigationFilterParams) -> Tuple[List[Investigation], int]:
        """List investigations with multi-criteria filtering, search, pagination, and sorting."""
        stmt = select(Investigation).where(Investigation.is_deleted.is_(False))
        count_stmt = select(func.count(Investigation.id)).where(Investigation.is_deleted.is_(False))
        conditions = []

        if params.query:
            pattern = f"%{params.query}%"
            conditions.append(
                or_(
                    Investigation.name.ilike(pattern),
                    Investigation.description.ilike(pattern),
                    Investigation.summary.ilike(pattern),
                )
            )

        if params.incident_id:
            conditions.append(Investigation.incident_id == params.incident_id)

        if params.status:
            conditions.append(Investigation.status == params.status)

        if params.priority:
            conditions.append(Investigation.priority == params.priority)

        if params.phase:
            conditions.append(Investigation.phase == params.phase)

        if params.assigned_investigator_id:
            conditions.append(Investigation.assigned_investigator_id == params.assigned_investigator_id)

        if params.min_risk_score is not None:
            conditions.append(Investigation.risk_score >= params.min_risk_score)

        if conditions:
            stmt = stmt.where(and_(*conditions))
            count_stmt = count_stmt.where(and_(*conditions))

        total_result = await self.session.execute(count_stmt)
        total_count = total_result.scalar_one()

        # Dynamic Sorting
        sort_attr = getattr(Investigation, params.sort_by, Investigation.started_at)
        sort_fn = desc if params.sort_order.lower() == "desc" else asc
        stmt = stmt.order_by(sort_fn(sort_attr))

        # Pagination
        offset = (params.page - 1) * params.page_size
        stmt = stmt.offset(offset).limit(params.page_size)

        result = await self.session.execute(stmt)
        investigations = list(result.scalars().all())

        return investigations, total_count

    async def update(self, investigation: Investigation, update_data: Dict[str, Any]) -> Investigation:
        """Update existing Investigation attributes."""
        for field, value in update_data.items():
            if value is not None and hasattr(investigation, field):
                setattr(investigation, field, value)

        self.session.add(investigation)
        await self.session.commit()
        await self.session.refresh(investigation)
        return investigation

    async def soft_delete(self, investigation_id: uuid.UUID) -> bool:
        """Soft delete investigation entity by setting is_deleted flag."""
        investigation = await self.get_by_id(investigation_id)
        if not investigation:
            return False
        investigation.is_deleted = True
        self.session.add(investigation)
        await self.session.commit()
        return True

    async def get_summary_stats(self) -> InvestigationSummaryStats:
        """Calculate summary statistics for investigations."""
        base_cond = Investigation.is_deleted.is_(False)

        total_stmt = select(func.count(Investigation.id)).where(base_cond)
        total = (await self.session.execute(total_stmt)).scalar_one()

        active_stmt = select(func.count(Investigation.id)).where(
            base_cond, Investigation.status.in_([InvestigationStatus.INITIATED, InvestigationStatus.IN_PROGRESS, InvestigationStatus.AWAITING_REVIEW])
        )
        active_count = (await self.session.execute(active_stmt)).scalar_one()

        # By status
        stat_stmt = select(Investigation.status, func.count(Investigation.id)).where(base_cond).group_by(Investigation.status)
        stat_res = await self.session.execute(stat_stmt)
        by_status = {stat.value if hasattr(stat, 'value') else str(stat): count for stat, count in stat_res.all()}

        # By priority
        pri_stmt = select(Investigation.priority, func.count(Investigation.id)).where(base_cond).group_by(Investigation.priority)
        pri_res = await self.session.execute(pri_stmt)
        by_priority = {pri.value if hasattr(pri, 'value') else str(pri): count for pri, count in pri_res.all()}

        # By phase
        pha_stmt = select(Investigation.phase, func.count(Investigation.id)).where(base_cond).group_by(Investigation.phase)
        pha_res = await self.session.execute(pha_stmt)
        by_phase = {pha.value if hasattr(pha, 'value') else str(pha): count for pha, count in pha_res.all()}

        unassigned_stmt = select(func.count(Investigation.id)).where(base_cond, Investigation.assigned_investigator_id.is_(None))
        unassigned_count = (await self.session.execute(unassigned_stmt)).scalar_one()

        return InvestigationSummaryStats(
            total_investigations=total,
            active_investigations=active_count,
            by_status=by_status,
            by_priority=by_priority,
            by_phase=by_phase,
            unassigned_count=unassigned_count,
        )
