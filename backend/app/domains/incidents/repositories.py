"""
Incidents Domain Repository.

Provides data access routines for Incident database entities using SQLAlchemy 2.0 async sessions.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, func, or_, and_, update, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import (
    Incident,
    IncidentSeverity,
    IncidentPriority,
    IncidentStatus,
    IncidentCategory,
)
from app.domains.incidents.schemas import IncidentCreate, IncidentFilterParams, IncidentSummaryStats


class IncidentRepository:
    """Repository handling database interactions for Incident entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def generate_next_code(self) -> str:
        """Generate unique human-readable incident reference code (e.g. INC-2026-0001)."""
        year = datetime.now(timezone.utc).year
        stmt = select(func.count(Incident.id))
        count = (await self.session.execute(stmt)).scalar_one()
        return f"INC-{year}-{count + 1:04d}"

    async def create(self, incident_in: IncidentCreate, created_by_user_id: Optional[uuid.UUID] = None) -> Incident:
        """Persist a new Incident entity."""
        incident_code = await self.generate_next_code()
        
        incident = Incident(
            incident_code=incident_code,
            title=incident_in.title,
            description=incident_in.description,
            severity=incident_in.severity,
            priority=incident_in.priority,
            status=incident_in.status,
            category=incident_in.category,
            source=incident_in.source,
            created_by_user_id=created_by_user_id,
            assigned_to_user_id=incident_in.assigned_to_user_id,
            risk_score=incident_in.risk_score,
            confidence_score=incident_in.confidence_score,
            mitre_mapping=incident_in.mitre_mapping,
            containment_status=incident_in.containment_status,
            recovery_status=incident_in.recovery_status,
            tags=incident_in.tags,
            incident_metadata=incident_in.incident_metadata,
            related_alert_count=len(incident_in.alert_ids) if incident_in.alert_ids else 0,
        )
        self.session.add(incident)
        await self.session.commit()
        await self.session.refresh(incident)
        return incident

    async def get_by_id(self, incident_id: uuid.UUID) -> Optional[Incident]:
        """Fetch Incident by primary key UUID."""
        stmt = select(Incident).where(Incident.id == incident_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_code(self, code: str) -> Optional[Incident]:
        """Fetch Incident by reference code."""
        stmt = select(Incident).where(Incident.incident_code == code)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_filtered(self, params: IncidentFilterParams) -> Tuple[List[Incident], int]:
        """List incidents matching query parameters with pagination and dynamic sorting."""
        stmt = select(Incident)
        count_stmt = select(func.count(Incident.id))
        conditions = []

        if params.query:
            pattern = f"%{params.query}%"
            conditions.append(
                or_(
                    Incident.title.ilike(pattern),
                    Incident.description.ilike(pattern),
                    Incident.incident_code.ilike(pattern),
                )
            )

        if params.category:
            conditions.append(Incident.category == params.category)

        if params.severity:
            conditions.append(Incident.severity == params.severity)

        if params.priority:
            conditions.append(Incident.priority == params.priority)

        if params.status:
            conditions.append(Incident.status == params.status)

        if params.assigned_to_user_id:
            conditions.append(Incident.assigned_to_user_id == params.assigned_to_user_id)

        if params.min_risk_score is not None:
            conditions.append(Incident.risk_score >= params.min_risk_score)

        if conditions:
            stmt = stmt.where(and_(*conditions))
            count_stmt = count_stmt.where(and_(*conditions))

        total_result = await self.session.execute(count_stmt)
        total_count = total_result.scalar_one()

        # Dynamic Sorting
        sort_attr = getattr(Incident, params.sort_by, Incident.created_at)
        sort_fn = desc if params.sort_order.lower() == "desc" else asc
        stmt = stmt.order_by(sort_fn(sort_attr))

        # Pagination
        offset = (params.page - 1) * params.page_size
        stmt = stmt.offset(offset).limit(params.page_size)

        result = await self.session.execute(stmt)
        incidents = list(result.scalars().all())

        return incidents, total_count

    async def update(self, incident: Incident, update_data: Dict[str, Any]) -> Incident:
        """Update existing Incident fields."""
        for field, value in update_data.items():
            if value is not None and hasattr(incident, field):
                setattr(incident, field, value)

        self.session.add(incident)
        await self.session.commit()
        await self.session.refresh(incident)
        return incident

    async def delete(self, incident_id: uuid.UUID) -> bool:
        """Delete incident entity."""
        incident = await self.get_by_id(incident_id)
        if not incident:
            return False
        await self.session.delete(incident)
        await self.session.commit()
        return True

    async def get_summary_stats(self) -> IncidentSummaryStats:
        """Calculate aggregated summary statistics across all security incidents."""
        # Total
        total_stmt = select(func.count(Incident.id))
        total = (await self.session.execute(total_stmt)).scalar_one()

        # Open incidents
        open_stmt = select(func.count(Incident.id)).where(Incident.status != IncidentStatus.CLOSED)
        open_count = (await self.session.execute(open_stmt)).scalar_one()

        # Critical severity incidents
        crit_stmt = select(func.count(Incident.id)).where(Incident.severity == IncidentSeverity.CRITICAL)
        crit_count = (await self.session.execute(crit_stmt)).scalar_one()

        # By severity
        sev_stmt = select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
        sev_res = await self.session.execute(sev_stmt)
        by_severity = {sev.value if hasattr(sev, 'value') else str(sev): count for sev, count in sev_res.all()}

        # By status
        stat_stmt = select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
        stat_res = await self.session.execute(stat_stmt)
        by_status = {stat.value if hasattr(stat, 'value') else str(stat): count for stat, count in stat_res.all()}

        # By category
        cat_stmt = select(Incident.category, func.count(Incident.id)).group_by(Incident.category)
        cat_res = await self.session.execute(cat_stmt)
        by_category = {cat.value if hasattr(cat, 'value') else str(cat): count for cat, count in cat_res.all()}

        # Unassigned
        unassigned_stmt = select(func.count(Incident.id)).where(Incident.assigned_to_user_id.is_(None))
        unassigned_count = (await self.session.execute(unassigned_stmt)).scalar_one()

        return IncidentSummaryStats(
            total_incidents=total,
            open_incidents=open_count,
            critical_incidents=crit_count,
            by_severity=by_severity,
            by_status=by_status,
            by_category=by_category,
            unassigned_count=unassigned_count,
        )
