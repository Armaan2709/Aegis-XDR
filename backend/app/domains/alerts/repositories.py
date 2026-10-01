"""
Alerts Domain Repository.

Provides data access logic and database operations for Alert entities.
"""

import uuid
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, func, or_, and_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.domains.alerts.schemas import AlertCreate, AlertFilterParams, AlertSummaryStats


class AlertRepository:
    """Repository handling database operations for Alert entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, alert_in: AlertCreate) -> Alert:
        """Persist a new security alert entity."""
        alert = Alert(
            title=alert_in.title,
            description=alert_in.description,
            source=alert_in.source,
            source_ref_id=alert_in.source_ref_id,
            severity=alert_in.severity,
            status=alert_in.status,
            risk_score=alert_in.risk_score,
            mitre_tactics=alert_in.mitre_tactics,
            mitre_techniques=alert_in.mitre_techniques,
            iocs=alert_in.iocs,
            raw_payload=alert_in.raw_payload,
            tags=alert_in.tags,
            assigned_user_id=alert_in.assigned_user_id,
            incident_id=alert_in.incident_id,
        )
        self.session.add(alert)
        await self.session.commit()
        await self.session.refresh(alert)
        return alert

    async def get_by_id(self, alert_id: uuid.UUID) -> Optional[Alert]:
        """Fetch alert entity by primary key UUID."""
        stmt = select(Alert).where(Alert.id == alert_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_filtered(self, params: AlertFilterParams) -> Tuple[List[Alert], int]:
        """List alerts matching search criteria with pagination and total count."""
        stmt = select(Alert)
        count_stmt = select(func.count(Alert.id))
        conditions = []

        if params.query:
            pattern = f"%{params.query}%"
            conditions.append(or_(Alert.title.ilike(pattern), Alert.description.ilike(pattern)))
        
        if params.source:
            conditions.append(Alert.source == params.source)
        
        if params.severity:
            conditions.append(Alert.severity == params.severity)
        
        if params.status:
            conditions.append(Alert.status == params.status)
        
        if params.assigned_user_id:
            conditions.append(Alert.assigned_user_id == params.assigned_user_id)
        
        if params.incident_id:
            conditions.append(Alert.incident_id == params.incident_id)

        if params.min_risk_score is not None:
            conditions.append(Alert.risk_score >= params.min_risk_score)

        if conditions:
            stmt = stmt.where(and_(*conditions))
            count_stmt = count_stmt.where(and_(*conditions))

        # Total matching count
        total_result = await self.session.execute(count_stmt)
        total_count = total_result.scalar_one()

        # Ordering & Pagination
        offset = (params.page - 1) * params.page_size
        stmt = stmt.order_by(Alert.created_at.desc()).offset(offset).limit(params.page_size)

        result = await self.session.execute(stmt)
        alerts = list(result.scalars().all())

        return alerts, total_count

    async def update(self, alert: Alert, update_data: Dict[str, Any]) -> Alert:
        """Update existing alert entity attributes."""
        for field, value in update_data.items():
            if value is not None and hasattr(alert, field):
                setattr(alert, field, value)

        self.session.add(alert)
        await self.session.commit()
        await self.session.refresh(alert)
        return alert

    async def delete(self, alert_id: uuid.UUID) -> bool:
        """Delete alert entity by ID."""
        alert = await self.get_by_id(alert_id)
        if not alert:
            return False
        await self.session.delete(alert)
        await self.session.commit()
        return True

    async def bulk_update_status(self, alert_ids: List[uuid.UUID], status: AlertStatus) -> int:
        """Bulk update status for list of alert IDs."""
        stmt = (
            update(Alert)
            .where(Alert.id.in_(alert_ids))
            .values(status=status)
            .execution_options(synchronize_session="fetch")
        )
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.rowcount

    async def get_summary_stats(self) -> AlertSummaryStats:
        """Calculate aggregated summary statistics across all ingested alerts."""
        # Total count
        total_stmt = select(func.count(Alert.id))
        total = (await self.session.execute(total_stmt)).scalar_one()

        # By severity
        sev_stmt = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
        sev_res = await self.session.execute(sev_stmt)
        by_severity = {sev.value if hasattr(sev, 'value') else str(sev): count for sev, count in sev_res.all()}

        # By status
        stat_stmt = select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
        stat_res = await self.session.execute(stat_stmt)
        by_status = {stat.value if hasattr(stat, 'value') else str(stat): count for stat, count in stat_res.all()}

        # Unassigned count
        unassigned_stmt = select(func.count(Alert.id)).where(Alert.assigned_user_id.is_(None))
        unassigned_count = (await self.session.execute(unassigned_stmt)).scalar_one()

        # High risk count (>= 75.0)
        high_risk_stmt = select(func.count(Alert.id)).where(Alert.risk_score >= 75.0)
        high_risk_count = (await self.session.execute(high_risk_stmt)).scalar_one()

        return AlertSummaryStats(
            total_alerts=total,
            by_severity=by_severity,
            by_status=by_status,
            unassigned_count=unassigned_count,
            high_risk_count=high_risk_count,
        )
