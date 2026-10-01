"""
Correlation Domain Repository.

Provides database interaction and query routines for retrieving unassigned Alerts,
associating Alerts with Correlated Incidents, and fetching entity relationship graphs.
"""

import uuid
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, update, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert, AlertStatus
from app.models.incident import Incident


class CorrelationRepository:
    """Repository managing DB interaction for Correlation Engine operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_unassigned_alerts(self, limit: int = 100) -> List[Alert]:
        """Fetch active alerts that are not yet assigned to an Incident."""
        stmt = (
            select(Alert)
            .where(
                Alert.incident_id.is_(None),
                Alert.status != AlertStatus.CLOSED,
                Alert.status != AlertStatus.RESOLVED,
                Alert.status != AlertStatus.FALSE_POSITIVE,
            )
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_alerts_by_ids(self, alert_ids: List[uuid.UUID]) -> List[Alert]:
        """Fetch alerts matching a list of UUID primary keys."""
        if not alert_ids:
            return []
        stmt = select(Alert).where(Alert.id.in_(alert_ids))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def link_alerts_to_incident(self, alert_ids: List[uuid.UUID], incident_id: uuid.UUID) -> int:
        """Update incident_id foreign association on correlated alerts."""
        if not alert_ids:
            return 0

        stmt = (
            update(Alert)
            .where(Alert.id.in_(alert_ids))
            .values(incident_id=incident_id, status=AlertStatus.INVESTIGATING)
        )
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.rowcount

    async def get_alerts_for_incident(self, incident_id: uuid.UUID) -> List[Alert]:
        """Fetch all alerts assigned to a specific Incident."""
        stmt = select(Alert).where(Alert.incident_id == incident_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
