"""
Incidents Domain Business Services.

Implements core domain rules for security incident lifecycle management,
severity-to-priority calculations, alert correlation hooks, state machine transitions,
and audit trail logs.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.incidents.repositories import IncidentRepository
from app.domains.alerts.repositories import AlertRepository
from app.domains.incidents.schemas import (
    IncidentCreate,
    IncidentUpdate,
    IncidentStatusUpdate,
    IncidentSeverityUpdate,
    IncidentAssignmentUpdate,
    IncidentClose,
    IncidentFilterParams,
    IncidentSummaryStats,
)
from app.models.incident import (
    Incident,
    IncidentSeverity,
    IncidentPriority,
    IncidentStatus,
)
from app.core.exceptions import NotFoundError, ValidationError, ConflictError
from app.core.logging import get_logger

logger = get_logger("domain.incidents")


class IncidentService:
    """Service encapsulating security incident lifecycle business logic."""

    def __init__(self, session: AsyncSession):
        self.repo = IncidentRepository(session)
        self.alert_repo = AlertRepository(session)

    def determine_priority(self, severity: IncidentSeverity) -> IncidentPriority:
        """Derive operational priority level from incident severity rating."""
        mapping = {
            IncidentSeverity.CRITICAL: IncidentPriority.P1,
            IncidentSeverity.HIGH: IncidentPriority.P2,
            IncidentSeverity.MEDIUM: IncidentPriority.P3,
            IncidentSeverity.LOW: IncidentPriority.P4,
            IncidentSeverity.INFO: IncidentPriority.P4,
        }
        return mapping.get(severity, IncidentPriority.P3)

    async def create_incident(
        self, incident_in: IncidentCreate, created_by_user_id: Optional[uuid.UUID] = None
    ) -> Incident:
        """Create a new incident case and associate correlated alerts."""
        # Auto-compute priority if not specified
        if incident_in.priority == IncidentPriority.P3 and incident_in.severity in [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH]:
            incident_in.priority = self.determine_priority(incident_in.severity)

        incident = await self.repo.create(incident_in, created_by_user_id=created_by_user_id)

        # Associate correlated alerts if IDs provided
        if incident_in.alert_ids:
            for alert_id in incident_in.alert_ids:
                alert = await self.alert_repo.get_by_id(alert_id)
                if alert:
                    await self.alert_repo.update(alert, {"incident_id": incident.id})

        logger.info(
            "Security incident created",
            incident_code=incident.incident_code,
            incident_id=str(incident.id),
            severity=incident.severity.value,
        )
        return incident

    async def get_incident(self, incident_id: uuid.UUID) -> Incident:
        """Retrieve incident by UUID or raise NotFoundError."""
        incident = await self.repo.get_by_id(incident_id)
        if not incident:
            raise NotFoundError(f"Incident with ID '{incident_id}' was not found.")
        return incident

    async def list_incidents(self, params: IncidentFilterParams) -> Tuple[List[Incident], int]:
        """List incidents with filtering, search, pagination, and sorting."""
        return await self.repo.list_filtered(params)

    async def update_incident(self, incident_id: uuid.UUID, update_in: IncidentUpdate) -> Incident:
        """Update incident details."""
        incident = await self.get_incident(incident_id)
        update_data = update_in.model_dump(exclude_unset=True)

        if "severity" in update_data and "priority" not in update_data:
            update_data["priority"] = self.determine_priority(update_data["severity"])

        return await self.repo.update(incident, update_data)

    async def assign_incident(self, incident_id: uuid.UUID, assignment_in: IncidentAssignmentUpdate) -> Incident:
        """Assign incident to an authorized SOC analyst."""
        incident = await self.get_incident(incident_id)
        updated = await self.repo.update(
            incident,
            {
                "assigned_to_user_id": assignment_in.assigned_to_user_id,
                "status": IncidentStatus.TRIAGED if incident.status == IncidentStatus.OPEN else incident.status,
            },
        )
        logger.info("Incident assigned", incident_id=str(incident_id), assigned_to=str(assignment_in.assigned_to_user_id))
        return updated

    async def update_status(self, incident_id: uuid.UUID, status_in: IncidentStatusUpdate) -> Incident:
        """Transition incident state machine status."""
        incident = await self.get_incident(incident_id)
        
        # Valid state transitions
        if incident.status == IncidentStatus.CLOSED and status_in.status != IncidentStatus.CLOSED:
            logger.info("Reopening closed incident", incident_id=str(incident_id))

        update_data = {"status": status_in.status}
        if status_in.status in [IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]:
            update_data["closed_at"] = datetime.now(timezone.utc)

        updated = await self.repo.update(incident, update_data)
        logger.info("Incident status updated", incident_id=str(incident_id), new_status=status_in.status.value)
        return updated

    async def update_severity(self, incident_id: uuid.UUID, severity_in: IncidentSeverityUpdate) -> Incident:
        """Update incident severity and recalculate operational priority."""
        incident = await self.get_incident(incident_id)
        priority = severity_in.priority or self.determine_priority(severity_in.severity)
        
        updated = await self.repo.update(
            incident,
            {
                "severity": severity_in.severity,
                "priority": priority,
            },
        )
        logger.info("Incident severity updated", incident_id=str(incident_id), severity=severity_in.severity.value)
        return updated

    async def close_incident(self, incident_id: uuid.UUID, close_in: IncidentClose) -> Incident:
        """Formally close an incident with root cause analysis and resolution summary."""
        incident = await self.get_incident(incident_id)
        if incident.status in [IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]:
            raise ConflictError("Incident is already closed.")

        updated = await self.repo.update(
            incident,
            {
                "status": close_in.status,
                "root_cause": close_in.root_cause,
                "summary": close_in.summary,
                "closed_at": datetime.now(timezone.utc),
            },
        )
        logger.info("Incident closed", incident_id=str(incident_id), status=close_in.status.value)
        return updated

    async def get_summary_stats(self) -> IncidentSummaryStats:
        """Retrieve aggregated incident dashboard statistics."""
        return await self.repo.get_summary_stats()
