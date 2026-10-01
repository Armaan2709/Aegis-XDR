"""
Timeline Domain Business Service.

Implements business logic for managing, sorting, searching, and validating chronological
timeline events across security investigations.
"""

import uuid
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.timeline.repositories import TimelineRepository
from app.domains.investigations.repositories import InvestigationRepository
from app.domains.incidents.repositories import IncidentRepository
from app.domains.evidence.repositories import EvidenceRepository
from app.domains.timeline.schemas import (
    TimelineEventCreate,
    TimelineEventUpdate,
    TimelineFilterParams,
    TimelineSummaryStats,
)
from app.models.timeline import TimelineEvent
from app.core.exceptions import NotFoundError, ValidationError
from app.core.logging import get_logger

logger = get_logger("domain.timeline")


class TimelineService:
    """Service encapsulating business rules for timeline event management."""

    def __init__(self, session: AsyncSession):
        self.repo = TimelineRepository(session)
        self.investigation_repo = InvestigationRepository(session)
        self.incident_repo = IncidentRepository(session)
        self.evidence_repo = EvidenceRepository(session)

    async def create_event(self, event_in: TimelineEventCreate) -> TimelineEvent:
        """Create a new timeline event linked to an Investigation and Incident."""
        investigation = await self.investigation_repo.get_by_id(event_in.investigation_id)
        if not investigation:
            raise NotFoundError(f"Target investigation with ID '{event_in.investigation_id}' does not exist.")

        incident = await self.incident_repo.get_by_id(event_in.incident_id)
        if not incident:
            raise NotFoundError(f"Target incident with ID '{event_in.incident_id}' does not exist.")

        if event_in.evidence_id:
            evidence = await self.evidence_repo.get_by_id(event_in.evidence_id)
            if not evidence:
                raise NotFoundError(f"Target evidence artifact with ID '{event_in.evidence_id}' does not exist.")

        event = await self.repo.create(event_in)
        logger.info(
            "Timeline event created",
            event_id=str(event.id),
            investigation_id=str(event.investigation_id),
            event_type=event.event_type.value,
        )
        return event

    async def get_event(self, event_id: uuid.UUID) -> TimelineEvent:
        """Fetch timeline event by ID or raise NotFoundError."""
        event = await self.repo.get_by_id(event_id)
        if not event:
            raise NotFoundError(f"Timeline event with ID '{event_id}' was not found.")
        return event

    async def list_events(self, params: TimelineFilterParams) -> Tuple[List[TimelineEvent], int]:
        """List timeline events matching search and filter criteria."""
        return await self.repo.list_filtered(params)

    async def list_by_investigation(self, investigation_id: uuid.UUID) -> List[TimelineEvent]:
        """Retrieve all chronological timeline events for a specific investigation."""
        investigation = await self.investigation_repo.get_by_id(investigation_id)
        if not investigation:
            raise NotFoundError(f"Investigation with ID '{investigation_id}' does not exist.")
        return await self.repo.list_by_investigation(investigation_id)

    async def list_by_incident(self, incident_id: uuid.UUID) -> List[TimelineEvent]:
        """Retrieve all chronological timeline events for a specific incident."""
        incident = await self.incident_repo.get_by_id(incident_id)
        if not incident:
            raise NotFoundError(f"Incident with ID '{incident_id}' does not exist.")
        return await self.repo.list_by_incident(incident_id)

    async def update_event(self, event_id: uuid.UUID, update_in: TimelineEventUpdate) -> TimelineEvent:
        """Update properties of an existing timeline event."""
        event = await self.get_event(event_id)
        update_data = update_in.model_dump(exclude_unset=True)

        if "evidence_id" in update_data and update_data["evidence_id"] is not None:
            evidence = await self.evidence_repo.get_by_id(update_data["evidence_id"])
            if not evidence:
                raise NotFoundError(f"Target evidence artifact with ID '{update_data['evidence_id']}' does not exist.")

        return await self.repo.update(event, update_data)

    async def delete_event(self, event_id: uuid.UUID) -> bool:
        """Soft delete a timeline event."""
        event = await self.get_event(event_id)
        return await self.repo.soft_delete(event.id)

    async def get_summary_stats(self) -> TimelineSummaryStats:
        """Calculate aggregate metrics across timeline events."""
        return await self.repo.get_summary_stats()
