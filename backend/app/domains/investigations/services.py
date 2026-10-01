"""
Investigations Domain Business Services.

Implements business logic for starting investigations, managing forensic analysis phases,
findings updates, state transitions, investigator assignments, and audit logging.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.investigations.repositories import InvestigationRepository
from app.domains.incidents.repositories import IncidentRepository
from app.domains.investigations.schemas import (
    InvestigationCreate,
    InvestigationUpdate,
    InvestigationStatusUpdate,
    InvestigationPriorityUpdate,
    InvestigationAssignmentUpdate,
    InvestigationNotesUpdate,
    InvestigationFindingsUpdate,
    InvestigationRecommendationsUpdate,
    InvestigationFilterParams,
    InvestigationSummaryStats,
)
from app.models.investigation import (
    Investigation,
    InvestigationStatus,
    InvestigationPriority,
    InvestigationPhase,
)
from app.core.exceptions import NotFoundError, ValidationError, ConflictError
from app.core.logging import get_logger

logger = get_logger("domain.investigations")


class InvestigationService:
    """Service encapsulating investigation lifecycle business rules."""

    def __init__(self, session: AsyncSession):
        self.repo = InvestigationRepository(session)
        self.incident_repo = IncidentRepository(session)

    async def start_investigation(
        self, investigation_in: InvestigationCreate, created_by_user_id: Optional[uuid.UUID] = None
    ) -> Investigation:
        """Start a new investigation session linked to a valid Incident."""
        incident = await self.incident_repo.get_by_id(investigation_in.incident_id)
        if not incident:
            raise NotFoundError(f"Target incident with ID '{investigation_in.incident_id}' does not exist.")

        # Check for duplicate active investigation with exact same name for this incident
        existing_investigations = await self.repo.list_by_incident(investigation_in.incident_id)
        if any(inv.name.lower() == investigation_in.name.lower() for inv in existing_investigations):
            raise ConflictError(f"An active investigation named '{investigation_in.name}' already exists for this incident.")

        investigation = await self.repo.create(investigation_in, created_by_user_id=created_by_user_id)
        logger.info(
            "Investigation started",
            investigation_id=str(investigation.id),
            incident_id=str(investigation.incident_id),
            name=investigation.name,
        )
        return investigation

    async def get_investigation(self, investigation_id: uuid.UUID) -> Investigation:
        """Fetch investigation by ID or raise NotFoundError."""
        investigation = await self.repo.get_by_id(investigation_id)
        if not investigation:
            raise NotFoundError(f"Investigation with ID '{investigation_id}' was not found.")
        return investigation

    async def list_investigations(self, params: InvestigationFilterParams) -> Tuple[List[Investigation], int]:
        """List investigations with filtering, search, and pagination."""
        return await self.repo.list_filtered(params)

    async def list_by_incident(self, incident_id: uuid.UUID) -> List[Investigation]:
        """Fetch all investigations belonging to an incident."""
        incident = await self.incident_repo.get_by_id(incident_id)
        if not incident:
            raise NotFoundError(f"Incident with ID '{incident_id}' does not exist.")
        return await self.repo.list_by_incident(incident_id)

    async def update_investigation(self, investigation_id: uuid.UUID, update_in: InvestigationUpdate) -> Investigation:
        """Update investigation details."""
        investigation = await self.get_investigation(investigation_id)
        update_data = update_in.model_dump(exclude_unset=True)
        return await self.repo.update(investigation, update_data)

    async def assign_investigator(
        self, investigation_id: uuid.UUID, assignment_in: InvestigationAssignmentUpdate
    ) -> Investigation:
        """Assign an investigator to the session."""
        investigation = await self.get_investigation(investigation_id)
        updated = await self.repo.update(
            investigation,
            {"assigned_investigator_id": assignment_in.assigned_investigator_id},
        )
        logger.info("Investigator assigned", investigation_id=str(investigation_id), investigator_id=str(assignment_in.assigned_investigator_id))
        return updated

    async def add_notes(self, investigation_id: uuid.UUID, notes_in: InvestigationNotesUpdate) -> Investigation:
        """Append or update investigation summary notes."""
        investigation = await self.get_investigation(investigation_id)
        current_summary = investigation.summary or ""
        new_summary = f"{current_summary}\n\n[{datetime.now(timezone.utc).isoformat()}] {notes_in.summary}".strip()
        return await self.repo.update(investigation, {"summary": new_summary})

    async def update_findings(
        self, investigation_id: uuid.UUID, findings_in: InvestigationFindingsUpdate
    ) -> Investigation:
        """Update investigation findings dictionary and confidence rating."""
        investigation = await self.get_investigation(investigation_id)
        update_data: Dict[str, Any] = {"findings": findings_in.findings}
        if findings_in.confidence_score is not None:
            update_data["confidence_score"] = findings_in.confidence_score
        return await self.repo.update(investigation, update_data)

    async def update_recommendations(
        self, investigation_id: uuid.UUID, recs_in: InvestigationRecommendationsUpdate
    ) -> Investigation:
        """Update actionable response recommendations list."""
        investigation = await self.get_investigation(investigation_id)
        return await self.repo.update(investigation, {"recommendations": recs_in.recommendations})

    async def update_status(self, investigation_id: uuid.UUID, status_in: InvestigationStatusUpdate) -> Investigation:
        """Transition investigation state machine lifecycle status."""
        investigation = await self.get_investigation(investigation_id)
        update_data: Dict[str, Any] = {"status": status_in.status}

        if status_in.status == InvestigationStatus.COMPLETED:
            update_data["completed_at"] = datetime.now(timezone.utc)

        updated = await self.repo.update(investigation, update_data)
        logger.info("Investigation status updated", investigation_id=str(investigation_id), status=status_in.status.value)
        return updated

    async def update_priority(
        self, investigation_id: uuid.UUID, priority_in: InvestigationPriorityUpdate
    ) -> Investigation:
        """Change investigation operational priority."""
        investigation = await self.get_investigation(investigation_id)
        return await self.repo.update(investigation, {"priority": priority_in.priority})

    async def close_investigation(self, investigation_id: uuid.UUID, summary: Optional[str] = None) -> Investigation:
        """Conclude investigation session."""
        investigation = await self.get_investigation(investigation_id)
        if investigation.status == InvestigationStatus.COMPLETED:
            raise ConflictError("Investigation is already completed.")

        update_data: Dict[str, Any] = {
            "status": InvestigationStatus.COMPLETED,
            "completed_at": datetime.now(timezone.utc),
        }
        if summary:
            update_data["summary"] = summary

        updated = await self.repo.update(investigation, update_data)
        logger.info("Investigation closed", investigation_id=str(investigation_id))
        return updated

    async def soft_delete_investigation(self, investigation_id: uuid.UUID) -> bool:
        """Soft delete investigation record."""
        return await self.repo.soft_delete(investigation_id)

    async def get_summary_stats(self) -> InvestigationSummaryStats:
        """Retrieve aggregate summary stats."""
        return await self.repo.get_summary_stats()
