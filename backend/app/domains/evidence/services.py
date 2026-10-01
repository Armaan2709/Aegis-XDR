"""
Evidence Domain Business Services.

Implements core domain rules for digital forensic evidence collection,
hash verification, duplicate checks, chain-of-custody transfer logging,
and evidence count synchronization with parent Investigation entities.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.evidence.repositories import EvidenceRepository
from app.domains.investigations.repositories import InvestigationRepository
from app.domains.incidents.repositories import IncidentRepository
from app.domains.evidence.schemas import (
    EvidenceCreate,
    EvidenceUpdate,
    EvidenceCustodyTransfer,
    EvidenceFilterParams,
    EvidenceSummaryStats,
)
from app.models.evidence import Evidence
from app.core.exceptions import NotFoundError, ValidationError, ConflictError
from app.core.logging import get_logger

logger = get_logger("domain.evidence")


class EvidenceService:
    """Service encapsulating DFIR digital evidence lifecycle operations."""

    def __init__(self, session: AsyncSession):
        self.repo = EvidenceRepository(session)
        self.investigation_repo = InvestigationRepository(session)
        self.incident_repo = IncidentRepository(session)

    async def create_evidence(
        self, evidence_in: EvidenceCreate, collected_by_user_id: Optional[uuid.UUID] = None
    ) -> Evidence:
        """Create and ingest a new digital forensic evidence artifact."""
        # 1. Validate parent Investigation existence
        investigation = await self.investigation_repo.get_by_id(evidence_in.investigation_id)
        if not investigation:
            raise NotFoundError(f"Parent investigation '{evidence_in.investigation_id}' does not exist.")

        # 2. Validate parent Incident existence
        incident = await self.incident_repo.get_by_id(evidence_in.incident_id)
        if not incident:
            raise NotFoundError(f"Parent incident '{evidence_in.incident_id}' does not exist.")

        # 3. Check duplicate hash within the same investigation
        if evidence_in.sha256:
            existing_hash = await self.repo.get_by_hash(evidence_in.sha256, evidence_in.investigation_id)
            if existing_hash:
                raise ConflictError(
                    f"Evidence artifact with SHA256 '{evidence_in.sha256}' already exists in this investigation."
                )

        evidence = await self.repo.create(evidence_in, collected_by_user_id=collected_by_user_id)

        # 4. Sync evidence_count on parent Investigation
        count = await self.repo.count_by_investigation(investigation.id)
        await self.investigation_repo.update(investigation, {"evidence_count": count})

        logger.info(
            "Evidence ingested",
            evidence_id=str(evidence.id),
            evidence_type=evidence.evidence_type.value,
            name=evidence.name,
            investigation_id=str(evidence.investigation_id),
        )
        return evidence

    async def get_evidence(self, evidence_id: uuid.UUID) -> Evidence:
        """Fetch evidence by UUID or raise NotFoundError."""
        evidence = await self.repo.get_by_id(evidence_id)
        if not evidence:
            raise NotFoundError(f"Evidence artifact with ID '{evidence_id}' was not found.")
        return evidence

    async def list_evidence(self, params: EvidenceFilterParams) -> Tuple[List[Evidence], int]:
        """List evidence artifacts with search, filtering, and pagination."""
        return await self.repo.list_filtered(params)

    async def list_by_investigation(self, investigation_id: uuid.UUID) -> List[Evidence]:
        """List all evidence belonging to an Investigation."""
        investigation = await self.investigation_repo.get_by_id(investigation_id)
        if not investigation:
            raise NotFoundError(f"Investigation '{investigation_id}' does not exist.")
        return await self.repo.list_by_investigation(investigation_id)

    async def update_evidence(self, evidence_id: uuid.UUID, update_in: EvidenceUpdate) -> Evidence:
        """Update existing evidence attributes."""
        evidence = await self.get_evidence(evidence_id)
        update_data = update_in.model_dump(exclude_unset=True)
        return await self.repo.update(evidence, update_data)

    async def transfer_custody(
        self, evidence_id: uuid.UUID, custody_in: EvidenceCustodyTransfer, actor_id: uuid.UUID
    ) -> Evidence:
        """Record a chain of custody transfer event for legal & DFIR compliance."""
        evidence = await self.get_evidence(evidence_id)
        transfer_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "CUSTODY_TRANSFER",
            "actor_id": str(actor_id),
            "transferred_to": custody_in.transferred_to,
            "purpose": custody_in.purpose,
            "notes": custody_in.notes or "",
        }
        updated = await self.repo.add_custody_transfer(evidence, transfer_entry)
        logger.info(
            "Evidence custody transferred",
            evidence_id=str(evidence_id),
            transferred_to=custody_in.transferred_to,
        )
        return updated

    async def verify_integrity(self, evidence_id: uuid.UUID, calculated_sha256: str) -> bool:
        """Verify evidence hash integrity against recorded SHA256."""
        evidence = await self.get_evidence(evidence_id)
        if not evidence.sha256:
            raise ValidationError("Evidence artifact has no recorded SHA256 hash to verify against.")

        is_valid = (evidence.sha256.lower() == calculated_sha256.strip().lower())
        await self.repo.update(evidence, {"integrity_verified": is_valid})
        
        logger.info("Evidence hash integrity verified", evidence_id=str(evidence_id), is_valid=is_valid)
        return is_valid

    async def delete_evidence(self, evidence_id: uuid.UUID) -> bool:
        """Soft delete evidence artifact and update parent investigation count."""
        evidence = await self.get_evidence(evidence_id)
        investigation_id = evidence.investigation_id
        success = await self.repo.soft_delete(evidence_id)

        if success:
            investigation = await self.investigation_repo.get_by_id(investigation_id)
            if investigation:
                count = await self.repo.count_by_investigation(investigation.id)
                await self.investigation_repo.update(investigation, {"evidence_count": count})

        return success

    async def get_summary_stats(self) -> EvidenceSummaryStats:
        """Calculate aggregate summary stats for evidence artifacts."""
        return await self.repo.get_summary_stats()
