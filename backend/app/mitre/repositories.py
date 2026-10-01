"""
MITRE ATT&CK Domain Repository Layer.

Encapsulates Async SQLAlchemy 2.0 database queries for Tactics, Techniques,
Sub-Techniques, Junction mappings, and Coverage snapshots.
"""

import uuid
from typing import Optional, List, Tuple
from sqlalchemy import select, update, delete, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.mitre.models import (
    MitreTactic,
    MitreTechnique,
    MitreSubTechnique,
    MitreMapping,
    IncidentTechnique,
    EvidenceTechnique,
    TimelineTechnique,
    MitreTacticEnum,
)
from app.mitre.schemas import (
    MitreTechniqueCreate,
    MitreTechniqueUpdate,
    MitreSubTechniqueCreate,
    MitreMappingCreate,
    MitreFilterParams,
)


class MitreRepository:
    """Repository handling database access for MITRE ATT&CK entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    # --- Technique CRUD ---
    async def create_technique(self, data: MitreTechniqueCreate) -> MitreTechnique:
        """Persist a new MITRE technique."""
        technique = MitreTechnique(
            technique_id=data.technique_id,
            tactic=data.tactic,
            name=data.name,
            description=data.description,
            platforms=data.platforms,
            detection_notes=data.detection_notes,
            data_sources=data.data_sources,
            mitigation_notes=data.mitigation_notes,
        )
        self.session.add(technique)
        await self.session.commit()
        await self.session.refresh(technique)
        return technique

    async def get_technique_by_id(self, technique_id: str) -> Optional[MitreTechnique]:
        """Fetch a technique by technique_id string (e.g. T1059) or UUID string."""
        stmt = select(MitreTechnique).where(
            or_(MitreTechnique.technique_id == technique_id, MitreTechnique.name == technique_id)
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_techniques(self, params: MitreFilterParams) -> Tuple[List[MitreTechnique], int]:
        """List techniques with filtering, searching, and pagination."""
        stmt = select(MitreTechnique)

        if params.tactic:
            stmt = stmt.where(MitreTechnique.tactic == params.tactic)

        if params.query:
            term = f"%{params.query}%"
            stmt = stmt.where(
                or_(
                    MitreTechnique.technique_id.ilike(term),
                    MitreTechnique.name.ilike(term),
                    MitreTechnique.description.ilike(term),
                )
            )

        count_stmt = select(MitreTechnique.id).select_from(stmt.subquery())
        count_res = await self.session.execute(count_stmt)
        total_count = len(count_res.scalars().all())

        stmt = stmt.order_by(MitreTechnique.technique_id.asc())
        stmt = stmt.offset((params.page - 1) * params.page_size).limit(params.page_size)

        result = await self.session.execute(stmt)
        return list(result.scalars().all()), total_count

    async def update_technique(self, technique_id: str, data: MitreTechniqueUpdate) -> Optional[MitreTechnique]:
        """Update an existing technique."""
        technique = await self.get_technique_by_id(technique_id)
        if not technique:
            return None

        update_data = data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(technique, field, value)

        await self.session.commit()
        await self.session.refresh(technique)
        return technique

    async def delete_technique(self, technique_id: str) -> bool:
        """Delete a technique entity."""
        technique = await self.get_technique_by_id(technique_id)
        if not technique:
            return False

        await self.session.delete(technique)
        await self.session.commit()
        return True

    # --- Sub-Technique CRUD ---
    async def create_subtechnique(self, data: MitreSubTechniqueCreate) -> MitreSubTechnique:
        """Persist a new sub-technique."""
        subtech = MitreSubTechnique(
            subtechnique_id=data.subtechnique_id,
            parent_technique_id=data.parent_technique_id,
            name=data.name,
            description=data.description,
            platforms=data.platforms,
            detection_notes=data.detection_notes,
        )
        self.session.add(subtech)
        await self.session.commit()
        await self.session.refresh(subtech)
        return subtech

    async def list_subtechniques(self, parent_technique_id: str) -> List[MitreSubTechnique]:
        """Fetch all sub-techniques for a parent technique."""
        stmt = select(MitreSubTechnique).where(MitreSubTechnique.parent_technique_id == parent_technique_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    # --- Mapping Operations ---
    async def create_mapping(self, data: MitreMappingCreate) -> MitreMapping:
        """Create a unified MITRE mapping entity."""
        mapping = MitreMapping(
            artifact_type=data.artifact_type,
            artifact_id=data.artifact_id,
            technique_id=data.technique_id,
            subtechnique_id=data.subtechnique_id,
            tactic=data.tactic,
            confidence_score=data.confidence_score,
            evidence_references=data.evidence_references,
            timeline_references=data.timeline_references,
            incident_references=data.incident_references,
            metadata_info=data.metadata_info,
        )
        self.session.add(mapping)
        await self.session.commit()
        await self.session.refresh(mapping)
        return mapping

    async def get_mappings_for_artifact(self, artifact_type: str, artifact_id: uuid.UUID) -> List[MitreMapping]:
        """Get all MITRE mappings associated with a specific artifact."""
        stmt = select(MitreMapping).where(
            and_(
                MitreMapping.artifact_type == artifact_type.upper(),
                MitreMapping.artifact_id == artifact_id,
                MitreMapping.is_deleted.is_(False),
            )
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_all_mappings(self) -> List[MitreMapping]:
        """Fetch all active MITRE mappings for global coverage metrics."""
        stmt = select(MitreMapping).where(MitreMapping.is_deleted.is_(False))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    # --- Junction Records ---
    async def create_incident_technique(
        self, incident_id: uuid.UUID, technique_id: str, tactic: MitreTacticEnum, confidence_score: float = 100.0
    ) -> IncidentTechnique:
        """Link an Incident directly to a MITRE technique in junction table."""
        rec = IncidentTechnique(
            incident_id=incident_id,
            technique_id=technique_id,
            tactic=tactic,
            confidence_score=confidence_score,
        )
        self.session.add(rec)
        await self.session.commit()
        await self.session.refresh(rec)
        return rec

    async def create_evidence_technique(
        self, evidence_id: uuid.UUID, technique_id: str, tactic: MitreTacticEnum, confidence_score: float = 100.0
    ) -> EvidenceTechnique:
        """Link an Evidence artifact directly to a MITRE technique in junction table."""
        rec = EvidenceTechnique(
            evidence_id=evidence_id,
            technique_id=technique_id,
            tactic=tactic,
            confidence_score=confidence_score,
        )
        self.session.add(rec)
        await self.session.commit()
        await self.session.refresh(rec)
        return rec

    async def create_timeline_technique(
        self, timeline_event_id: uuid.UUID, technique_id: str, tactic: MitreTacticEnum, confidence_score: float = 100.0
    ) -> TimelineTechnique:
        """Link a Timeline event directly to a MITRE technique in junction table."""
        rec = TimelineTechnique(
            timeline_event_id=timeline_event_id,
            technique_id=technique_id,
            tactic=tactic,
            confidence_score=confidence_score,
        )
        self.session.add(rec)
        await self.session.commit()
        await self.session.refresh(rec)
        return rec
