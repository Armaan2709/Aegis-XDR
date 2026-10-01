"""
MITRE ATT&CK Domain Service Layer.

Handles business logic for Technique management, Sub-Techniques, deterministic artifact mapping,
coverage statistics calculation, and local knowledge base seeding.
"""

import uuid
from typing import List, Tuple, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.mitre.repositories import MitreRepository
from app.mitre.mapper import MitreMapper, MitreMappingMatch
from app.mitre.coverage import MitreCoverageCalculator, MitreCoverageReport
from app.mitre.knowledge_base import MitreKnowledgeBase
from app.mitre.schemas import (
    MitreTechniqueCreate,
    MitreTechniqueUpdate,
    MitreTechniqueRead,
    MitreSubTechniqueCreate,
    MitreSubTechniqueRead,
    MitreMappingCreate,
    MitreMappingRead,
    MitreFilterParams,
    ArtifactMappingRequest,
)
from app.core.exceptions import NotFoundError, ConflictError
from app.core.logging import get_logger

logger = get_logger("domain.mitre")


class MitreService:
    """Application Service encapsulating MITRE ATT&CK operations."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = MitreRepository(session)

    async def create_technique(self, data: MitreTechniqueCreate) -> MitreTechniqueRead:
        """Create a new MITRE technique."""
        existing = await self.repo.get_technique_by_id(data.technique_id)
        if existing:
            raise ConflictError(f"Technique with ID '{data.technique_id}' already exists.")

        technique = await self.repo.create_technique(data)
        logger.info("MITRE Technique created", technique_id=technique.technique_id, name=technique.name)
        return MitreTechniqueRead.model_validate(technique)

    async def get_technique(self, technique_id: str) -> MitreTechniqueRead:
        """Retrieve a single technique by ID."""
        technique = await self.repo.get_technique_by_id(technique_id)
        if not technique:
            raise NotFoundError(f"Technique with ID '{technique_id}' was not found.")
        return MitreTechniqueRead.model_validate(technique)

    async def list_techniques(self, params: MitreFilterParams) -> Tuple[List[MitreTechniqueRead], int]:
        """List techniques with filtering and pagination."""
        techniques, total = await self.repo.list_techniques(params)
        dtos = [MitreTechniqueRead.model_validate(t) for t in techniques]
        return dtos, total

    async def update_technique(self, technique_id: str, data: MitreTechniqueUpdate) -> MitreTechniqueRead:
        """Update an existing technique."""
        technique = await self.repo.update_technique(technique_id, data)
        if not technique:
            raise NotFoundError(f"Technique with ID '{technique_id}' was not found.")
        return MitreTechniqueRead.model_validate(technique)

    async def delete_technique(self, technique_id: str) -> bool:
        """Delete a technique."""
        success = await self.repo.delete_technique(technique_id)
        if not success:
            raise NotFoundError(f"Technique with ID '{technique_id}' was not found.")
        return True

    async def create_subtechnique(self, data: MitreSubTechniqueCreate) -> MitreSubTechniqueRead:
        """Create a new sub-technique."""
        subtech = await self.repo.create_subtechnique(data)
        return MitreSubTechniqueRead.model_validate(subtech)

    async def list_subtechniques(self, parent_technique_id: str) -> List[MitreSubTechniqueRead]:
        """List sub-techniques for parent technique."""
        subtechs = await self.repo.list_subtechniques(parent_technique_id)
        return [MitreSubTechniqueRead.model_validate(s) for s in subtechs]

    async def map_artifact(self, req: ArtifactMappingRequest) -> List[MitreMappingRead]:
        """
        Deterministically evaluate artifact payload against MITRE signatures,
        persist resulting mappings, and return mapping DTOs.
        """
        payload = req.payload
        payload["id"] = str(req.artifact_id)

        matches = MitreMapper.map_artifact(payload)
        created_mappings: List[MitreMappingRead] = []

        for match in matches:
            mapping_data = MitreMappingCreate(
                artifact_type=req.artifact_type.upper(),
                artifact_id=req.artifact_id,
                technique_id=match.technique_id,
                subtechnique_id=match.subtechnique_id,
                tactic=match.tactic,
                confidence_score=match.confidence_score,
                evidence_references=match.evidence_refs,
                metadata_info={"matched_rule": match.matched_rule},
            )
            mapping_entity = await self.repo.create_mapping(mapping_data)
            created_mappings.append(MitreMappingRead.model_validate(mapping_entity))

        logger.info(
            "Artifact MITRE mapping evaluated",
            artifact_type=req.artifact_type,
            artifact_id=str(req.artifact_id),
            matches_count=len(created_mappings),
        )

        return created_mappings

    async def get_artifact_mappings(self, artifact_type: str, artifact_id: uuid.UUID) -> List[MitreMappingRead]:
        """Get MITRE mappings associated with an artifact."""
        mappings = await self.repo.get_mappings_for_artifact(artifact_type, artifact_id)
        return [MitreMappingRead.model_validate(m) for m in mappings]

    async def get_coverage_report(self, scope: str = "ENVIRONMENT") -> MitreCoverageReport:
        """Calculate and return MITRE ATT&CK coverage report."""
        mappings = await self.repo.list_all_mappings()
        return MitreCoverageCalculator.calculate_coverage(mappings, scope=scope)

    async def seed_knowledge_base(self) -> int:
        """Seed default MITRE catalog techniques if empty."""
        techniques, total = await self.repo.list_techniques(MitreFilterParams(page=1, page_size=1))
        if total > 0:
            return 0

        default_techs = MitreKnowledgeBase.get_techniques()
        seeded = 0
        for tech in default_techs:
            create_dto = MitreTechniqueCreate(
                technique_id=tech["technique_id"],
                tactic=tech["tactic"],
                name=tech["name"],
                description=tech["description"],
                platforms=tech["platforms"],
                detection_notes=tech.get("detection_notes"),
                data_sources=tech.get("data_sources", []),
                mitigation_notes=tech.get("mitigation_notes"),
            )
            await self.repo.create_technique(create_dto)
            seeded += 1

        default_subtechs = MitreKnowledgeBase.get_subtechniques()
        for sub in default_subtechs:
            sub_dto = MitreSubTechniqueCreate(
                subtechnique_id=sub["subtechnique_id"],
                parent_technique_id=sub["parent_technique_id"],
                name=sub["name"],
                description=sub["description"],
                platforms=sub["platforms"],
                detection_notes=sub.get("detection_notes"),
            )
            await self.repo.create_subtechnique(sub_dto)

        logger.info("MITRE Knowledge Base seeded", seeded_techniques=seeded)
        return seeded
