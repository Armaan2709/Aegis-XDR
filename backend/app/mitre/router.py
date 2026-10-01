"""
MITRE ATT&CK Domain REST API Router.

Exposes REST endpoints for CRUD operations on Techniques & Sub-Techniques,
deterministic artifact mapping, coverage statistics, and knowledge base seeding.
"""

import uuid
from typing import Annotated, List
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.users.router import get_current_user
from app.models.user import User
from app.mitre.schemas import (
    MitreTechniqueCreate,
    MitreTechniqueUpdate,
    MitreTechniqueRead,
    MitreSubTechniqueCreate,
    MitreSubTechniqueRead,
    MitreMappingRead,
    MitreFilterParams,
    ArtifactMappingRequest,
)
from app.mitre.coverage import MitreCoverageReport
from app.mitre.services import MitreService
from app.schemas.response import APIResponse, PaginatedResponse

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK Engine"])


@router.get("/techniques", response_model=PaginatedResponse[MitreTechniqueRead])
async def list_techniques(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    query: Annotated[str | None, Query(description="Search keyword")] = None,
    tactic: Annotated[str | None, Query(description="Filter by tactic")] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> PaginatedResponse[MitreTechniqueRead]:
    """Search and filter MITRE ATT&CK techniques with pagination."""
    service = MitreService(db)
    params = MitreFilterParams(query=query, tactic=tactic, page=page, page_size=page_size)
    items, total = await service.list_techniques(params)
    return PaginatedResponse.create(items=items, total=total, page=page, page_size=page_size)


@router.post("/techniques", response_model=APIResponse[MitreTechniqueRead], status_code=status.HTTP_201_CREATED)
async def create_technique(
    data: MitreTechniqueCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[MitreTechniqueRead]:
    """Create a new MITRE ATT&CK technique."""
    service = MitreService(db)
    technique = await service.create_technique(data)
    return APIResponse(message=f"Technique '{technique.technique_id}' created successfully", data=technique)


@router.get("/techniques/{technique_id}", response_model=APIResponse[MitreTechniqueRead])
async def get_technique(
    technique_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[MitreTechniqueRead]:
    """Retrieve details for a specific MITRE ATT&CK technique."""
    service = MitreService(db)
    technique = await service.get_technique(technique_id)
    return APIResponse(message="Technique details retrieved", data=technique)


@router.put("/techniques/{technique_id}", response_model=APIResponse[MitreTechniqueRead])
async def update_technique(
    technique_id: str,
    data: MitreTechniqueUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[MitreTechniqueRead]:
    """Update an existing MITRE ATT&CK technique."""
    service = MitreService(db)
    technique = await service.update_technique(technique_id, data)
    return APIResponse(message=f"Technique '{technique_id}' updated successfully", data=technique)


@router.delete("/techniques/{technique_id}", response_model=APIResponse[dict])
async def delete_technique(
    technique_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Delete a MITRE ATT&CK technique."""
    service = MitreService(db)
    await service.delete_technique(technique_id)
    return APIResponse(message=f"Technique '{technique_id}' deleted successfully", data={"success": True})


@router.get("/techniques/{technique_id}/subtechniques", response_model=APIResponse[List[MitreSubTechniqueRead]])
async def list_subtechniques(
    technique_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[MitreSubTechniqueRead]]:
    """List all sub-techniques for a parent MITRE technique."""
    service = MitreService(db)
    items = await service.list_subtechniques(technique_id)
    return APIResponse(message=f"Sub-techniques for '{technique_id}' retrieved", data=items)


@router.post("/subtechniques", response_model=APIResponse[MitreSubTechniqueRead], status_code=status.HTTP_201_CREATED)
async def create_subtechnique(
    data: MitreSubTechniqueCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[MitreSubTechniqueRead]:
    """Create a new MITRE ATT&CK sub-technique."""
    service = MitreService(db)
    subtech = await service.create_subtechnique(data)
    return APIResponse(message=f"Sub-technique '{subtech.subtechnique_id}' created successfully", data=subtech)


@router.post("/map", response_model=APIResponse[List[MitreMappingRead]])
async def map_artifact(
    request: ArtifactMappingRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[MitreMappingRead]]:
    """Deterministically map a security artifact to MITRE ATT&CK techniques."""
    service = MitreService(db)
    mappings = await service.map_artifact(request)
    return APIResponse(
        message=f"Mapped {len(mappings)} MITRE techniques to {request.artifact_type} '{request.artifact_id}'",
        data=mappings,
    )


@router.get("/mappings/{artifact_type}/{artifact_id}", response_model=APIResponse[List[MitreMappingRead]])
async def get_artifact_mappings(
    artifact_type: str,
    artifact_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[MitreMappingRead]]:
    """Retrieve MITRE ATT&CK mappings associated with a specific artifact."""
    service = MitreService(db)
    mappings = await service.get_artifact_mappings(artifact_type, artifact_id)
    return APIResponse(message="Artifact MITRE mappings retrieved", data=mappings)


@router.get("/coverage", response_model=APIResponse[MitreCoverageReport])
async def get_mitre_coverage(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    scope: Annotated[str, Query()] = "ENVIRONMENT",
) -> APIResponse[MitreCoverageReport]:
    """Retrieve MITRE ATT&CK coverage statistics and heatmap report."""
    service = MitreService(db)
    report = await service.get_coverage_report(scope=scope)
    return APIResponse(message="MITRE ATT&CK coverage report generated", data=report)


@router.get("/matrix", response_model=APIResponse[MitreCoverageReport])
async def get_mitre_matrix(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    scope: Annotated[str, Query()] = "ENVIRONMENT",
) -> APIResponse[MitreCoverageReport]:
    """Retrieve MITRE ATT&CK matrix and coverage data for SOC visualization."""
    service = MitreService(db)
    report = await service.get_coverage_report(scope=scope)
    return APIResponse(message="MITRE ATT&CK matrix retrieved successfully", data=report)


@router.post("/seed", response_model=APIResponse[dict])
async def seed_mitre_knowledge_base(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Seed default offline MITRE ATT&CK knowledge base catalog."""
    service = MitreService(db)
    seeded_count = await service.seed_knowledge_base()
    return APIResponse(
        message=f"Seeded {seeded_count} MITRE techniques into local knowledge base",
        data={"seeded_count": seeded_count},
    )
