"""
Evidence Domain REST API Endpoints Router.

Exposes REST API routes for forensic evidence ingestion, searching, hash filtering,
chain-of-custody transfer logging, integrity verification, and soft deletion.
"""

import math
import uuid
from typing import Annotated, List
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.users.router import get_current_user
from app.models.user import User
from app.models.evidence import EvidenceType, EvidenceClassification
from app.domains.evidence.schemas import (
    EvidenceCreate,
    EvidenceUpdate,
    EvidenceCustodyTransfer,
    EvidenceRead,
    EvidenceFilterParams,
    EvidenceSummaryStats,
)
from app.domains.evidence.services import EvidenceService
from app.schemas.response import APIResponse, PaginatedResponse, PaginationMeta

router = APIRouter(prefix="/evidence", tags=["Evidence Domain"])


@router.post("/", response_model=APIResponse[EvidenceRead], status_code=status.HTTP_201_CREATED)
async def create_evidence(
    evidence_in: EvidenceCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[EvidenceRead]:
    """Ingest a new digital forensic evidence artifact for an investigation."""
    service = EvidenceService(db)
    evidence = await service.create_evidence(evidence_in, collected_by_user_id=current_user.id)
    return APIResponse(
        message=f"Evidence artifact '{evidence.name}' ingested successfully",
        data=EvidenceRead.model_validate(evidence),
    )


@router.get("/", response_model=PaginatedResponse[EvidenceRead])
async def list_evidence(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    query: Annotated[str | None, Query(description="Search name, description, file_name, or host")] = None,
    investigation_id: Annotated[uuid.UUID | None, Query(description="Filter by investigation UUID")] = None,
    incident_id: Annotated[uuid.UUID | None, Query(description="Filter by incident UUID")] = None,
    evidence_type: Annotated[EvidenceType | None, Query(description="Filter by evidence type category")] = None,
    classification: Annotated[EvidenceClassification | None, Query(description="Filter by classification rating")] = None,
    hash_value: Annotated[str | None, Query(description="Filter by SHA256, MD5, or SHA1 hash")] = None,
    ip_address: Annotated[str | None, Query(description="Filter by IP address")] = None,
    sort_by: Annotated[str, Query(description="Field to sort by (created_at, name, evidence_type)")] = "created_at",
    sort_order: Annotated[str, Query(description="Sort direction (asc or desc)")] = "desc",
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PaginatedResponse[EvidenceRead]:
    """Search, filter, and paginate digital forensic evidence artifacts."""
    params = EvidenceFilterParams(
        query=query,
        investigation_id=investigation_id,
        incident_id=incident_id,
        evidence_type=evidence_type,
        classification=classification,
        hash_value=hash_value,
        ip_address=ip_address,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )
    service = EvidenceService(db)
    evidence_list, total_items = await service.list_evidence(params)
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 0

    return PaginatedResponse(
        data=[EvidenceRead.model_validate(ev) for ev in evidence_list],
        meta=PaginationMeta(
            page=page,
            page_size=page_size,
            total_items=total_items,
            total_pages=total_pages,
        ),
    )


@router.get("/summary", response_model=APIResponse[EvidenceSummaryStats])
async def get_evidence_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[EvidenceSummaryStats]:
    """Retrieve aggregate evidence metrics and classification statistics."""
    service = EvidenceService(db)
    stats = await service.get_summary_stats()
    return APIResponse(
        message="Evidence summary statistics retrieved",
        data=stats,
    )


@router.get("/investigation/{investigation_id}", response_model=APIResponse[List[EvidenceRead]])
async def list_by_investigation(
    investigation_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[EvidenceRead]]:
    """Retrieve all evidence artifacts for a specific Investigation."""
    service = EvidenceService(db)
    evidence_list = await service.list_by_investigation(investigation_id)
    return APIResponse(
        message=f"Retrieved {len(evidence_list)} evidence artifacts for investigation",
        data=[EvidenceRead.model_validate(ev) for ev in evidence_list],
    )


@router.get("/{evidence_id}", response_model=APIResponse[EvidenceRead])
async def get_evidence_detail(
    evidence_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[EvidenceRead]:
    """Retrieve detailed information for a specific evidence artifact by UUID."""
    service = EvidenceService(db)
    evidence = await service.get_evidence(evidence_id)
    return APIResponse(
        message="Evidence details retrieved",
        data=EvidenceRead.model_validate(evidence),
    )


@router.put("/{evidence_id}", response_model=APIResponse[EvidenceRead])
async def update_evidence(
    evidence_id: uuid.UUID,
    update_in: EvidenceUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[EvidenceRead]:
    """Update evidence artifact metadata or hash attributes."""
    service = EvidenceService(db)
    evidence = await service.update_evidence(evidence_id, update_in)
    return APIResponse(
        message="Evidence artifact updated successfully",
        data=EvidenceRead.model_validate(evidence),
    )


@router.post("/{evidence_id}/custody", response_model=APIResponse[EvidenceRead])
async def transfer_custody(
    evidence_id: uuid.UUID,
    custody_in: EvidenceCustodyTransfer,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[EvidenceRead]:
    """Record a chain-of-custody transfer entry for an evidence artifact."""
    service = EvidenceService(db)
    evidence = await service.transfer_custody(evidence_id, custody_in, actor_id=current_user.id)
    return APIResponse(
        message="Chain of custody transfer recorded successfully",
        data=EvidenceRead.model_validate(evidence),
    )


@router.post("/{evidence_id}/verify-integrity", response_model=APIResponse[dict])
async def verify_integrity(
    evidence_id: uuid.UUID,
    calculated_sha256: Annotated[str, Query(description="SHA256 hash calculated from evidence file")],
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Verify hash integrity of an evidence artifact against recorded SHA256."""
    service = EvidenceService(db)
    is_valid = await service.verify_integrity(evidence_id, calculated_sha256)
    return APIResponse(
        message="Integrity check complete",
        data={"evidence_id": str(evidence_id), "integrity_verified": is_valid},
    )


@router.delete("/{evidence_id}", response_model=APIResponse[dict])
async def delete_evidence(
    evidence_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Soft delete digital evidence artifact."""
    service = EvidenceService(db)
    success = await service.delete_evidence(evidence_id)
    return APIResponse(
        message="Evidence artifact soft deleted successfully",
        data={"evidence_id": str(evidence_id), "deleted": success},
    )
