"""
Detection Rule Engine REST API Router.

Exposes REST endpoints for Detection Rule CRUD, syntax validation,
dry-run testing, version history, diff comparison, rollbacks, and statistics.
"""

import uuid
from typing import Annotated, List
from fastapi import APIRouter, Depends, status, Query, Body
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.users.router import get_current_user
from app.models.user import User
from app.detection_engine.models import RuleType, RuleStatus, RuleSeverity
from app.detection_engine.schemas import (
    DetectionRuleCreate,
    DetectionRuleUpdate,
    DetectionRuleRead,
    RuleVersionRead,
    RollbackRequest,
    DetectionRuleStatisticsRead,
)
from app.detection_engine.rule_validator import RuleValidationResult
from app.detection_engine.rule_tester import RuleTestResult
from app.detection_engine.rule_versions import VersionDiffResult
from app.detection_engine.rule_registry import RuleRegistry
from app.detection_engine.services import DetectionRuleService
from app.schemas.response import APIResponse, PaginatedResponse

router = APIRouter(prefix="/detection-rules", tags=["Detection Rule Engine"])


@router.get("", response_model=PaginatedResponse[DetectionRuleRead])
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    query: Annotated[str | None, Query(description="Search keyword")] = None,
    rule_type: Annotated[RuleType | None, Query(description="Filter by rule type")] = None,
    rule_status: Annotated[RuleStatus | None, Query(alias="status", description="Filter by status")] = None,
    severity: Annotated[RuleSeverity | None, Query(description="Filter by severity")] = None,
    category: Annotated[str | None, Query(description="Filter by category")] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> PaginatedResponse[DetectionRuleRead]:
    """Search and list detection rules with pagination."""
    service = DetectionRuleService(db)
    from app.detection_engine.schemas import RuleFilterParams
    params = RuleFilterParams(
        query=query,
        rule_type=rule_type,
        status=rule_status,
        severity=severity,
        category=category,
        page=page,
        page_size=page_size,
    )
    items, total = await service.list_rules(params)
    return PaginatedResponse.create(items=items, total=total, page=page, page_size=page_size)


@router.post("", response_model=APIResponse[DetectionRuleRead], status_code=status.HTTP_201_CREATED)
async def create_rule(
    data: DetectionRuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[DetectionRuleRead]:
    """Create a new Detection Rule."""
    service = DetectionRuleService(db)
    rule = await service.create_rule(data)
    return APIResponse(message=f"Detection Rule '{rule.name}' created successfully", data=rule)


@router.get("/templates", response_model=APIResponse[List[dict]])
async def list_rule_templates(
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[dict]]:
    """List reusable rule templates (Sigma, YARA, Suricata)."""
    templates = RuleRegistry.get_default_templates()
    return APIResponse(message="Rule templates retrieved", data=templates)


@router.get("/statistics", response_model=APIResponse[DetectionRuleStatisticsRead])
async def get_statistics(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[DetectionRuleStatisticsRead]:
    """Retrieve Detection Rule Engine metrics and statistics."""
    service = DetectionRuleService(db)
    stats = await service.get_statistics()
    return APIResponse(message="Detection rule statistics generated", data=stats)


@router.post("/validate", response_model=APIResponse[RuleValidationResult])
async def validate_rule(
    data: DetectionRuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[RuleValidationResult]:
    """Validate detection rule syntax and metadata without saving."""
    service = DetectionRuleService(db)
    result = await service.validate_rule(data)
    return APIResponse(message="Rule syntax validation completed", data=result)


@router.get("/{rule_id}", response_model=APIResponse[DetectionRuleRead])
async def get_rule(
    rule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[DetectionRuleRead]:
    """Retrieve details for a specific Detection Rule."""
    service = DetectionRuleService(db)
    rule = await service.get_rule(rule_id)
    return APIResponse(message="Detection Rule details retrieved", data=rule)


@router.put("/{rule_id}", response_model=APIResponse[DetectionRuleRead])
async def update_rule(
    rule_id: uuid.UUID,
    data: DetectionRuleUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[DetectionRuleRead]:
    """Update an existing Detection Rule and snapshot version."""
    service = DetectionRuleService(db)
    rule = await service.update_rule(rule_id, data)
    return APIResponse(message="Detection Rule updated successfully", data=rule)


@router.delete("/{rule_id}", response_model=APIResponse[dict])
async def delete_rule(
    rule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Delete a Detection Rule."""
    service = DetectionRuleService(db)
    await service.delete_rule(rule_id)
    return APIResponse(message="Detection Rule deleted successfully", data={"success": True})


@router.post("/{rule_id}/test", response_model=APIResponse[RuleTestResult])
async def test_rule(
    rule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    sample_data: Annotated[str, Body(embed=True, description="Sample log/text payload")],
) -> APIResponse[RuleTestResult]:
    """Execute dry-run matching test of a detection rule against sample data."""
    service = DetectionRuleService(db)
    res = await service.test_rule(rule_id, sample_data)
    return APIResponse(message="Rule dry-run test completed", data=res)


@router.get("/{rule_id}/versions", response_model=APIResponse[List[RuleVersionRead]])
async def list_versions(
    rule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[RuleVersionRead]]:
    """List version history snapshots for a detection rule."""
    service = DetectionRuleService(db)
    versions = await service.list_versions(rule_id)
    return APIResponse(message="Rule version history retrieved", data=versions)


@router.get("/{rule_id}/diff", response_model=APIResponse[VersionDiffResult])
async def compare_versions(
    rule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    version_a: Annotated[int, Query(ge=1)],
    version_b: Annotated[int, Query(ge=1)],
) -> APIResponse[VersionDiffResult]:
    """Compare two rule version contents line by line."""
    service = DetectionRuleService(db)
    diff = await service.compare_versions(rule_id, version_a, version_b)
    return APIResponse(message=f"Diff between version {version_a} and {version_b} generated", data=diff)


@router.post("/{rule_id}/rollback", response_model=APIResponse[DetectionRuleRead])
async def rollback_rule(
    rule_id: uuid.UUID,
    req: RollbackRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[DetectionRuleRead]:
    """Rollback detection rule content to a specific target version number."""
    service = DetectionRuleService(db)
    rule = await service.rollback_rule(rule_id, req.target_version)
    return APIResponse(message=f"Detection Rule rolled back to version {req.target_version}", data=rule)
