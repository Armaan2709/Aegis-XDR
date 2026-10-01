"""
Correlation Engine REST API Endpoints Router.

Exposes REST API routes for deterministic alert correlation evaluation, rule management,
and entity relationship graph network visualization.
"""

import uuid
from typing import Annotated, List
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.users.router import get_current_user
from app.models.user import User
from app.correlation.schemas import (
    CorrelationRequest,
    CorrelationExecutionResult,
    CorrelationRuleCreate,
    CorrelationRuleRead,
    CorrelationGraphRead,
)
from app.correlation.rules import get_default_correlation_rules
from app.correlation.services import CorrelationService
from app.schemas.response import APIResponse

router = APIRouter(prefix="/correlation", tags=["Correlation Engine"])


@router.post("/evaluate", response_model=APIResponse[CorrelationExecutionResult])
async def evaluate_correlation(
    request: CorrelationRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CorrelationExecutionResult]:
    """Trigger deterministic alert correlation over unassigned or selected alerts."""
    service = CorrelationService(db)
    result = await service.evaluate(request)
    return APIResponse(
        message=f"Correlation evaluation complete: {result.candidates_count} candidates generated",
        data=result,
    )


@router.get("/rules", response_model=APIResponse[List[CorrelationRuleRead]])
async def list_correlation_rules(
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[CorrelationRuleRead]]:
    """List active deterministic correlation rules."""
    rules = get_default_correlation_rules()
    return APIResponse(
        message=f"Retrieved {len(rules)} correlation rules",
        data=[CorrelationRuleRead.model_validate(r) for r in rules],
    )


@router.get("/graph/{incident_id}", response_model=APIResponse[CorrelationGraphRead])
async def get_incident_correlation_graph(
    incident_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[CorrelationGraphRead]:
    """Retrieve entity relationship graph network for a correlated Incident."""
    service = CorrelationService(db)
    graph_data = await service.get_incident_graph(incident_id)
    return APIResponse(
        message="Incident correlation graph network retrieved",
        data=graph_data,
    )
