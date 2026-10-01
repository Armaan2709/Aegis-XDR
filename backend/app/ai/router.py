"""
AI Orchestrator REST API Router.

Exposes endpoints for querying registered agents, security tools, LLM models, system health,
and triggering structured AI investigation workflows.
Mounted under /api/v1/ai.
"""

import uuid
from typing import Annotated, List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.exceptions import NotFoundError
from app.domains.users.router import get_current_user
from app.models.user import User
from app.domains.investigations.repositories import InvestigationRepository
from app.ai.agents.registry import AgentRegistry
from app.ai.agents.threat_hunter.agent import ThreatHunterAgent
from app.ai.agents.dfir.agent import DFIRInvestigatorAgent
from app.ai.agents.threat_intel.agent import ThreatIntelligenceAnalystAgent
from app.ai.agents.detection_generator.agent import DetectionRuleGeneratorAgent
from app.ai.agents.incident_commander.agent import IncidentCommanderAgent
from app.ai.tools.registry import ToolRegistry
from app.ai.tools.security_tools import (
    QuerySIEMTool,
    QueryThreatIntelTool,
    QueryMitreTool,
    QueryEvidenceTool,
    ExecutePlaybookTool,
)
from app.ai.models.provider import LLMProviderFactory
from app.ai.orchestrator.engine import AIOrchestrator, OrchestrationResult
from app.ai.workflows.investigation import InvestigationWorkflow
from app.ai.schemas import (
    AgentInfoResponse,
    ToolInfoResponse,
    ModelInfoResponse,
    AIHealthResponse,
    InvestigationStartRequest,
)
from app.schemas.response import APIResponse

router = APIRouter(prefix="/ai", tags=["AI Orchestrator Domain"])

# Global registries initialization for router scope
_agent_registry = AgentRegistry()
_agent_registry.register_agent(ThreatHunterAgent())
_agent_registry.register_agent(DFIRInvestigatorAgent())
_agent_registry.register_agent(ThreatIntelligenceAnalystAgent(), alias="ThreatIntelAgent")
_agent_registry.register_agent(DetectionRuleGeneratorAgent(), alias="DetectionAgent")
_agent_registry.register_agent(IncidentCommanderAgent())

_tool_registry = ToolRegistry()






# Register default safe read-only tools
_tool_registry.register(QuerySIEMTool())
_tool_registry.register(QueryThreatIntelTool())
_tool_registry.register(QueryMitreTool())
_tool_registry.register(QueryEvidenceTool())
_tool_registry.register(ExecutePlaybookTool())

_llm_factory = LLMProviderFactory()


@router.get("/agents", response_model=APIResponse[List[AgentInfoResponse]])
async def list_agents(
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[AgentInfoResponse]]:
    """List registered AI agents and their security capabilities."""
    agents = _agent_registry.list_agents()
    data = [
        AgentInfoResponse(
            name=a.name,
            description=a.description,
            capabilities=a.capabilities,
        )
        for a in agents
    ]
    return APIResponse(
        message="Registered AI agents retrieved successfully",
        data=data,
    )


@router.get("/tools", response_model=APIResponse[List[ToolInfoResponse]])
async def list_tools(
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[ToolInfoResponse]]:
    """List registered safe AI security tools."""
    tools = _tool_registry.list()
    data = [
        ToolInfoResponse(
            name=t.name,
            description=t.description,
            parameters_schema=t.parameters_schema,
        )
        for t in tools
    ]
    return APIResponse(
        message="Registered security tools retrieved successfully",
        data=data,
    )


@router.get("/models", response_model=APIResponse[List[ModelInfoResponse]])
async def list_models(
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[ModelInfoResponse]]:
    """List registered LLM inference models."""
    provider_names = _llm_factory.list_providers()
    data = [
        ModelInfoResponse(model_name=name, is_mock=True, status="AVAILABLE")
        for name in provider_names
    ]
    return APIResponse(
        message="Registered LLM models retrieved successfully",
        data=data,
    )


@router.get("/health", response_model=APIResponse[AIHealthResponse])
async def ai_health(
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[AIHealthResponse]:
    """Return health status of the AI Orchestration layer."""
    health_data = AIHealthResponse(
        status="HEALTHY",
        agents_registered=len(_agent_registry.list_agents()),
        tools_registered=len(_tool_registry.list()),
        models_registered=len(_llm_factory.list_providers()),
    )
    return APIResponse(
        message="AI Orchestrator health status OK",
        data=health_data,
    )


@router.post("/investigations/{investigation_id}/start", response_model=APIResponse[OrchestrationResult], status_code=status.HTTP_200_OK)
async def start_investigation_orchestration(
    investigation_id: uuid.UUID,
    payload: InvestigationStartRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[OrchestrationResult]:
    """Verify investigation entity exists and execute multi-agent AI orchestration workflow."""
    inv_repo = InvestigationRepository(db)
    investigation = await inv_repo.get_by_id(investigation_id)
    if not investigation:
        raise NotFoundError(f"Investigation with ID '{investigation_id}' not found")

    orchestrator = AIOrchestrator(
        agent_registry=_agent_registry,
        tool_registry=_tool_registry,
        llm_factory=_llm_factory,
    )

    state = orchestrator.start_investigation(
        investigation_id=str(investigation.id),
        incident_id=str(investigation.incident_id) if investigation.incident_id else payload.incident_id,
        case_id=payload.case_id,
        initial_alerts=payload.initial_alerts,
    )

from app.ai.pipeline.pipeline import AutonomousInvestigationPipeline
from app.ai.pipeline.schemas import PipelineRunRequest, PipelineContext


_pipeline_engine = AutonomousInvestigationPipeline()
_pipeline_store: dict[str, PipelineContext] = {}


@router.post("/investigations/{investigation_id}/run", response_model=APIResponse[dict], status_code=status.HTTP_200_OK)
async def run_autonomous_investigation_pipeline(
    investigation_id: uuid.UUID,
    payload: PipelineRunRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Execute end-to-end autonomous investigation pipeline."""
    inv_repo = InvestigationRepository(db)
    investigation = await inv_repo.get_by_id(investigation_id)
    if not investigation:
        raise NotFoundError(f"Investigation with ID '{investigation_id}' not found")

    context = _pipeline_engine.initialize_context(payload)
    if payload.auto_approve_routine:
        context.approval_status = "AUTO_APPROVED"

    result_context = await _pipeline_engine.run(context)
    _pipeline_store[result_context.pipeline_id] = result_context
    _pipeline_store[str(investigation_id)] = result_context

    return APIResponse(
        message=f"Autonomous investigation pipeline executed with status '{result_context.status.value}'",
        data={
            "pipeline_id": result_context.pipeline_id,
            "investigation_id": result_context.investigation_id,
            "status": result_context.status.value,
            "current_stage": result_context.current_stage.value,
            "approval_required": result_context.approval_required,
            "approval_status": result_context.approval_status,
        },
    )


@router.get("/investigations/{investigation_id}/status", response_model=APIResponse[dict])
async def get_investigation_pipeline_status(
    investigation_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Retrieve status of investigation pipeline."""
    ctx = _pipeline_store.get(str(investigation_id))
    if not ctx:
        raise NotFoundError(f"Pipeline status for investigation ID '{investigation_id}' not found")

    return APIResponse(
        message="Pipeline status retrieved successfully",
        data={
            "pipeline_id": ctx.pipeline_id,
            "investigation_id": ctx.investigation_id,
            "status": ctx.status.value,
            "current_stage": ctx.current_stage.value,
            "stage_results": {k: v.model_dump() for k, v in ctx.stage_results.items()},
        },
    )


@router.get("/investigations/{investigation_id}/timeline", response_model=APIResponse[List[dict]])
async def get_investigation_pipeline_timeline(
    investigation_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[List[dict]]:
    """Retrieve auditable timeline of investigation pipeline events."""
    ctx = _pipeline_store.get(str(investigation_id))
    if not ctx:
        raise NotFoundError(f"Pipeline timeline for investigation ID '{investigation_id}' not found")

    return APIResponse(
        message="Pipeline timeline retrieved successfully",
        data=[t.model_dump() for t in ctx.timeline],
    )


@router.post("/investigations/{investigation_id}/cancel", response_model=APIResponse[dict])
async def cancel_investigation_pipeline(
    investigation_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Safely cancel running investigation pipeline."""
    ctx = _pipeline_store.get(str(investigation_id))
    if not ctx:
        raise NotFoundError(f"Active pipeline for investigation ID '{investigation_id}' not found")

    cancelled_ctx = _pipeline_engine.cancel(ctx, reason=f"Cancelled by user '{current_user.username}'")
    _pipeline_store[str(investigation_id)] = cancelled_ctx

    return APIResponse(
        message="Pipeline cancelled successfully",
        data={"pipeline_id": cancelled_ctx.pipeline_id, "status": cancelled_ctx.status.value},
    )


@router.get("/pipelines/{pipeline_id}", response_model=APIResponse[dict])
async def get_pipeline_by_id(
    pipeline_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[dict]:
    """Retrieve pipeline context payload by pipeline_id."""
    ctx = _pipeline_store.get(pipeline_id)
    if not ctx:
        raise NotFoundError(f"Pipeline with ID '{pipeline_id}' not found")

    return APIResponse(
        message="Pipeline context retrieved successfully",
        data={
            "pipeline_id": ctx.pipeline_id,
            "investigation_id": ctx.investigation_id,
            "status": ctx.status.value,
            "current_stage": ctx.current_stage.value,
            "approval_status": ctx.approval_status,
        },
    )

