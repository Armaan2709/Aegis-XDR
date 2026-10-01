"""
AI Orchestrator API Schemas.

Pydantic v2 data transfer objects for AI agents, tools, models, health checks,
and investigation execution requests.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.ai.agents.base import AgentResult
from app.ai.orchestrator.consensus import ConsensusResult


class AgentInfoResponse(BaseModel):
    """Schema representing registered agent info."""
    name: str
    description: str
    capabilities: List[str]


class ToolInfoResponse(BaseModel):
    """Schema representing registered security tool info."""
    name: str
    description: str
    parameters_schema: Dict[str, Any]


class ModelInfoResponse(BaseModel):
    """Schema representing registered LLM model info."""
    model_name: str
    is_mock: bool = True
    status: str = "AVAILABLE"


class AIHealthResponse(BaseModel):
    """Schema representing AI Orchestrator system health."""
    status: str = "HEALTHY"
    agents_registered: int
    tools_registered: int
    models_registered: int


class InvestigationStartRequest(BaseModel):
    """Payload to trigger an AI investigation orchestration run."""
    incident_id: Optional[str] = Field(default=None, description="Associated Incident UUID string")
    case_id: Optional[str] = Field(default=None, description="Associated Case UUID string")
    initial_alerts: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="Initial alert records")
