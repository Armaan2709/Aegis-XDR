"""
AI Orchestrator Agent Base Abstraction.

Defines the core abstract base class BaseAgent, AgentStatus enum, and structured AgentResult DTO.
"""

import enum
import time
from abc import ABC, abstractmethod
from typing import List, Dict, Any, TYPE_CHECKING
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from app.ai.orchestrator.state import InvestigationState


class AgentStatus(str, enum.Enum):
    """Operational lifecycle status of an AI agent execution."""
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    WAITING = "WAITING"


class AgentResult(BaseModel):
    """Structured response result produced by an AI agent execution."""
    agent_name: str = Field(..., description="Name of the executing agent")
    status: AgentStatus = Field(default=AgentStatus.SUCCESS, description="Execution status outcome")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Structured analytical findings")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Artifact evidence items identified")
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Agent confidence rating (0.0 to 1.0)")
    recommendations: List[str] = Field(default_factory=list, description="Actionable security recommendations")
    execution_time_ms: float = Field(default=0.0, description="Execution duration in milliseconds")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary execution metadata")


class BaseAgent(ABC):
    """Abstract Base Class for all AegisAI XDR security agents."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique agent identifier name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Overview of agent security domain and role."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> List[str]:
        """List of functional capability keywords supported by this agent."""
        pass

    @abstractmethod
    async def execute(self, state: "InvestigationState") -> AgentResult:
        """Execute agent analysis on the shared investigation state."""
        pass

    def validate_input(self, state: "InvestigationState") -> bool:
        """Validate whether the shared investigation state contains required fields for execution."""
        return state is not None and bool(state.investigation_id)

    def health_check(self) -> bool:
        """Verify agent operational readiness."""
        return True
