"""
AegisAI XDR — AI Orchestrator Foundation Package.

Exposes core abstractions for agents, state model, workflow DAGs, consensus engine,
memory stores, security tools, prompt registry, LLM providers, and API router.
"""

from app.ai.agents.base import AgentStatus, AgentResult, BaseAgent
from app.ai.agents.registry import AgentRegistry
from app.ai.orchestrator.state import InvestigationState
from app.ai.orchestrator.graph import WorkflowStep, AgentNode, WorkflowGraph, WorkflowExecution
from app.ai.orchestrator.consensus import ConsensusResult, ConsensusEngine
from app.ai.orchestrator.engine import OrchestrationResult, AIOrchestrator
from app.ai.models.base import BaseLLMProvider
from app.ai.models.mock import MockLLMProvider
from app.ai.models.provider import LLMProviderFactory
from app.ai.memory.interface import BaseMemoryStore
from app.ai.memory.short_term import ShortTermMemory
from app.ai.memory.case_memory import CaseMemory
from app.ai.tools.base import BaseSecurityTool
from app.ai.tools.registry import ToolRegistry
from app.ai.prompts.registry import PromptTemplate, PromptRegistry
from app.ai.workflows.base import BaseWorkflow
from app.ai.workflows.investigation import InvestigationWorkflow

__all__ = [
    "AgentStatus",
    "AgentResult",
    "BaseAgent",
    "AgentRegistry",
    "InvestigationState",
    "WorkflowStep",
    "AgentNode",
    "WorkflowGraph",
    "WorkflowExecution",
    "ConsensusResult",
    "ConsensusEngine",
    "OrchestrationResult",
    "AIOrchestrator",
    "BaseLLMProvider",
    "MockLLMProvider",
    "LLMProviderFactory",
    "BaseMemoryStore",
    "ShortTermMemory",
    "CaseMemory",
    "BaseSecurityTool",
    "ToolRegistry",
    "PromptTemplate",
    "PromptRegistry",
    "BaseWorkflow",
    "InvestigationWorkflow",
]

