"""
Abstract AI Agent Orchestrator Interface.

Defines the execution lifecycle contract for multi-agent graph orchestrators.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseAgentOrchestrator(ABC):
    """Abstract Base Class for multi-agent investigation graph orchestrators."""

    @abstractmethod
    async def run_investigation(
        self, incident_id: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute autonomous multi-agent investigation workflow graph."""
        pass

    @abstractmethod
    async def get_orchestrator_state(self, session_id: str) -> Dict[str, Any]:
        """Retrieve active state snapshot of multi-agent graph execution."""
        pass
