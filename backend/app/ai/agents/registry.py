"""
AI Orchestrator Agent Registry Manager.

Manages registration, lookup, capability searching, and health checks for AI agents.
Prevents duplicate registrations.
"""

from typing import Dict, List, Optional
from app.ai.agents.base import BaseAgent
from app.core.exceptions import ConflictError, NotFoundError


class AgentRegistry:
    """Registry engine for managing security AI agents."""

    def __init__(self):
        self._agents: Dict[str, BaseAgent] = {}

    def register_agent(self, agent: BaseAgent, alias: Optional[str] = None) -> None:
        """Register an agent instance. Raises ConflictError on duplicate name."""
        name_key = agent.name.lower().strip()
        if name_key in self._agents:
            raise ConflictError(f"Agent with name '{agent.name}' is already registered.")
        self._agents[name_key] = agent
        if alias:
            alias_key = alias.lower().strip()
            self._agents[alias_key] = agent


    def unregister_agent(self, agent_name: str) -> None:
        """Unregister an agent by name. Raises NotFoundError if not found."""
        name_key = agent_name.lower().strip()
        if name_key not in self._agents:
            raise NotFoundError(f"Agent '{agent_name}' is not registered.")
        del self._agents[name_key]

    def get_agent(self, agent_name: str) -> Optional[BaseAgent]:
        """Fetch agent by name."""
        return self._agents.get(agent_name.lower().strip())

    def list_agents(self) -> List[BaseAgent]:
        """List all unique registered agents."""
        seen = set()
        unique = []
        for agent in self._agents.values():
            if agent.name not in seen:
                seen.add(agent.name)
                unique.append(agent)
        return unique

    def find_by_capability(self, capability: str) -> List[BaseAgent]:
        """Find agents providing a specific capability keyword."""
        cap_key = capability.lower().strip()
        results = []
        for agent in self._agents.values():
            if any(cap_key == cap.lower().strip() for cap in agent.capabilities):
                results.append(agent)
        return results

    def health_check_all(self) -> Dict[str, bool]:
        """Perform health checks on all registered agents."""
        return {agent.name: agent.health_check() for agent in self._agents.values()}
