"""
AI Orchestrator Engine Registry Manager.

Manages registration, lookup, and health checks for AI Orchestrator engine instances.
Prevents duplicate registrations.
"""

from typing import Dict, List, Optional, Any
from app.core.exceptions import ConflictError, NotFoundError


class OrchestratorRegistry:
    """Registry for managing AIOrchestrator engine instances."""

    def __init__(self):
        self._orchestrators: Dict[str, Any] = {}

    def register_orchestrator(self, name: str, orchestrator: Any) -> None:
        """Register orchestrator instance. Raises ConflictError on duplicate name."""
        key = name.lower().strip()
        if key in self._orchestrators:
            raise ConflictError(f"Orchestrator '{name}' is already registered.")
        self._orchestrators[key] = orchestrator

    def get_orchestrator(self, name: str) -> Optional[Any]:
        """Fetch orchestrator instance by name."""
        return self._orchestrators.get(name.lower().strip())

    def list_orchestrators(self) -> List[str]:
        """List registered orchestrator names."""
        return list(self._orchestrators.keys())

    def health_check_all(self) -> Dict[str, bool]:
        """Perform health checks on registered orchestrators."""
        results = {}
        for name, orch in self._orchestrators.items():
            results[name] = hasattr(orch, "health_check") and orch.health_check()
        return results
