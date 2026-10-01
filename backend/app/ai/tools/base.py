"""
AI Orchestrator Security Tool Base Abstraction.

Defines the abstract BaseSecurityTool interface for all AI-invokable security tools.
GUARANTEE: Security tools are strictly controlled read-only abstractions.
No shell execution, arbitrary Python code, or destructive operations are permitted.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseSecurityTool(ABC):
    """Abstract Base Class for AI security tools."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique tool identifier name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Detailed description of tool functionality and usage boundaries."""
        pass

    @property
    @abstractmethod
    def parameters_schema(self) -> Dict[str, Any]:
        """JSON Schema dictionary describing required and optional parameters."""
        pass

    @abstractmethod
    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the security tool safely."""
        pass

    def health_check(self) -> bool:
        """Verify tool operational status."""
        return True
