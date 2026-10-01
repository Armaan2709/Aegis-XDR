"""
Abstract Agent Security Tool Interface.

Defines the contract for functions executable by AI agents.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseAgentTool(ABC):
    """Abstract interface for AI agent executable tools."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        """Execute tool logic and return structured result payload."""
        pass
