"""
Abstract Specialized AI Agent Interface.

Defines the contract for individual domain-specialized AI agents.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseAgent(ABC):
    """Abstract Base Class for specialized autonomous security AI agents."""

    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role

    @abstractmethod
    async def analyze(
        self, input_data: Dict[str, Any], history: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Execute agent specialized reasoning and tool invocations."""
        pass
