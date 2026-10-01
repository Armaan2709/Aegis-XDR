"""
AI Orchestrator LLM Provider Base Abstraction.

Defines BaseLLMProvider abstract class for AI model generation interfaces.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class BaseLLMProvider(ABC):
    """Abstract interface for LLM inference providers."""

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate textual completion for a prompt."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Check provider operational availability."""
        pass

    @abstractmethod
    def model_name(self) -> str:
        """Return identifier string of underlying LLM model."""
        pass
