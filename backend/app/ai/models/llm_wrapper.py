"""
Abstract LLM Provider Interface.

Defines the contract for LLM inference model wrappers.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseLLMProvider(ABC):
    """Abstract interface for LLM inference backends."""

    @abstractmethod
    async def generate_response(
        self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.2
    ) -> str:
        """Generate text completion from prompt input."""
        pass
