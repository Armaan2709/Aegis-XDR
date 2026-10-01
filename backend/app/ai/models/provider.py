"""
AI Orchestrator LLM Provider Factory.

Manages registration and retrieval of LLM inference providers.
"""

from typing import Dict, List, Optional
from app.ai.models.base import BaseLLMProvider
from app.ai.models.mock import MockLLMProvider
from app.core.exceptions import NotFoundError, ConflictError


class LLMProviderFactory:
    """Factory and registry for LLM inference providers."""

    def __init__(self):
        self._providers: Dict[str, BaseLLMProvider] = {}
        # Register default mock provider
        default_mock = MockLLMProvider()
        self.register_provider(default_mock, default=True)

    def register_provider(self, provider: BaseLLMProvider, default: bool = False) -> None:
        """Register a provider instance."""
        name_key = provider.model_name().lower().strip()
        if name_key in self._providers:
            raise ConflictError(f"LLM Provider '{provider.model_name()}' already registered.")
        self._providers[name_key] = provider
        if default or "default" not in self._providers:
            self._providers["default"] = provider

    def get_provider(self, model_name: Optional[str] = None) -> BaseLLMProvider:
        """Retrieve provider by model name or return default provider."""
        if not model_name:
            return self._providers["default"]
        key = model_name.lower().strip()
        provider = self._providers.get(key)
        if not provider:
            raise NotFoundError(f"LLM Provider for model '{model_name}' not found.")
        return provider

    def list_providers(self) -> List[str]:
        """List registered provider model names."""
        return [p.model_name() for k, p in self._providers.items() if k != "default"]
