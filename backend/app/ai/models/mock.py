"""
AI Orchestrator Deterministic Mock LLM Provider.

Provides MockLLMProvider for offline deterministic local testing without external network calls or cloud credentials.
"""

from typing import Dict, Any, Optional
from app.ai.models.base import BaseLLMProvider


class MockLLMProvider(BaseLLMProvider):
    """Deterministic local mock LLM provider implementation."""

    def __init__(self, name: str = "mock-aegis-llm-v1"):
        self._name = name

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Return deterministic structured response based on prompt context."""
        p_lower = prompt.lower()
        if "triage" in p_lower:
            return "ANALYSIS: Security incident alert triage completed. Severity: HIGH. Recommended Action: Initiate containment."
        elif "threat" in p_lower:
            return "ANALYSIS: Threat Intel lookup matched known C2 IOC 198.51.100.50. Risk: CRITICAL."
        elif "dfir" in p_lower or "evidence" in p_lower:
            return "ANALYSIS: Memory dump contains inject payload. Artifact verified."
        else:
            return "ANALYSIS: Automated mock AI response. Analysis completed with high confidence."

    def health_check(self) -> bool:
        """Health check returns True."""
        return True

    def model_name(self) -> str:
        """Return mock model identifier."""
        return self._name
