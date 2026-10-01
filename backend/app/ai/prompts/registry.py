"""
AI Orchestrator Versioned Prompt Registry Manager.

Manages registration, versioning, template validation, and activation for AI agent prompts.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.core.exceptions import ConflictError, NotFoundError, ValidationError


class PromptTemplate(BaseModel):
    """Versioned prompt template entity."""
    name: str = Field(..., description="Prompt identifier name")
    version: str = Field(..., description="Version tag string (e.g. '1.0.0')")
    description: str = Field(..., description="Description of prompt objective and usage")
    template: str = Field(..., description="Template body containing placeholder variables")
    variables: List[str] = Field(default_factory=list, description="List of placeholder variable names")
    is_active: bool = Field(default=True, description="Whether this version is currently active")

    def format(self, **kwargs) -> str:
        """Format the template string with provided keyword arguments."""
        try:
            return self.template.format(**kwargs)
        except KeyError as e:
            raise ValidationError(f"Missing required prompt variable: {str(e)}")


class PromptRegistry:
    """Registry engine for managing versioned prompt templates."""

    def __init__(self):
        # Key format: name:version
        self._prompts: Dict[str, PromptTemplate] = {}

    def register(self, prompt: PromptTemplate) -> None:
        """Register a versioned prompt template. Raises ConflictError on duplicate name+version."""
        key = f"{prompt.name.lower().strip()}:{prompt.version.strip()}"
        if key in self._prompts:
            raise ConflictError(f"Prompt '{prompt.name}' version '{prompt.version}' is already registered.")

        # If marked active, deactivate other versions of the same prompt name
        if prompt.is_active:
            for k, p in self._prompts.items():
                if p.name.lower().strip() == prompt.name.lower().strip():
                    p.is_active = False

        self._prompts[key] = prompt

    def get(self, name: str, version: Optional[str] = None) -> Optional[PromptTemplate]:
        """Fetch prompt by name and version. If version is omitted, returns active version."""
        if version:
            key = f"{name.lower().strip()}:{version.strip()}"
            return self._prompts.get(key)
        return self.get_active_version(name)

    def get_active_version(self, name: str) -> Optional[PromptTemplate]:
        """Fetch active version of prompt by name."""
        n_key = name.lower().strip()
        for p in self._prompts.values():
            if p.name.lower().strip() == n_key and p.is_active:
                return p
        return None

    def activate(self, name: str, version: str) -> None:
        """Activate specific prompt version and deactivate others."""
        target_key = f"{name.lower().strip()}:{version.strip()}"
        if target_key not in self._prompts:
            raise NotFoundError(f"Prompt '{name}' version '{version}' not found.")

        n_key = name.lower().strip()
        for k, p in self._prompts.items():
            if p.name.lower().strip() == n_key:
                p.is_active = (k == target_key)

    def deactivate(self, name: str, version: str) -> None:
        """Deactivate specific prompt version."""
        key = f"{name.lower().strip()}:{version.strip()}"
        if key not in self._prompts:
            raise NotFoundError(f"Prompt '{name}' version '{version}' not found.")
        self._prompts[key].is_active = False

    def list(self) -> List[PromptTemplate]:
        """List all registered prompt templates across all versions."""
        return list(self._prompts.values())
