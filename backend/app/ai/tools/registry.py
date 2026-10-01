"""
AI Orchestrator Tool Registry Manager.

Manages registration, lookup, capability search, and health checks for AI security tools.
Prevents duplicate registrations and arbitrary unvalidated tool execution.
"""

from typing import Dict, List, Optional
from app.ai.tools.base import BaseSecurityTool
from app.core.exceptions import ConflictError, NotFoundError


class ToolRegistry:
    """Registry engine for managing security AI tools."""

    def __init__(self):
        self._tools: Dict[str, BaseSecurityTool] = {}

    def register(self, tool: BaseSecurityTool) -> None:
        """Register a security tool. Raises ConflictError on duplicate name."""
        name_key = tool.name.lower().strip()
        if name_key in self._tools:
            raise ConflictError(f"Tool with name '{tool.name}' is already registered.")
        self._tools[name_key] = tool

    def unregister(self, tool_name: str) -> None:
        """Unregister a security tool. Raises NotFoundError if not found."""
        name_key = tool_name.lower().strip()
        if name_key not in self._tools:
            raise NotFoundError(f"Tool '{tool_name}' is not registered.")
        del self._tools[name_key]

    def get(self, tool_name: str) -> Optional[BaseSecurityTool]:
        """Fetch tool instance by name."""
        return self._tools.get(tool_name.lower().strip())

    def list(self) -> List[BaseSecurityTool]:
        """List all registered tools."""
        return list(self._tools.values())

    def find_by_capability(self, capability: str) -> List[BaseSecurityTool]:
        """Search tools by matching capability keyword in description or name."""
        cap_key = capability.lower().strip()
        results = []
        for tool in self._tools.values():
            if cap_key in tool.name.lower() or cap_key in tool.description.lower():
                results.append(tool)
        return results

    def health_check_all(self) -> Dict[str, bool]:
        """Check operational readiness of all registered tools."""
        return {tool.name: tool.health_check() for tool in self._tools.values()}
