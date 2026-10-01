"""
Abstract Base Plugin Interface.

Establishes lifecycle management contract for third-party extensions.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BasePlugin(ABC):
    """Abstract interface for extensible platform plugins."""

    def __init__(self, plugin_id: str, name: str, version: str):
        self.plugin_id = plugin_id
        self.name = name
        self.version = version

    @abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize plugin configuration and state."""
        pass

    @abstractmethod
    async def execute(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute plugin action."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify plugin target connectivity."""
        pass
