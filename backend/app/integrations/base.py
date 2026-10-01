"""
Abstract Security Integration Client Interface.

Defines standard lifecycle and lookup methods for external security API connectors.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseIntegration(ABC):
    """Abstract interface for external threat intelligence and security integrations."""

    def __init__(self, name: str, api_key: str = ""):
        self.name = name
        self.api_key = api_key

    @abstractmethod
    async def query_ioc(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """Query external API for Indicator of Compromise (IOC) reputation."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify integration API connectivity."""
        pass
