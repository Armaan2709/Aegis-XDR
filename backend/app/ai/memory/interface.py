"""
AI Orchestrator Memory Store Base Abstraction.

Defines BaseMemoryStore interface for managing short-term and case investigation memory.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseMemoryStore(ABC):
    """Abstract interface for memory persistence stores."""

    @abstractmethod
    def store(self, key: str, value: Any) -> None:
        """Store a key-value entry in memory."""
        pass

    @abstractmethod
    def retrieve(self, key: str) -> Optional[Any]:
        """Retrieve an entry from memory by key."""
        pass

    @abstractmethod
    def search(self, query: str) -> List[Dict[str, Any]]:
        """Search memory entries matching query term."""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete an entry from memory by key."""
        pass
