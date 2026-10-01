"""
AI Orchestrator Ephemeral Short-Term Memory Store.

Provides ShortTermMemory for in-memory temporary execution scope caching.
"""

from typing import Any, Dict, List, Optional
from app.ai.memory.interface import BaseMemoryStore


class ShortTermMemory(BaseMemoryStore):
    """In-memory ephemeral key-value store for investigation execution scope."""

    def __init__(self):
        self._store: Dict[str, Any] = {}

    def store(self, key: str, value: Any) -> None:
        """Store key-value pair in short term memory."""
        self._store[key] = value

    def retrieve(self, key: str) -> Optional[Any]:
        """Retrieve value by key."""
        return self._store.get(key)

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Search short term memory keys or stringified values for matching query."""
        q = query.lower()
        results = []
        for k, v in self._store.items():
            if q in k.lower() or q in str(v).lower():
                results.append({"key": k, "value": v})
        return results

    def delete(self, key: str) -> bool:
        """Delete key from short term memory."""
        if key in self._store:
            del self._store[key]
            return True
        return False

    def clear(self) -> None:
        """Clear all short term memory entries."""
        self._store.clear()
