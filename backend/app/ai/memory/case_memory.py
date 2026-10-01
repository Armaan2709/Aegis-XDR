"""
AI Orchestrator Case Investigation Memory Store.

Provides CaseMemory for storing investigation and case level contextual memory entries.
"""

from typing import Any, Dict, List, Optional
from app.ai.memory.interface import BaseMemoryStore


class CaseMemory(BaseMemoryStore):
    """Case-scoped memory store indexing investigative artifacts by case/investigation ID."""

    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {}

    def store_for_case(self, case_id: str, key: str, value: Any) -> None:
        """Store a memory entry scoped under a specific case_id."""
        if case_id not in self._store:
            self._store[case_id] = {}
        self._store[case_id][key] = value

    def retrieve_for_case(self, case_id: str, key: str) -> Optional[Any]:
        """Retrieve a memory entry for a specific case_id."""
        return self._store.get(case_id, {}).get(key)

    def store(self, key: str, value: Any) -> None:
        """Global store fallback using default case scope."""
        self.store_for_case("global", key, value)

    def retrieve(self, key: str) -> Optional[Any]:
        """Global retrieve fallback."""
        return self.retrieve_for_case("global", key)

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Search memory entries across all cases."""
        q = query.lower()
        results = []
        for case_id, case_entries in self._store.items():
            for k, v in case_entries.items():
                if q in k.lower() or q in str(v).lower():
                    results.append({"case_id": case_id, "key": k, "value": v})
        return results

    def delete(self, key: str) -> bool:
        """Delete key from global case scope."""
        if "global" in self._store and key in self._store["global"]:
            del self._store["global"][key]
            return True
        return False
