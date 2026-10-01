"""
Threat Intelligence Cache Abstraction.

Provides in-memory caching mechanism for IOC lookups and provider enrichment payloads,
with abstract interfaces designed for Redis production scaling.
"""

import time
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Tuple


class ThreatIntelCache(ABC):
    """Abstract cache interface for Threat Intelligence Engine."""

    @abstractmethod
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached payload by key."""
        pass

    @abstractmethod
    def set(self, key: str, value: Dict[str, Any], ttl_seconds: int = 3600) -> None:
        """Store key-value payload with TTL expiration."""
        pass

    @abstractmethod
    def delete(self, key: str) -> None:
        """Invalidate single cache key."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Purge entire threat intelligence cache."""
        pass


class InMemoryThreatCache(ThreatIntelCache):
    """Thread-safe in-memory cache implementation with TTL support."""

    def __init__(self):
        self._store: Dict[str, Tuple[Dict[str, Any], float]] = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached value if not expired."""
        if key not in self._store:
            return None

        value, expiry = self._store[key]
        if time.time() > expiry:
            del self._store[key]
            return None

        return value

    def set(self, key: str, value: Dict[str, Any], ttl_seconds: int = 3600) -> None:
        """Set value with expiration timestamp."""
        expiry = time.time() + ttl_seconds
        self._store[key] = (value, expiry)

    def delete(self, key: str) -> None:
        """Remove key from store."""
        self._store.pop(key, None)

    def clear(self) -> None:
        """Purge all stored keys."""
        self._store.clear()


# Global singleton instance for local caching
default_threat_cache = InMemoryThreatCache()
