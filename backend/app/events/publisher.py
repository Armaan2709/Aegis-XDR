"""
Abstract Event Publisher Interface.

Defines the contract for event broadcasting implementations (Redis, Memory, Kafka).
"""

from abc import ABC, abstractmethod
from app.events.schemas import EventPayload


class BaseEventPublisher(ABC):
    """Abstract interface for publishing domain events."""

    @abstractmethod
    async def publish(self, event: EventPayload) -> None:
        """Broadcast event to event broker."""
        pass
