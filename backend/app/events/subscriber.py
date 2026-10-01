"""
Abstract Event Subscriber Interface.

Defines the contract for subscribing and reacting to platform domain events.
"""

from abc import ABC, abstractmethod
from typing import Callable, Coroutine, Any
from app.events.event_types import EventType
from app.events.schemas import EventPayload


class BaseEventSubscriber(ABC):
    """Abstract interface for listening to domain events."""

    @abstractmethod
    async def subscribe(
        self, event_type: EventType, handler: Callable[[EventPayload], Coroutine[Any, Any, None]]
    ) -> None:
        """Register asynchronous event listener callback."""
        pass
