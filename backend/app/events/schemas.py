"""
Event Envelope Schemas.

Defines Pydantic data payloads attached to published platform events.
"""

from datetime import datetime, timezone
import uuid
from typing import Any, Dict
from pydantic import BaseModel, Field

from app.events.event_types import EventType


class EventPayload(BaseModel):
    """Base event payload envelope schema."""

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    event_type: EventType
    producer: str = "aegis_backend"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: Dict[str, Any] = Field(default_factory=dict)
