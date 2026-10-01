"""
Timeline Domain Pydantic Validation Schemas.

Defines data transfer objects and validation contracts for creating, updating, searching,
filtering, and reporting chronological security timeline events across investigations.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from app.models.timeline import (
    TimelineEventType,
    TimelineEventCategory,
    TimelineEventSeverity,
)


class TimelineEventBase(BaseModel):
    """Base schema for security timeline event properties."""

    timestamp: Optional[datetime] = Field(None, description="Event occurrence timestamp in UTC")
    event_type: TimelineEventType = Field(..., description="Categorical event type indicator")
    event_category: TimelineEventCategory = Field(
        TimelineEventCategory.EXECUTION, description="Tactical/Security domain classification"
    )
    source: str = Field("Timeline Generator", max_length=100, description="Telemetry source or component")
    hostname: Optional[str] = Field(None, max_length=255, description="Affected host identifier")
    username: Optional[str] = Field(None, max_length=100, description="User account associated with event")
    process_name: Optional[str] = Field(None, max_length=255, description="Executing process executable name")
    process_id: Optional[int] = Field(None, ge=0, description="Process identifier (PID)")
    parent_process_id: Optional[int] = Field(None, ge=0, description="Parent process identifier (PPID)")
    file_path: Optional[str] = Field(None, description="File system path accessed or modified")
    registry_key: Optional[str] = Field(None, description="Windows registry key path")
    network_address: Optional[str] = Field(None, max_length=255, description="IP address or FQDN host domain")
    description: Optional[str] = Field(None, description="Detailed summary description of the event")
    severity: TimelineEventSeverity = Field(
        TimelineEventSeverity.INFORMATIONAL, description="Event severity rating"
    )
    confidence_score: float = Field(100.0, ge=0.0, le=100.0, description="Event confidence rating (0 to 100)")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    metadata_info: Dict[str, Any] = Field(default_factory=dict, description="Custom event metadata dictionary")


class TimelineEventCreate(TimelineEventBase):
    """Schema for ingesting a new security timeline event."""

    investigation_id: uuid.UUID = Field(..., description="Parent Investigation UUID")
    incident_id: uuid.UUID = Field(..., description="Parent Incident UUID")
    evidence_id: Optional[uuid.UUID] = Field(None, description="Associated Evidence UUID artifact")


class TimelineEventUpdate(BaseModel):
    """Schema for updating timeline event properties."""

    timestamp: Optional[datetime] = None
    event_type: Optional[TimelineEventType] = None
    event_category: Optional[TimelineEventCategory] = None
    source: Optional[str] = Field(None, max_length=100)
    hostname: Optional[str] = Field(None, max_length=255)
    username: Optional[str] = Field(None, max_length=100)
    process_name: Optional[str] = Field(None, max_length=255)
    process_id: Optional[int] = Field(None, ge=0)
    parent_process_id: Optional[int] = Field(None, ge=0)
    file_path: Optional[str] = None
    registry_key: Optional[str] = None
    network_address: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    severity: Optional[TimelineEventSeverity] = None
    confidence_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    tags: Optional[List[str]] = None
    metadata_info: Optional[Dict[str, Any]] = None
    evidence_id: Optional[uuid.UUID] = None


class TimelineEventRead(TimelineEventBase):
    """Response schema for timeline event entity."""

    id: uuid.UUID
    investigation_id: uuid.UUID
    incident_id: uuid.UUID
    evidence_id: Optional[uuid.UUID] = None
    timestamp: datetime
    created_at: datetime
    updated_at: datetime
    is_deleted: bool = False

    model_config = ConfigDict(from_attributes=True)


class TimelineFilterParams(BaseModel):
    """Query parameters for searching and filtering timeline events."""

    query: Optional[str] = Field(
        None, description="Free text search matching description, hostname, username, process, or file path"
    )
    investigation_id: Optional[uuid.UUID] = Field(None, description="Filter by Investigation UUID")
    incident_id: Optional[uuid.UUID] = Field(None, description="Filter by Incident UUID")
    evidence_id: Optional[uuid.UUID] = Field(None, description="Filter by Evidence UUID")
    event_type: Optional[TimelineEventType] = Field(None, description="Filter by event type")
    event_category: Optional[TimelineEventCategory] = Field(None, description="Filter by tactical category")
    severity: Optional[TimelineEventSeverity] = Field(None, description="Filter by severity level")
    hostname: Optional[str] = Field(None, description="Filter by target hostname")
    username: Optional[str] = Field(None, description="Filter by user account")
    start_time: Optional[datetime] = Field(None, description="Filter events after timestamp")
    end_time: Optional[datetime] = Field(None, description="Filter events before timestamp")
    sort_by: str = Field("timestamp", description="Field to sort by: timestamp, created_at, severity")
    sort_order: str = Field("asc", description="Sort direction: asc or desc")
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Items per page")


class TimelineSummaryStats(BaseModel):
    """Aggregated statistics for timeline events."""

    total_events: int
    by_type: Dict[str, int]
    by_category: Dict[str, int]
    by_severity: Dict[str, int]
    first_event_at: Optional[datetime] = None
    last_event_at: Optional[datetime] = None
