"""
Incidents Domain Pydantic Validation Schemas.

Defines request/response contracts for security incident creation, filtering,
updates, assignments, triage status state changes, and executive summaries.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from app.models.incident import (
    IncidentSeverity,
    IncidentPriority,
    IncidentStatus,
    IncidentCategory,
    ContainmentStatus,
    RecoveryStatus,
)


class IncidentBase(BaseModel):
    """Base incident properties."""

    title: str = Field(..., max_length=255, description="High-level incident title")
    description: Optional[str] = Field(None, description="Detailed explanation of incident scope")
    severity: IncidentSeverity = Field(IncidentSeverity.MEDIUM, description="Incident severity level")
    priority: IncidentPriority = Field(IncidentPriority.P3, description="Operational triage priority")
    status: IncidentStatus = Field(IncidentStatus.OPEN, description="Current lifecycle state")
    category: IncidentCategory = Field(IncidentCategory.OTHER, description="Security event category")
    source: str = Field("Alert Correlation", max_length=100, description="Log or rule source")
    risk_score: float = Field(50.0, ge=0.0, le=100.0, description="Overall incident risk score")
    confidence_score: float = Field(80.0, ge=0.0, le=100.0, description="Detection confidence score")
    mitre_mapping: Dict[str, Any] = Field(default_factory=dict, description="MITRE ATT&CK tactic/technique mapping")
    containment_status: ContainmentStatus = Field(ContainmentStatus.NOT_CONTAINED)
    recovery_status: RecoveryStatus = Field(RecoveryStatus.NOT_STARTED)
    tags: List[str] = Field(default_factory=list, description="Incident tags")
    incident_metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata dictionary")


class IncidentCreate(IncidentBase):
    """Schema for creating/correlating a new incident."""

    assigned_to_user_id: Optional[uuid.UUID] = Field(None, description="Assigned SOC analyst UUID")
    alert_ids: Optional[List[uuid.UUID]] = Field(default_factory=list, description="Alert UUIDs to correlate into incident")


class IncidentUpdate(BaseModel):
    """Schema for updating incident fields."""

    title: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    priority: Optional[IncidentPriority] = None
    status: Optional[IncidentStatus] = None
    category: Optional[IncidentCategory] = None
    root_cause: Optional[str] = None
    summary: Optional[str] = None
    risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    confidence_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    mitre_mapping: Optional[Dict[str, Any]] = None
    current_investigation_status: Optional[str] = None
    containment_status: Optional[ContainmentStatus] = None
    recovery_status: Optional[RecoveryStatus] = None
    tags: Optional[List[str]] = None
    incident_metadata: Optional[Dict[str, Any]] = None
    assigned_to_user_id: Optional[uuid.UUID] = None


class IncidentStatusUpdate(BaseModel):
    """Schema for changing incident status."""

    status: IncidentStatus
    comment: Optional[str] = Field(None, description="Note explaining status change")


class IncidentSeverityUpdate(BaseModel):
    """Schema for updating severity & priority."""

    severity: IncidentSeverity
    priority: Optional[IncidentPriority] = None
    reason: Optional[str] = None


class IncidentAssignmentUpdate(BaseModel):
    """Schema for assigning incident to an analyst."""

    assigned_to_user_id: uuid.UUID


class IncidentClose(BaseModel):
    """Schema for closing an incident."""

    root_cause: str = Field(..., description="Root cause summary for closure")
    summary: str = Field(..., description="Executive resolution summary")
    status: IncidentStatus = Field(IncidentStatus.CLOSED, description="CLOSED or FALSE_POSITIVE")


class IncidentRead(IncidentBase):
    """Schema for Incident entity response."""

    id: uuid.UUID
    incident_code: str
    created_by_user_id: Optional[uuid.UUID] = None
    assigned_to_user_id: Optional[uuid.UUID] = None
    opened_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    root_cause: Optional[str] = None
    summary: Optional[str] = None
    current_investigation_status: str
    related_alert_count: int
    investigation_id: Optional[uuid.UUID] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentFilterParams(BaseModel):
    """Query parameter schema for searching, filtering, and sorting incidents."""

    query: Optional[str] = Field(None, description="Search term matching title, description, or code")
    category: Optional[IncidentCategory] = Field(None, description="Filter by category")
    severity: Optional[IncidentSeverity] = Field(None, description="Filter by severity level")
    priority: Optional[IncidentPriority] = Field(None, description="Filter by priority")
    status: Optional[IncidentStatus] = Field(None, description="Filter by lifecycle status")
    assigned_to_user_id: Optional[uuid.UUID] = Field(None, description="Filter by assigned analyst")
    min_risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    sort_by: str = Field("created_at", description="Field to sort by: created_at, risk_score, severity, priority")
    sort_order: str = Field("desc", description="Sort direction: asc or desc")
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Items per page")


class IncidentSummaryStats(BaseModel):
    """Schema for incident dashboard summary statistics."""

    total_incidents: int
    open_incidents: int
    critical_incidents: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    by_category: Dict[str, int]
    unassigned_count: int
