"""
Correlation Engine Pydantic Validation Schemas.

Defines request/response contracts for rule configuration, correlation execution requests,
incident generation payloads, and graph network representations.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from app.models.alert import AlertSeverity
from app.models.incident import IncidentSeverity, IncidentPriority, IncidentCategory
from app.correlation.rules import CorrelationRule
from app.correlation.graph import GraphNode, GraphEdge


class CorrelationRuleCreate(BaseModel):
    """Schema for creating a new deterministic correlation rule."""

    name: str = Field(..., max_length=255, description="Correlation rule name")
    description: str = Field(..., description="Rule intent description")
    enabled: bool = Field(True, description="Active status")
    time_window_minutes: int = Field(60, ge=1, le=1440, description="Time window in minutes")
    group_by_fields: List[str] = Field(
        default_factory=lambda: ["hostname"], description="Alert attributes to group by"
    )
    min_alerts: int = Field(2, ge=2, description="Minimum matching alerts required")
    min_severity: AlertSeverity = Field(AlertSeverity.MEDIUM, description="Minimum severity threshold")
    category_match: Optional[str] = Field(None, description="Optional category filter")
    weight: float = Field(1.0, ge=0.1, le=10.0, description="Risk calculation weight multiplier")
    custom_criteria: Dict[str, Any] = Field(default_factory=dict, description="Custom criteria match dictionary")


class CorrelationRuleUpdate(BaseModel):
    """Schema for updating correlation rule properties."""

    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    enabled: Optional[bool] = None
    time_window_minutes: Optional[int] = Field(None, ge=1, le=1440)
    group_by_fields: Optional[List[str]] = None
    min_alerts: Optional[int] = Field(None, ge=2)
    min_severity: Optional[AlertSeverity] = None
    category_match: Optional[str] = None
    weight: Optional[float] = Field(None, ge=0.1, le=10.0)
    custom_criteria: Optional[Dict[str, Any]] = None


class CorrelationRuleRead(CorrelationRuleCreate):
    """Response schema for a correlation rule."""

    id: str

    model_config = ConfigDict(from_attributes=True)


class CorrelationRequest(BaseModel):
    """Request payload for triggering correlation evaluation."""

    alert_ids: Optional[List[uuid.UUID]] = Field(
        None, description="Optional list of specific Alert UUIDs to correlate. If omitted, evaluates unassigned alerts."
    )
    rule_ids: Optional[List[str]] = Field(None, description="Optional filter for specific rule IDs to evaluate")
    time_window_minutes: Optional[int] = Field(None, ge=1, le=1440, description="Override correlation time window")
    auto_create_incidents: bool = Field(True, description="Automatically persist correlated Incidents into DB")


class CorrelatedCandidateRead(BaseModel):
    """DTO for a generated correlated incident candidate."""

    candidate_id: str
    title: str
    description: str
    category: IncidentCategory
    severity: IncidentSeverity
    priority: IncidentPriority
    risk_score: float
    confidence_score: float
    alert_ids: List[uuid.UUID]
    matched_rule_id: Optional[str] = None
    matched_rule_name: Optional[str] = None


class CorrelationExecutionResult(BaseModel):
    """Summary response payload for correlation engine execution."""

    evaluated_alerts_count: int
    duplicates_removed: int
    candidates_count: int
    created_incident_ids: List[uuid.UUID] = Field(default_factory=list)
    candidates: List[CorrelatedCandidateRead] = Field(default_factory=list)
    execution_time_ms: float


class CorrelationGraphRead(BaseModel):
    """Response schema for correlation graph network visualization."""

    incident_id: Optional[uuid.UUID] = None
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
