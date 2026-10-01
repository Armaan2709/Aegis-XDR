"""
Alerts Domain Pydantic Validation Schemas.

Defines input/output data transfer contracts for security alert ingestion,
triage updates, search filters, statistics aggregation, and responses.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from app.models.alert import AlertSeverity, AlertStatus


class AlertBase(BaseModel):
    """Base properties for a security alert."""

    title: str = Field(..., max_length=255, description="Short descriptive title of the alert")
    description: Optional[str] = Field(None, description="Detailed explanation of the detected activity")
    source: str = Field(..., max_length=100, description="Log source system (e.g. CrowdStrike, Suricata, AWS CloudTrail)")
    source_ref_id: Optional[str] = Field(None, max_length=255, description="External reference ID in source system")
    severity: AlertSeverity = Field(AlertSeverity.MEDIUM, description="Alert severity level")
    status: AlertStatus = Field(AlertStatus.NEW, description="Current triage lifecycle status")
    risk_score: float = Field(50.0, ge=0.0, le=100.0, description="Calculated risk score between 0.0 and 100.0")
    mitre_tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK Tactic IDs or names")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK Technique IDs or names")
    iocs: Dict[str, Any] = Field(default_factory=dict, description="Extracted Indicators of Compromise (IPs, hashes, domains)")
    raw_payload: Dict[str, Any] = Field(default_factory=dict, description="Original raw event payload")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")


class AlertCreate(AlertBase):
    """Schema for ingesting a new security alert."""

    assigned_user_id: Optional[uuid.UUID] = Field(None, description="SOC analyst assigned to triage this alert")
    incident_id: Optional[uuid.UUID] = Field(None, description="Associated security incident ID")


class AlertUpdate(BaseModel):
    """Schema for partial update of an alert entity."""

    title: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    severity: Optional[AlertSeverity] = None
    status: Optional[AlertStatus] = None
    risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    iocs: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    assigned_user_id: Optional[uuid.UUID] = None
    incident_id: Optional[uuid.UUID] = None


class AlertStatusUpdate(BaseModel):
    """Schema for updating alert status."""

    status: AlertStatus
    comment: Optional[str] = Field(None, description="Optional analyst note explaining status change")


class BulkAlertStatusUpdate(BaseModel):
    """Schema for bulk updating alert status."""

    alert_ids: List[uuid.UUID] = Field(..., min_items=1)
    status: AlertStatus
    comment: Optional[str] = None


class AlertRead(AlertBase):
    """Schema for returning alert details."""

    id: uuid.UUID
    assigned_user_id: Optional[uuid.UUID] = None
    incident_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertFilterParams(BaseModel):
    """Query parameter schema for searching and filtering alerts."""

    query: Optional[str] = Field(None, description="Search term matching title or description")
    source: Optional[str] = Field(None, description="Filter by alert source")
    severity: Optional[AlertSeverity] = Field(None, description="Filter by severity level")
    status: Optional[AlertStatus] = Field(None, description="Filter by triage status")
    assigned_user_id: Optional[uuid.UUID] = Field(None, description="Filter by assigned user")
    incident_id: Optional[uuid.UUID] = Field(None, description="Filter by associated incident")
    tag: Optional[str] = Field(None, description="Filter by tag")
    min_risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Items per page")


class AlertSummaryStats(BaseModel):
    """Schema for aggregated alert summary statistics."""

    total_alerts: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    unassigned_count: int
    high_risk_count: int
