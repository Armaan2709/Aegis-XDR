"""
Investigations Domain Pydantic Validation Schemas.

Defines request/response data transfer contracts for starting, updating, assignment,
phase progression, findings/notes updates, search/filtering, and summary metrics.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from app.models.investigation import (
    InvestigationStatus,
    InvestigationPriority,
    InvestigationPhase,
)


class InvestigationBase(BaseModel):
    """Base Investigation properties."""

    name: str = Field(..., max_length=255, description="Investigation title or code name")
    description: Optional[str] = Field(None, description="Scope and objective of the investigation")
    status: InvestigationStatus = Field(InvestigationStatus.INITIATED, description="Lifecycle status")
    priority: InvestigationPriority = Field(InvestigationPriority.P3, description="Operational priority")
    phase: InvestigationPhase = Field(InvestigationPhase.TRIAGE, description="Current investigation phase")
    summary: Optional[str] = Field(None, description="Executive investigation summary")
    findings: Dict[str, Any] = Field(default_factory=dict, description="Structured investigation findings dictionary")
    recommendations: List[str] = Field(default_factory=list, description="Actionable response recommendations")
    confidence_score: float = Field(85.0, ge=0.0, le=100.0, description="Confidence rating")
    risk_score: float = Field(50.0, ge=0.0, le=100.0, description="Risk level rating")
    ai_investigation_enabled: bool = Field(True, description="Whether autonomous AI agents are active")
    human_review_required: bool = Field(True, description="Whether analyst sign-off is required")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    investigation_metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata dictionary")


class InvestigationCreate(InvestigationBase):
    """Schema for initiating a new investigation for an incident."""

    incident_id: uuid.UUID = Field(..., description="Target Incident UUID")
    assigned_investigator_id: Optional[uuid.UUID] = Field(None, description="Assigned investigator user UUID")


class InvestigationUpdate(BaseModel):
    """Schema for updating investigation fields."""

    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    status: Optional[InvestigationStatus] = None
    priority: Optional[InvestigationPriority] = None
    phase: Optional[InvestigationPhase] = None
    summary: Optional[str] = None
    findings: Optional[Dict[str, Any]] = None
    recommendations: Optional[List[str]] = None
    confidence_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    ai_investigation_enabled: Optional[bool] = None
    human_review_required: Optional[bool] = None
    tags: Optional[List[str]] = None
    investigation_metadata: Optional[Dict[str, Any]] = None
    assigned_investigator_id: Optional[uuid.UUID] = None


class InvestigationStatusUpdate(BaseModel):
    """Schema for changing investigation status state."""

    status: InvestigationStatus
    comment: Optional[str] = Field(None, description="Status transition note")


class InvestigationPriorityUpdate(BaseModel):
    """Schema for changing priority."""

    priority: InvestigationPriority


class InvestigationAssignmentUpdate(BaseModel):
    """Schema for assigning an investigator."""

    assigned_investigator_id: uuid.UUID


class InvestigationNotesUpdate(BaseModel):
    """Schema for appending notes or summary updates."""

    summary: str = Field(..., description="Updated summary or notes text")


class InvestigationFindingsUpdate(BaseModel):
    """Schema for updating findings dictionary."""

    findings: Dict[str, Any] = Field(..., description="Findings payload")
    confidence_score: Optional[float] = Field(None, ge=0.0, le=100.0)


class InvestigationRecommendationsUpdate(BaseModel):
    """Schema for updating recommendations list."""

    recommendations: List[str] = Field(..., description="Action recommendations")


class InvestigationRead(InvestigationBase):
    """Schema for Investigation entity response."""

    id: uuid.UUID
    incident_id: uuid.UUID
    assigned_investigator_id: Optional[uuid.UUID] = None
    created_by_user_id: Optional[uuid.UUID] = None
    started_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    evidence_count: int
    timeline_event_count: int

    model_config = ConfigDict(from_attributes=True)


class InvestigationFilterParams(BaseModel):
    """Query parameter schema for searching and filtering investigations."""

    query: Optional[str] = Field(None, description="Search term matching name, description, or summary")
    incident_id: Optional[uuid.UUID] = Field(None, description="Filter by Incident UUID")
    status: Optional[InvestigationStatus] = Field(None, description="Filter by status")
    priority: Optional[InvestigationPriority] = Field(None, description="Filter by priority")
    phase: Optional[InvestigationPhase] = Field(None, description="Filter by phase")
    assigned_investigator_id: Optional[uuid.UUID] = Field(None, description="Filter by assigned investigator")
    min_risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    sort_by: str = Field("started_at", description="Field to sort by: started_at, risk_score, priority")
    sort_order: str = Field("desc", description="Sort direction: asc or desc")
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Items per page")


class InvestigationSummaryStats(BaseModel):
    """Schema for aggregated investigation summary statistics."""

    total_investigations: int
    active_investigations: int
    by_status: Dict[str, int]
    by_priority: Dict[str, int]
    by_phase: Dict[str, int]
    unassigned_count: int
