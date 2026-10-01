"""
Case Management Domain Pydantic v2 Schemas & Data Transfer Objects (DTOs).

Defines request/response schemas for Cases, Comments, Attachments, Tasks,
Approvals, Activity Logs, Analyst Assignments, Linkings, and Summary Statistics.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from app.case_management.models import (
    CaseStatus,
    CaseSeverity,
    CasePriority,
    AttachmentType,
    TaskStatus,
    TaskPriority,
    ApprovalStatus,
    AssignmentRole,
    ActivityType,
)


# ==========================================
# Case Base & CRUD Schemas
# ==========================================

class CaseCreate(BaseModel):
    """Schema for creating a new Case workspace."""

    title: str = Field(..., min_length=3, max_length=255, description="Case title")
    description: Optional[str] = Field(default=None, description="Detailed case overview")
    status: CaseStatus = Field(default=CaseStatus.OPEN, description="Initial case status")
    severity: CaseSeverity = Field(default=CaseSeverity.MEDIUM, description="Severity level")
    priority: CasePriority = Field(default=CasePriority.P3, description="Operational priority")
    owner_id: Optional[uuid.UUID] = Field(default=None, description="Primary owner analyst UUID")
    due_date: Optional[datetime] = Field(default=None, description="Case resolution target due date")
    sla_target_at: Optional[datetime] = Field(default=None, description="SLA breach target timestamp")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    case_metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary JSON metadata")
    
    related_incidents: List[str] = Field(default_factory=list, description="Linked Incident UUIDs")
    related_investigations: List[str] = Field(default_factory=list, description="Linked Investigation UUIDs")
    related_evidence: List[str] = Field(default_factory=list, description="Linked Evidence UUIDs")
    related_timeline_events: List[str] = Field(default_factory=list, description="Linked Timeline Event UUIDs")
    related_mitre_techniques: List[str] = Field(default_factory=list, description="Linked MITRE technique IDs")
    related_threat_indicators: List[str] = Field(default_factory=list, description="Linked Threat Indicator UUIDs")
    related_rule_matches: List[str] = Field(default_factory=list, description="Linked Detection Rule UUIDs")


class CaseUpdate(BaseModel):
    """Schema for updating an existing Case."""

    title: Optional[str] = Field(default=None, min_length=3, max_length=255)
    description: Optional[str] = Field(default=None)
    status: Optional[CaseStatus] = Field(default=None)
    severity: Optional[CaseSeverity] = Field(default=None)
    priority: Optional[CasePriority] = Field(default=None)
    owner_id: Optional[uuid.UUID] = Field(default=None)
    due_date: Optional[datetime] = Field(default=None)
    sla_target_at: Optional[datetime] = Field(default=None)
    sla_breached: Optional[bool] = Field(default=None)
    tags: Optional[List[str]] = Field(default=None)
    case_metadata: Optional[Dict[str, Any]] = Field(default=None)


class CaseClose(BaseModel):
    """Schema for closing a Case."""

    closure_notes: str = Field(..., min_length=5, description="Final case closure summary notes")


class CaseLinkUpdate(BaseModel):
    """Schema for linking external domain entities to a Case."""

    entity_type: str = Field(
        ...,
        description="Type of entity: incident, investigation, evidence, timeline, mitre, threat_indicator, rule_match",
    )
    entity_id: str = Field(..., description="UUID or identifier of the entity to link")


class CaseResponse(BaseModel):
    """Response schema representing a Case entity."""

    id: uuid.UUID
    case_number: str
    title: str
    description: Optional[str] = None
    status: CaseStatus
    severity: CaseSeverity
    priority: CasePriority
    owner_id: Optional[uuid.UUID] = None
    created_by_id: Optional[uuid.UUID] = None
    opened_at: datetime
    closed_at: Optional[datetime] = None
    due_date: Optional[datetime] = None
    sla_target_at: Optional[datetime] = None
    sla_breached: bool
    tags: List[str]
    case_metadata: Dict[str, Any]
    related_incidents: List[str]
    related_investigations: List[str]
    related_evidence: List[str]
    related_timeline_events: List[str]
    related_mitre_techniques: List[str]
    related_threat_indicators: List[str]
    related_rule_matches: List[str]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseFilterParams(BaseModel):
    """Query parameters for filtering, searching, and sorting cases."""

    query: Optional[str] = None
    status: Optional[CaseStatus] = None
    severity: Optional[CaseSeverity] = None
    priority: Optional[CasePriority] = None
    owner_id: Optional[uuid.UUID] = None
    assigned_user_id: Optional[uuid.UUID] = None
    sla_breached: Optional[bool] = None
    sort_by: str = "created_at"
    sort_order: str = "desc"
    page: int = 1
    page_size: int = 20


# ==========================================
# Comments Schemas
# ==========================================

class CaseCommentCreate(BaseModel):
    """Schema for adding a comment to a Case."""

    content: str = Field(..., min_length=1, description="Markdown comment content")
    parent_id: Optional[uuid.UUID] = Field(default=None, description="Parent comment UUID for threading")
    mentions: List[str] = Field(default_factory=list, description="Mentioned user handles/IDs")


class CaseCommentUpdate(BaseModel):
    """Schema for editing an existing comment."""

    content: str = Field(..., min_length=1, description="Updated Markdown content")


class CaseCommentResponse(BaseModel):
    """Response schema for a Case comment."""

    id: uuid.UUID
    case_id: uuid.UUID
    author_id: Optional[uuid.UUID] = None
    author_name: Optional[str] = None
    content: str
    parent_id: Optional[uuid.UUID] = None
    mentions: List[str]
    edit_history: List[Dict[str, Any]]
    is_deleted: bool
    deleted_at: Optional[datetime] = None
    deleted_by_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Attachment Metadata Schemas
# ==========================================

class CaseAttachmentCreate(BaseModel):
    """Schema for adding attachment metadata (no live upload)."""

    attachment_type: AttachmentType = Field(..., description="Document type")
    filename: str = Field(..., min_length=1, max_length=255, description="File name with extension")
    file_size_bytes: int = Field(..., ge=0, description="File size in bytes")
    file_hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 hex string")
    mime_type: str = Field(default="application/octet-stream", description="MIME type")
    storage_uri: Optional[str] = Field(default=None, description="Metadata storage URI pointer")
    description: Optional[str] = Field(default=None, description="Attachment description")


class CaseAttachmentResponse(BaseModel):
    """Response schema for case attachment metadata."""

    id: uuid.UUID
    case_id: uuid.UUID
    attachment_type: AttachmentType
    filename: str
    file_size_bytes: int
    file_hash: str
    mime_type: str
    storage_uri: Optional[str] = None
    description: Optional[str] = None
    uploaded_by_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Task Management Schemas
# ==========================================

class CaseTaskCreate(BaseModel):
    """Schema for creating a task under a Case."""

    title: str = Field(..., min_length=2, max_length=255, description="Task title")
    description: Optional[str] = Field(default=None, description="Task description")
    assigned_to_id: Optional[uuid.UUID] = Field(default=None, description="Assigned analyst UUID")
    priority: TaskPriority = Field(default=TaskPriority.MEDIUM, description="Task priority")
    due_date: Optional[datetime] = Field(default=None, description="Task due date")
    notes: Optional[str] = Field(default=None, description="Operational notes")


class CaseTaskUpdate(BaseModel):
    """Schema for updating task status/assignment."""

    title: Optional[str] = Field(default=None)
    description: Optional[str] = Field(default=None)
    assigned_to_id: Optional[uuid.UUID] = Field(default=None)
    status: Optional[TaskStatus] = Field(default=None)
    priority: Optional[TaskPriority] = Field(default=None)
    due_date: Optional[datetime] = Field(default=None)
    notes: Optional[str] = Field(default=None)


class CaseTaskResponse(BaseModel):
    """Response schema for case task."""

    id: uuid.UUID
    case_id: uuid.UUID
    title: str
    description: Optional[str] = None
    assigned_to_id: Optional[uuid.UUID] = None
    status: TaskStatus
    priority: TaskPriority
    due_date: Optional[datetime] = None
    notes: Optional[str] = None
    completed_at: Optional[datetime] = None
    completed_by_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Approvals System Schemas
# ==========================================

class CaseApprovalCreate(BaseModel):
    """Schema for requesting a case approval."""

    title: str = Field(..., min_length=3, max_length=255, description="Approval title")
    description: Optional[str] = Field(default=None, description="Justification and context")
    is_auto_approval: bool = Field(default=False, description="Flag for policy auto-approval evaluation")


class CaseApprovalDecision(BaseModel):
    """Schema for approving or rejecting an approval request."""

    approved: bool = Field(..., description="True to approve, False to reject")
    decision_notes: Optional[str] = Field(default=None, description="Approver decision reasoning")


class CaseApprovalResponse(BaseModel):
    """Response schema for case approval request."""

    id: uuid.UUID
    case_id: uuid.UUID
    title: str
    description: Optional[str] = None
    status: ApprovalStatus
    is_auto_approval: bool
    approver_id: Optional[uuid.UUID] = None
    decision_notes: Optional[str] = None
    decided_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Activity Log Schemas
# ==========================================

class CaseActivityResponse(BaseModel):
    """Response schema for case activity timeline event."""

    id: uuid.UUID
    case_id: uuid.UUID
    activity_type: ActivityType
    summary: str
    details: Dict[str, Any]
    actor_id: Optional[uuid.UUID] = None
    timestamp: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Analyst Assignments Schemas
# ==========================================

class CaseAssignmentCreate(BaseModel):
    """Schema for assigning an analyst to a case."""

    user_id: uuid.UUID = Field(..., description="Analyst user UUID")
    role: AssignmentRole = Field(default=AssignmentRole.CO_ANALYST, description="Assignment role")


class CaseAssignmentResponse(BaseModel):
    """Response schema for case assignment."""

    id: uuid.UUID
    case_id: uuid.UUID
    user_id: uuid.UUID
    role: AssignmentRole
    assigned_by_id: Optional[uuid.UUID] = None
    assigned_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Summary Statistics Schemas
# ==========================================

class CaseSummaryStats(BaseModel):
    """Aggregated case management metrics schema."""

    total_cases: int
    open_cases: int
    closed_cases: int
    sla_breached_count: int
    sla_breach_rate: float
    avg_resolution_hours: float
    task_completion_rate: float
    cases_by_severity: Dict[str, int]
    cases_by_status: Dict[str, int]
    cases_by_priority: Dict[str, int]
    approval_counts: Dict[str, int]
