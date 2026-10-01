"""
Case Management Domain SQLAlchemy Entity Models.

Defines database schema entities for enterprise case workspace management including:
Case, CaseComment, CaseAttachment, CaseTask, CaseApproval, CaseActivity,
CaseAssignment, and associated lifecycle state enums.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, Integer, Boolean, Enum, JSON, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class CaseStatus(str, enum.Enum):
    """Case lifecycle operational status."""
    DRAFT = "DRAFT"
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


class CaseSeverity(str, enum.Enum):
    """Case severity classification levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CasePriority(str, enum.Enum):
    """Case operational priority levels."""
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class AttachmentType(str, enum.Enum):
    """Case forensic attachment document classification."""
    REPORT = "REPORT"
    SCREENSHOT = "SCREENSHOT"
    PCAP = "PCAP"
    MEMORY_DUMP = "MEMORY_DUMP"
    LOG_FILE = "LOG_FILE"
    IOC_LIST = "IOC_LIST"


class TaskStatus(str, enum.Enum):
    """Operational task status levels."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class TaskPriority(str, enum.Enum):
    """Task operational urgency priority."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    URGENT = "URGENT"


class ApprovalStatus(str, enum.Enum):
    """Case governance approval status."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    AUTO_APPROVED = "AUTO_APPROVED"


class AssignmentRole(str, enum.Enum):
    """SOC analyst case assignment roles."""
    PRIMARY_LEAD = "PRIMARY_LEAD"
    CO_ANALYST = "CO_ANALYST"
    REVIEWER = "REVIEWER"
    OBSERVER = "OBSERVER"


class ActivityType(str, enum.Enum):
    """Auditable case event activity types."""
    CASE_CREATED = "CASE_CREATED"
    CASE_UPDATED = "CASE_UPDATED"
    INCIDENT_LINKED = "INCIDENT_LINKED"
    INVESTIGATION_LINKED = "INVESTIGATION_LINKED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"
    TIMELINE_LINKED = "TIMELINE_LINKED"
    MITRE_LINKED = "MITRE_LINKED"
    THREAT_INDICATOR_LINKED = "THREAT_INDICATOR_LINKED"
    COMMENT_ADDED = "COMMENT_ADDED"
    COMMENT_EDITED = "COMMENT_EDITED"
    COMMENT_DELETED = "COMMENT_DELETED"
    TASK_CREATED = "TASK_CREATED"
    TASK_UPDATED = "TASK_UPDATED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_DECIDED = "APPROVAL_DECIDED"
    ANALYST_ASSIGNED = "ANALYST_ASSIGNED"
    ANALYST_REMOVED = "ANALYST_REMOVED"
    CASE_CLOSED = "CASE_CLOSED"


class Case(Base):
    """Enterprise SOC Case entity model."""

    __tablename__ = "cases"

    case_number: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[CaseStatus] = mapped_column(
        Enum(CaseStatus, native_enum=False),
        default=CaseStatus.OPEN,
        nullable=False,
        index=True,
    )
    severity: Mapped[CaseSeverity] = mapped_column(
        Enum(CaseSeverity, native_enum=False),
        default=CaseSeverity.MEDIUM,
        nullable=False,
        index=True,
    )
    priority: Mapped[CasePriority] = mapped_column(
        Enum(CasePriority, native_enum=False),
        default=CasePriority.P3,
        nullable=False,
        index=True,
    )

    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_target_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_breached: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    case_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Referenced Domain Entity Identifiers (JSON arrays of UUID strings / strings)
    related_incidents: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    related_investigations: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    related_evidence: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    related_timeline_events: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    related_mitre_techniques: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    related_threat_indicators: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    related_rule_matches: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)


class CaseComment(Base):
    """Threaded Markdown comment model for Case workspace."""

    __tablename__ = "case_comments"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    author_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)

    parent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("case_comments.id", ondelete="CASCADE"), nullable=True, index=True
    )
    mentions: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    edit_history: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)

    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class CaseAttachment(Base):
    """Metadata model for case forensic attachments (reports, dumps, logs, pcap)."""

    __tablename__ = "case_attachments"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attachment_type: Mapped[AttachmentType] = mapped_column(
        Enum(AttachmentType, native_enum=False), nullable=False
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    file_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), default="application/octet-stream", nullable=False)
    storage_uri: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    uploaded_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class CaseTask(Base):
    """Operational task entity model for case resolution management."""

    __tablename__ = "case_tasks"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    assigned_to_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[TaskStatus] = mapped_column(
        Enum(TaskStatus, native_enum=False), default=TaskStatus.PENDING, nullable=False, index=True
    )
    priority: Mapped[TaskPriority] = mapped_column(
        Enum(TaskPriority, native_enum=False), default=TaskPriority.MEDIUM, nullable=False, index=True
    )
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class CaseApproval(Base):
    """Case governance manual & auto approval entity model."""

    __tablename__ = "case_approvals"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[ApprovalStatus] = mapped_column(
        Enum(ApprovalStatus, native_enum=False), default=ApprovalStatus.PENDING, nullable=False, index=True
    )
    is_auto_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approver_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    decision_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class CaseActivity(Base):
    """Auditable audit trail timeline event record for case workspace."""

    __tablename__ = "case_activities"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    activity_type: Mapped[ActivityType] = mapped_column(
        Enum(ActivityType, native_enum=False), nullable=False, index=True
    )
    summary: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class CaseAssignment(Base):
    """Analyst assignment model for multi-analyst collaboration on cases."""

    __tablename__ = "case_assignments"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[AssignmentRole] = mapped_column(
        Enum(AssignmentRole, native_enum=False), default=AssignmentRole.CO_ANALYST, nullable=False
    )
    assigned_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
