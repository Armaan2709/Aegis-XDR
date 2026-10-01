"""
SOAR Playbook Engine Domain SQLAlchemy Entity Models.

Defines database schema entities for automated security playbook orchestration:
Playbook, PlaybookStep, PlaybookExecution, PlaybookStepExecution, and associated lifecycle enums.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, Integer, Boolean, Enum, JSON, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class PlaybookStatus(str, enum.Enum):
    """Playbook lifecycle operational state."""
    DRAFT = "DRAFT"
    TESTING = "TESTING"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    ARCHIVED = "ARCHIVED"


class PlaybookCategory(str, enum.Enum):
    """Playbook security domain category."""
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    THREAT_HUNTING = "THREAT_HUNTING"
    CONTAINMENT = "CONTAINMENT"
    ENRICHMENT = "ENRICHMENT"
    NOTIFICATION = "NOTIFICATION"
    REMEDIATION = "REMEDIATION"
    OTHER = "OTHER"


class PlaybookSeverity(str, enum.Enum):
    """Playbook severity trigger threshold."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    ALL = "ALL"


class ActionType(str, enum.Enum):
    """SOAR Response Action classification types."""
    BLOCK_IP = "BLOCK_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    COLLECT_EVIDENCE = "COLLECT_EVIDENCE"
    QUERY_THREAT_INTEL = "QUERY_THREAT_INTEL"
    CREATE_CASE = "CREATE_CASE"
    CREATE_INCIDENT = "CREATE_INCIDENT"
    SEND_NOTIFICATION = "SEND_NOTIFICATION"
    ADD_TAG = "ADD_TAG"
    UPDATE_INCIDENT = "UPDATE_INCIDENT"
    RUN_DETECTION = "RUN_DETECTION"
    GENERATE_REPORT = "GENERATE_REPORT"


class ExecutionStatus(str, enum.Enum):
    """Playbook workflow execution lifecycle status."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"


class StepExecutionStatus(str, enum.Enum):
    """Individual playbook step execution status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class Playbook(Base):
    """Enterprise SOAR Playbook entity definition."""

    __tablename__ = "playbooks"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[str] = mapped_column(String(50), default="1.0.0", nullable=False)

    status: Mapped[PlaybookStatus] = mapped_column(
        Enum(PlaybookStatus, native_enum=False),
        default=PlaybookStatus.DRAFT,
        nullable=False,
        index=True,
    )
    category: Mapped[PlaybookCategory] = mapped_column(
        Enum(PlaybookCategory, native_enum=False),
        default=PlaybookCategory.INCIDENT_RESPONSE,
        nullable=False,
        index=True,
    )
    severity_trigger: Mapped[PlaybookSeverity] = mapped_column(
        Enum(PlaybookSeverity, native_enum=False),
        default=PlaybookSeverity.ALL,
        nullable=False,
        index=True,
    )

    author: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    updated_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    playbook_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class PlaybookStep(Base):
    """Sequential step definition within a Playbook workflow."""

    __tablename__ = "playbook_steps"

    playbook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    step_order: Mapped[int] = mapped_column(Integer, nullable=False, index=True)

    action_type: Mapped[ActionType] = mapped_column(
        Enum(ActionType, native_enum=False), nullable=False, index=True
    )

    configuration: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    conditions: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    timeout_seconds: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    continue_on_failure: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class PlaybookExecution(Base):
    """Record of a Playbook execution instance."""

    __tablename__ = "playbook_executions"

    playbook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False, index=True
    )

    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    case_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True
    )
    investigation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True, index=True
    )

    trigger_source: Mapped[str] = mapped_column(String(100), default="MANUAL", nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    status: Mapped[ExecutionStatus] = mapped_column(
        Enum(ExecutionStatus, native_enum=False),
        default=ExecutionStatus.QUEUED,
        nullable=False,
        index=True,
    )
    current_step_order: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    execution_context: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    results: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    approval_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("case_approvals.id", ondelete="SET NULL"), nullable=True, index=True
    )
    executed_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )


class PlaybookStepExecution(Base):
    """Detailed execution record for an individual step within a playbook execution run."""

    __tablename__ = "playbook_step_executions"

    execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("playbook_executions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("playbook_steps.id", ondelete="CASCADE"), nullable=False, index=True
    )

    step_name: Mapped[str] = mapped_column(String(255), nullable=False)
    action_type: Mapped[ActionType] = mapped_column(
        Enum(ActionType, native_enum=False), nullable=False
    )
    status: Mapped[StepExecutionStatus] = mapped_column(
        Enum(StepExecutionStatus, native_enum=False),
        default=StepExecutionStatus.PENDING,
        nullable=False,
        index=True,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    input_parameters: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    output_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retries_attempted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
