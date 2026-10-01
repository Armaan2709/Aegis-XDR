"""
Timeline Event Entity SQLAlchemy Model.

Represents chronological security events and indicators belonging to investigations,
serving as the backbone for incident reconstruction, attack chain visualization, DFIR analysis,
and AI-assisted investigation workflows.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, Integer, Float, Enum, JSON, ForeignKey, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class TimelineEventType(str, enum.Enum):
    """Categories of timeline events."""
    PROCESS_CREATION = "PROCESS_CREATION"
    PROCESS_TERMINATION = "PROCESS_TERMINATION"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    DNS_QUERY = "DNS_QUERY"
    FILE_MODIFICATION = "FILE_MODIFICATION"
    FILE_CREATION = "FILE_CREATION"
    FILE_DELETION = "FILE_DELETION"
    REGISTRY_MODIFICATION = "REGISTRY_MODIFICATION"
    USER_LOGIN = "USER_LOGIN"
    USER_LOGOUT = "USER_LOGOUT"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    SCRIPT_EXECUTION = "SCRIPT_EXECUTION"
    ALERT_TRIGGERED = "ALERT_TRIGGERED"
    EVIDENCE_COLLECTED = "EVIDENCE_COLLECTED"
    SYSTEM_EVENT = "SYSTEM_EVENT"
    CUSTOM = "CUSTOM"


class TimelineEventCategory(str, enum.Enum):
    """Tactical & Security domains for timeline events."""
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"
    SYSTEM = "SYSTEM"
    OTHER = "OTHER"


class TimelineEventSeverity(str, enum.Enum):
    """Severity level of timeline events."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TimelineEvent(Base):
    """SQLAlchemy Model representing a chronological security timeline event."""

    __tablename__ = "timeline_events"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    event_type: Mapped[TimelineEventType] = mapped_column(
        Enum(TimelineEventType, native_enum=False),
        nullable=False,
        index=True,
    )
    event_category: Mapped[TimelineEventCategory] = mapped_column(
        Enum(TimelineEventCategory, native_enum=False),
        default=TimelineEventCategory.EXECUTION,
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(
        String(100), default="Timeline Generator", nullable=False, index=True
    )

    # Host & Process Execution Identifiers
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    parent_process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    registry_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    network_address: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)

    # Event Description & Assessment Metrics
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[TimelineEventSeverity] = mapped_column(
        Enum(TimelineEventSeverity, native_enum=False),
        default=TimelineEventSeverity.INFORMATIONAL,
        nullable=False,
        index=True,
    )
    confidence_score: Mapped[float] = mapped_column(Float, default=100.0, nullable=False)

    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    metadata_info: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Soft Delete Support
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
