"""
Incident Entity SQLAlchemy Model.

Represents security incidents aggregated from correlated alerts or created manually by SOC analysts.
Acts as the central entity for autonomous AI agent investigations, forensic timelines,
containment states, and executive incident reporting.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, Integer, Float, Enum, JSON, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class IncidentSeverity(str, enum.Enum):
    """Incident severity classification levels."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentPriority(str, enum.Enum):
    """Incident operational priority levels."""
    P1 = "P1"  # Critical operational impact
    P2 = "P2"  # High priority
    P3 = "P3"  # Moderate priority
    P4 = "P4"  # Low priority / informational


class IncidentStatus(str, enum.Enum):
    """Incident lifecycle state machine statuses."""
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    ERADICATED = "ERADICATED"
    RECOVERED = "RECOVERED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentCategory(str, enum.Enum):
    """Security incident classification categories."""
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    RANSOMWARE = "RANSOMWARE"
    INSIDER_THREAT = "INSIDER_THREAT"
    OTHER = "OTHER"


class ContainmentStatus(str, enum.Enum):
    """Containment operational states."""
    NOT_CONTAINED = "NOT_CONTAINED"
    PARTIALLY_CONTAINED = "PARTIALLY_CONTAINED"
    FULLY_CONTAINED = "FULLY_CONTAINED"


class RecoveryStatus(str, enum.Enum):
    """System recovery operational states."""
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    FULLY_RECOVERED = "FULLY_RECOVERED"


class Incident(Base):
    """Incident entity model representing security investigation cases."""

    __tablename__ = "incidents"

    incident_code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(IncidentSeverity, native_enum=False),
        default=IncidentSeverity.MEDIUM,
        nullable=False,
        index=True,
    )
    priority: Mapped[IncidentPriority] = mapped_column(
        Enum(IncidentPriority, native_enum=False),
        default=IncidentPriority.P3,
        nullable=False,
        index=True,
    )
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, native_enum=False),
        default=IncidentStatus.OPEN,
        nullable=False,
        index=True,
    )
    category: Mapped[IncidentCategory] = mapped_column(
        Enum(IncidentCategory, native_enum=False),
        default=IncidentCategory.OTHER,
        nullable=False,
        index=True,
    )

    source: Mapped[str] = mapped_column(String(100), default="Alert Correlation", nullable=False)
    
    # Ownership and Assignments
    created_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    assigned_to_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Lifecyle Timestamps
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Investigation & Operational Findings
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    risk_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False, index=True)
    confidence_score: Mapped[float] = mapped_column(Float, default=80.0, nullable=False)

    # MITRE ATT&CK Mapping Placeholder for AI Layer
    mitre_mapping: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Investigation & Operational Containment States
    current_investigation_status: Mapped[str] = mapped_column(
        String(100), default="Pending Analysis", nullable=False
    )
    containment_status: Mapped[ContainmentStatus] = mapped_column(
        Enum(ContainmentStatus, native_enum=False),
        default=ContainmentStatus.NOT_CONTAINED,
        nullable=False,
    )
    recovery_status: Mapped[RecoveryStatus] = mapped_column(
        Enum(RecoveryStatus, native_enum=False),
        default=RecoveryStatus.NOT_STARTED,
        nullable=False,
    )

    # Metadata & Relations
    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    incident_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    related_alert_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Placeholder link for future multi-agent investigation session graph
    investigation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
