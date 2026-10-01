"""
Investigation Entity SQLAlchemy Model.

Represents an in-depth security investigation session associated with an Incident.
Serves as the execution context for autonomous AI agent workflows (Threat Hunter,
Malware Analyst, DFIR Investigator) and human SOC investigator notes, findings,
and evidence timelines.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, Integer, Float, Enum, JSON, ForeignKey, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class InvestigationStatus(str, enum.Enum):
    """Investigation lifecycle states."""
    INITIATED = "INITIATED"
    IN_PROGRESS = "IN_PROGRESS"
    PAUSED = "PAUSED"
    AWAITING_REVIEW = "AWAITING_REVIEW"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class InvestigationPriority(str, enum.Enum):
    """Investigation operational priorities."""
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class InvestigationPhase(str, enum.Enum):
    """Investigation operational phase classification."""
    TRIAGE = "TRIAGE"
    FORENSIC_ANALYSIS = "FORENSIC_ANALYSIS"
    THREAT_HUNTING = "THREAT_HUNTING"
    CONTAINMENT_VERIFICATION = "CONTAINMENT_VERIFICATION"
    POST_INCIDENT_REVIEW = "POST_INCIDENT_REVIEW"


class Investigation(Base):
    """Investigation entity model linking Incident cases to forensic & AI investigation streams."""

    __tablename__ = "investigations"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[InvestigationStatus] = mapped_column(
        Enum(InvestigationStatus, native_enum=False),
        default=InvestigationStatus.INITIATED,
        nullable=False,
        index=True,
    )
    priority: Mapped[InvestigationPriority] = mapped_column(
        Enum(InvestigationPriority, native_enum=False),
        default=InvestigationPriority.P3,
        nullable=False,
        index=True,
    )
    phase: Mapped[InvestigationPhase] = mapped_column(
        Enum(InvestigationPhase, native_enum=False),
        default=InvestigationPhase.TRIAGE,
        nullable=False,
        index=True,
    )

    # Assigned Personnel & Authorship
    assigned_investigator_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Lifecyle Timestamps
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Investigation Results & Analysis Payload
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    findings: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    recommendations: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    # Scoring & Flag Controllers for Autonomous AI Layer
    confidence_score: Mapped[float] = mapped_column(Float, default=85.0, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False, index=True)
    ai_investigation_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    human_review_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Metadata & Counts
    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    investigation_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    timeline_event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Soft Delete Support
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
