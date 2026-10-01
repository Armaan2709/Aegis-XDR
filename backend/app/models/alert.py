"""
Alert Entity SQLAlchemy Model.

Represents enterprise security alerts ingested from SIEM, EDR, Network telemetry, or Cloud Audit logs.
Includes severity scoring, triage lifecycle state, MITRE ATT&CK mapping, IOC attributes,
and links to assigned SOC analysts or aggregated security incidents.
"""

import enum
import uuid
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, Integer, Float, Enum, JSON, ForeignKey, Table, Column
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class AlertSeverity(str, enum.Enum):
    """Alert severity classification levels."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, enum.Enum):
    """Alert lifecycle status states."""
    NEW = "NEW"
    IN_PROGRESS = "IN_PROGRESS"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"


class Alert(Base):
    """Alert entity model for enterprise security detection ingestion and triage."""

    __tablename__ = "alerts"

    title: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    source_ref_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, native_enum=False),
        default=AlertSeverity.MEDIUM,
        nullable=False,
        index=True,
    )
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, native_enum=False),
        default=AlertStatus.NEW,
        nullable=False,
        index=True,
    )
    
    risk_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False, index=True)
    
    # MITRE ATT&CK Mapping
    mitre_tactics: Mapped[Optional[List[str]]] = mapped_column(JSON, default=list, nullable=False)
    mitre_techniques: Mapped[Optional[List[str]]] = mapped_column(JSON, default=list, nullable=False)
    
    # Indicators of Compromise (IPs, Hashes, Domains, URLs, File Paths)
    iocs: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    
    # Raw log payload or context metadata
    raw_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    # Assignments and Relationships
    assigned_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
