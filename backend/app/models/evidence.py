"""
Evidence Entity SQLAlchemy Model.

Represents digital forensic evidence artifacts collected during security incident investigations.
Serves as the foundation for multi-agent DFIR workflows, chain-of-custody tracking,
IOC extraction, process tree analysis, and timeline correlation.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, Integer, Enum, JSON, ForeignKey, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class EvidenceType(str, enum.Enum):
    """Categories of digital forensic evidence."""
    FILE = "FILE"
    PROCESS = "PROCESS"
    MEMORY = "MEMORY"
    REGISTRY = "REGISTRY"
    NETWORK = "NETWORK"
    DNS = "DNS"
    URL = "URL"
    IP = "IP"
    DOMAIN = "DOMAIN"
    USER_ACTIVITY = "USER_ACTIVITY"
    EVENT_LOG = "EVENT_LOG"
    WINDOWS_EVENT = "WINDOWS_EVENT"
    LINUX_AUDIT = "LINUX_AUDIT"
    BROWSER_ARTIFACT = "BROWSER_ARTIFACT"
    EMAIL = "EMAIL"
    SCREENSHOT = "SCREENSHOT"
    MALWARE_SAMPLE = "MALWARE_SAMPLE"
    IOC = "IOC"


class EvidenceClassification(str, enum.Enum):
    """Sensitivity & security classification ratings."""
    UNCLASSIFIED = "UNCLASSIFIED"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    CRITICAL_EVIDENCE = "CRITICAL_EVIDENCE"


class Evidence(Base):
    """Evidence entity model representing digital artifacts collected during investigations."""

    __tablename__ = "evidence"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence_type: Mapped[EvidenceType] = mapped_column(
        Enum(EvidenceType, native_enum=False),
        nullable=False,
        index=True,
    )
    classification: Mapped[EvidenceClassification] = mapped_column(
        Enum(EvidenceClassification, native_enum=False),
        default=EvidenceClassification.UNCLASSIFIED,
        nullable=False,
        index=True,
    )

    source: Mapped[str] = mapped_column(String(100), default="Agent Collector", nullable=False)
    source_hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)

    collected_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    collection_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # File & Hash Properties
    file_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    md5: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    sha1: Mapped[Optional[str]] = mapped_column(String(40), nullable=True, index=True)
    mime_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Process & OS Execution Artifacts
    process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    parent_process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    registry_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Network & Domain Identifiers
    network_connection: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)

    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # DFIR Chain of Custody & Audit Log
    chain_of_custody: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    integrity_verified: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    evidence_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Soft Delete Support
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
