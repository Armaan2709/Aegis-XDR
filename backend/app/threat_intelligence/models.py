"""
Threat Intelligence Domain SQLAlchemy Entities.

Models Threat Indicators, Feeds, Sources, Reputations, IOCs,
IOC Relationships, Threat Enrichments, Tags, and Categories.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, Integer, Float, Enum, JSON, ForeignKey, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class IOCType(str, enum.Enum):
    """Supported Indicators of Compromise (IOC) types."""
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    HOSTNAME = "HOSTNAME"
    URL = "URL"
    EMAIL = "EMAIL"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    MD5 = "MD5"
    REGISTRY_KEY = "REGISTRY_KEY"
    MUTEX = "MUTEX"
    PROCESS = "PROCESS"
    CERTIFICATE = "CERTIFICATE"
    USER_AGENT = "USER_AGENT"
    FILENAME = "FILENAME"


class ThreatReputationLevel(str, enum.Enum):
    """Threat reputation severity levels."""
    UNKNOWN = "UNKNOWN"
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    MALICIOUS = "MALICIOUS"
    BENIGN = "BENIGN"


class ThreatCategory(Base):
    """Classification category for threat actors, campaigns, or malware families."""

    __tablename__ = "threat_categories"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ThreatTag(Base):
    """Metadata tag associated with threat indicators."""

    __tablename__ = "threat_tags"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    color_hex: Mapped[str] = mapped_column(String(10), default="#FF0000", nullable=False)


class ThreatSource(Base):
    """Source provider registry (e.g. VirusTotal, AbuseIPDB, MISP)."""

    __tablename__ = "threat_sources"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    provider_type: Mapped[str] = mapped_column(String(50), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    trust_score: Mapped[float] = mapped_column(Float, default=80.0, nullable=False)


class ThreatFeed(Base):
    """Threat intelligence feed definition."""

    __tablename__ = "threat_feeds"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    feed_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    format_type: Mapped[str] = mapped_column(String(50), default="JSON", nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    item_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class IOC(Base):
    """Indicator of Compromise (IOC) main entity."""

    __tablename__ = "threat_iocs"

    ioc_type: Mapped[IOCType] = mapped_column(
        Enum(IOCType, native_enum=False),
        nullable=False,
        index=True,
    )
    value: Mapped[str] = mapped_column(String(1000), nullable=False, index=True)
    normalized_value: Mapped[str] = mapped_column(String(1000), nullable=False, index=True)
    reputation: Mapped[ThreatReputationLevel] = mapped_column(
        Enum(ThreatReputationLevel, native_enum=False),
        default=ThreatReputationLevel.UNKNOWN,
        nullable=False,
        index=True,
    )
    confidence_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False)
    threat_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # 0.0 to 100.0
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    sources: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    metadata_info: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class ThreatIndicator(Base):
    """Detailed threat indicator entity wrapping IOCs with contextual intelligence."""

    __tablename__ = "threat_indicators"

    ioc_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    actor: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    malware_family: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    campaign: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


class ThreatReputation(Base):
    """Aggregated threat reputation record for an IOC."""

    __tablename__ = "threat_reputations"

    ioc_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)  # 0 to 100
    level: Mapped[ThreatReputationLevel] = mapped_column(Enum(ThreatReputationLevel, native_enum=False), nullable=False)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class ThreatEnrichment(Base):
    """Enrichment result payload from a threat intelligence provider."""

    __tablename__ = "threat_enrichments"

    ioc_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    provider_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    reputation_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    raw_response: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    enrichment_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class IOCRelationship(Base):
    """Entity relationship mapping between IOCs (e.g. Domain resolves to IP)."""

    __tablename__ = "ioc_relationships"

    source_ioc_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    target_ioc_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False)  # RESOLVES_TO, HOSTED_ON, EXECUTED_BY


class IndicatorReference(Base):
    """Reference linking IOCs to platform Incidents, Evidence, or Alerts."""

    __tablename__ = "indicator_references"

    ioc_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("threat_iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # INCIDENT, ALERT, EVIDENCE, TIMELINE
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
