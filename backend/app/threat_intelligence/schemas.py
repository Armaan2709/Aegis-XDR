"""
Threat Intelligence Pydantic v2 Validation Contracts.

DTO request/response schemas for IOCs, Threat Feeds, Enrichments,
Relationships, Search, Filtering, and Statistics.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from app.threat_intelligence.models import IOCType, ThreatReputationLevel


class IOCCreate(BaseModel):
    """Schema for creating a new IOC entity."""

    ioc_type: Optional[IOCType] = Field(None, description="IOC type (auto-detected if None)")
    value: str = Field(..., description="IOC raw string value (e.g. 192.168.1.1, evil.com, MD5 hash)")
    reputation: ThreatReputationLevel = Field(ThreatReputationLevel.UNKNOWN)
    confidence_score: float = Field(50.0, ge=0.0, le=100.0)
    threat_score: float = Field(0.0, ge=0.0, le=100.0)
    tags: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    metadata_info: Dict[str, Any] = Field(default_factory=dict)


class IOCUpdate(BaseModel):
    """Schema for updating an existing IOC."""

    reputation: Optional[ThreatReputationLevel] = None
    confidence_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    threat_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    is_active: Optional[bool] = None
    tags: Optional[List[str]] = None
    sources: Optional[List[str]] = None
    metadata_info: Optional[Dict[str, Any]] = None


class IOCRead(BaseModel):
    """Schema for IOC response payload."""

    id: uuid.UUID
    ioc_type: IOCType
    value: str
    normalized_value: str
    reputation: ThreatReputationLevel
    confidence_score: float
    threat_score: float
    first_seen: datetime
    last_seen: datetime
    is_active: bool
    tags: List[str]
    sources: List[str]
    metadata_info: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IOCFilterParams(BaseModel):
    """Query parameter schema for searching & filtering IOCs."""

    query: Optional[str] = Field(None, description="Search term in IOC value or tags")
    ioc_type: Optional[IOCType] = Field(None, description="Filter by IOC type")
    reputation: Optional[ThreatReputationLevel] = Field(None, description="Filter by reputation level")
    is_active: Optional[bool] = Field(None, description="Filter active IOCs")
    page: int = Field(1, ge=1)
    page_size: int = Field(20, ge=1, le=100)


class ThreatFeedCreate(BaseModel):
    """Schema for registering a threat intelligence feed."""

    name: str = Field(..., description="Unique feed title")
    feed_url: Optional[str] = Field(None, description="Feed URL endpoint")
    format_type: str = Field("JSON", description="Feed data format (JSON, STIX, CSV)")
    is_enabled: bool = Field(True)


class ThreatFeedRead(ThreatFeedCreate):
    """Schema for threat feed response."""

    id: uuid.UUID
    last_synced_at: Optional[datetime] = None
    item_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IOCEnrichmentRequest(BaseModel):
    """Payload to request immediate enrichment of an IOC."""

    ioc_value: str = Field(..., description="IOC raw string value")
    ioc_type: Optional[IOCType] = Field(None, description="Optional explicit IOC type")


class IOCRelationshipCreate(BaseModel):
    """Schema for linking two IOCs."""

    source_ioc_id: uuid.UUID
    target_ioc_id: uuid.UUID
    relationship_type: str = Field(..., description="RESOLVES_TO, HOSTED_ON, EXECUTED_BY")


class IOCRelationshipRead(IOCRelationshipCreate):
    """Schema for IOC relationship response."""

    id: uuid.UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ThreatIntelStatisticsRead(BaseModel):
    """Dashboard statistics summary for Threat Intelligence Engine."""

    total_iocs_count: int = 0
    active_iocs_count: int = 0
    malicious_iocs_count: int = 0
    ioc_types_breakdown: Dict[str, int] = Field(default_factory=dict)
    reputation_breakdown: Dict[str, int] = Field(default_factory=dict)
    active_feeds_count: int = 0
