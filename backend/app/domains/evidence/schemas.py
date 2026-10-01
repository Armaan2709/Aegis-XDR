"""
Evidence Domain Pydantic Validation Schemas.

Defines request/response schemas for digital forensic evidence collection,
hash validation, chain-of-custody tracking, searching, and aggregate analytics.
"""

import re
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, field_validator

from app.models.evidence import EvidenceType, EvidenceClassification


class EvidenceBase(BaseModel):
    """Base digital forensic evidence properties."""

    name: str = Field(..., max_length=255, description="Evidence artifact name")
    evidence_type: EvidenceType = Field(..., description="Evidence category")
    classification: EvidenceClassification = Field(
        EvidenceClassification.UNCLASSIFIED, description="Sensitivity rating"
    )
    source: str = Field("Agent Collector", max_length=100, description="Collection tool/source")
    source_hostname: Optional[str] = Field(None, max_length=255, description="Host from which evidence was pulled")
    source_ip: Optional[str] = Field(None, max_length=45, description="Source IP address")
    file_name: Optional[str] = Field(None, max_length=255)
    file_path: Optional[str] = None
    file_size: Optional[int] = Field(None, ge=0)
    sha256: Optional[str] = Field(None, description="SHA256 hash (64 hex characters)")
    md5: Optional[str] = Field(None, description="MD5 hash (32 hex characters)")
    sha1: Optional[str] = Field(None, description="SHA1 hash (40 hex characters)")
    mime_type: Optional[str] = Field(None, max_length=100)
    process_name: Optional[str] = Field(None, max_length=255)
    process_id: Optional[int] = Field(None, ge=0)
    parent_process_id: Optional[int] = Field(None, ge=0)
    registry_key: Optional[str] = None
    network_connection: Dict[str, Any] = Field(default_factory=dict)
    url: Optional[str] = None
    domain: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = Field(None, max_length=45)
    username: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = None
    integrity_verified: bool = Field(True, description="Whether hash integrity is verified")
    tags: List[str] = Field(default_factory=list)
    evidence_metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip():
            v = v.strip().lower()
            if not re.fullmatch(r"[a-f0-9]{64}", v):
                raise ValueError("SHA256 must be exactly 64 hexadecimal characters.")
            return v
        return None

    @field_validator("md5")
    @classmethod
    def validate_md5(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip():
            v = v.strip().lower()
            if not re.fullmatch(r"[a-f0-9]{32}", v):
                raise ValueError("MD5 must be exactly 32 hexadecimal characters.")
            return v
        return None

    @field_validator("sha1")
    @classmethod
    def validate_sha1(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip():
            v = v.strip().lower()
            if not re.fullmatch(r"[a-f0-9]{40}", v):
                raise ValueError("SHA1 must be exactly 40 hexadecimal characters.")
            return v
        return None


class EvidenceCreate(EvidenceBase):
    """Schema for adding new evidence to an investigation."""

    investigation_id: uuid.UUID = Field(..., description="Parent Investigation UUID")
    incident_id: uuid.UUID = Field(..., description="Parent Incident UUID")
    collected_by_user_id: Optional[uuid.UUID] = Field(None, description="Collector User UUID")


class EvidenceUpdate(BaseModel):
    """Schema for updating evidence properties."""

    name: Optional[str] = Field(None, max_length=255)
    evidence_type: Optional[EvidenceType] = None
    classification: Optional[EvidenceClassification] = None
    source: Optional[str] = Field(None, max_length=100)
    source_hostname: Optional[str] = Field(None, max_length=255)
    source_ip: Optional[str] = Field(None, max_length=45)
    file_name: Optional[str] = Field(None, max_length=255)
    file_path: Optional[str] = None
    file_size: Optional[int] = Field(None, ge=0)
    sha256: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    mime_type: Optional[str] = Field(None, max_length=100)
    process_name: Optional[str] = Field(None, max_length=255)
    process_id: Optional[int] = Field(None, ge=0)
    parent_process_id: Optional[int] = Field(None, ge=0)
    registry_key: Optional[str] = None
    network_connection: Optional[Dict[str, Any]] = None
    url: Optional[str] = None
    domain: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = Field(None, max_length=45)
    username: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = None
    integrity_verified: Optional[bool] = None
    tags: Optional[List[str]] = None
    evidence_metadata: Optional[Dict[str, Any]] = None

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip():
            v = v.strip().lower()
            if not re.fullmatch(r"[a-f0-9]{64}", v):
                raise ValueError("SHA256 must be exactly 64 hexadecimal characters.")
            return v
        return None

    @field_validator("md5")
    @classmethod
    def validate_md5(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip():
            v = v.strip().lower()
            if not re.fullmatch(r"[a-f0-9]{32}", v):
                raise ValueError("MD5 must be exactly 32 hexadecimal characters.")
            return v
        return None

    @field_validator("sha1")
    @classmethod
    def validate_sha1(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip():
            v = v.strip().lower()
            if not re.fullmatch(r"[a-f0-9]{40}", v):
                raise ValueError("SHA1 must be exactly 40 hexadecimal characters.")
            return v
        return None


class EvidenceCustodyTransfer(BaseModel):
    """Schema for recording a DFIR chain-of-custody transfer event."""

    transferred_to: str = Field(..., max_length=255, description="Receiving entity, analyst, or vault")
    purpose: str = Field(..., description="Reason for transfer/access")
    notes: Optional[str] = None


class EvidenceRead(EvidenceBase):
    """Schema for Evidence entity response."""

    id: uuid.UUID
    investigation_id: uuid.UUID
    incident_id: uuid.UUID
    collected_by_user_id: Optional[uuid.UUID] = None
    collection_time: datetime
    chain_of_custody: List[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EvidenceFilterParams(BaseModel):
    """Query parameter schema for searching and filtering evidence."""

    query: Optional[str] = Field(None, description="Search term matching name, description, file_name, or host")
    investigation_id: Optional[uuid.UUID] = Field(None, description="Filter by Investigation UUID")
    incident_id: Optional[uuid.UUID] = Field(None, description="Filter by Incident UUID")
    evidence_type: Optional[EvidenceType] = Field(None, description="Filter by Evidence Type")
    classification: Optional[EvidenceClassification] = Field(None, description="Filter by sensitivity rating")
    hash_value: Optional[str] = Field(None, description="Search SHA256, MD5, or SHA1 hash")
    ip_address: Optional[str] = Field(None, description="Filter by source or network IP")
    sort_by: str = Field("created_at", description="Field to sort by: created_at, name, evidence_type")
    sort_order: str = Field("desc", description="Sort direction: asc or desc")
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Items per page")


class EvidenceSummaryStats(BaseModel):
    """Schema for evidence metrics summary statistics."""

    total_evidence_count: int
    by_type: Dict[str, int]
    by_classification: Dict[str, int]
    integrity_verified_count: int
    unverified_count: int
