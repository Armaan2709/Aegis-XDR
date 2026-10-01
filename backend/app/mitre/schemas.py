"""
MITRE ATT&CK Pydantic v2 Validation Schemas.

Defines DTO request/response contracts for Tactics, Techniques, Sub-Techniques,
Artifact Mappings, Filtering, and Coverage Reports.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from app.mitre.models import MitreTacticEnum


class MitreTacticRead(BaseModel):
    """Schema for MITRE Tactic response."""

    id: uuid.UUID
    tactic_id: str
    name: str
    description: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class MitreSubTechniqueCreate(BaseModel):
    """Schema for creating a Sub-Technique."""

    subtechnique_id: str = Field(..., description="Sub-technique ID e.g. T1059.001")
    parent_technique_id: str = Field(..., description="Parent technique ID e.g. T1059")
    name: str = Field(..., description="Sub-technique display name")
    description: Optional[str] = None
    platforms: List[str] = Field(default_factory=list)
    detection_notes: Optional[str] = None


class MitreSubTechniqueRead(MitreSubTechniqueCreate):
    """Schema for Sub-Technique response."""

    id: uuid.UUID

    model_config = ConfigDict(from_attributes=True)


class MitreTechniqueCreate(BaseModel):
    """Schema for creating a Technique."""

    technique_id: str = Field(..., description="Technique ID e.g. T1059")
    tactic: MitreTacticEnum = Field(..., description="Tactical category")
    name: str = Field(..., description="Technique name")
    description: Optional[str] = None
    platforms: List[str] = Field(default_factory=list)
    detection_notes: Optional[str] = None
    data_sources: List[str] = Field(default_factory=list)
    mitigation_notes: Optional[str] = None


class MitreTechniqueUpdate(BaseModel):
    """Schema for updating a Technique."""

    name: Optional[str] = None
    tactic: Optional[MitreTacticEnum] = None
    description: Optional[str] = None
    platforms: Optional[List[str]] = None
    detection_notes: Optional[str] = None
    data_sources: Optional[List[str]] = None
    mitigation_notes: Optional[str] = None


class MitreTechniqueRead(MitreTechniqueCreate):
    """Schema for Technique response."""

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MitreMappingCreate(BaseModel):
    """Schema for creating a MITRE mapping."""

    artifact_type: str = Field(..., description="INCIDENT, EVIDENCE, TIMELINE, or ALERT")
    artifact_id: uuid.UUID
    technique_id: str = Field(..., description="Technique ID e.g. T1059")
    subtechnique_id: Optional[str] = Field(None, description="Sub-technique ID e.g. T1059.001")
    tactic: MitreTacticEnum
    confidence_score: float = Field(100.0, ge=0.0, le=100.0)
    evidence_references: List[str] = Field(default_factory=list)
    timeline_references: List[str] = Field(default_factory=list)
    incident_references: List[str] = Field(default_factory=list)
    metadata_info: Dict[str, Any] = Field(default_factory=dict)


class MitreMappingRead(MitreMappingCreate):
    """Schema for MITRE mapping response."""

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ArtifactMappingRequest(BaseModel):
    """Payload to trigger automatic deterministic MITRE mapping for a specific artifact."""

    artifact_type: str = Field(..., description="INCIDENT, EVIDENCE, or TIMELINE")
    artifact_id: uuid.UUID
    payload: Dict[str, Any] = Field(default_factory=dict, description="Artifact attributes dictionary for signature matching")


class MitreFilterParams(BaseModel):
    """Query parameter schema for searching & filtering MITRE techniques."""

    query: Optional[str] = Field(None, description="Search keyword in technique ID, name, or description")
    tactic: Optional[MitreTacticEnum] = Field(None, description="Filter by tactic")
    platform: Optional[str] = Field(None, description="Filter by platform (e.g. Windows, Linux)")
    page: int = Field(1, ge=1)
    page_size: int = Field(20, ge=1, le=100)
