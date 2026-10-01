"""
Detection Rule Engine Pydantic v2 Validation Schemas.

DTO request/response contracts for Detection Rules, Versioning, Testing, Diffs,
Validation, Filtering, and Performance Statistics.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from app.detection_engine.models import RuleType, RuleStatus, RuleSeverity


class DetectionRuleCreate(BaseModel):
    """Schema for creating a new detection rule."""

    name: str = Field(..., description="Unique rule title")
    rule_type: RuleType = Field(RuleType.SIGMA, description="Rule format (SIGMA, YARA, SURICATA, CUSTOM)")
    category: str = Field("GENERAL", description="Rule category e.g. MALWARE, EXECUTION")
    description: Optional[str] = None
    severity: RuleSeverity = Field(RuleSeverity.MEDIUM)
    status: RuleStatus = Field(RuleStatus.DRAFT)
    author: str = Field("SOC Analyst")
    source: str = Field("INTERNAL")
    content: str = Field(..., description="Raw rule content text (YAML, YARA, Suricata string)")
    tags: List[str] = Field(default_factory=list)
    metadata_info: Dict[str, Any] = Field(default_factory=dict)


class DetectionRuleUpdate(BaseModel):
    """Schema for updating an existing detection rule."""

    name: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[RuleSeverity] = None
    status: Optional[RuleStatus] = None
    content: Optional[str] = None
    tags: Optional[List[str]] = None
    change_summary: Optional[str] = Field(None, description="Summary of changes for version history snapshot")
    metadata_info: Optional[Dict[str, Any]] = None


class DetectionRuleRead(BaseModel):
    """Schema for detection rule response payload."""

    id: uuid.UUID
    name: str
    rule_type: RuleType
    category: str
    description: Optional[str] = None
    severity: RuleSeverity
    status: RuleStatus
    version: int
    author: str
    source: str
    content: str
    validation_status: str
    execution_count: int
    match_count: int
    last_triggered: Optional[datetime] = None
    tags: List[str]
    metadata_info: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RuleFilterParams(BaseModel):
    """Query parameter schema for searching & filtering detection rules."""

    query: Optional[str] = Field(None, description="Search term in rule name, content, or tags")
    rule_type: Optional[RuleType] = Field(None, description="Filter by rule format")
    status: Optional[RuleStatus] = Field(None, description="Filter by lifecycle status")
    severity: Optional[RuleSeverity] = Field(None, description="Filter by severity level")
    category: Optional[str] = Field(None, description="Filter by category")
    page: int = Field(1, ge=1)
    page_size: int = Field(20, ge=1, le=100)


class RuleVersionRead(BaseModel):
    """Schema for rule version history response."""

    id: uuid.UUID
    rule_id: uuid.UUID
    version: int
    content: str
    change_summary: Optional[str] = None
    created_by: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RollbackRequest(BaseModel):
    """Request payload to revert a detection rule to a specific version number."""

    target_version: int = Field(..., ge=1, description="Version number to restore")


class DetectionRuleStatisticsRead(BaseModel):
    """Dashboard statistics summary for Detection Rule Engine."""

    total_rules_count: int = 0
    active_rules_count: int = 0
    draft_rules_count: int = 0
    testing_rules_count: int = 0
    rule_types_breakdown: Dict[str, int] = Field(default_factory=dict)
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
