"""
Threat Hunter Agent Schemas and DTOs.

Defines Pydantic v2 data models for Observables, Hypotheses, Findings, and Recommendations.
"""

import enum
import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ObservableType(str, enum.Enum):
    """Enumeration of recognizable security observable artifact types."""
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH = "HASH"
    PROCESS = "PROCESS"
    COMMAND_LINE = "COMMAND_LINE"
    REGISTRY_KEY = "REGISTRY_KEY"
    USER_ACCOUNT = "USER_ACCOUNT"


class ObservableItem(BaseModel):
    """Structured security observable item extracted from investigation state."""
    value: str = Field(..., description="Observable string value (IP, hash, process name, etc.)")
    type: ObservableType = Field(..., description="Type classification of observable")
    source: str = Field(..., description="Source origin artifact (alert ID, evidence ID, etc.)")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Extraction confidence rating")
    first_seen: Optional[str] = Field(default=None, description="ISO timestamp when first observed")
    last_seen: Optional[str] = Field(default=None, description="ISO timestamp when last observed")
    related_entity: Optional[str] = Field(default=None, description="Associated host or user entity name")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Contextual observable metadata")


class HypothesisStatus(str, enum.Enum):
    """Lifecycle evaluation status of an investigative hypothesis."""
    PROPOSED = "PROPOSED"
    INVESTIGATING = "INVESTIGATING"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ThreatHypothesis(BaseModel):
    """Threat hypothesis container formulated during threat hunting."""
    hypothesis_id: str = Field(default_factory=lambda: f"HYP-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(..., description="Brief hypothesis title")
    description: str = Field(..., description="Detailed hypothesis reasoning statement")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Linked evidence artifacts")
    supporting_indicators: List[str] = Field(default_factory=list, description="List of supporting observable values")
    contradicting_indicators: List[str] = Field(default_factory=list, description="List of contradicting observable values")
    mitre_techniques: List[str] = Field(default_factory=list, description="Mapped MITRE ATT&CK technique IDs")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Hypothesis confidence rating (0.0 to 1.0)")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Hypothesis risk impact score (0 to 100)")
    status: HypothesisStatus = Field(default=HypothesisStatus.PROPOSED, description="Current evaluation status")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary evaluation metadata")


class ThreatFinding(BaseModel):
    """Structured analytical finding produced by Threat Hunter agent."""
    finding_id: str = Field(default_factory=lambda: f"FND-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Detailed description of finding")
    severity: str = Field(default="MEDIUM", description="Severity: LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence rating (0.0 to 1.0)")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Calculated risk score (0 to 100)")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Supporting evidence items")
    related_iocs: List[str] = Field(default_factory=list, description="Associated IOC values")
    mitre_techniques: List[str] = Field(default_factory=list, description="Mapped MITRE technique IDs")
    affected_entities: List[str] = Field(default_factory=list, description="List of impacted hosts/users")
    reasoning_summary: str = Field(..., description="Traceable summary of evidence-based reasoning")


class ThreatRecommendation(BaseModel):
    """Actionable security recommendation output."""
    recommendation_id: str = Field(default_factory=lambda: f"REC-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(..., description="Recommendation title")
    description: str = Field(..., description="Actionable recommendation detail")
    priority: str = Field(default="MEDIUM", description="Priority: LOW, MEDIUM, HIGH, URGENT")
    rationale: str = Field(..., description="Justification and risk reduction rationale")
    related_finding: Optional[str] = Field(default=None, description="Associated finding ID if linked")
    suggested_playbook: Optional[str] = Field(default=None, description="Suggested SOAR playbook ID")
    requires_human_approval: bool = Field(default=True, description="Strictly True for response actions requiring supervisor review")
