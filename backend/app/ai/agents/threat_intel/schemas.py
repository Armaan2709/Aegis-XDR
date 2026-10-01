"""
Threat Intelligence Analyst Agent Schemas and DTOs.

Defines Pydantic v2 data models for IOC Observations, Provider Assessments, Intelligence Consensus,
Threat Clusters, Conservative Attribution Assessments, Threat Intelligence Findings, Intelligence Gaps,
and Human-Governed Recommendations.
"""

import enum
import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.threat_intelligence.models import IOCType, ThreatReputationLevel


class AttributionLevel(str, enum.Enum):
    """Conservative attribution assessment levels."""
    UNKNOWN = "UNKNOWN"
    POTENTIAL_CAMPAIGN = "POTENTIAL_CAMPAIGN"
    POSSIBLE_THREAT_GROUP = "POSSIBLE_THREAT_GROUP"
    INFRASTRUCTURE_RELATIONSHIP = "INFRASTRUCTURE_RELATIONSHIP"


class IOCObservation(BaseModel):
    """Normalized IOC extracted from investigation state telemetry."""
    ioc_id: str = Field(default_factory=lambda: f"IOC-OBS-{uuid.uuid4().hex[:8].upper()}")
    raw_value: str = Field(..., description="Raw unnormalized indicator string")
    normalized_value: str = Field(..., description="Validated normalized indicator string")
    ioc_type: IOCType = Field(..., description="IOC classification type")
    source: str = Field(..., description="Origin state telemetry source")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Extraction confidence")
    relevance: str = Field(default="HIGH", description="Investigation relevance rating")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Contextual indicator metadata")


class ProviderAssessment(BaseModel):
    """Reputation query response payload from a threat intelligence provider."""
    provider_name: str = Field(..., description="Threat provider name (e.g., VirusTotal, AbuseIPDB)")
    verdict: ThreatReputationLevel = Field(default=ThreatReputationLevel.UNKNOWN, description="Provider reputation verdict")
    score: float = Field(default=0.0, ge=0.0, le=100.0, description="Raw provider threat score (0 to 100)")
    details: Dict[str, Any] = Field(default_factory=dict, description="Provider threat detail payload")
    status: str = Field(default="SUCCESS", description="Query status: SUCCESS or ERROR")
    error_message: Optional[str] = Field(default=None, description="Explicit error details if query failed")


class IntelligenceConsensus(BaseModel):
    """Provider consensus analysis for an indicator."""
    ioc_value: str = Field(..., description="Indicator value")
    malicious_count: int = Field(default=0, ge=0, description="Number of providers marking malicious")
    benign_count: int = Field(default=0, ge=0, description="Number of providers marking benign")
    unknown_count: int = Field(default=0, ge=0, description="Number of providers marking unknown/inconclusive")
    agreement_ratio: float = Field(default=0.0, ge=0.0, le=1.0, description="Provider agreement ratio")
    disagreement_ratio: float = Field(default=0.0, ge=0.0, le=1.0, description="Provider disagreement ratio")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Calculated intelligence confidence")
    consolidated_threat_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Consolidated threat score (0 to 100)")
    provider_assessments: List[ProviderAssessment] = Field(default_factory=list, description="List of provider assessments")


class ThreatCluster(BaseModel):
    """Deterministic grouping of related indicators."""
    cluster_id: str = Field(default_factory=lambda: f"CLUSTER-{uuid.uuid4().hex[:8].upper()}")
    name: str = Field(..., description="Cluster descriptive name")
    indicators: List[str] = Field(default_factory=list, description="Member IOC values")
    relationship_summary: str = Field(..., description="Summary of connecting infrastructure/behavior")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Cluster confidence score")
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Aggregate cluster threat score (0 to 100)")
    evidence_refs: List[str] = Field(default_factory=list, description="Linked evidence or timeline references")


class AttributionAssessment(BaseModel):
    """Conservative attribution assessment payload."""
    attribution_id: str = Field(default_factory=lambda: f"ATTR-{uuid.uuid4().hex[:8].upper()}")
    level: AttributionLevel = Field(default=AttributionLevel.UNKNOWN, description="Attribution assessment level")
    statement: str = Field(..., description="Conservative attribution statement")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Attribution confidence score")
    evidence_refs: List[str] = Field(default_factory=list, description="Linked evidence references")
    supporting_indicators: List[str] = Field(default_factory=list, description="Supporting indicator values")


class ThreatIntelligenceFinding(BaseModel):
    """Traceable threat intelligence finding produced by agent."""
    finding_id: str = Field(default_factory=lambda: f"TI-FND-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Detailed threat finding description")
    severity: str = Field(default="MEDIUM", description="Severity: LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence rating (0.0 to 1.0)")
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Threat score rating (0 to 100)")
    ioc_values: List[str] = Field(default_factory=list, description="Linked indicator values")
    ioc_types: List[str] = Field(default_factory=list, description="Linked indicator types")
    provider_evidence: Dict[str, Any] = Field(default_factory=dict, description="Summarized provider evidence")
    mitre_techniques: List[str] = Field(default_factory=list, description="Mapped MITRE technique IDs")
    related_entities: List[str] = Field(default_factory=list, description="Linked host/user entities")
    relationship_refs: List[str] = Field(default_factory=list, description="Linked infrastructure relationship IDs")
    reasoning_summary: str = Field(..., description="Evidence-backed reasoning summary")


class IntelligenceGap(BaseModel):
    """Identified intelligence gap to recommend for future collection/enrichment."""
    gap_id: str = Field(default_factory=lambda: f"TI-GAP-{uuid.uuid4().hex[:8].upper()}")
    description: str = Field(..., description="Description of missing intelligence or provider disagreement")
    importance: str = Field(default="HIGH", description="Importance: LOW, MEDIUM, HIGH, CRITICAL")
    recommended_next_step: str = Field(..., description="Recommended enrichment/collection action")
    priority: str = Field(default="MEDIUM", description="Priority: LOW, MEDIUM, HIGH, URGENT")


class ThreatIntelligenceRecommendation(BaseModel):
    """Human-governed threat intelligence recommendation output."""
    recommendation_id: str = Field(default_factory=lambda: f"TI-REC-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(..., description="Recommendation title")
    description: str = Field(..., description="Actionable recommendation detail")
    priority: str = Field(default="MEDIUM", description="Priority: LOW, MEDIUM, HIGH, URGENT")
    rationale: str = Field(..., description="Justification and risk reduction rationale")
    related_finding: Optional[str] = Field(default=None, description="Associated threat intelligence finding ID")
    suggested_playbook: Optional[str] = Field(default=None, description="Suggested SOAR playbook ID")
    requires_human_approval: bool = Field(default=True, description="Strictly True for response actions requiring supervisor review")
