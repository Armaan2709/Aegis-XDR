"""
DFIR Investigator Agent Schemas and DTOs.

Defines Pydantic v2 data models for Forensic Artifacts, Attack Phases, Root Cause Hypotheses,
Evidence Gaps, DFIR Findings, and Human-Governed Recommendations.
"""

import enum
import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ArtifactCategory(str, enum.Enum):
    """Forensic artifact category classification."""
    PROCESS = "PROCESS"
    FILE = "FILE"
    NETWORK = "NETWORK"
    REGISTRY = "REGISTRY"
    AUTHENTICATION = "AUTHENTICATION"
    USER_ACTIVITY = "USER_ACTIVITY"
    MEMORY = "MEMORY"
    LOG = "LOG"
    MALWARE = "MALWARE"
    OTHER = "OTHER"


class AttackPhase(str, enum.Enum):
    """MITRE ATT&CK kill-chain attack phases."""
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    COLLECTION = "COLLECTION"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"


class RootCauseStatus(str, enum.Enum):
    """Status evaluation of root-cause hypotheses."""
    SUPPORTED = "SUPPORTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    REFUTED = "REFUTED"


class NormalizedArtifact(BaseModel):
    """Normalized forensic artifact extracted from state telemetry."""
    artifact_id: str = Field(default_factory=lambda: f"ART-{uuid.uuid4().hex[:8].upper()}")
    timestamp: Optional[str] = Field(default=None, description="ISO timestamp of observed activity")
    entity: Optional[str] = Field(default=None, description="Target host or user entity")
    category: ArtifactCategory = Field(default=ArtifactCategory.OTHER, description="Artifact category")
    value: str = Field(..., description="Observed forensic string or summary value")
    source: str = Field(..., description="Source origin artifact/alert/timeline ID")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Extraction confidence")
    related_evidence_id: Optional[str] = Field(default=None, description="Linked Evidence ID if present")
    related_timeline_event_id: Optional[str] = Field(default=None, description="Linked Timeline Event ID if present")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Contextual forensic metadata")


class RootCauseHypothesis(BaseModel):
    """Structured root-cause hypothesis evaluated during forensic reconstruction."""
    hypothesis_id: str = Field(default_factory=lambda: f"RC-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(..., description="Root cause hypothesis title")
    description: str = Field(..., description="Detailed explanation of potential attack vector")
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Supporting forensic evidence")
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Contradictory evidence")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Root cause confidence (0.0 to 1.0)")
    status: RootCauseStatus = Field(default=RootCauseStatus.INCONCLUSIVE, description="Evaluation status")


class EvidenceGap(BaseModel):
    """Identified telemetry gap to recommend for future collection."""
    gap_id: str = Field(default_factory=lambda: f"GAP-{uuid.uuid4().hex[:8].upper()}")
    description: str = Field(..., description="Description of missing forensic evidence")
    importance: str = Field(default="HIGH", description="Importance rating: LOW, MEDIUM, HIGH, CRITICAL")
    recommended_collection: str = Field(..., description="Specific collection action recommended")
    priority: str = Field(default="MEDIUM", description="Priority rating: LOW, MEDIUM, HIGH, URGENT")


class DFIRFinding(BaseModel):
    """Traceable forensic finding produced by DFIR Investigator agent."""
    finding_id: str = Field(default_factory=lambda: f"DFIR-FND-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Detailed description of forensic finding")
    severity: str = Field(default="MEDIUM", description="Severity: LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence rating (0.0 to 1.0)")
    evidence_ids: List[str] = Field(default_factory=list, description="Linked Evidence IDs")
    timeline_event_ids: List[str] = Field(default_factory=list, description="Linked Timeline Event IDs")
    affected_entities: List[str] = Field(default_factory=list, description="Impacted host/user entities")
    mitre_techniques: List[str] = Field(default_factory=list, description="Mapped MITRE technique IDs")
    root_cause: Optional[str] = Field(default=None, description="Associated root cause hypothesis title")
    reasoning_summary: str = Field(..., description="Evidence-backed reasoning summary")


class DFIRRecommendation(BaseModel):
    """Human-governed DFIR recommendation output."""
    recommendation_id: str = Field(default_factory=lambda: f"DFIR-REC-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(..., description="Recommendation title")
    description: str = Field(..., description="Actionable recommendation detail")
    priority: str = Field(default="MEDIUM", description="Priority: LOW, MEDIUM, HIGH, URGENT")
    rationale: str = Field(..., description="Justification and risk reduction rationale")
    related_finding: Optional[str] = Field(default=None, description="Associated DFIR finding ID")
    suggested_playbook: Optional[str] = Field(default=None, description="Suggested SOAR playbook ID")
    requires_human_approval: bool = Field(default=True, description="Strictly True for response actions requiring supervisor review")
