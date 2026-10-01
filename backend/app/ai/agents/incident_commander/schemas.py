"""
Incident Commander Agent Schemas and DTOs.

Defines Pydantic v2 data models for Incident Assessment, Attack Chain Reconstruction,
Consensus Findings, Human-Governed Response Plans, and Executive Incident Summaries.
"""

import enum
import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class AttackStageStatus(str, enum.Enum):
    """Attack chain stage observation status."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    NOT_OBSERVED = "NOT_OBSERVED"
    UNKNOWN = "UNKNOWN"


class AttackChainStage(BaseModel):
    """Reconstructed MITRE ATT&CK attack chain stage."""
    stage: str = Field(..., description="Tactical attack stage name (e.g., INITIAL_ACCESS, EXECUTION)")
    status: AttackStageStatus = Field(default=AttackStageStatus.UNKNOWN, description="Observation state")
    timestamp: Optional[str] = Field(default=None, description="Observed event timestamp")
    description: str = Field(default="", description="Stage summary details")
    evidence_refs: List[str] = Field(default_factory=list, description="Linked evidence or timeline IDs")
    mitre_techniques: List[str] = Field(default_factory=list, description="Associated MITRE technique IDs")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Stage confidence score")


class CommanderFinding(BaseModel):
    """Synthesized finding across multi-agent evidence."""
    finding_id: str = Field(default_factory=lambda: f"CMD-FIND-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Synthesized finding description")
    severity: str = Field(default="MEDIUM", description="Severity: LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Finding confidence")
    evidence_refs: List[str] = Field(default_factory=list, description="Linked evidence IDs")
    supporting_agents: List[str] = Field(default_factory=list, description="Agents supporting this finding")
    conflicting_agents: List[str] = Field(default_factory=list, description="Agents contradicting this finding")


class CommanderRecommendation(BaseModel):
    """Actionable recommendation produced by Incident Commander."""
    recommendation_id: str = Field(default_factory=lambda: f"CMD-REC-{uuid.uuid4().hex[:8].upper()}")
    action: str = Field(..., description="Action type or title (e.g. ISOLATE_HOST, REVIEW_LOGS)")
    rationale: str = Field(..., description="Evidence-backed justification")
    priority: str = Field(default="MEDIUM", description="Priority: LOW, MEDIUM, HIGH, URGENT")
    risk_reduction: str = Field(default="MODERATE", description="Expected risk reduction impact")
    requires_human_approval: bool = Field(default=True, description="Strictly True for all SOAR/deployment recommendations")
    related_playbook_id: Optional[str] = Field(default=None, description="Associated SOAR Playbook ID")
    related_case_id: Optional[str] = Field(default=None, description="Associated Case ID")


class ResponsePlan(BaseModel):
    """Categorized human-governed incident response plan."""
    immediate_actions: List[CommanderRecommendation] = Field(default_factory=list)
    containment_actions: List[CommanderRecommendation] = Field(default_factory=list)
    investigation_actions: List[CommanderRecommendation] = Field(default_factory=list)
    eradication_actions: List[CommanderRecommendation] = Field(default_factory=list)
    recovery_actions: List[CommanderRecommendation] = Field(default_factory=list)
    monitoring_actions: List[CommanderRecommendation] = Field(default_factory=list)
    approval_required: bool = Field(default=True, description="Strictly True for response execution")


class ExecutiveIncidentSummary(BaseModel):
    """Management-level executive summary payload."""
    incident_title: str = Field(..., description="Incident high-level title")
    executive_summary: str = Field(..., description="Concise non-technical SOC summary")
    business_impact: str = Field(default="Business impact not determined.", description="Business impact assessment")
    technical_impact: str = Field(default="", description="Technical impact details")
    current_status: str = Field(default="UNDER_INVESTIGATION", description="Incident status")
    severity: str = Field(default="HIGH", description="Incident severity level")
    confidence: float = Field(default=0.85, ge=0.0, le=1.0, description="Overall confidence rating")
    key_findings: List[str] = Field(default_factory=list, description="Key confirmed findings")
    recommended_actions: List[str] = Field(default_factory=list, description="Top priority recommended actions")


class IncidentAssessment(BaseModel):
    """Unified master incident assessment synthesized by Incident Commander."""
    assessment_id: str = Field(default_factory=lambda: f"ASSESS-{uuid.uuid4().hex[:8].upper()}")
    incident_id: Optional[str] = Field(default=None)
    investigation_id: str = Field(...)
    case_id: Optional[str] = Field(default=None)
    title: str = Field(..., description="Master incident assessment title")
    summary: str = Field(..., description="Unified synthesized summary")
    severity: str = Field(default="HIGH", description="Severity rating: LOW, MEDIUM, HIGH, CRITICAL")
    priority: str = Field(default="P2", description="Priority rating: P1, P2, P3, P4")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    attack_stage: str = Field(default="UNKNOWN", description="Current overall attack stage")
    root_cause: str = Field(default="Unknown / Inconclusive", description="Likely root cause assessment")
    impact_assessment: str = Field(default="Technical impact under assessment")
    affected_assets: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    confirmed_findings: List[CommanderFinding] = Field(default_factory=list)
    suspected_findings: List[CommanderFinding] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    contributing_agents: List[str] = Field(default_factory=list)
    conflicting_findings: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[CommanderRecommendation] = Field(default_factory=list)
    response_plan: ResponsePlan = Field(default_factory=ResponsePlan)
    executive_summary: Optional[ExecutiveIncidentSummary] = Field(default=None)
    requires_human_review: bool = Field(default=True, description="Strictly True for human governance boundary")
