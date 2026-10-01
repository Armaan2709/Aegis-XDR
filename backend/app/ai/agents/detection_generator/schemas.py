"""
Detection Rule Generator Agent Schemas and DTOs.

Defines Pydantic v2 data models for Detection Rule Candidates, Quality Scores,
Rule Generation Results, and Human-Governed Recommendations.
"""

import enum
import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.detection_engine.models import RuleType, RuleSeverity


class RuleQualityLevel(str, enum.Enum):
    """Rule quality assessment levels."""
    EXCELLENT = "EXCELLENT"
    GOOD = "GOOD"
    ACCEPTABLE = "ACCEPTABLE"
    WEAK = "WEAK"
    REJECTED = "REJECTED"


class DetectionRuleCandidate(BaseModel):
    """Candidate defensive detection rule generated from investigation telemetry."""
    candidate_id: str = Field(default_factory=lambda: f"RULE-CAND-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(..., description="Rule descriptive title")
    description: str = Field(..., description="Rule technical description and scope")
    rule_type: RuleType = Field(..., description="Rule format type: SIGMA, YARA, SURICATA, or CUSTOM")
    severity: RuleSeverity = Field(default=RuleSeverity.MEDIUM, description="Rule alert severity level")
    confidence: float = Field(default=0.80, ge=0.0, le=1.0, description="Generation confidence score")
    mitre_techniques: List[str] = Field(default_factory=list, description="Associated MITRE technique IDs")
    evidence_refs: List[str] = Field(default_factory=list, description="Linked evidence or timeline IDs")
    detection_logic: str = Field(..., description="Raw syntax rule content (YAML, YARA, Suricata)")
    false_positive_notes: str = Field(..., description="Potential false positive scenarios and notes")
    generation_rationale: str = Field(..., description="Evidence-backed generation rationale")


class RuleQualityScore(BaseModel):
    """Quality analysis score payload produced by DetectionRuleQualityAnalyzer."""
    quality_score: float = Field(..., ge=0.0, le=100.0, description="Overall quality score (0 to 100)")
    quality_level: RuleQualityLevel = Field(..., description="Rule quality rating level")
    warnings: List[str] = Field(default_factory=list, description="Syntax or metadata warnings")
    recommendations: List[str] = Field(default_factory=list, description="Quality enhancement recommendations")
    is_duplicate: bool = Field(default=False, description="True if similar or duplicate rule exists in registry")
    duplicate_rule_name: Optional[str] = Field(default=None, description="Name of matching existing rule if duplicate")


class RuleGenerationResult(BaseModel):
    """Aggregated rule generation payload produced by agent pipeline."""
    candidates: List[DetectionRuleCandidate] = Field(default_factory=list, description="Generated candidate rules")
    generated_count: int = Field(default=0, ge=0, description="Number of rules generated")
    rejected_count: int = Field(default=0, ge=0, description="Number of low-quality or invalid rules rejected")
    validation_results: Dict[str, Any] = Field(default_factory=dict, description="Rule validation results from Sprint 8 validator")
    dry_run_results: Dict[str, Any] = Field(default_factory=dict, description="Dry-run match results from Sprint 8 tester")
    quality_scores: Dict[str, Any] = Field(default_factory=dict, description="Quality scores per candidate ID")


class DetectionRuleRecommendation(BaseModel):
    """Human-governed advisory recommendation for rule activation or deployment."""
    recommendation_id: str = Field(default_factory=lambda: f"RULE-REC-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(..., description="Recommendation title")
    description: str = Field(..., description="Actionable detail and suggested action")
    priority: str = Field(default="MEDIUM", description="Priority: LOW, MEDIUM, HIGH, URGENT")
    rationale: str = Field(..., description="Defensive coverage justification")
    candidate_rule_id: Optional[str] = Field(default=None, description="Associated candidate rule ID")
    validation_status: str = Field(default="VALID", description="Validation status from Detection Engine")
    quality_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Quality score of candidate rule")
    suggested_action: str = Field(..., description="Suggested deployment or review action")
    requires_human_approval: bool = Field(default=True, description="Strictly True for all deployment/activation recommendations")
