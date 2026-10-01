"""
AI Orchestrator Shared Investigation State Model.

Maintains shared state across multi-agent security investigation workflows.
Supports JSON serialization, validation, and deterministic updates.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict
from app.ai.agents.base import AgentResult


class InvestigationState(BaseModel):
    """Shared contextual state passed between security AI agents during investigation workflows."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    investigation_id: str = Field(..., description="Unique investigation identifier UUID string")
    incident_id: Optional[str] = Field(default=None, description="Associated incident ID if linked")
    case_id: Optional[str] = Field(default=None, description="Associated SOC Case ID if linked")

    alerts: List[Dict[str, Any]] = Field(default_factory=list, description="Ingested security alerts")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Linked DFIR forensic evidence items")
    timeline: List[Dict[str, Any]] = Field(default_factory=list, description="Chronological timeline event records")
    mitre_mappings: List[Dict[str, Any]] = Field(default_factory=list, description="Mapped MITRE ATT&CK techniques")
    threat_intelligence: List[Dict[str, Any]] = Field(default_factory=list, description="Threat intel IOC reputation data")
    detection_matches: List[Dict[str, Any]] = Field(default_factory=list, description="Detection engine rule hits")

    agent_results: Dict[str, AgentResult] = Field(default_factory=dict, description="Results produced by executed AI agents")
    hypotheses: List[Dict[str, Any]] = Field(default_factory=list, description="Investigative hypotheses formulated by AI agents")

    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Calculated aggregate risk score (0 to 100)")
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Aggregate confidence rating (0.0 to 1.0)")
    recommendations: List[str] = Field(default_factory=list, description="Aggregated actionable recommendations")

    current_phase: str = Field(default="TRIAGE", description="Current workflow investigation phase")
    execution_metadata: Dict[str, Any] = Field(default_factory=dict, description="Execution parameters and timing metadata")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize state object to dictionary representation."""
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationState":
        """Reconstruct state object from dictionary representation."""
        return cls.model_validate(data)

    def add_agent_result(self, result: AgentResult) -> None:
        """Register result of an agent execution run."""
        self.agent_results[result.agent_name] = result

    def add_recommendation(self, recommendation: str) -> None:
        """Add an actionable recommendation if not duplicate."""
        if recommendation and recommendation not in self.recommendations:
            self.recommendations.append(recommendation)
