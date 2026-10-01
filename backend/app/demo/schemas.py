"""
Demonstration Framework Pydantic Validation Schemas.

Defines scenario definitions, synthetic telemetry schemas, execution request/response models,
20-point validation assertion results, and structured demonstration reports.
"""

import uuid
from enum import Enum
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from app.models.alert import AlertSeverity
from app.ai.pipeline.schemas import PipelineStage, PipelineStatus


class ScenarioID(str, Enum):
    """Supported deterministic synthetic security scenarios."""

    CREDENTIAL_COMPROMISE = "credential_compromise"
    RANSOMWARE_SIMULATION = "ransomware_simulation"
    DATA_EXFILTRATION = "data_exfiltration"


class TelemetryTag(str, Enum):
    """Tagging classification for demo telemetry items."""

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    SIMULATED = "SIMULATED"
    RECOMMENDED = "RECOMMENDED"


class SyntheticAlertTelemetry(BaseModel):
    """Synthetic security alert payload for scenario seeding."""

    title: str = Field(..., max_length=255)
    description: str
    source: str = Field("Synthetic Telemetry Engine", max_length=100)
    source_ref_id: str
    severity: AlertSeverity = AlertSeverity.HIGH
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    iocs: Dict[str, Any] = Field(default_factory=dict)
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=lambda: ["synthetic_telemetry", "demo_scenario"])


class ScenarioDefinition(BaseModel):
    """Metadata specification for a deterministic attack scenario."""

    scenario_id: ScenarioID
    name: str
    description: str
    attack_phases: List[str]
    synthetic_alerts: List[SyntheticAlertTelemetry]
    expected_agents: List[str] = Field(
        default_factory=lambda: [
            "ThreatHunterAgent",
            "DFIRInvestigatorAgent",
            "ThreatIntelAnalystAgent",
            "DetectionGeneratorAgent",
            "IncidentCommanderAgent",
        ]
    )
    expected_mitre_techniques: List[str]
    expected_risk_range: List[float] = Field(default_factory=lambda: [70.0, 100.0])
    expected_severity: str = "CRITICAL"
    expected_governance_state: str = "AWAITING_APPROVAL"
    expected_final_stage: PipelineStage = PipelineStage.COMPLETED


class ScenarioRunRequest(BaseModel):
    """Request params for running a synthetic demo scenario."""

    auto_approve: bool = Field(False, description="Whether to auto-approve CaseApproval gate for SOAR mock execution")
    inject_stage_failure: Optional[str] = Field(None, description="Optional stage name to simulate pipeline error recovery")


class AssertionDetail(BaseModel):
    """Result status of an individual validation assertion."""

    assertion_id: int
    name: str
    passed: bool
    details: str


class DemonstrationMetrics(BaseModel):
    """Performance metrics captured during scenario execution."""

    execution_duration_ms: float
    pipeline_duration_ms: float
    agent_latencies_ms: Dict[str, float] = Field(default_factory=dict)
    db_operations_count: int = 0


class ScenarioReportSection(BaseModel):
    """Structured section inside a scenario execution report."""

    title: str
    classification: TelemetryTag
    content: Dict[str, Any]


class ScenarioReport(BaseModel):
    """Comprehensive structured demonstration report."""

    scenario_id: ScenarioID
    scenario_name: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    overview: str
    attack_chain: List[Dict[str, Any]]
    observed_telemetry: List[Dict[str, Any]]
    ai_agent_findings: Dict[str, Any]
    mitre_mappings: List[str]
    threat_intelligence: Dict[str, Any]
    detection_rules: List[Dict[str, Any]]
    risk_assessment: Dict[str, Any]
    incident_commander_synthesis: Dict[str, Any]
    evidence_gaps: List[str]
    response_plan: Dict[str, Any]
    approval_decision: Dict[str, Any]
    soar_execution_result: Dict[str, Any]
    timeline_summary: List[Dict[str, Any]]
    final_outcome: str


class ScenarioExecutionResult(BaseModel):
    """Combined output of scenario execution run."""

    scenario_id: ScenarioID
    name: str
    status: PipelineStatus
    duration_ms: float
    created_alert_ids: List[uuid.UUID]
    created_incident_id: Optional[uuid.UUID] = None
    created_investigation_id: Optional[uuid.UUID] = None
    created_case_id: Optional[uuid.UUID] = None
    approval_status: str = "PENDING"
    soar_execution_mode: str = "SAFE_MOCK_EXECUTION"
    pipeline_final_stage: PipelineStage
    assertions_passed: int
    total_assertions: int = 20
    assertions: List[AssertionDetail]
    agent_findings: Dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: List[str] = Field(default_factory=list)
    risk_score: float = 0.0
    severity: str = "MEDIUM"
    generated_rules: List[Dict[str, Any]] = Field(default_factory=list)
    response_plan: List[Dict[str, Any]] = Field(default_factory=list)
    metrics: DemonstrationMetrics

    model_config = ConfigDict(from_attributes=True)
