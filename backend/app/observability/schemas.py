"""
Pydantic V2 Schemas for AegisAI XDR Enterprise Observability & SOC Analytics.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field



class TimeSeriesPoint(BaseModel):
    """Timestamped data point for time-series charts."""
    timestamp: datetime
    value: float
    label: Optional[str] = None


class MetricTrend(BaseModel):
    """Calculated trend comparison across time windows."""
    current_value: float
    previous_value: float
    percentage_change: float
    trend_direction: str = Field(description="UP, DOWN, STABLE")


class PlatformMetrics(BaseModel):
    """Platform-wide operational counter summary."""
    total_alerts: int = 0
    alerts_today: int = 0
    critical_alerts: int = 0
    open_incidents: int = 0
    active_investigations: int = 0
    open_cases: int = 0
    pending_approvals: int = 0
    active_playbook_executions: int = 0
    total_iocs: int = 0
    malicious_iocs: int = 0
    total_detection_rules: int = 0
    active_ai_agents: int = 6


class SOCMetrics(BaseModel):
    """MTTD / MTTR operational velocity metrics."""
    mttd_seconds: Optional[float] = Field(None, description="Mean Time To Detect in seconds")
    mttr_seconds: Optional[float] = Field(None, description="Mean Time To Respond in seconds")
    avg_triage_time_seconds: Optional[float] = None
    avg_investigation_duration_seconds: Optional[float] = None
    avg_approval_wait_seconds: Optional[float] = None
    alert_to_incident_ratio: float = 0.0
    incident_to_case_ratio: float = 0.0
    conversion_funnel: Dict[str, int] = Field(default_factory=dict)


class AlertMetrics(BaseModel):
    """Detailed alert analytics."""
    total_count: int = 0
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    status_breakdown: Dict[str, int] = Field(default_factory=dict)
    false_positive_rate: float = 0.0
    top_sources: List[Dict[str, Any]] = Field(default_factory=list) if False else Field(default_factory=list)
    top_hosts: List[Dict[str, Any]] = Field(default_factory=list)
    top_users: List[Dict[str, Any]] = Field(default_factory=list)


class IncidentMetrics(BaseModel):
    """Incident lifecycle and backlog metrics."""
    total_created: int = 0
    open_count: int = 0
    resolved_count: int = 0
    severity_distribution: Dict[str, int] = Field(default_factory=dict)
    priority_distribution: Dict[str, int] = Field(default_factory=dict)
    avg_resolution_seconds: Optional[float] = None
    sla_breaches: int = 0


class InvestigationMetrics(BaseModel):
    """Investigation domain metrics."""
    total_investigations: int = 0
    active_count: int = 0
    completed_count: int = 0
    avg_duration_seconds: Optional[float] = None



class StagePerformanceMetric(BaseModel):
    """Sprint 17 Pipeline stage performance telemetry."""
    stage: str
    execution_count: int = 0
    avg_duration_ms: float = 0.0
    failure_rate: float = 0.0
    retry_count: int = 0
    is_bottleneck: bool = False


class PipelineMetrics(BaseModel):
    """Autonomous investigation pipeline execution analytics."""
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    cancelled_executions: int = 0
    avg_duration_seconds: Optional[float] = None
    median_duration_seconds: Optional[float] = None
    recovery_frequency: int = 0
    stage_performance: List[StagePerformanceMetric] = Field(default_factory=list)
    bottleneck_stage: Optional[str] = None


class SingleAgentMetric(BaseModel):
    """Performance metrics for an individual specialized AI agent."""
    agent_name: str
    execution_count: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    success_rate: float = 100.0
    avg_execution_duration_ms: float = 0.0
    avg_confidence_score: float = 0.0
    total_findings_generated: int = 0
    total_recommendations_generated: int = 0


class AgentMetrics(BaseModel):
    """Aggregated AI agent performance metrics."""
    total_agent_runs: int = 0
    overall_success_rate: float = 100.0
    avg_overall_confidence: float = 0.0
    consensus_score: float = 100.0
    agents: List[SingleAgentMetric] = Field(default_factory=list)


class ThreatIntelMetrics(BaseModel):
    """Threat Intelligence feed and IOC analytics."""
    total_iocs: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    benign_count: int = 0
    unknown_count: int = 0
    type_breakdown: Dict[str, int] = Field(default_factory=dict)
    category_distribution: Dict[str, int] = Field(default_factory=dict)


class DetectionMetrics(BaseModel):
    """Detection Rule Engine analytics."""
    total_rules: int = 0
    active_production_rules: int = 0
    candidate_rules: int = 0
    experimental_rules: int = 0
    rule_format_breakdown: Dict[str, int] = Field(default_factory=dict)
    avg_quality_score: float = 0.0
    ai_generated_rules_count: int = 0


class CaseMetrics(BaseModel):
    """Case Management and analyst workload analytics."""
    total_cases: int = 0
    open_cases: int = 0
    resolved_cases: int = 0
    sla_breaches: int = 0
    pending_approvals: int = 0
    avg_resolution_hours: Optional[float] = None
    approval_velocity_hours: Optional[float] = None


class PlaybookMetrics(BaseModel):
    """SOAR playbook safe mock execution analytics."""
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    is_safe_simulated_mode: bool = True
    playbook_usage_count: Dict[str, int] = Field(default_factory=dict)


class ComponentHealthStatus(BaseModel):
    """Individual infrastructure service health status."""
    service_name: str
    status: str = "HEALTHY"  # HEALTHY, DEGRADED, UNHEALTHY
    latency_ms: float = 0.0
    message: Optional[str] = None


class SystemHealthMetrics(BaseModel):
    """Comprehensive system health metrics."""
    overall_status: str = "HEALTHY"
    components: List[ComponentHealthStatus] = Field(default_factory=list)
    active_connections: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ObservabilityOverview(BaseModel):
    """Master response schema for GET /api/v1/observability/overview."""
    time_window: str = "24h"
    platform: PlatformMetrics
    soc: SOCMetrics
    alerts: AlertMetrics
    incidents: IncidentMetrics
    pipeline: PipelineMetrics
    agents: AgentMetrics
    threat_intel: ThreatIntelMetrics
    detections: DetectionMetrics
    cases: CaseMetrics
    playbooks: PlaybookMetrics
    health: SystemHealthMetrics
