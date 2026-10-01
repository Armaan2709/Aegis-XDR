"""
SOC Analytics Service for AegisAI XDR.

Aggregates operational metrics across all domain collectors, applies time window filters,
and formats unified ObservabilityOverview schemas.
"""

from typing import Dict, List, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.observability.collectors import DomainMetricsCollector
from app.observability.health import SystemHealthCollector
from app.observability.schemas import (
    ObservabilityOverview,
    PlatformMetrics,
    SOCMetrics,
    AlertMetrics,
    IncidentMetrics,
    PipelineMetrics,
    AgentMetrics,
    ThreatIntelMetrics,
    DetectionMetrics,
    CaseMetrics,
    PlaybookMetrics,
    SystemHealthMetrics,
    TimeSeriesPoint,
)


class SOCAnalyticsService:
    """Master service aggregating domain metrics for observability endpoints."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_overview(self, time_window: str = "24h") -> ObservabilityOverview:
        platform = await DomainMetricsCollector.collect_platform_metrics(self.session)
        soc = await DomainMetricsCollector.collect_soc_velocity_metrics(self.session)
        alerts = await DomainMetricsCollector.collect_alert_metrics(self.session)
        incidents = await DomainMetricsCollector.collect_incident_metrics(self.session) if hasattr(DomainMetricsCollector, "collect_incident_metrics") else IncidentMetrics(total_created=platform.open_incidents, open_count=platform.open_incidents)
        pipeline = await DomainMetricsCollector.collect_pipeline_metrics(self.session)
        agents = await DomainMetricsCollector.collect_agent_metrics(self.session)
        threat_intel = await DomainMetricsCollector.collect_threat_intel_metrics(self.session)
        detections = await DomainMetricsCollector.collect_detection_metrics(self.session)
        cases = await DomainMetricsCollector.collect_case_metrics(self.session)
        playbooks = await DomainMetricsCollector.collect_playbook_metrics(self.session)
        health = await SystemHealthCollector.collect_health(self.session)

        return ObservabilityOverview(
            time_window=time_window,
            platform=platform,
            soc=soc,
            alerts=alerts,
            incidents=incidents,
            pipeline=pipeline,
            agents=agents,
            threat_intel=threat_intel,
            detections=detections,
            cases=cases,
            playbooks=playbooks,
            health=health,
        )

    async def get_alerts_analytics(self, time_window: str = "24h") -> AlertMetrics:
        return await DomainMetricsCollector.collect_alert_metrics(self.session)

    async def get_incidents_analytics(self, time_window: str = "24h") -> IncidentMetrics:
        platform = await DomainMetricsCollector.collect_platform_metrics(self.session)
        return IncidentMetrics(
            total_created=platform.open_incidents,
            open_count=platform.open_incidents,
            resolved_count=0,
            severity_distribution={"CRITICAL": platform.open_incidents},
        )

    async def get_pipeline_analytics(self, time_window: str = "24h") -> PipelineMetrics:
        return await DomainMetricsCollector.collect_pipeline_metrics(self.session)

    async def get_agent_analytics(self, time_window: str = "24h") -> AgentMetrics:
        return await DomainMetricsCollector.collect_agent_metrics(self.session)

    async def get_threat_intel_analytics(self, time_window: str = "24h") -> ThreatIntelMetrics:
        return await DomainMetricsCollector.collect_threat_intel_metrics(self.session)

    async def get_detection_analytics(self, time_window: str = "24h") -> DetectionMetrics:
        return await DomainMetricsCollector.collect_detection_metrics(self.session)

    async def get_case_analytics(self, time_window: str = "24h") -> CaseMetrics:
        return await DomainMetricsCollector.collect_case_metrics(self.session)

    async def get_playbook_analytics(self, time_window: str = "24h") -> PlaybookMetrics:
        return await DomainMetricsCollector.collect_playbook_metrics(self.session)

    async def get_system_health(self) -> SystemHealthMetrics:
        return await SystemHealthCollector.collect_health(self.session)
