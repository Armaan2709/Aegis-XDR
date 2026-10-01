"""
FastAPI Router for AegisAI XDR Enterprise Observability & SOC Analytics.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.observability.services import SOCAnalyticsService
from app.observability.exporters import generate_prometheus_metrics
from app.observability.schemas import (
    ObservabilityOverview,
    AlertMetrics,
    IncidentMetrics,
    PipelineMetrics,
    AgentMetrics,
    ThreatIntelMetrics,
    DetectionMetrics,
    CaseMetrics,
    PlaybookMetrics,
    SystemHealthMetrics,
)

observability_router = APIRouter(prefix="/observability", tags=["Observability & SOC Analytics"])


@observability_router.get("/overview", response_model=ObservabilityOverview)
async def get_observability_overview(
    time_window: str = Query("24h", description="Time window (1h, 6h, 24h, 7d, 30d)"),
    db: AsyncSession = Depends(get_db),
) -> ObservabilityOverview:
    """Retrieve consolidated enterprise observability & SOC analytics overview."""
    service = SOCAnalyticsService(db)
    return await service.get_overview(time_window=time_window)


@observability_router.get("/alerts", response_model=AlertMetrics)
async def get_alerts_analytics(
    time_window: str = Query("24h"),
    db: AsyncSession = Depends(get_db),
) -> AlertMetrics:
    """Retrieve security alert ingestion & severity analytics."""
    service = SOCAnalyticsService(db)
    return await service.get_alerts_analytics(time_window=time_window)


@observability_router.get("/incidents", response_model=IncidentMetrics)
async def get_incidents_analytics(
    time_window: str = Query("24h"),
    db: AsyncSession = Depends(get_db),
) -> IncidentMetrics:
    """Retrieve incident lifecycle & priority analytics."""
    service = SOCAnalyticsService(db)
    return await service.get_incidents_analytics(time_window=time_window)


@observability_router.get("/pipeline", response_model=PipelineMetrics)
async def get_pipeline_analytics(
    time_window: str = Query("24h"),
    db: AsyncSession = Depends(get_db),
) -> PipelineMetrics:
    """Retrieve Sprint 17 11-stage autonomous investigation pipeline analytics."""
    service = SOCAnalyticsService(db)
    return await service.get_pipeline_analytics(time_window=time_window)


@observability_router.get("/agents", response_model=AgentMetrics)
async def get_agent_analytics(
    time_window: str = Query("24h"),
    db: AsyncSession = Depends(get_db),
) -> AgentMetrics:
    """Retrieve specialized AI agent execution, duration & consensus analytics."""
    service = SOCAnalyticsService(db)
    return await service.get_agent_analytics(time_window=time_window)


@observability_router.get("/threat-intelligence", response_model=ThreatIntelMetrics)
async def get_threat_intel_analytics(
    time_window: str = Query("24h"),
    db: AsyncSession = Depends(get_db),
) -> ThreatIntelMetrics:
    """Retrieve threat intelligence feed & IOC reputation analytics."""
    service = SOCAnalyticsService(db)
    return await service.get_threat_intel_analytics(time_window=time_window)


@observability_router.get("/detections", response_model=DetectionMetrics)
async def get_detection_analytics(
    time_window: str = Query("24h"),
    db: AsyncSession = Depends(get_db),
) -> DetectionMetrics:
    """Retrieve Detection Rule Engine analytics."""
    service = SOCAnalyticsService(db)
    return await service.get_detection_analytics(time_window=time_window)


@observability_router.get("/cases", response_model=CaseMetrics)
async def get_case_analytics(
    time_window: str = Query("24h"),
    db: AsyncSession = Depends(get_db),
) -> CaseMetrics:
    """Retrieve Case Management & governance approval analytics."""
    service = SOCAnalyticsService(db)
    return await service.get_case_analytics(time_window=time_window)


@observability_router.get("/playbooks", response_model=PlaybookMetrics)
async def get_playbook_analytics(
    time_window: str = Query("24h"),
    db: AsyncSession = Depends(get_db),
) -> PlaybookMetrics:
    """Retrieve SOAR playbook safe mock execution analytics."""
    service = SOCAnalyticsService(db)
    return await service.get_playbook_analytics(time_window=time_window)


@observability_router.get("/system", response_model=SystemHealthMetrics)
async def get_system_health(
    db: AsyncSession = Depends(get_db),
) -> SystemHealthMetrics:
    """Retrieve platform infrastructure & AI pipeline health status."""
    service = SOCAnalyticsService(db)
    return await service.get_system_health()


@observability_router.get("/metrics", response_class=PlainTextResponse)
async def get_prometheus_metrics(
    db: AsyncSession = Depends(get_db),
) -> str:
    """Expose native Prometheus text format operational metrics for scraping."""
    service = SOCAnalyticsService(db)
    overview = await service.get_overview(time_window="24h")
    return generate_prometheus_metrics(overview.model_dump())

