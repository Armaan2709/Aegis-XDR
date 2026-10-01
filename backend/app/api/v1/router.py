"""
API Version 1 Central Router Aggregator.

Mounts version 1 domain routes (Auth, Health, and domain router hooks).
"""

from fastapi import APIRouter
from app.api.v1.health import router as health_router
from app.domains.users.router import router as auth_router
from app.domains.alerts.router import router as alerts_router
from app.domains.incidents.router import router as incidents_router
from app.domains.investigations.router import router as investigations_router
from app.domains.evidence.router import router as evidence_router
from app.domains.timeline.router import router as timeline_router
from app.correlation.router import router as correlation_router
from app.mitre.router import router as mitre_router
from app.threat_intelligence.router import router as threat_intel_router
from app.detection_engine.router import router as detection_rules_router
from app.case_management.router import router as cases_router
from app.playbooks.router import router as playbooks_router
from app.ai.router import router as ai_router
from app.api.v1.overview import router as overview_router
from app.observability.router import observability_router
from app.demo.router import router as demo_router


api_v1_router = APIRouter()

api_v1_router.include_router(health_router)
api_v1_router.include_router(overview_router)
api_v1_router.include_router(observability_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(incidents_router)
api_v1_router.include_router(investigations_router)
api_v1_router.include_router(evidence_router)
api_v1_router.include_router(timeline_router)
api_v1_router.include_router(correlation_router)
api_v1_router.include_router(mitre_router)
api_v1_router.include_router(threat_intel_router)
api_v1_router.include_router(detection_rules_router)
api_v1_router.include_router(cases_router)
api_v1_router.include_router(playbooks_router)
api_v1_router.include_router(ai_router)
api_v1_router.include_router(demo_router)









