"""
Executive SOC Summary & Platform Aggregated Metrics API Router.
"""

from typing import Annotated
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.users.router import get_current_user
from app.models.user import User
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.investigation import Investigation, InvestigationStatus
from app.case_management.models import CaseApproval, ApprovalStatus
from app.threat_intelligence.models import IOC, ThreatReputationLevel
from app.detection_engine.models import DetectionRule
from app.playbooks.models import Playbook, PlaybookStatus
from app.schemas.response import APIResponse

router = APIRouter(prefix="/overview", tags=["SOC Overview"])


class SOCOverviewMetrics(BaseModel):
    """Aggregated executive metrics for the SOC Command Center."""

    total_alerts: int
    critical_alerts: int
    open_incidents: int
    critical_incidents: int
    active_investigations: int
    pending_approvals: int
    total_iocs: int
    malicious_iocs: int
    total_detection_rules: int
    active_playbooks: int
    average_risk_score: float
    system_status: str


@router.get("", response_model=APIResponse[SOCOverviewMetrics])
async def get_soc_overview(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIResponse[SOCOverviewMetrics]:
    """Retrieve consolidated real-time operational metrics across all AegisAI XDR security domains."""
    # Alerts
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar_one() or 0
    critical_alerts = (
        await db.execute(select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.CRITICAL))
    ).scalar_one() or 0

    avg_risk_query = select(func.avg(Alert.risk_score))
    avg_risk = (await db.execute(avg_risk_query)).scalar_one() or 0.0

    # Incidents
    open_incidents = (
        await db.execute(
            select(func.count(Incident.id)).where(
                Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.TRIAGED, IncidentStatus.INVESTIGATING])
            )
        )
    ).scalar_one() or 0

    critical_incidents = (
        await db.execute(
            select(func.count(Incident.id)).where(
                Incident.severity == IncidentSeverity.CRITICAL
            )
        )
    ).scalar_one() or 0

    # Investigations
    active_investigations = (
        await db.execute(
            select(func.count(Investigation.id)).where(
                Investigation.status.in_([InvestigationStatus.INITIATED, InvestigationStatus.IN_PROGRESS])
            )
        )
    ).scalar_one() or 0

    # Approvals
    pending_approvals = (
        await db.execute(
            select(func.count(CaseApproval.id)).where(CaseApproval.status == ApprovalStatus.PENDING)
        )
    ).scalar_one() or 0

    # IOCs
    total_iocs = (await db.execute(select(func.count(IOC.id)))).scalar_one() or 0
    malicious_iocs = (
        await db.execute(
            select(func.count(IOC.id)).where(
                IOC.reputation.in_([ThreatReputationLevel.MALICIOUS, ThreatReputationLevel.CRITICAL, ThreatReputationLevel.HIGH])
            )
        )
    ).scalar_one() or 0

    # Detection Rules
    total_detection_rules = (await db.execute(select(func.count(DetectionRule.id)))).scalar_one() or 0

    # Playbooks
    active_playbooks = (
        await db.execute(
            select(func.count(Playbook.id)).where(Playbook.status == PlaybookStatus.ACTIVE)
        )
    ).scalar_one() or 0

    metrics = SOCOverviewMetrics(
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        open_incidents=open_incidents,
        critical_incidents=critical_incidents,
        active_investigations=active_investigations,
        pending_approvals=pending_approvals,
        total_iocs=total_iocs,
        malicious_iocs=malicious_iocs,
        total_detection_rules=total_detection_rules,
        active_playbooks=active_playbooks,
        average_risk_score=round(float(avg_risk), 2),
        system_status="HEALTHY",
    )

    return APIResponse(
        message="SOC Overview executive metrics retrieved successfully",
        data=metrics,
    )
