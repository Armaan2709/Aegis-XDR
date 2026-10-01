"""
Alerts Domain Business Services.

Orchestrates security alert ingestion, automated risk score calculation,
event bus notifications, and triage lifecycle transitions.
"""

import uuid
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.alerts.repositories import AlertRepository
from app.domains.alerts.schemas import (
    AlertCreate,
    AlertUpdate,
    AlertFilterParams,
    AlertSummaryStats,
    AlertStatusUpdate,
    BulkAlertStatusUpdate,
)
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.core.exceptions import NotFoundError, ValidationError
from app.events.event_types import EventType
from app.events.schemas import EventPayload
from app.core.logging import get_logger

logger = get_logger("domain.alerts")


class AlertService:
    """Service encapsulating alert management business rules and event publishing."""

    def __init__(self, session: AsyncSession):
        self.repo = AlertRepository(session)

    def calculate_risk_score(self, severity: AlertSeverity, mitre_tactics: List[str], iocs: Dict[str, Any]) -> float:
        """Calculate dynamic risk score based on severity, MITRE tactics, and IOC counts."""
        base_scores = {
            AlertSeverity.INFO: 10.0,
            AlertSeverity.LOW: 35.0,
            AlertSeverity.MEDIUM: 60.0,
            AlertSeverity.HIGH: 85.0,
            AlertSeverity.CRITICAL: 98.0,
        }
        score = base_scores.get(severity, 50.0)

        # Tactical weight boost
        if mitre_tactics:
            score = min(100.0, score + len(mitre_tactics) * 2.5)

        # IOC density boost
        ioc_count = sum(len(v) if isinstance(v, list) else 1 for v in iocs.values()) if iocs else 0
        if ioc_count > 0:
            score = min(100.0, score + min(15.0, ioc_count * 1.5))

        return round(score, 1)

    async def ingest_alert(self, alert_in: AlertCreate) -> Alert:
        """Ingest security alert, compute initial risk score, and publish event."""
        # Auto-compute risk score if default
        if alert_in.risk_score == 50.0:
            alert_in.risk_score = self.calculate_risk_score(
                alert_in.severity, alert_in.mitre_tactics, alert_in.iocs
            )

        alert = await self.repo.create(alert_in)
        logger.info("Security alert ingested", alert_id=str(alert.id), title=alert.title, severity=alert.severity.value)

        return alert

    async def get_alert(self, alert_id: uuid.UUID) -> Alert:
        """Retrieve alert by ID or raise NotFoundError."""
        alert = await self.repo.get_by_id(alert_id)
        if not alert:
            raise NotFoundError(f"Alert with ID '{alert_id}' was not found.")
        return alert

    async def list_alerts(self, params: AlertFilterParams) -> Tuple[List[Alert], int]:
        """Query alerts with filtering and pagination."""
        return await self.repo.list_filtered(params)

    async def update_alert(self, alert_id: uuid.UUID, update_in: AlertUpdate) -> Alert:
        """Update alert details and re-evaluate risk score if severity/tactics changed."""
        alert = await self.get_alert(alert_id)
        update_data = update_in.model_dump(exclude_unset=True)

        if "severity" in update_data or "mitre_tactics" in update_data or "iocs" in update_data:
            severity = update_data.get("severity", alert.severity)
            tactics = update_data.get("mitre_tactics", alert.mitre_tactics)
            iocs = update_data.get("iocs", alert.iocs)
            update_data["risk_score"] = self.calculate_risk_score(severity, tactics, iocs)

        return await self.repo.update(alert, update_data)

    async def update_status(self, alert_id: uuid.UUID, status_in: AlertStatusUpdate) -> Alert:
        """Transition alert lifecycle state."""
        alert = await self.get_alert(alert_id)
        updated = await self.repo.update(alert, {"status": status_in.status})
        logger.info("Alert status updated", alert_id=str(alert_id), new_status=status_in.status.value)
        return updated

    async def bulk_update_status(self, bulk_in: BulkAlertStatusUpdate) -> int:
        """Bulk update triage status across multiple alerts."""
        updated_count = await self.repo.bulk_update_status(bulk_in.alert_ids, bulk_in.status)
        logger.info("Bulk alert status updated", count=updated_count, status=bulk_in.status.value)
        return updated_count

    async def get_summary_stats(self) -> AlertSummaryStats:
        """Get summary alert metrics for dashboard."""
        return await self.repo.get_summary_stats()
