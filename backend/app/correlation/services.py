"""
Correlation Domain Service Layer.

Orchestrates deterministic correlation evaluation over database alerts, manages automatic
creation of aggregated Incident entities, links correlated Alert IDs, and constructs relationship graphs.
"""

import time
import uuid
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.repositories import CorrelationRepository
from app.domains.incidents.repositories import IncidentRepository
from app.domains.incidents.schemas import IncidentCreate
from app.correlation.engine import CorrelationEngine
from app.correlation.rules import get_default_correlation_rules, CorrelationRule
from app.correlation.graph import CorrelationGraph
from app.correlation.schemas import (
    CorrelationRequest,
    CorrelationExecutionResult,
    CorrelatedCandidateRead,
    CorrelationGraphRead,
)
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger

logger = get_logger("domain.correlation")


class CorrelationService:
    """Service encapsulating deterministic alert correlation workflows."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = CorrelationRepository(session)
        self.incident_repo = IncidentRepository(session)
        self.engine = CorrelationEngine(rules=get_default_correlation_rules())

    async def evaluate(self, req: CorrelationRequest) -> CorrelationExecutionResult:
        """Execute deterministic correlation over database alerts."""
        start_time = time.perf_counter()

        if req.alert_ids:
            alerts = await self.repo.get_alerts_by_ids(req.alert_ids)
        else:
            alerts = await self.repo.get_unassigned_alerts(limit=200)

        if not alerts:
            exec_time = (time.perf_counter() - start_time) * 1000.0
            return CorrelationExecutionResult(
                evaluated_alerts_count=0,
                duplicates_removed=0,
                candidates_count=0,
                created_incident_ids=[],
                candidates=[],
                execution_time_ms=round(exec_time, 2),
            )

        # Evaluate rules using engine
        candidates = self.engine.evaluate(alerts)

        created_incident_ids: List[uuid.UUID] = []
        candidate_dtos: List[CorrelatedCandidateRead] = []

        for candidate in candidates:
            candidate_dtos.append(
                CorrelatedCandidateRead(
                    candidate_id=candidate.candidate_id,
                    title=candidate.title,
                    description=candidate.description,
                    category=candidate.category,
                    severity=candidate.severity,
                    priority=candidate.priority,
                    risk_score=candidate.risk_score,
                    confidence_score=candidate.confidence_score,
                    alert_ids=candidate.alert_ids,
                    matched_rule_id=candidate.matched_rule_id,
                    matched_rule_name=candidate.matched_rule_name,
                )
            )

            if req.auto_create_incidents and candidate.alert_ids:
                incident_in = IncidentCreate(
                    title=candidate.title,
                    description=candidate.description,
                    severity=candidate.severity,
                    priority=candidate.priority,
                    category=candidate.category,
                    risk_score=candidate.risk_score,
                    confidence_score=candidate.confidence_score,
                    source=f"Correlation Engine ({candidate.matched_rule_name or 'Rule'})",
                    alert_ids=candidate.alert_ids,
                )
                incident = await self.incident_repo.create(incident_in)
                created_incident_ids.append(incident.id)

                # Link alerts in DB to created incident
                await self.repo.link_alerts_to_incident(candidate.alert_ids, incident.id)

                logger.info(
                    "Correlated Incident created",
                    incident_id=str(incident.id),
                    title=incident.title,
                    alert_count=len(candidate.alert_ids),
                )

        exec_time = (time.perf_counter() - start_time) * 1000.0

        return CorrelationExecutionResult(
            evaluated_alerts_count=len(alerts),
            duplicates_removed=0,
            candidates_count=len(candidates),
            created_incident_ids=created_incident_ids,
            candidates=candidate_dtos,
            execution_time_ms=round(exec_time, 2),
        )

    async def get_incident_graph(self, incident_id: uuid.UUID) -> CorrelationGraphRead:
        """Build and retrieve correlation graph network for an Incident."""
        incident = await self.incident_repo.get_by_id(incident_id)
        if not incident:
            raise NotFoundError(f"Incident with ID '{incident_id}' was not found.")

        alerts = await self.repo.get_alerts_for_incident(incident_id)

        graph = CorrelationGraph()
        graph.build_from_alerts(alerts, incident_id=str(incident_id))

        return CorrelationGraphRead(
            incident_id=incident_id,
            nodes=list(graph.nodes.values()),
            edges=graph.edges,
        )
