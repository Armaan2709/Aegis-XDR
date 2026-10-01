"""
Enterprise Correlation Engine Package.

Deterministic alert aggregation, deduplication, rule evaluation, risk score calculation,
and relationship graph generation for AegisAI XDR.
"""

from app.correlation.rules import CorrelationRule, get_default_correlation_rules
from app.correlation.graph import (
    CorrelationGraph,
    GraphNode,
    GraphEdge,
    CorrelationNodeType,
    CorrelationEdgeType,
)
from app.correlation.engine import (
    CorrelationEngine,
    AlertDeduplicationRecord,
    CorrelatedIncidentCandidate,
)
from app.correlation.schemas import (
    CorrelationRuleCreate,
    CorrelationRuleUpdate,
    CorrelationRuleRead,
    CorrelationRequest,
    CorrelationExecutionResult,
    CorrelationGraphRead,
)
from app.correlation.repositories import CorrelationRepository
from app.correlation.services import CorrelationService
from app.correlation.router import router

__all__ = [
    "CorrelationRule",
    "get_default_correlation_rules",
    "CorrelationGraph",
    "GraphNode",
    "GraphEdge",
    "CorrelationNodeType",
    "CorrelationEdgeType",
    "CorrelationEngine",
    "AlertDeduplicationRecord",
    "CorrelatedIncidentCandidate",
    "CorrelationRuleCreate",
    "CorrelationRuleUpdate",
    "CorrelationRuleRead",
    "CorrelationRequest",
    "CorrelationExecutionResult",
    "CorrelationGraphRead",
    "CorrelationRepository",
    "CorrelationService",
    "router",
]
