"""
Unit Tests for Enterprise Correlation Engine.

Verifies deterministic rule matching, cryptographic alert fingerprint deduplication,
aggregated risk calculation formulas, entity relationship graph networks, and schema models.
"""

import uuid
import pytest

from app.models.alert import AlertSeverity
from app.models.incident import IncidentSeverity, IncidentPriority
from app.correlation.rules import (
    CorrelationRule,
    get_default_correlation_rules,
)
from app.correlation.engine import (
    CorrelationEngine,
)
from app.correlation.graph import (
    CorrelationGraph,
    GraphNode,
    GraphEdge,
    CorrelationNodeType,
    CorrelationEdgeType,
)
from app.correlation.schemas import (
    CorrelationRuleCreate,
    CorrelationRequest,
)


def test_default_correlation_rules():
    """Verify default correlation rules initialization."""
    rules = get_default_correlation_rules()
    assert len(rules) >= 4
    rule_names = [r.name for r in rules]
    assert "Same Host Multi-Alert Correlation" in rule_names
    assert "Network IP Address Attack Chain" in rule_names


def test_alert_fingerprinting_and_deduplication():
    """Verify SHA256 alert fingerprint calculation and deduplication."""
    alert1 = {
        "id": str(uuid.uuid4()),
        "source": "CrowdStrike",
        "title": "Suspicious Process Execution",
        "raw_payload": {"hostname": "WKSTN-SEC-01", "username": "admin"},
        "iocs": {"ip": "192.168.1.100"},
        "risk_score": 60.0,
    }
    alert2 = {
        "id": str(uuid.uuid4()),
        "source": "CrowdStrike",
        "title": "Suspicious Process Execution",
        "raw_payload": {"hostname": "WKSTN-SEC-01", "username": "admin"},
        "iocs": {"ip": "192.168.1.100"},
        "risk_score": 60.0,
    }
    alert3 = {
        "id": str(uuid.uuid4()),
        "source": "PaloAlto Firewall",
        "title": "Port Scan Detected",
        "raw_payload": {"hostname": "WKSTN-SEC-02", "username": "guest"},
        "iocs": {"ip": "10.0.0.5"},
        "risk_score": 40.0,
    }

    engine = CorrelationEngine()

    fp1 = engine.calculate_alert_fingerprint(alert1)
    fp2 = engine.calculate_alert_fingerprint(alert2)
    assert fp1 == fp2  # Identical fingerprints

    dedup = engine.deduplicate_alerts([alert1, alert2, alert3])
    assert len(dedup.unique_alerts) == 2
    assert dedup.duplicate_count == 1


def test_aggregated_risk_score_calculation():
    """Verify risk score aggregation formula calculation."""
    engine = CorrelationEngine()
    alerts = [{"risk_score": 60.0}, {"risk_score": 75.0}, {"risk_score": 50.0}]

    # Max risk = 75.0, Volume bonus = ln(4) * 10 ≈ 13.86
    aggregated = engine.calculate_aggregated_risk_score(alerts, rule_weight=1.0)
    assert aggregated > 75.0
    assert aggregated <= 100.0


def test_correlation_engine_rule_evaluation():
    """Verify deterministic rule matching and Candidate Incident generation."""
    rule = CorrelationRule(
        id="test-same-host",
        name="Same Host Rule",
        description="Matches alerts on same host",
        enabled=True,
        group_by_fields=["hostname"],
        min_alerts=2,
        weight=1.2,
    )
    engine = CorrelationEngine(rules=[rule])

    alert_a = {
        "id": str(uuid.uuid4()),
        "source": "EDR",
        "title": "LSASS Dump Attempt",
        "raw_payload": {"hostname": "FINANCE-PC"},
        "iocs": {"ip": "10.0.1.15"},
        "risk_score": 80.0,
    }
    alert_b = {
        "id": str(uuid.uuid4()),
        "source": "Sysmon",
        "title": "Mimikatz Process Executed",
        "raw_payload": {"hostname": "FINANCE-PC"},
        "iocs": {"ip": "10.0.1.15"},
        "risk_score": 85.0,
    }

    candidates = engine.evaluate([alert_a, alert_b])
    assert len(candidates) == 1
    candidate = candidates[0]
    assert "Same Host Rule" in candidate.title
    assert len(candidate.alert_ids) == 2
    assert candidate.risk_score >= 85.0


def test_correlation_graph_construction():
    """Verify relationship graph node and edge construction."""
    graph = CorrelationGraph()

    node1 = GraphNode(id="alert:1", label="Process Alert", node_type=CorrelationNodeType.ALERT)
    node2 = GraphNode(id="host:HOST-01", label="HOST-01", node_type=CorrelationNodeType.HOST)
    edge = GraphEdge(source_id="alert:1", target_id="host:HOST-01", relationship=CorrelationEdgeType.TRIGGERED_ON)

    graph.add_node(node1)
    graph.add_node(node2)
    graph.add_edge(edge)

    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    clusters = graph.find_connected_components()
    assert len(clusters) == 1
    assert "alert:1" in clusters[0]
    assert "host:HOST-01" in clusters[0]
