"""
Unit Tests for AegisAI XDR Observability & Metrics Exporter.
"""

import pytest
from app.observability.tracing import start_trace_span, sanitize_attributes
from app.observability.exporters import generate_prometheus_metrics


def test_tracing_sanitization():
    raw = {
        "user": "analyst@aegis.ai",
        "password": "SecretPassword123!",
        "api_key": "sk-12345",
        "nested": {"token": "jwt_token_abc"},
    }
    sanitized = sanitize_attributes(raw)
    assert sanitized["user"] == "analyst@aegis.ai"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["token"] == "[REDACTED]"


def test_trace_span_context():
    with start_trace_span("test_operation", attributes={"user": "test_user"}) as span:
        assert span.name == "test_operation"
        assert span.status == "OK"
    assert span.duration_ms is not None
    assert span.duration_ms >= 0


def test_prometheus_exporter_formatting():
    data = {
        "platform": {"total_alerts": 42, "open_incidents": 5, "active_investigations": 2, "total_iocs": 150, "malicious_iocs": 20},
        "soc": {"mttd_seconds": 30.0, "mttr_seconds": 120.0},
        "pipeline": {"total_executions": 10, "failed_executions": 0},
        "agents": {
            "total_agent_runs": 60,
            "overall_success_rate": 100.0,
            "agents": [{"agent_name": "ThreatHunterAgent", "execution_count": 10, "success_rate": 100.0}],
        },
    }

    metrics_text = generate_prometheus_metrics(data)
    assert "aegis_alerts_total 42" in metrics_text
    assert "aegis_incidents_total 5" in metrics_text
    assert "aegis_mttd_seconds 30.0" in metrics_text
    assert 'aegis_agent_runs_total{agent="threathunteragent"} 10' in metrics_text
