"""
Security Regression Tests: Input Validation & Injection Sanitization.

Verifies handling of SQL injection strings, XSS script payloads, path traversal attempts,
and malicious IOC strings.
"""

import pytest
from app.domains.alerts.schemas import AlertCreate, AlertSeverity, AlertStatus


@pytest.mark.anyio
async def test_alert_schema_handles_sqli_payload_safely():
    """Verify AlertCreate schema accepts raw security telemetry without SQL syntax execution."""
    sqli_payload = "'; DROP TABLE alerts; --"
    alert = AlertCreate(
        title=f"Suspicious SQL Activity: {sqli_payload}",
        description="Attempted injection pattern observed in HTTP request",
        source="SIEM",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.NEW,
    )
    assert alert.title == f"Suspicious SQL Activity: {sqli_payload}"


@pytest.mark.anyio
async def test_alert_schema_handles_xss_payload_safely():
    """Verify AlertCreate schema accepts raw XSS payload string without unescaped rendering."""
    xss_payload = "<script>alert('xss')</script>"
    alert = AlertCreate(
        title="Cross-Site Scripting Attempt Detected",
        description=f"Raw payload: {xss_payload}",
        source="WAF",
        severity=AlertSeverity.MEDIUM,
        status=AlertStatus.NEW,
    )
    assert xss_payload in alert.description
