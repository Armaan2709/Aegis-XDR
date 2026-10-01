"""
Correlation Rules Definition & Prepackaged Engine Rules.

Defines deterministic rule specifications, matching logic, and enterprise rule templates
for aggregating security alerts into correlated incidents without non-deterministic AI.
"""

import uuid
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from app.models.alert import Alert, AlertSeverity


class CorrelationRule(BaseModel):
    """Specification for a deterministic security alert correlation rule."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Rule unique identifier")
    name: str = Field(..., max_length=255, description="Rule name")
    description: str = Field(..., description="Explanation of correlation intent")
    enabled: bool = Field(True, description="Rule active status")
    time_window_minutes: int = Field(60, ge=1, le=1440, description="Correlation time window in minutes")
    group_by_fields: List[str] = Field(
        default_factory=lambda: ["hostname"],
        description="Alert payload fields or IOC attributes to group by (e.g., hostname, source_ip, username)",
    )
    min_alerts: int = Field(2, ge=2, description="Minimum number of alerts to trigger correlation")
    min_severity: AlertSeverity = Field(AlertSeverity.MEDIUM, description="Minimum alert severity threshold")
    category_match: Optional[str] = Field(None, description="Optional category or tactic filter requirement")
    weight: float = Field(1.0, ge=0.1, le=10.0, description="Rule weighting factor for risk calculation")
    custom_criteria: Dict[str, Any] = Field(default_factory=dict, description="Custom criteria match key-values")

    model_config = ConfigDict(from_attributes=True)


def get_default_correlation_rules() -> List[CorrelationRule]:
    """Retrieve prepackaged enterprise correlation rules."""
    return [
        CorrelationRule(
            id="rule-same-host-multi-alert",
            name="Same Host Multi-Alert Correlation",
            description="Groups multiple security alerts originating from the same hostname within 60 minutes.",
            enabled=True,
            time_window_minutes=60,
            group_by_fields=["hostname"],
            min_alerts=2,
            min_severity=AlertSeverity.MEDIUM,
            weight=1.2,
        ),
        CorrelationRule(
            id="rule-same-ip-attack-chain",
            name="Network IP Address Attack Chain",
            description="Groups alerts sharing identical source or destination IP addresses within 30 minutes.",
            enabled=True,
            time_window_minutes=30,
            group_by_fields=["ip_address", "source_ip"],
            min_alerts=2,
            min_severity=AlertSeverity.MEDIUM,
            weight=1.5,
        ),
        CorrelationRule(
            id="rule-user-account-compromise",
            name="User Identity Compromise Surge",
            description="Groups suspicious activity alerts targeting or executed by the same user account.",
            enabled=True,
            time_window_minutes=120,
            group_by_fields=["username"],
            min_alerts=2,
            min_severity=AlertSeverity.HIGH,
            weight=1.4,
        ),
        CorrelationRule(
            id="rule-critical-severity-surge",
            name="Critical Severity Alert Cluster",
            description="Groups any combination of High/Critical severity alerts occurring within 15 minutes.",
            enabled=True,
            time_window_minutes=15,
            group_by_fields=[],
            min_alerts=2,
            min_severity=AlertSeverity.HIGH,
            weight=2.0,
        ),
    ]
