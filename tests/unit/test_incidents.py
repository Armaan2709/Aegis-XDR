"""
Unit Tests for Incidents Domain.

Verifies schema validations, risk score boundaries, severity enums, filter parameter defaults,
and status update serialization for security incidents.
"""

import uuid
import pytest
from pydantic import ValidationError

from app.models.incident import (
    IncidentSeverity,
    IncidentPriority,
    IncidentStatus,
    IncidentCategory,
)
from app.domains.incidents.schemas import (
    IncidentCreate,
    IncidentUpdate,
    IncidentStatusUpdate,
    IncidentFilterParams,
)


def test_incident_schema_valid_creation():
    """Verify IncidentCreate schema validation with valid input data."""
    incident_in = IncidentCreate(
        title="Ransomware Outbreak - Workstation 102",
        description="Multiple high-severity alerts detected on host",
        severity=IncidentSeverity.CRITICAL,
        priority=IncidentPriority.P1,
        status=IncidentStatus.OPEN,
        category=IncidentCategory.MALWARE,
        source="Alert Correlation",
        risk_score=92.5,
        confidence_score=95.0,
        tags=["Ransomware", "Critical"],
    )

    assert incident_in.title == "Ransomware Outbreak - Workstation 102"
    assert incident_in.severity == IncidentSeverity.CRITICAL
    assert incident_in.priority == IncidentPriority.P1
    assert incident_in.risk_score == 92.5
    assert incident_in.confidence_score == 95.0


def test_incident_schema_score_validation():
    """Verify risk_score and confidence_score validation range (0.0 to 100.0)."""
    with pytest.raises(ValidationError):
        IncidentCreate(
            title="Invalid Risk Score Test",
            risk_score=150.0,  # Invalid: > 100
        )

    with pytest.raises(ValidationError):
        IncidentCreate(
            title="Invalid Confidence Score Test",
            confidence_score=-10.0,  # Invalid: < 0
        )


def test_incident_filter_params_defaults():
    """Verify IncidentFilterParams pagination and default sorting parameters."""
    params = IncidentFilterParams(page=1, page_size=20)
    assert params.page == 1
    assert params.page_size == 20
    assert params.sort_by == "created_at"
    assert params.sort_order == "desc"


def test_incident_status_update_schema():
    """Verify status update payload serialization."""
    status_update = IncidentStatusUpdate(
        status=IncidentStatus.CLOSED,
        comment="Threat isolated and host remediated",
    )
    assert status_update.status == IncidentStatus.CLOSED
    assert "isolated" in status_update.comment
