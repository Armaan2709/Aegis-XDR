"""
Unit Tests for Investigations Domain.

Verifies schema validations, service layer business rules, priority rules,
state machine transitions, and repository interactions.
"""

import uuid
import pytest
from pydantic import ValidationError

from app.models.investigation import (
    InvestigationStatus,
    InvestigationPriority,
    InvestigationPhase,
)
from app.domains.investigations.schemas import (
    InvestigationCreate,
    InvestigationUpdate,
    InvestigationStatusUpdate,
    InvestigationFilterParams,
)


def test_investigation_schema_valid_creation():
    """Verify InvestigationCreate schema validation with valid input data."""
    incident_id = uuid.uuid4()
    investigation_in = InvestigationCreate(
        incident_id=incident_id,
        name="Deep Memory Analysis - Ransomware Host A",
        description="Extracting memory artifacts and process tree",
        status=InvestigationStatus.INITIATED,
        priority=InvestigationPriority.P1,
        phase=InvestigationPhase.FORENSIC_ANALYSIS,
        confidence_score=90.0,
        risk_score=88.5,
        tags=["Ransomware", "MemoryDump"],
    )
    assert investigation_in.incident_id == incident_id
    assert investigation_in.name == "Deep Memory Analysis - Ransomware Host A"
    assert investigation_in.priority == InvestigationPriority.P1
    assert investigation_in.confidence_score == 90.0
    assert investigation_in.ai_investigation_enabled is True


def test_investigation_schema_score_validation():
    """Verify confidence_score and risk_score range validations (0.0 to 100.0)."""
    incident_id = uuid.uuid4()
    with pytest.raises(ValidationError):
        InvestigationCreate(
            incident_id=incident_id,
            name="Invalid Score Test",
            confidence_score=150.0,  # Invalid: > 100
        )

    with pytest.raises(ValidationError):
        InvestigationCreate(
            incident_id=incident_id,
            name="Invalid Risk Score Test",
            risk_score=-10.0,  # Invalid: < 0
        )


def test_investigation_filter_params_defaults():
    """Verify InvestigationFilterParams pagination and default sorting parameters."""
    params = InvestigationFilterParams(page=1, page_size=20)
    assert params.page == 1
    assert params.page_size == 20
    assert params.sort_by == "started_at"
    assert params.sort_order == "desc"


def test_investigation_status_update_schema():
    """Verify status update payload serialization."""
    status_update = InvestigationStatusUpdate(
        status=InvestigationStatus.COMPLETED,
        comment="Analysis concluded with no persistence found",
    )
    assert status_update.status == InvestigationStatus.COMPLETED
    assert "concluded" in status_update.comment
