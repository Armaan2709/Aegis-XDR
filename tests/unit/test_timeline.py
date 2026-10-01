"""
Unit Tests for Timeline Domain.

Verifies schema validations, confidence score boundaries, event types, tactical categories,
filter parameter defaults, and update payloads for chronological security events.
"""

import uuid
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.models.timeline import (
    TimelineEventType,
    TimelineEventCategory,
    TimelineEventSeverity,
)
from app.domains.timeline.schemas import (
    TimelineEventCreate,
    TimelineEventUpdate,
    TimelineFilterParams,
)


def test_timeline_event_schema_valid_creation():
    """Verify TimelineEventCreate schema validation with valid fields."""
    investigation_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    event_in = TimelineEventCreate(
        investigation_id=investigation_id,
        incident_id=incident_id,
        evidence_id=evidence_id,
        timestamp=now_utc,
        event_type=TimelineEventType.PROCESS_CREATION,
        event_category=TimelineEventCategory.EXECUTION,
        source="EDR Agent",
        hostname="WKSTN-SEC-01",
        username="domain_admin",
        process_name="powershell.exe",
        process_id=4102,
        parent_process_id=1024,
        file_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        description="PowerShell executed with obfuscated base64 payload",
        severity=TimelineEventSeverity.HIGH,
        confidence_score=95.0,
        tags=["PowerShell", "Obfuscation", "Execution"],
    )

    assert event_in.investigation_id == investigation_id
    assert event_in.incident_id == incident_id
    assert event_in.evidence_id == evidence_id
    assert event_in.event_type == TimelineEventType.PROCESS_CREATION
    assert event_in.event_category == TimelineEventCategory.EXECUTION
    assert event_in.severity == TimelineEventSeverity.HIGH
    assert event_in.confidence_score == 95.0
    assert event_in.process_id == 4102


def test_timeline_event_schema_confidence_validation():
    """Verify confidence_score range validation (0.0 to 100.0)."""
    investigation_id = uuid.uuid4()
    incident_id = uuid.uuid4()

    with pytest.raises(ValidationError):
        TimelineEventCreate(
            investigation_id=investigation_id,
            incident_id=incident_id,
            event_type=TimelineEventType.COMMAND_EXECUTION,
            confidence_score=125.0,  # Invalid: > 100
        )

    with pytest.raises(ValidationError):
        TimelineEventCreate(
            investigation_id=investigation_id,
            incident_id=incident_id,
            event_type=TimelineEventType.COMMAND_EXECUTION,
            confidence_score=-5.0,  # Invalid: < 0
        )


def test_timeline_filter_params_defaults():
    """Verify TimelineFilterParams default sorting and pagination parameters."""
    params = TimelineFilterParams(page=1, page_size=20)
    assert params.page == 1
    assert params.page_size == 20
    assert params.sort_by == "timestamp"
    assert params.sort_order == "asc"


def test_timeline_event_update_schema():
    """Verify timeline update payload serialization."""
    update_in = TimelineEventUpdate(
        description="Updated event analysis details",
        severity=TimelineEventSeverity.CRITICAL,
        confidence_score=99.0,
    )
    assert update_in.description == "Updated event analysis details"
    assert update_in.severity == TimelineEventSeverity.CRITICAL
    assert update_in.confidence_score == 99.0
