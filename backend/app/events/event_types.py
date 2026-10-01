"""
Platform Event Types Enumeration.

Defines all reactive events published across AegisAI XDR domains.
"""

from enum import Enum


class EventType(str, Enum):
    """Platform system event types."""

    ALERT_CREATED = "AlertCreated"
    INCIDENT_CREATED = "IncidentCreated"
    INVESTIGATION_STARTED = "InvestigationStarted"
    THREAT_INTEL_COMPLETED = "ThreatIntelCompleted"
    PLAYBOOK_EXECUTED = "PlaybookExecuted"
    INCIDENT_CLOSED = "IncidentClosed"
