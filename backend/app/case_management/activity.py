"""
Case Management Activity Audit Submodule.

Provides formatted logging helpers for generating append-only auditable
timeline event entries across all case lifecycle operations.
"""

from typing import Dict, Any, Optional, Tuple
from app.case_management.models import ActivityType


class ActivityLogger:
    """Helper factory for structuring case activity logs."""

    @staticmethod
    def build_entry(
        activity_type: ActivityType,
        case_number: str,
        summary: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """Construct normalized activity summary and detail dictionary."""
        detail_payload = details or {}
        detail_payload["case_number"] = case_number

        default_summaries = {
            ActivityType.CASE_CREATED: f"Case {case_number} created",
            ActivityType.CASE_UPDATED: f"Case {case_number} metadata updated",
            ActivityType.INCIDENT_LINKED: f"Incident linked to case {case_number}",
            ActivityType.INVESTIGATION_LINKED: f"Investigation linked to case {case_number}",
            ActivityType.EVIDENCE_LINKED: f"Evidence artifact linked to case {case_number}",
            ActivityType.TIMELINE_LINKED: f"Timeline event linked to case {case_number}",
            ActivityType.MITRE_LINKED: f"MITRE ATT&CK technique linked to case {case_number}",
            ActivityType.THREAT_INDICATOR_LINKED: f"Threat Indicator IOC linked to case {case_number}",
            ActivityType.COMMENT_ADDED: f"Comment posted on case {case_number}",
            ActivityType.COMMENT_EDITED: f"Comment edited on case {case_number}",
            ActivityType.COMMENT_DELETED: f"Comment deleted on case {case_number}",
            ActivityType.TASK_CREATED: f"Task created in case {case_number}",
            ActivityType.TASK_UPDATED: f"Task status updated in case {case_number}",
            ActivityType.APPROVAL_REQUESTED: f"Governance approval requested for case {case_number}",
            ActivityType.APPROVAL_DECIDED: f"Governance approval decision recorded for case {case_number}",
            ActivityType.ANALYST_ASSIGNED: f"Analyst assigned to case {case_number}",
            ActivityType.ANALYST_REMOVED: f"Analyst assignment removed from case {case_number}",
            ActivityType.CASE_CLOSED: f"Case {case_number} closed",
        }

        final_summary = summary or default_summaries.get(activity_type, f"Activity recorded on {case_number}")
        return final_summary, detail_payload

