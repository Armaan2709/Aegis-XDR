"""
Pipeline Audit Logger.

Generates auditable lifecycle event records for all autonomous investigation pipeline events.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from app.ai.pipeline.schemas import PipelineContext, PipelineTimelineEntry


class PipelineAuditLogger:
    """Audit logging system recording structured lifecycle pipeline events."""

    def log_event(
        self,
        context: PipelineContext,
        event_type: str,
        description: str,
        actor: str = "AutonomousPipelineEngine",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PipelineTimelineEntry:
        """Record and append an auditable timeline entry to PipelineContext."""
        entry = PipelineTimelineEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            stage=context.current_stage,
            event_type=event_type,
            description=description,
            actor=actor,
            metadata=metadata or {},
        )
        context.timeline.append(entry)
        return entry
