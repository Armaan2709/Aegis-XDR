"""
Autonomous Investigation Pipeline Schemas and State Machine Enums.

Defines Pydantic v2 data models for Pipeline Context, Stage Enums, Stage Execution Results,
Timeline Event Entries, and Execution Request/Response DTOs.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict
from app.ai.orchestrator.state import InvestigationState


class PipelineStage(str, enum.Enum):
    """Deterministic investigation lifecycle stages."""
    CREATED = "CREATED"
    TRIAGING = "TRIAGING"
    CORRELATING = "CORRELATING"
    INVESTIGATION_STARTED = "INVESTIGATION_STARTED"
    THREAT_HUNTING = "THREAT_HUNTING"
    DFIR_ANALYSIS = "DFIR_ANALYSIS"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    DETECTION_GENERATION = "DETECTION_GENERATION"
    INCIDENT_SYNTHESIS = "INCIDENT_SYNTHESIS"
    AWAITING_REVIEW = "AWAITING_REVIEW"
    RESPONSE_APPROVED = "RESPONSE_APPROVED"
    RESPONSE_EXECUTING = "RESPONSE_EXECUTING"
    RESPONSE_COMPLETED = "RESPONSE_COMPLETED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class PipelineStatus(str, enum.Enum):
    """Pipeline execution state."""
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class StageStatus(str, enum.Enum):
    """Individual stage execution status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILURE = "FAILURE"
    SKIPPED = "SKIPPED"


class StageResult(BaseModel):
    """Output metadata recorded for a single pipeline stage execution."""
    stage: PipelineStage = Field(..., description="Stage enum identifier")
    status: StageStatus = Field(default=StageStatus.PENDING)
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = Field(default=None)
    execution_time_ms: float = Field(default=0.0)
    error: Optional[str] = Field(default=None)
    retry_count: int = Field(default=0)
    output: Dict[str, Any] = Field(default_factory=dict)


class PipelineTimelineEntry(BaseModel):
    """Auditable event entry for investigation timeline visualization."""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    stage: PipelineStage = Field(...)
    event_type: str = Field(...)
    description: str = Field(...)
    actor: str = Field(default="AutonomousPipelineEngine")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PipelineContext(BaseModel):
    """Strongly typed context passed across all autonomous investigation pipeline stages."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    pipeline_id: str = Field(default_factory=lambda: f"PIPE-{uuid.uuid4().hex[:8].upper()}")
    investigation_id: str = Field(...)
    incident_id: Optional[str] = Field(default=None)
    case_id: Optional[str] = Field(default=None)

    current_stage: PipelineStage = Field(default=PipelineStage.CREATED)
    previous_stage: Optional[PipelineStage] = Field(default=None)
    status: PipelineStatus = Field(default=PipelineStatus.RUNNING)

    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = Field(default=None)

    investigation_state: InvestigationState = Field(...)
    stage_results: Dict[str, StageResult] = Field(default_factory=dict)
    timeline: List[PipelineTimelineEntry] = Field(default_factory=list)

    errors: List[str] = Field(default_factory=list)
    retries: Dict[str, int] = Field(default_factory=dict)

    approval_required: bool = Field(default=False)
    approval_id: Optional[str] = Field(default=None)
    approval_status: str = Field(default="PENDING")
    approved_by: Optional[str] = Field(default=None)
    approved_at: Optional[str] = Field(default=None)

    response_plan: Optional[Dict[str, Any]] = Field(default=None)
    final_assessment: Optional[Dict[str, Any]] = Field(default=None)
    execution_metadata: Dict[str, Any] = Field(default_factory=dict)


class PipelineRunRequest(BaseModel):
    """Payload to initiate or resume an autonomous investigation pipeline run."""
    investigation_id: str = Field(...)
    incident_id: Optional[str] = Field(default=None)
    initial_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    auto_approve_routine: bool = Field(default=False)
