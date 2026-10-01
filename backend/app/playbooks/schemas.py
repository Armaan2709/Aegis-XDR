"""
SOAR Playbook Engine Domain Pydantic v2 Data Transfer Objects (DTOs).

Defines validation and serialization schemas for Playbooks, Steps, Executions,
Validation Results, and Query Filter parameters.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from app.playbooks.models import (
    PlaybookStatus,
    PlaybookCategory,
    PlaybookSeverity,
    ActionType,
    ExecutionStatus,
    StepExecutionStatus,
)


class PlaybookStepCreate(BaseModel):
    """Payload for creating a step within a Playbook."""
    name: str = Field(..., min_length=2, max_length=255, description="Unique name of step within playbook")
    description: Optional[str] = Field(default=None, description="Detailed step description")
    step_order: int = Field(..., ge=1, description="Sequential order execution index")
    action_type: ActionType = Field(..., description="Action type classification")
    configuration: Dict[str, Any] = Field(default_factory=dict, description="Parameters required by action executor")
    conditions: Dict[str, Any] = Field(default_factory=dict, description="Pre-condition rules for step execution")
    timeout_seconds: int = Field(default=60, ge=1, le=3600, description="Maximum execution duration seconds")
    retry_count: int = Field(default=0, ge=0, le=10, description="Number of retry attempts on step failure")
    continue_on_failure: bool = Field(default=False, description="Continue playbook if step fails")
    requires_approval: bool = Field(default=False, description="Requires manual approval before step execution")


class PlaybookStepUpdate(BaseModel):
    """Payload for updating a Playbook step."""
    name: Optional[str] = Field(default=None, min_length=2, max_length=255)
    description: Optional[str] = None
    step_order: Optional[int] = Field(default=None, ge=1)
    action_type: Optional[ActionType] = None
    configuration: Optional[Dict[str, Any]] = None
    conditions: Optional[Dict[str, Any]] = None
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=3600)
    retry_count: Optional[int] = Field(default=None, ge=0, le=10)
    continue_on_failure: Optional[bool] = None
    requires_approval: Optional[bool] = None


class PlaybookStepResponse(BaseModel):
    """Response representation of a Playbook Step."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    playbook_id: uuid.UUID
    name: str
    description: Optional[str] = None
    step_order: int
    action_type: ActionType
    configuration: Dict[str, Any]
    conditions: Dict[str, Any]
    timeout_seconds: int
    retry_count: int
    continue_on_failure: bool
    requires_approval: bool
    created_at: datetime
    updated_at: datetime


class PlaybookCreate(BaseModel):
    """Payload for defining a new SOAR Playbook."""
    name: str = Field(..., min_length=3, max_length=255, description="Playbook name")
    description: Optional[str] = Field(default=None, description="Detailed overview of playbook purpose")
    version: str = Field(default="1.0.0", description="Semantic version string")
    status: PlaybookStatus = Field(default=PlaybookStatus.DRAFT, description="Initial playbook lifecycle status")
    category: PlaybookCategory = Field(default=PlaybookCategory.INCIDENT_RESPONSE, description="Domain category")
    severity_trigger: PlaybookSeverity = Field(default=PlaybookSeverity.ALL, description="Target severity threshold")
    author: Optional[str] = Field(default=None, description="Playbook author name")
    is_active: bool = Field(default=True, description="Whether playbook is available for execution")
    requires_approval: bool = Field(default=False, description="Global approval requirement flag")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    playbook_metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary custom metadata")
    steps: List[PlaybookStepCreate] = Field(default_factory=list, description="Initial playbook steps")


class PlaybookUpdate(BaseModel):
    """Payload for modifying an existing Playbook."""
    name: Optional[str] = Field(default=None, min_length=3, max_length=255)
    description: Optional[str] = None
    version: Optional[str] = None
    status: Optional[PlaybookStatus] = None
    category: Optional[PlaybookCategory] = None
    severity_trigger: Optional[PlaybookSeverity] = None
    author: Optional[str] = None
    is_active: Optional[bool] = None
    requires_approval: Optional[bool] = None
    tags: Optional[List[str]] = None
    playbook_metadata: Optional[Dict[str, Any]] = None


class PlaybookResponse(BaseModel):
    """Response model representing a Playbook with its configured steps."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: Optional[str] = None
    version: str
    status: PlaybookStatus
    category: PlaybookCategory
    severity_trigger: PlaybookSeverity
    author: Optional[str] = None
    created_by_id: Optional[uuid.UUID] = None
    updated_by_id: Optional[uuid.UUID] = None
    is_active: bool
    requires_approval: bool
    tags: List[str]
    playbook_metadata: Dict[str, Any]
    steps: List[PlaybookStepResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class PlaybookFilterParams(BaseModel):
    """Query parameter filter options for Playbooks."""
    query: Optional[str] = Field(default=None, description="Search term across name, description, author")
    status: Optional[PlaybookStatus] = Field(default=None, description="Filter by status")
    category: Optional[PlaybookCategory] = Field(default=None, description="Filter by category")
    severity_trigger: Optional[PlaybookSeverity] = Field(default=None, description="Filter by severity trigger")
    is_active: Optional[bool] = Field(default=None, description="Filter active status")
    sort_by: str = Field(default="created_at", description="Sort field name")
    sort_order: str = Field(default="desc", description="Sort direction (asc, desc)")
    page: int = Field(default=1, ge=1, description="Page number")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")


class PlaybookExecutionCreate(BaseModel):
    """Payload to trigger execution of a Playbook."""
    playbook_id: uuid.UUID = Field(..., description="Target playbook UUID")
    incident_id: Optional[uuid.UUID] = Field(default=None, description="Optional associated incident UUID")
    case_id: Optional[uuid.UUID] = Field(default=None, description="Optional associated case UUID")
    investigation_id: Optional[uuid.UUID] = Field(default=None, description="Optional associated investigation UUID")
    trigger_source: str = Field(default="MANUAL", description="Source trigger identifier")
    initial_context: Dict[str, Any] = Field(default_factory=dict, description="Initial context payload")


class PlaybookStepExecutionResponse(BaseModel):
    """Response representing individual step execution results."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    execution_id: uuid.UUID
    step_id: uuid.UUID
    step_name: str
    action_type: ActionType
    status: StepExecutionStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    input_parameters: Dict[str, Any]
    output_data: Dict[str, Any]
    error_message: Optional[str] = None
    retries_attempted: int
    created_at: datetime
    updated_at: datetime


class PlaybookExecutionResponse(BaseModel):
    """Response model for Playbook Execution instance state."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    playbook_id: uuid.UUID
    incident_id: Optional[uuid.UUID] = None
    case_id: Optional[uuid.UUID] = None
    investigation_id: Optional[uuid.UUID] = None
    trigger_source: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: ExecutionStatus
    current_step_order: int
    execution_context: Dict[str, Any]
    results: Dict[str, Any]
    error_details: Optional[str] = None
    approval_id: Optional[uuid.UUID] = None
    executed_by_id: Optional[uuid.UUID] = None
    step_executions: List[PlaybookStepExecutionResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class PlaybookValidationResult(BaseModel):
    """Validation report returned by PlaybookValidator."""
    is_valid: bool
    playbook_id: Optional[uuid.UUID] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
