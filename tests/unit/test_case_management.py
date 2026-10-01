"""
Comprehensive Unit Tests for Enterprise Case Management System (Sprint 9).

Verifies Enum validations, Pydantic v2 schema constraints, Comment threading,
Attachment metadata validations, Task state transitions, AutoApproval policies,
Activity audit logger, and full Async Repository/Service CRUD & operations.
"""

import uuid
import pytest
from datetime import datetime, timezone
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.models.base import Base
from app.case_management.models import (
    CaseStatus,
    CaseSeverity,
    CasePriority,
    AttachmentType,
    TaskStatus,
    TaskPriority,
    ApprovalStatus,
    AssignmentRole,
    ActivityType,
)
from app.case_management.schemas import (
    CaseCreate,
    CaseUpdate,
    CaseClose,
    CaseLinkUpdate,
    CaseFilterParams,
    CaseCommentCreate,
    CaseCommentUpdate,
    CaseAttachmentCreate,
    CaseTaskCreate,
    CaseTaskUpdate,
    CaseApprovalCreate,
    CaseApprovalDecision,
    CaseAssignmentCreate,
)
from app.case_management.comments import CommentManager
from app.case_management.attachments import AttachmentValidator
from app.case_management.tasks import TaskStateEngine
from app.case_management.approvals import AutoApprovalPolicy
from app.case_management.activity import ActivityLogger
from app.case_management.services import CaseService
from app.core.exceptions import ValidationError as DomainValidationError, NotFoundError, ConflictError


# ==========================================
# 1. Enum & Schema Unit Tests
# ==========================================

def test_case_management_enums():
    """Verify enum value assignments and representation."""
    assert CaseStatus.OPEN == "OPEN"
    assert CaseSeverity.CRITICAL == "CRITICAL"
    assert CasePriority.P1 == "P1"
    assert AttachmentType.PCAP == "PCAP"
    assert TaskStatus.IN_PROGRESS == "IN_PROGRESS"
    assert TaskPriority.URGENT == "URGENT"
    assert ApprovalStatus.AUTO_APPROVED == "AUTO_APPROVED"
    assert AssignmentRole.PRIMARY_LEAD == "PRIMARY_LEAD"
    assert ActivityType.CASE_CREATED == "CASE_CREATED"


def test_case_create_schema_valid():
    """Verify valid CaseCreate schema initialization."""
    case_in = CaseCreate(
        title="APT29 Spearphishing Incident Workspace",
        description="Investigation into credential harvesting campaign",
        severity=CaseSeverity.HIGH,
        priority=CasePriority.P2,
        status=CaseStatus.OPEN,
        tags=["APT29", "Phishing"],
        related_incidents=[str(uuid.uuid4())],
    )
    assert case_in.title == "APT29 Spearphishing Incident Workspace"
    assert case_in.severity == CaseSeverity.HIGH
    assert len(case_in.tags) == 2
    assert len(case_in.related_incidents) == 1


def test_case_create_schema_invalid_short_title():
    """Verify min_length constraint on CaseCreate title."""
    with pytest.raises(ValidationError):
        CaseCreate(title="AB")


def test_case_filter_params_defaults():
    """Verify CaseFilterParams defaults."""
    params = CaseFilterParams()
    assert params.page == 1
    assert params.page_size == 20
    assert params.sort_by == "created_at"
    assert params.sort_order == "desc"


# ==========================================
# 2. Comment Logic Unit Tests
# ==========================================

def test_comment_mention_extraction():
    """Verify @mention handles extraction from markdown."""
    markdown = "Assigning to @analyst_jane and @john-doe for review on @case-123"
    mentions = CommentManager.extract_mentions(markdown)
    assert "analyst_jane" in mentions
    assert "john-doe" in mentions
    assert "case-123" in mentions


def test_comment_schema_validation():
    """Verify CaseCommentCreate schema validation."""
    comment_in = CaseCommentCreate(
        content="Investigated memory dump artifact, found injected DLL",
        mentions=["analyst_jane"],
    )
    assert "memory dump" in comment_in.content
    assert comment_in.mentions == ["analyst_jane"]


# ==========================================
# 3. Attachment Metadata Validation Unit Tests
# ==========================================

def test_attachment_metadata_validation_valid():
    """Verify valid attachment metadata."""
    valid_sha256 = "a" * 64
    AttachmentValidator.validate_metadata(
        filename="memory_dump.raw",
        file_size_bytes=1048576,
        file_hash=valid_sha256,
        attachment_type=AttachmentType.MEMORY_DUMP,
    )


def test_attachment_metadata_validation_invalid_hash():
    """Verify SHA-256 hash length enforcement."""
    with pytest.raises(DomainValidationError):
        AttachmentValidator.validate_metadata(
            filename="bad_hash.pcap",
            file_size_bytes=500,
            file_hash="invalid_hash_string",
            attachment_type=AttachmentType.PCAP,
        )


def test_attachment_metadata_validation_negative_size():
    """Verify negative file size restriction."""
    valid_sha256 = "b" * 64
    with pytest.raises(DomainValidationError):
        AttachmentValidator.validate_metadata(
            filename="negative.log",
            file_size_bytes=-100,
            file_hash=valid_sha256,
            attachment_type=AttachmentType.LOG_FILE,
        )


# ==========================================
# 4. Task State Machine Unit Tests
# ==========================================

def test_task_state_transitions_valid():
    """Verify allowed task status transitions."""
    TaskStateEngine.validate_transition(TaskStatus.PENDING, TaskStatus.IN_PROGRESS)
    TaskStateEngine.validate_transition(TaskStatus.IN_PROGRESS, TaskStatus.COMPLETED)
    TaskStateEngine.validate_transition(TaskStatus.COMPLETED, TaskStatus.IN_PROGRESS)


def test_task_state_transitions_invalid():
    """Verify invalid task status transition exceptions."""
    with pytest.raises(DomainValidationError):
        TaskStateEngine.validate_transition(TaskStatus.COMPLETED, TaskStatus.CANCELLED)


# ==========================================
# 5. Governance Auto-Approval Policy Unit Tests
# ==========================================

def test_auto_approval_policy_low_severity():
    """Verify low severity auto-approval policy evaluation."""
    approved, reason = AutoApprovalPolicy.evaluate_auto_approval(
        title="Routine log archive approval",
        description="Standard retention policy",
        case_severity=CaseSeverity.LOW,
    )
    assert approved is True
    assert "LOW severity" in reason


def test_auto_approval_policy_keyword():
    """Verify routine triage keyword auto-approval policy."""
    approved, reason = AutoApprovalPolicy.evaluate_auto_approval(
        title="Standard triage request",
        description="Standard triage routine analysis",
        case_severity=CaseSeverity.MEDIUM,
    )
    assert approved is True
    assert "standard triage" in reason.lower()


def test_auto_approval_policy_manual_required():
    """Verify high severity requiring manual approval."""
    approved, reason = AutoApprovalPolicy.evaluate_auto_approval(
        title="Host Isolation Override Request",
        description="Domain controller isolation exception",
        case_severity=CaseSeverity.CRITICAL,
    )
    assert approved is False
    assert "Manual supervisor approval required" in reason


# ==========================================
# 6. Activity Logger Unit Tests
# ==========================================

def test_activity_logger_builder():
    """Verify ActivityLogger entry construction."""
    summary, details = ActivityLogger.build_entry(
        ActivityType.CASE_CREATED, "CASE-2026-0001", "Created initial case workspace"
    )
    assert summary == "Created initial case workspace"
    assert details["case_number"] == "CASE-2026-0001"


# ==========================================
# 7. Integration & Async Service Unit Tests
# ==========================================

@pytest.fixture
def anyio_backend():
    """Specify asyncio backend for anyio test execution."""
    return "asyncio"


@pytest.fixture
async def async_session():

    """Create in-memory SQLite async database session fixture for isolated testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.mark.anyio
async def test_case_service_full_lifecycle(async_session: AsyncSession):
    """Test Case creation, updating, linking, tasking, approvals, comments, and closing."""
    service = CaseService(async_session)

    # 1. Create Case
    case_in = CaseCreate(
        title="FIN7 Malware Outbreak Case",
        description="POS malware outbreak across retail endpoints",
        severity=CaseSeverity.HIGH,
        priority=CasePriority.P1,
    )
    case = await service.create_case(case_in)
    assert case.case_number.startswith("CASE-")
    assert case.title == "FIN7 Malware Outbreak Case"
    assert case.status == CaseStatus.OPEN

    # 2. Update Case
    update_in = CaseUpdate(description="Updated description - multi-node outbreak confirmed")
    updated_case = await service.update_case(case.id, update_in)
    assert "multi-node" in updated_case.description

    # 3. Assign Analyst
    assign_in = CaseAssignmentCreate(user_id=uuid.uuid4(), role=AssignmentRole.PRIMARY_LEAD)
    assignment = await service.assign_analyst(case.id, assign_in)
    assert assignment.role == AssignmentRole.PRIMARY_LEAD

    # 4. Link Domain Entities
    link_in = CaseLinkUpdate(entity_type="mitre", entity_id="T1059.001")
    linked_case = await service.link_entity(case.id, link_in)
    assert "T1059.001" in linked_case.related_mitre_techniques

    # 5. Add Comment
    comment_in = CaseCommentCreate(content="Analyzed memory dump, matched FIN7 signatures @lead-analyst")
    comment = await service.add_comment(case.id, comment_in)
    assert comment.content == comment_in.content
    assert "lead-analyst" in comment.mentions

    # 6. Add Attachment Metadata
    attachment_in = CaseAttachmentCreate(
        attachment_type=AttachmentType.PCAP,
        filename="network_capture.pcap",
        file_size_bytes=5242880,
        file_hash="c" * 64,
        description="Full packet capture of C2 traffic",
    )
    attachment = await service.add_attachment_metadata(case.id, attachment_in)
    assert attachment.filename == "network_capture.pcap"

    # 7. Create & Update Task
    task_in = CaseTaskCreate(title="Isolate infected VLAN 20")
    task = await service.create_task(case.id, task_in)
    assert task.status == TaskStatus.PENDING

    task_update = CaseTaskUpdate(status=TaskStatus.COMPLETED)
    updated_task = await service.update_task_status(case.id, task.id, task_update)
    assert updated_task.status == TaskStatus.COMPLETED
    assert updated_task.completed_at is not None

    # 8. Request & Approve Approval
    approval_in = CaseApprovalCreate(title="Approve firewall block rule for C2 IP", is_auto_approval=False)
    approval = await service.request_approval(case.id, approval_in)
    assert approval.status == ApprovalStatus.PENDING

    decision_in = CaseApprovalDecision(approved=True, decision_notes="Block rule verified safe")
    decided_approval = await service.process_approval(case.id, approval.id, decision_in)
    assert decided_approval.status == ApprovalStatus.APPROVED

    # 9. Verify Activity Log
    activities = await service.get_case_activity(case.id)
    assert len(activities) >= 7

    # 10. Close Case
    close_in = CaseClose(closure_notes="Threat contained and C2 blocked globally.")
    closed_case = await service.close_case(case.id, close_in)
    assert closed_case.status == CaseStatus.CLOSED

    # 11. Verify Case Statistics
    stats = await service.get_case_statistics()
    assert stats.total_cases >= 1
    assert stats.closed_cases >= 1
