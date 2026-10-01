"""
Comprehensive Unit Tests for SOAR Playbook Engine (Sprint 10).

Verifies Enum validations, Pydantic v2 schema constraints, Playbook structure validation,
Deterministic Condition Engine evaluation, 12 safe mock action execution, ActionRegistry,
PlaybookRegistry, Approval integration bridge, Execution Tracker, and Async Playbook Engine / Service operations.
"""

import uuid
import pytest
from datetime import datetime, timezone
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.models.base import Base
from app.playbooks.models import (
    PlaybookStatus,
    PlaybookCategory,
    PlaybookSeverity,
    ActionType,
    ExecutionStatus,
    StepExecutionStatus,
    Playbook,
    PlaybookStep,
    PlaybookExecution,
    PlaybookStepExecution,
)
from app.playbooks.schemas import (
    PlaybookCreate,
    PlaybookUpdate,
    PlaybookStepCreate,
    PlaybookStepUpdate,
    PlaybookFilterParams,
    PlaybookExecutionCreate,
)
from app.playbooks.actions import (
    ActionRegistry,
    BlockIPAction,
    IsolateHostAction,
    DisableAccountAction,
    CollectEvidenceAction,
    QueryThreatIntelAction,
    CreateCaseAction,
    CreateIncidentAction,
    SendNotificationAction,
    AddTagAction,
    UpdateIncidentAction,
    RunDetectionAction,
    GenerateReportAction,
)
from app.playbooks.conditions import ConditionEvaluator
from app.playbooks.validators import PlaybookValidator
from app.playbooks.registry import PlaybookRegistry
from app.playbooks.executions import ExecutionTracker
from app.playbooks.services import PlaybookService
from app.case_management.services import CaseService
from app.case_management.schemas import CaseCreate, CaseApprovalDecision
from app.case_management.models import CaseStatus, CaseSeverity, CasePriority, ApprovalStatus
from app.core.exceptions import ValidationError as DomainValidationError, NotFoundError, ConflictError


# ==========================================
# 1. Enum & Schema Unit Tests
# ==========================================

def test_playbook_enums():
    """Verify Playbook enum values and representations."""
    assert PlaybookStatus.ACTIVE == "ACTIVE"
    assert PlaybookCategory.INCIDENT_RESPONSE == "INCIDENT_RESPONSE"
    assert PlaybookSeverity.CRITICAL == "CRITICAL"
    assert ActionType.BLOCK_IP == "BLOCK_IP"
    assert ExecutionStatus.WAITING_APPROVAL == "WAITING_APPROVAL"
    assert StepExecutionStatus.SKIPPED == "SKIPPED"


def test_playbook_create_schema_valid():
    """Verify valid PlaybookCreate schema initialization."""
    pb_in = PlaybookCreate(
        name="Ransomware Rapid Containment Playbook",
        description="Automated isolation and IP block workflow for ransomware alerts",
        version="1.1.0",
        category=PlaybookCategory.CONTAINMENT,
        severity_trigger=PlaybookSeverity.HIGH,
        tags=["Ransomware", "EDR"],
        steps=[
            PlaybookStepCreate(
                name="Block Command & Control IP",
                step_order=1,
                action_type=ActionType.BLOCK_IP,
                configuration={"ip_address": "198.51.100.45"},
            ),
            PlaybookStepCreate(
                name="Isolate Target Host",
                step_order=2,
                action_type=ActionType.ISOLATE_HOST,
                configuration={"hostname": "WKSTN-FIN-99"},
                requires_approval=True,
            ),
        ],
    )
    assert pb_in.name == "Ransomware Rapid Containment Playbook"
    assert len(pb_in.steps) == 2
    assert pb_in.steps[1].requires_approval is True


def test_playbook_create_schema_invalid_short_name():
    """Verify min_length constraint on PlaybookCreate name."""
    with pytest.raises(PydanticValidationError):
        PlaybookCreate(name="AB")


# ==========================================
# 2. Validation Engine Unit Tests
# ==========================================

def test_validator_duplicate_step_order():
    """Verify PlaybookValidator detects duplicate step ordering."""
    pb_in = PlaybookCreate(
        name="Invalid Order Playbook",
        steps=[
            PlaybookStepCreate(name="Step 1", step_order=1, action_type=ActionType.ADD_TAG),
            PlaybookStepCreate(name="Step 2", step_order=1, action_type=ActionType.SEND_NOTIFICATION),
        ],
    )
    res = PlaybookValidator.validate_create_schema(pb_in)
    assert res.is_valid is False
    assert any("Duplicate step order" in err for err in res.errors)


def test_validator_status_transitions():
    """Verify allowed and disallowed status transitions."""
    assert PlaybookValidator.validate_status_transition(PlaybookStatus.DRAFT, PlaybookStatus.ACTIVE) is True
    assert PlaybookValidator.validate_status_transition(PlaybookStatus.ACTIVE, PlaybookStatus.DISABLED) is True
    assert PlaybookValidator.validate_status_transition(PlaybookStatus.ARCHIVED, PlaybookStatus.ACTIVE) is False


# ==========================================
# 3. Deterministic Condition Engine Unit Tests
# ==========================================

def test_condition_evaluator_operators():
    """Verify operator evaluation logic."""
    context = {
        "severity": "CRITICAL",
        "risk_score": 85.0,
        "ioc_confidence": 90,
        "hostname": "SRV-DB-01",
        "tags": ["MALWARE", "APT29"],
    }

    # Equality & Greater Than
    assert ConditionEvaluator.evaluate({"field": "severity", "operator": ">=", "value": "HIGH"}, context) is True
    assert ConditionEvaluator.evaluate({"field": "risk_score", "operator": ">", "value": 80.0}, context) is True
    assert ConditionEvaluator.evaluate({"field": "risk_score", "operator": "<", "value": 50.0}, context) is False

    # IN & CONTAINS
    assert ConditionEvaluator.evaluate({"field": "hostname", "operator": "IN", "value": ["SRV-DB-01", "SRV-WEB-01"]}, context) is True
    assert ConditionEvaluator.evaluate({"field": "tags", "operator": "CONTAINS", "value": "APT29"}, context) is True

    # Logical Compound AND / OR
    compound_and = {
        "operator": "AND",
        "rules": [
            {"field": "severity", "operator": "==", "value": "CRITICAL"},
            {"field": "risk_score", "operator": ">=", "value": 70.0},
        ],
    }
    assert ConditionEvaluator.evaluate(compound_and, context) is True

    compound_or = {
        "operator": "OR",
        "rules": [
            {"field": "severity", "operator": "==", "value": "LOW"},
            {"field": "risk_score", "operator": ">=", "value": 80.0},
        ],
    }
    assert ConditionEvaluator.evaluate(compound_or, context) is True


# ==========================================
# 4. Safe Mock Action & Registry Unit Tests
# ==========================================

@pytest.mark.anyio
async def test_all_12_mock_actions_execute_safely():
    """Verify all 12 ActionTypes execute safely and return simulated outputs."""
    action_types = list(ActionType)
    assert len(action_types) == 12

    for act_type in action_types:
        executor = ActionRegistry.get_executor(act_type)
        res = await executor.execute(config={"target": "10.0.0.1"}, context={"incident_id": "INC-001"})
        assert res["status"] == "simulated"
        assert res["action"] == act_type.value
        assert "execution_mode" in res and res["execution_mode"] == "MOCK_SIMULATION"


# ==========================================
# 5. Playbook Registry Unit Tests
# ==========================================

def test_playbook_registry_in_memory():
    """Verify registry registration, lookup, search, enable, and disable operations."""
    registry = PlaybookRegistry()

    pb = Playbook(
        id=uuid.uuid4(),
        name="Phishing Enrichment Playbook",
        description="Automated IOC lookup for email phishing alerts",
        status=PlaybookStatus.ACTIVE,
        category=PlaybookCategory.ENRICHMENT,
        severity_trigger=PlaybookSeverity.ALL,
        is_active=True,
    )
    registry.register(pb)

    assert registry.lookup_by_id(pb.id) == pb
    assert registry.lookup_by_name("Phishing Enrichment Playbook") == pb
    assert len(registry.search("Phishing")) == 1
    assert len(registry.filter_by_category(PlaybookCategory.ENRICHMENT)) == 1
    assert len(registry.get_active_playbooks()) == 1

    registry.disable_playbook(pb.id)
    assert len(registry.get_active_playbooks()) == 0


# ==========================================
# 6. Integration & Async Service Unit Tests
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
async def test_playbook_service_full_execution_lifecycle(async_session: AsyncSession):
    """Test full Playbook creation, step addition, execution run, context propagation, approval pause, and completion."""
    playbook_service = PlaybookService(async_session)
    case_service = CaseService(async_session)

    # 1. Create Case for Approval Integration
    case_in = CaseCreate(
        title="Active Malware Breach Case",
        description="Outbreak requiring automated containment playbook",
        severity=CaseSeverity.HIGH,
        priority=CasePriority.P1,
    )
    case = await case_service.create_case(case_in)

    # 2. Create Playbook Definition with 3 steps (Step 2 requires approval)
    pb_in = PlaybookCreate(
        name="Automated Incident Response Workflow",
        description="Comprehensive containment and enrichment workflow",
        status=PlaybookStatus.ACTIVE,
        category=PlaybookCategory.INCIDENT_RESPONSE,
        severity_trigger=PlaybookSeverity.HIGH,
        is_active=True,
        steps=[
            PlaybookStepCreate(
                name="Query Threat Intel Reputation",
                step_order=1,
                action_type=ActionType.QUERY_THREAT_INTEL,
                configuration={"ioc": "198.51.100.50"},
            ),
            PlaybookStepCreate(
                name="Block Malicious IP Address",
                step_order=2,
                action_type=ActionType.BLOCK_IP,
                configuration={"ip_address": "198.51.100.50"},
                requires_approval=True,
            ),
            PlaybookStepCreate(
                name="Send SOC Alert Notification",
                step_order=3,
                action_type=ActionType.SEND_NOTIFICATION,
                configuration={"channel": "SOC-Alerts", "message": "Host containment completed"},
            ),
        ],
    )

    playbook = await playbook_service.create_playbook(pb_in)
    assert playbook.name == "Automated Incident Response Workflow"
    assert len(playbook.steps) == 3

    # 3. Trigger Playbook Execution (Execution should pause at Step 2 for approval)
    exec_in = PlaybookExecutionCreate(
        playbook_id=playbook.id,
        case_id=case.id,
        trigger_source="INCIDENT_EVENT",
        initial_context={"severity": "HIGH", "risk_score": 90.0},
    )

    execution = await playbook_service.execute_playbook(exec_in)
    assert execution.status == ExecutionStatus.WAITING_APPROVAL
    assert execution.approval_id is not None
    assert execution.current_step_order == 2

    # Verify step 1 was completed and step output propagated
    step_execs = execution.step_executions
    assert len(step_execs) == 1
    assert step_execs[0].status == StepExecutionStatus.COMPLETED
    assert step_execs[0].action_type == ActionType.QUERY_THREAT_INTEL

    # 4. Approve the pending CaseApproval in Case Management
    decision_in = CaseApprovalDecision(approved=True, decision_notes="Supervisory approval granted for IP block")
    await case_service.process_approval(case.id, execution.approval_id, decision_in)

    # 5. Resume Playbook Execution after approval
    resumed_execution = await playbook_service.resume_execution(execution.id)
    assert resumed_execution.status == ExecutionStatus.COMPLETED
    assert len(resumed_execution.step_executions) == 3

    # Verify steps 2 and 3 executed successfully
    assert resumed_execution.step_executions[1].action_type == ActionType.BLOCK_IP
    assert resumed_execution.step_executions[1].status == StepExecutionStatus.COMPLETED
    assert resumed_execution.step_executions[2].action_type == ActionType.SEND_NOTIFICATION
    assert resumed_execution.step_executions[2].status == StepExecutionStatus.COMPLETED

    # 6. Verify Execution History List
    executions, total = await playbook_service.list_executions(playbook_id=playbook.id)
    assert total == 1
    assert executions[0].status == ExecutionStatus.COMPLETED


@pytest.mark.anyio
async def test_playbook_approval_rejection_cancels_execution(async_session: AsyncSession):
    """Test that rejecting an approval request cancels the playbook execution."""
    playbook_service = PlaybookService(async_session)
    case_service = CaseService(async_session)

    case = await case_service.create_case(
        CaseCreate(title="Test Rejection Case", severity=CaseSeverity.HIGH)
    )

    playbook = await playbook_service.create_playbook(
        PlaybookCreate(
            name="Host Isolation Workflow",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStepCreate(
                    name="Isolate Host Endpoint",
                    step_order=1,
                    action_type=ActionType.ISOLATE_HOST,
                    configuration={"hostname": "WKSTN-01"},
                    requires_approval=True,
                )
            ],
        )
    )

    execution = await playbook_service.execute_playbook(
        PlaybookExecutionCreate(playbook_id=playbook.id, case_id=case.id)
    )
    assert execution.status == ExecutionStatus.WAITING_APPROVAL

    # Reject approval
    await case_service.process_approval(
        case.id, execution.approval_id, CaseApprovalDecision(approved=False, decision_notes="Rejected isolation")
    )

    resumed = await playbook_service.resume_execution(execution.id)
    assert resumed.status == ExecutionStatus.CANCELLED
    assert "rejected" in resumed.error_details.lower()


@pytest.mark.anyio
async def test_playbook_execution_cancellation(async_session: AsyncSession):
    """Test manual cancellation of a playbook execution."""
    playbook_service = PlaybookService(async_session)

    playbook = await playbook_service.create_playbook(
        PlaybookCreate(
            name="Long Running Evidence Collection",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStepCreate(
                    name="Dump RAM",
                    step_order=1,
                    action_type=ActionType.COLLECT_EVIDENCE,
                    requires_approval=True,
                )
            ],
        )
    )

    execution = await playbook_service.execute_playbook(
        PlaybookExecutionCreate(playbook_id=playbook.id)
    )
    assert execution.status == ExecutionStatus.WAITING_APPROVAL

    cancelled = await playbook_service.cancel_execution(execution.id, reason="User terminated run")
    assert cancelled.status == ExecutionStatus.CANCELLED
    assert cancelled.error_details == "User terminated run"
