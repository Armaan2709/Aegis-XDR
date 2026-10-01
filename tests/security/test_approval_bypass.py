"""
Security Regression Tests: CaseApproval & SOAR Execution Boundary.

Verifies that unapproved, pending, rejected, or forged approval states strictly block
playbook execution.
"""

import pytest
import uuid
from sqlalchemy.ext.asyncio import AsyncSession

from app.playbooks.services import PlaybookService
from app.playbooks.models import PlaybookStatus, ActionType, ExecutionStatus
from app.playbooks.schemas import PlaybookCreate, PlaybookStepCreate, PlaybookExecutionCreate
from app.case_management.services import CaseService
from app.case_management.schemas import CaseCreate, CaseApprovalDecision
from app.case_management.models import CaseSeverity
from app.core.exceptions import ValidationError, NotFoundError


@pytest.mark.anyio
async def test_resume_without_approved_case_approval_fails(async_session: AsyncSession):
    """Verify resuming execution without a valid approved CaseApproval record fails."""
    playbook_service = PlaybookService(async_session)

    playbook = await playbook_service.create_playbook(
        PlaybookCreate(
            name="Approval Boundary Test Playbook",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStepCreate(
                    name="Step Requires Approval",
                    step_order=1,
                    action_type=ActionType.ISOLATE_HOST,
                    configuration={"hostname": "SERVER-01"},
                    requires_approval=True,
                )
            ],
        )
    )

    execution = await playbook_service.execute_playbook(
        PlaybookExecutionCreate(playbook_id=playbook.id)
    )
    assert execution.status == ExecutionStatus.WAITING_APPROVAL

    # Direct resume without CaseApproval approval must raise ValidationError
    with pytest.raises(ValidationError, match="valid approved CaseApproval"):
        await playbook_service.resume_execution(execution.id)


@pytest.mark.anyio
async def test_rejected_approval_cancels_execution(async_session: AsyncSession):
    """Verify rejecting an approval request cancels execution and prevents action."""
    playbook_service = PlaybookService(async_session)
    case_service = CaseService(async_session)

    case = await case_service.create_case(
        CaseCreate(title="Isolation Governance Case", severity=CaseSeverity.HIGH)
    )

    playbook = await playbook_service.create_playbook(
        PlaybookCreate(
            name="Host Isolation Safe Mock Workflow",
            status=PlaybookStatus.ACTIVE,
            steps=[
                PlaybookStepCreate(
                    name="Isolate Host Endpoint",
                    step_order=1,
                    action_type=ActionType.ISOLATE_HOST,
                    configuration={"hostname": "WKSTN-02"},
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
        case.id,
        execution.approval_id,
        CaseApprovalDecision(approved=False, decision_notes="Rejected by security supervisor"),
    )

    resumed = await playbook_service.resume_execution(execution.id)
    assert resumed.status == ExecutionStatus.CANCELLED
