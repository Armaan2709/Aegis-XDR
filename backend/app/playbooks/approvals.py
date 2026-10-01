"""
SOAR Playbook Engine Case Approval Integration Bridge.

Integrates Playbook step approval requirements with the existing Case Management
CaseApproval architecture. Reuses CaseApproval entities without creating a duplicate approval system.
"""

import uuid
from typing import Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.case_management.models import CaseApproval, ApprovalStatus
from app.case_management.schemas import CaseApprovalCreate
from app.case_management.services import CaseService
from app.core.exceptions import NotFoundError, ValidationError


class PlaybookApprovalBridge:
    """Bridge for interfacing SOAR playbook executions with Case Management approvals."""

    @staticmethod
    async def request_step_approval(
        session: AsyncSession,
        case_id: uuid.UUID,
        step_name: str,
        playbook_name: str,
        actor_id: Optional[uuid.UUID] = None,
    ) -> CaseApproval:
        """Submit approval request through the authoritative Case Management approval system."""
        case_service = CaseService(session)
        approval_in = CaseApprovalCreate(
            title=f"SOAR Approval Required: {playbook_name} - Step '{step_name}'",
            description=(
                f"Automated security playbook '{playbook_name}' execution paused at step '{step_name}'. "
                f"Supervisor approval is required before executing this automated response action."
            ),
            is_auto_approval=False,
        )
        approval = await case_service.request_approval(case_id, approval_in, actor_id=actor_id)
        return approval

    @staticmethod
    async def check_approval_status(
        session: AsyncSession, approval_id: uuid.UUID
    ) -> Tuple[ApprovalStatus, Optional[str]]:
        """Check the status of an existing CaseApproval entity."""
        stmt = select(CaseApproval).where(CaseApproval.id == approval_id)
        res = await session.execute(stmt)
        approval = res.scalar_one_or_none()

        if not approval:
            raise NotFoundError(f"CaseApproval record with ID '{approval_id}' not found")

        return approval.status, approval.decision_notes
