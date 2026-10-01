"""
SOAR Playbook Engine Main Orchestrator Engine.

Handles playbook loading, structure validation, context loading, condition evaluation,
sequential step execution, retries, approval pauses, approval resumption, failure handling,
and execution state persistence.
"""

import uuid
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession

from app.playbooks.models import (
    Playbook,
    PlaybookStep,
    PlaybookExecution,
    PlaybookStepExecution,
    ExecutionStatus,
    StepExecutionStatus,
    PlaybookStatus,
)
from app.playbooks.repositories import (
    PlaybookRepository,
    PlaybookStepRepository,
    PlaybookExecutionRepository,
    PlaybookStepExecutionRepository,
)
from app.playbooks.actions import ActionRegistry
from app.playbooks.conditions import ConditionEvaluator
from app.playbooks.validators import PlaybookValidator
from app.playbooks.executions import ExecutionTracker
from app.playbooks.approvals import PlaybookApprovalBridge
from app.case_management.models import ApprovalStatus
from app.core.exceptions import NotFoundError, ValidationError, ConflictError


class PlaybookEngine:
    """Core execution engine for orchestrating SOAR Playbooks."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.playbook_repo = PlaybookRepository(session)
        self.step_repo = PlaybookStepRepository(session)
        self.execution_repo = PlaybookExecutionRepository(session)
        self.step_exec_repo = PlaybookStepExecutionRepository(session)

    async def execute_playbook(
        self,
        playbook_id: uuid.UUID,
        initial_context: Optional[Dict[str, Any]] = None,
        trigger_source: str = "MANUAL",
        incident_id: Optional[uuid.UUID] = None,
        case_id: Optional[uuid.UUID] = None,
        investigation_id: Optional[uuid.UUID] = None,
        executed_by_id: Optional[uuid.UUID] = None,
    ) -> PlaybookExecution:
        """Load, validate, and execute a playbook sequentially."""
        playbook = await self.playbook_repo.get_by_id(playbook_id)
        if not playbook:
            raise NotFoundError(f"Playbook '{playbook_id}' not found")

        if not playbook.is_active or playbook.status not in (PlaybookStatus.ACTIVE, PlaybookStatus.TESTING):
            raise ConflictError(f"Playbook '{playbook.name}' is inactive or in state '{playbook.status.value}'")

        # Validate structure
        val_result = PlaybookValidator.validate_playbook(playbook)
        if not val_result.is_valid:
            raise ValidationError(f"Playbook validation failed: {'; '.join(val_result.errors)}")

        # Create execution run
        context_payload = initial_context or {}
        context_payload["playbook_id"] = str(playbook.id)
        context_payload["playbook_name"] = playbook.name
        if incident_id:
            context_payload["incident_id"] = str(incident_id)
        if case_id:
            context_payload["case_id"] = str(case_id)

        execution = await self.execution_repo.create(
            playbook_id=playbook.id,
            trigger_source=trigger_source,
            initial_context=context_payload,
            incident_id=incident_id,
            case_id=case_id,
            investigation_id=investigation_id,
            executed_by_id=executed_by_id,
        )

        await self.execution_repo.update(execution, {"status": ExecutionStatus.RUNNING})
        tracker = ExecutionTracker(execution)

        # Run steps starting at current_step_order
        steps = sorted(playbook.steps, key=lambda s: s.step_order)
        return await self._run_steps(playbook, steps, tracker, execution)

    async def _run_steps(
        self,
        playbook: Playbook,
        steps: list[PlaybookStep],
        tracker: ExecutionTracker,
        execution: PlaybookExecution,
    ) -> PlaybookExecution:
        """Internal sequential step execution loop."""
        for step in steps:
            if step.step_order < tracker.execution.current_step_order:
                continue  # Already executed in prior run

            # 1. Condition Evaluation
            should_run = ConditionEvaluator.evaluate(step.conditions, tracker.context)
            if not should_run:
                step_exec = await self.step_exec_repo.create(
                    execution_id=execution.id,
                    step_id=step.id,
                    step_name=step.name,
                    action_type=step.action_type,
                    input_parameters=step.configuration,
                )
                await self.step_exec_repo.update(
                    step_exec,
                    {
                        "status": StepExecutionStatus.SKIPPED,
                        "completed_at": datetime.now(timezone.utc),
                        "output_data": {"message": "Step skipped due to condition evaluation"},
                    },
                )
                tracker.execution.current_step_order = step.step_order + 1
                await self.execution_repo.update(
                    tracker.execution, {"current_step_order": tracker.execution.current_step_order}
                )
                continue

            # 2. Check Approval Requirements
            step_requires_appr = step.requires_approval or (playbook.requires_approval and step.step_order == 1)
            if step_requires_appr and tracker.execution.status != ExecutionStatus.RUNNING:
                # If already approved, proceed. Otherwise request approval if not yet requested.
                pass

            if step_requires_appr and tracker.execution.approval_id is None:
                # Require case_id for case approval integration
                bound_case_id = execution.case_id
                if bound_case_id:
                    approval = await PlaybookApprovalBridge.request_step_approval(
                        self.session,
                        case_id=bound_case_id,
                        step_name=step.name,
                        playbook_name=playbook.name,
                        actor_id=execution.executed_by_id,
                    )
                    tracker.mark_waiting_approval(approval.id)
                    await self.execution_repo.update(
                        tracker.execution,
                        {
                            "status": ExecutionStatus.WAITING_APPROVAL,
                            "approval_id": approval.id,
                            "current_step_order": step.step_order,
                        },
                    )
                    return tracker.execution
                else:
                    # No bound case: pause execution with waiting approval flag
                    dummy_approval_id = uuid.uuid4()
                    tracker.mark_waiting_approval(dummy_approval_id)
                    await self.execution_repo.update(
                        tracker.execution,
                        {
                            "status": ExecutionStatus.WAITING_APPROVAL,
                            "approval_id": dummy_approval_id,
                            "current_step_order": step.step_order,
                        },
                    )
                    return tracker.execution

            # 3. Create Step Execution Record
            step_exec = await self.step_exec_repo.create(
                execution_id=execution.id,
                step_id=step.id,
                step_name=step.name,
                action_type=step.action_type,
                input_parameters=step.configuration,
            )
            await self.step_exec_repo.update(step_exec, {"status": StepExecutionStatus.RUNNING})

            # 4. Execute Action with Retries
            executor = ActionRegistry.get_executor(step.action_type)
            retries = 0
            success = False
            last_error = None
            output = {}

            while retries <= step.retry_count and not success:
                try:
                    output = await executor.execute(step.configuration, tracker.context)
                    success = True
                except Exception as ex:
                    last_error = str(ex)
                    retries += 1

            if success:
                await self.step_exec_repo.update(
                    step_exec,
                    {
                        "status": StepExecutionStatus.COMPLETED,
                        "completed_at": datetime.now(timezone.utc),
                        "output_data": output,
                        "retries_attempted": retries,
                    },
                )
                tracker.record_step_result(step.name, step.step_order, output)
                # Inject action outputs into context
                for k, v in output.items():
                    tracker.update_context(f"step_{step.step_order}_{k}", v)

                await self.execution_repo.update(
                    tracker.execution,
                    {
                        "current_step_order": step.step_order + 1,
                        "execution_context": tracker.context,
                        "results": tracker.results,
                    },
                )
            else:
                await self.step_exec_repo.update(
                    step_exec,
                    {
                        "status": StepExecutionStatus.FAILED,
                        "completed_at": datetime.now(timezone.utc),
                        "error_message": last_error,
                        "retries_attempted": retries,
                    },
                )

                if step.continue_on_failure:
                    tracker.record_step_result(
                        step.name, step.step_order, {"error": last_error, "status": "failed_continued"}
                    )
                    await self.execution_repo.update(
                        tracker.execution,
                        {
                            "current_step_order": step.step_order + 1,
                            "results": tracker.results,
                        },
                    )
                else:
                    tracker.mark_failed(f"Step '{step.name}' failed after {retries} retries: {last_error}")
                    await self.execution_repo.update(
                        tracker.execution,
                        {
                            "status": ExecutionStatus.FAILED,
                            "completed_at": datetime.now(timezone.utc),
                            "error_details": tracker.execution.error_details,
                        },
                    )
                    return tracker.execution

        # All steps complete
        tracker.mark_completed()
        await self.execution_repo.update(
            tracker.execution,
            {
                "status": ExecutionStatus.COMPLETED,
                "completed_at": datetime.now(timezone.utc),
            },
        )

        return await self.execution_repo.get_by_id(execution.id)

    async def resume_execution_after_approval(
        self, execution_id: uuid.UUID, actor_id: Optional[uuid.UUID] = None
    ) -> PlaybookExecution:
        """Resume a paused WAITING_APPROVAL execution after approval decision."""
        execution = await self.execution_repo.get_by_id(execution_id)
        if not execution:
            raise NotFoundError(f"Execution '{execution_id}' not found")

        if execution.status != ExecutionStatus.WAITING_APPROVAL:
            raise ConflictError(f"Execution '{execution_id}' is in state '{execution.status.value}', not WAITING_APPROVAL")

        if execution.approval_id and execution.case_id:
            status, notes = await PlaybookApprovalBridge.check_approval_status(
                self.session, execution.approval_id
            )
            if status in (ApprovalStatus.APPROVED, ApprovalStatus.AUTO_APPROVED):
                await self.execution_repo.update(execution, {"status": ExecutionStatus.RUNNING})
                playbook = await self.playbook_repo.get_by_id(execution.playbook_id)
                tracker = ExecutionTracker(execution)
                steps = sorted(playbook.steps, key=lambda s: s.step_order)
                return await self._run_steps(playbook, steps, tracker, execution)
            elif status == ApprovalStatus.REJECTED:
                tracker = ExecutionTracker(execution)
                reason = "Approval request was rejected by supervisor"
                tracker.mark_cancelled(reason)
                await self.execution_repo.update(
                    execution,
                    {
                        "status": ExecutionStatus.CANCELLED,
                        "completed_at": datetime.now(timezone.utc),
                        "error_details": reason,
                    },
                )
                return execution
            elif status == ApprovalStatus.PENDING:
                raise ValidationError(f"Cannot resume execution while CaseApproval '{execution.approval_id}' is PENDING")

        raise ValidationError("Cannot resume execution without a valid approved CaseApproval record")


    async def cancel_execution(
        self, execution_id: uuid.UUID, reason: str = "Execution cancelled by user"
    ) -> PlaybookExecution:
        """Cancel a running or queued execution run."""
        execution = await self.execution_repo.get_by_id(execution_id)
        if not execution:
            raise NotFoundError(f"Execution '{execution_id}' not found")

        if execution.status in (ExecutionStatus.COMPLETED, ExecutionStatus.FAILED, ExecutionStatus.CANCELLED):
            raise ConflictError(f"Cannot cancel execution in terminal state '{execution.status.value}'")

        tracker = ExecutionTracker(execution)
        tracker.mark_cancelled(reason)
        return await self.execution_repo.update(
            execution,
            {
                "status": ExecutionStatus.CANCELLED,
                "completed_at": datetime.now(timezone.utc),
                "error_details": reason,
            },
        )
