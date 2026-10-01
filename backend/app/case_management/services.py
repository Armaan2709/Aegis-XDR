"""
Case Management Domain Core Service Layer.

Orchestrates business logic, state machine validations, repository interactions,
activity audit logging, comment threading, attachment metadata validations, task tracking,
approval governance policies, analyst assignments, and metric aggregations.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ValidationError, ConflictError
from app.case_management.models import (
    Case,
    CaseComment,
    CaseAttachment,
    CaseTask,
    CaseApproval,
    CaseActivity,
    CaseAssignment,
    CaseStatus,
    TaskStatus,
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
    CaseSummaryStats,
)
from app.case_management.repositories import (
    CaseRepository,
    CaseCommentRepository,
    CaseAttachmentRepository,
    CaseTaskRepository,
    CaseApprovalRepository,
    CaseActivityRepository,
    CaseAssignmentRepository,
)
from app.case_management.comments import CommentManager
from app.case_management.attachments import AttachmentValidator
from app.case_management.tasks import TaskStateEngine
from app.case_management.approvals import AutoApprovalPolicy
from app.case_management.activity import ActivityLogger
from app.case_management.statistics import CaseStatisticsCalculator


class CaseService:
    """Core domain service for Case Management workspace."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.case_repo = CaseRepository(session)
        self.comment_repo = CaseCommentRepository(session)
        self.attachment_repo = CaseAttachmentRepository(session)
        self.task_repo = CaseTaskRepository(session)
        self.approval_repo = CaseApprovalRepository(session)
        self.activity_repo = CaseActivityRepository(session)
        self.assignment_repo = CaseAssignmentRepository(session)

    # ==========================================
    # Case Workspace Operations
    # ==========================================

    async def create_case(
        self, case_in: CaseCreate, created_by_id: Optional[uuid.UUID] = None
    ) -> Case:
        """Create a new enterprise case workspace and log initial activity."""
        case = await self.case_repo.create(case_in, created_by_id=created_by_id)

        summary, details = ActivityLogger.build_entry(
            ActivityType.CASE_CREATED, case.case_number, f"Created case '{case.title}'"
        )
        await self.activity_repo.log_activity(
            case.id, ActivityType.CASE_CREATED, summary, details, actor_id=created_by_id
        )

        return case

    async def get_case(self, case_id: uuid.UUID) -> Case:
        """Retrieve case by UUID or raise NotFoundError."""
        case = await self.case_repo.get_by_id(case_id)
        if not case:
            raise NotFoundError(f"Case with ID '{case_id}' not found")
        return case

    async def list_cases(self, params: CaseFilterParams) -> Tuple[List[Case], int]:
        """Search, filter, and paginate cases."""
        return await self.case_repo.list_filtered(params)

    async def update_case(
        self, case_id: uuid.UUID, update_in: CaseUpdate, actor_id: Optional[uuid.UUID] = None
    ) -> Case:
        """Update case fields and record activity log."""
        case = await self.get_case(case_id)
        update_dict = update_in.model_dump(exclude_unset=True)

        updated_case = await self.case_repo.update(case, update_dict)

        summary, details = ActivityLogger.build_entry(
            ActivityType.CASE_UPDATED, updated_case.case_number, details={"updated_fields": list(update_dict.keys())}
        )
        await self.activity_repo.log_activity(
            case.id, ActivityType.CASE_UPDATED, summary, details, actor_id=actor_id
        )

        return updated_case

    async def close_case(
        self, case_id: uuid.UUID, close_in: CaseClose, actor_id: Optional[uuid.UUID] = None
    ) -> Case:
        """Close case workspace with audit notes."""
        case = await self.get_case(case_id)
        if case.status == CaseStatus.CLOSED:
            raise ConflictError(f"Case '{case.case_number}' is already closed")

        now = datetime.now(timezone.utc)
        meta = dict(case.case_metadata or {})
        meta["closure_notes"] = close_in.closure_notes
        meta["closed_by_id"] = str(actor_id) if actor_id else None

        update_data = {
            "status": CaseStatus.CLOSED,
            "closed_at": now,
            "case_metadata": meta,
        }
        updated_case = await self.case_repo.update(case, update_data)

        summary, details = ActivityLogger.build_entry(
            ActivityType.CASE_CLOSED,
            updated_case.case_number,
            f"Case '{updated_case.case_number}' closed. Notes: {close_in.closure_notes}",
            details={"closure_notes": close_in.closure_notes},
        )
        await self.activity_repo.log_activity(
            case.id, ActivityType.CASE_CLOSED, summary, details, actor_id=actor_id
        )

        return updated_case

    # ==========================================
    # Analyst Assignments
    # ==========================================

    async def assign_analyst(
        self,
        case_id: uuid.UUID,
        assign_in: CaseAssignmentCreate,
        assigned_by_id: Optional[uuid.UUID] = None,
    ) -> CaseAssignment:
        """Assign analyst to case workspace."""
        case = await self.get_case(case_id)
        assignment = await self.assignment_repo.assign(
            case_id=case.id,
            user_id=assign_in.user_id,
            role=assign_in.role,
            assigned_by_id=assigned_by_id,
        )

        # Update case owner if role is PRIMARY_LEAD
        if assign_in.role == AssignmentRole.PRIMARY_LEAD:
            await self.case_repo.update(case, {"owner_id": assign_in.user_id})

        summary, details = ActivityLogger.build_entry(
            ActivityType.ANALYST_ASSIGNED,
            case.case_number,
            f"Assigned user '{assign_in.user_id}' as {assign_in.role.value}",
            details={"assigned_user_id": str(assign_in.user_id), "role": assign_in.role.value},
        )
        await self.activity_repo.log_activity(
            case.id, ActivityType.ANALYST_ASSIGNED, summary, details, actor_id=assigned_by_id
        )

        return assignment

    async def remove_analyst(
        self, case_id: uuid.UUID, user_id: uuid.UUID, actor_id: Optional[uuid.UUID] = None
    ) -> bool:
        """Remove analyst assignment from case."""
        case = await self.get_case(case_id)
        removed = await self.assignment_repo.remove(case_id, user_id)
        if not removed:
            raise NotFoundError(f"No assignment found for user '{user_id}' on case '{case_id}'")

        if case.owner_id == user_id:
            await self.case_repo.update(case, {"owner_id": None})

        summary, details = ActivityLogger.build_entry(
            ActivityType.ANALYST_REMOVED,
            case.case_number,
            f"Removed assignment for user '{user_id}'",
            details={"removed_user_id": str(user_id)},
        )
        await self.activity_repo.log_activity(
            case.id, ActivityType.ANALYST_REMOVED, summary, details, actor_id=actor_id
        )

        return True

    async def list_assignments(self, case_id: uuid.UUID) -> List[CaseAssignment]:
        """List assignments for a case."""
        await self.get_case(case_id)
        return await self.assignment_repo.list_by_case(case_id)

    # ==========================================
    # Domain Entity Linking
    # ==========================================

    async def link_entity(
        self, case_id: uuid.UUID, link_in: CaseLinkUpdate, actor_id: Optional[uuid.UUID] = None
    ) -> Case:
        """Link an external domain entity identifier to case."""
        case = await self.get_case(case_id)

        target_map = {
            "incident": ("related_incidents", ActivityType.INCIDENT_LINKED),
            "investigation": ("related_investigations", ActivityType.INVESTIGATION_LINKED),
            "evidence": ("related_evidence", ActivityType.EVIDENCE_LINKED),
            "timeline": ("related_timeline_events", ActivityType.TIMELINE_LINKED),
            "mitre": ("related_mitre_techniques", ActivityType.MITRE_LINKED),
            "threat_indicator": ("related_threat_indicators", ActivityType.THREAT_INDICATOR_LINKED),
            "rule_match": ("related_rule_matches", ActivityType.CASE_UPDATED),
        }

        entity_type = link_in.entity_type.lower()
        if entity_type not in target_map:
            raise ValidationError(
                f"Unsupported entity type '{link_in.entity_type}'. Allowed: {list(target_map.keys())}"
            )

        attr_name, activity_type = target_map[entity_type]
        existing_list = list(getattr(case, attr_name) or [])

        if link_in.entity_id not in existing_list:
            existing_list.append(link_in.entity_id)

        updated_case = await self.case_repo.update(case, {attr_name: existing_list})

        summary, details = ActivityLogger.build_entry(
            activity_type,
            case.case_number,
            f"Linked {entity_type} '{link_in.entity_id}' to case {case.case_number}",
            details={"entity_type": entity_type, "entity_id": link_in.entity_id},
        )
        await self.activity_repo.log_activity(
            case.id, activity_type, summary, details, actor_id=actor_id
        )

        return updated_case

    # ==========================================
    # Comments Operations
    # ==========================================

    async def add_comment(
        self,
        case_id: uuid.UUID,
        comment_in: CaseCommentCreate,
        author_id: Optional[uuid.UUID] = None,
        author_name: Optional[str] = None,
    ) -> CaseComment:
        """Post a threaded comment to case."""
        case = await self.get_case(case_id)

        if comment_in.parent_id:
            parent = await self.comment_repo.get_by_id(comment_in.parent_id)
            if not parent or parent.case_id != case_id:
                raise NotFoundError(f"Parent comment '{comment_in.parent_id}' not found in case '{case_id}'")

        mentions = comment_in.mentions or CommentManager.extract_mentions(comment_in.content)

        comment = await self.comment_repo.create(
            case_id=case.id,
            content=comment_in.content,
            author_id=author_id,
            author_name=author_name,
            parent_id=comment_in.parent_id,
            mentions=mentions,
        )

        summary, details = ActivityLogger.build_entry(
            ActivityType.COMMENT_ADDED,
            case.case_number,
            f"Added comment to case '{case.case_number}'",
            details={"comment_id": str(comment.id)},
        )
        await self.activity_repo.log_activity(
            case.id, ActivityType.COMMENT_ADDED, summary, details, actor_id=author_id
        )

        return comment

    async def edit_comment(
        self,
        case_id: uuid.UUID,
        comment_id: uuid.UUID,
        update_in: CaseCommentUpdate,
        actor_id: Optional[uuid.UUID] = None,
    ) -> CaseComment:
        """Edit comment content preserving edit history."""
        await self.get_case(case_id)
        comment = await self.comment_repo.get_by_id(comment_id)
        if not comment or comment.case_id != case_id:
            raise NotFoundError(f"Comment '{comment_id}' not found in case '{case_id}'")

        if comment.is_deleted:
            raise ConflictError("Cannot edit a deleted comment")

        updated = await self.comment_repo.update_content(comment, update_in.content, updated_by_id=actor_id)

        summary, details = ActivityLogger.build_entry(
            ActivityType.COMMENT_EDITED,
            "",
            details={"comment_id": str(comment_id)},
        )
        await self.activity_repo.log_activity(
            case_id, ActivityType.COMMENT_EDITED, summary, details, actor_id=actor_id
        )

        return updated

    async def delete_comment(
        self, case_id: uuid.UUID, comment_id: uuid.UUID, actor_id: Optional[uuid.UUID] = None
    ) -> CaseComment:
        """Soft delete a comment preserving audit log."""
        await self.get_case(case_id)
        comment = await self.comment_repo.get_by_id(comment_id)
        if not comment or comment.case_id != case_id:
            raise NotFoundError(f"Comment '{comment_id}' not found in case '{case_id}'")

        deleted = await self.comment_repo.soft_delete(comment, deleted_by_id=actor_id)

        summary, details = ActivityLogger.build_entry(
            ActivityType.COMMENT_DELETED,
            "",
            details={"comment_id": str(comment_id)},
        )
        await self.activity_repo.log_activity(
            case_id, ActivityType.COMMENT_DELETED, summary, details, actor_id=actor_id
        )

        return deleted

    async def list_comments(self, case_id: uuid.UUID) -> List[CaseComment]:
        """List comments for a case."""
        await self.get_case(case_id)
        return await self.comment_repo.list_by_case(case_id)

    # ==========================================
    # Attachment Metadata Operations
    # ==========================================

    async def add_attachment_metadata(
        self,
        case_id: uuid.UUID,
        attachment_in: CaseAttachmentCreate,
        uploaded_by_id: Optional[uuid.UUID] = None,
    ) -> CaseAttachment:
        """Validate and record attachment metadata."""
        case = await self.get_case(case_id)

        AttachmentValidator.validate_metadata(
            filename=attachment_in.filename,
            file_size_bytes=attachment_in.file_size_bytes,
            file_hash=attachment_in.file_hash,
            attachment_type=attachment_in.attachment_type,
        )

        storage_uri = attachment_in.storage_uri or AttachmentValidator.generate_storage_uri_placeholder(
            case.case_number, attachment_in.filename
        )

        attachment = await self.attachment_repo.create(
            case_id=case.id,
            attachment_type=attachment_in.attachment_type,
            filename=attachment_in.filename,
            file_size_bytes=attachment_in.file_size_bytes,
            file_hash=attachment_in.file_hash,
            mime_type=attachment_in.mime_type,
            storage_uri=storage_uri,
            description=attachment_in.description,
            uploaded_by_id=uploaded_by_id,
        )

        summary, details = ActivityLogger.build_entry(
            ActivityType.EVIDENCE_LINKED,
            case.case_number,
            f"Attached metadata for '{attachment.filename}' ({attachment.attachment_type.value})",
            details={"attachment_id": str(attachment.id), "filename": attachment.filename},
        )
        await self.activity_repo.log_activity(
            case.id, ActivityType.EVIDENCE_LINKED, summary, details, actor_id=uploaded_by_id
        )

        return attachment

    async def list_attachments(self, case_id: uuid.UUID) -> List[CaseAttachment]:
        """List attachment metadata records for a case."""
        await self.get_case(case_id)
        return await self.attachment_repo.list_by_case(case_id)

    # ==========================================
    # Task Management Operations
    # ==========================================

    async def create_task(
        self, case_id: uuid.UUID, task_in: CaseTaskCreate, actor_id: Optional[uuid.UUID] = None
    ) -> CaseTask:
        """Create an operational case task."""
        case = await self.get_case(case_id)
        task = await self.task_repo.create(
            case_id=case.id,
            title=task_in.title,
            description=task_in.description,
            assigned_to_id=task_in.assigned_to_id,
            priority=task_in.priority,
            due_date=task_in.due_date,
            notes=task_in.notes,
        )

        summary, details = ActivityLogger.build_entry(
            ActivityType.TASK_CREATED,
            case.case_number,
            f"Task '{task.title}' created in case '{case.case_number}'",
            details={"task_id": str(task.id), "title": task.title},
        )
        await self.activity_repo.log_activity(
            case.id, ActivityType.TASK_CREATED, summary, details, actor_id=actor_id
        )

        return task

    async def update_task_status(
        self,
        case_id: uuid.UUID,
        task_id: uuid.UUID,
        update_in: CaseTaskUpdate,
        actor_id: Optional[uuid.UUID] = None,
    ) -> CaseTask:
        """Update task status with state transition validation."""
        await self.get_case(case_id)
        task = await self.task_repo.get_by_id(task_id)
        if not task or task.case_id != case_id:
            raise NotFoundError(f"Task '{task_id}' not found in case '{case_id}'")

        update_dict = update_in.model_dump(exclude_unset=True)

        if "status" in update_dict:
            new_status = update_dict["status"]
            TaskStateEngine.validate_transition(task.status, new_status)

            if new_status == TaskStatus.COMPLETED:
                update_dict["completed_at"] = datetime.now(timezone.utc)
                update_dict["completed_by_id"] = actor_id
            elif task.status == TaskStatus.COMPLETED and new_status != TaskStatus.COMPLETED:
                update_dict["completed_at"] = None
                update_dict["completed_by_id"] = None

        updated_task = await self.task_repo.update(task, update_dict)

        summary, details = ActivityLogger.build_entry(
            ActivityType.TASK_UPDATED,
            "",
            f"Updated task '{task.title}' status to '{updated_task.status.value}'",
            details={"task_id": str(task_id), "status": updated_task.status.value},
        )
        await self.activity_repo.log_activity(
            case_id, ActivityType.TASK_UPDATED, summary, details, actor_id=actor_id
        )

        return updated_task

    async def list_tasks(self, case_id: uuid.UUID) -> List[CaseTask]:
        """List tasks for a case."""
        await self.get_case(case_id)
        return await self.task_repo.list_by_case(case_id)

    # ==========================================
    # Governance Approval Operations
    # ==========================================

    async def request_approval(
        self,
        case_id: uuid.UUID,
        approval_in: CaseApprovalCreate,
        actor_id: Optional[uuid.UUID] = None,
    ) -> CaseApproval:
        """Submit approval request and evaluate placeholder auto-approval policy if requested."""
        case = await self.get_case(case_id)
        approval = await self.approval_repo.create(
            case_id=case.id,
            title=approval_in.title,
            description=approval_in.description,
            is_auto_approval=approval_in.is_auto_approval,
        )

        # Evaluate AutoApprovalPolicy placeholder
        if approval_in.is_auto_approval:
            is_auto, reason = AutoApprovalPolicy.evaluate_auto_approval(
                title=approval_in.title,
                description=approval_in.description,
                case_severity=case.severity,
            )
            if is_auto:
                approval = await self.approval_repo.update_decision(
                    approval,
                    status=ApprovalStatus.AUTO_APPROVED,
                    approver_id=actor_id,
                    decision_notes=reason,
                )

        summary, details = ActivityLogger.build_entry(
            ActivityType.APPROVAL_REQUESTED,
            case.case_number,
            f"Approval requested: '{approval.title}' (Status: {approval.status.value})",
            details={"approval_id": str(approval.id), "status": approval.status.value},
        )
        await self.activity_repo.log_activity(
            case.id, ActivityType.APPROVAL_REQUESTED, summary, details, actor_id=actor_id
        )

        return approval

    async def process_approval(
        self,
        case_id: uuid.UUID,
        approval_id: uuid.UUID,
        decision_in: CaseApprovalDecision,
        approver_id: Optional[uuid.UUID] = None,
    ) -> CaseApproval:
        """Record manual approval or rejection decision."""
        await self.get_case(case_id)
        approval = await self.approval_repo.get_by_id(approval_id)
        if not approval or approval.case_id != case_id:
            raise NotFoundError(f"Approval request '{approval_id}' not found in case '{case_id}'")

        if approval.status != ApprovalStatus.PENDING:
            raise ConflictError(f"Approval request '{approval_id}' has already been decided ({approval.status.value})")

        new_status = ApprovalStatus.APPROVED if decision_in.approved else ApprovalStatus.REJECTED
        decided = await self.approval_repo.update_decision(
            approval,
            status=new_status,
            approver_id=approver_id,
            decision_notes=decision_in.decision_notes,
        )

        summary, details = ActivityLogger.build_entry(
            ActivityType.APPROVAL_DECIDED,
            "",
            f"Approval '{approval.title}' decision recorded: {new_status.value}",
            details={"approval_id": str(approval_id), "status": new_status.value},
        )
        await self.activity_repo.log_activity(
            case_id, ActivityType.APPROVAL_DECIDED, summary, details, actor_id=approver_id
        )

        return decided

    async def list_approvals(self, case_id: uuid.UUID) -> List[CaseApproval]:
        """List approval requests for a case."""
        await self.get_case(case_id)
        return await self.approval_repo.list_by_case(case_id)

    async def list_all_pending_approvals(self) -> List[CaseApproval]:
        """List all pending approval requests across all cases."""
        return await self.approval_repo.list_all_pending()


    # ==========================================
    # Activity Log & Statistics Operations
    # ==========================================

    async def get_case_activity(self, case_id: uuid.UUID) -> List[CaseActivity]:
        """Retrieve auditable activity timeline events for a case."""
        await self.get_case(case_id)
        return await self.activity_repo.list_by_case(case_id)

    async def get_case_statistics(self) -> CaseSummaryStats:
        """Calculate workspace summary statistics across all cases."""
        calculator = CaseStatisticsCalculator(self.session)
        return await calculator.calculate()
