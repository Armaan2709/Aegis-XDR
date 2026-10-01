"""
Case Management Domain Repositories.

Provides async database access routines for Case entities, comments, attachments,
tasks, approvals, activities, and assignments using Async SQLAlchemy 2.0.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, func, or_, and_, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

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
from app.case_management.schemas import CaseCreate, CaseFilterParams


class CaseRepository:
    """Repository handling database operations for Case entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def generate_next_code(self) -> str:
        """Generate safe, deterministic unique case reference code (e.g. CASE-2026-0001)."""
        year = datetime.now(timezone.utc).year
        stmt = select(func.count(Case.id))
        count = (await self.session.execute(stmt)).scalar_one()
        return f"CASE-{year}-{count + 1:04d}"

    async def create(self, case_in: CaseCreate, created_by_id: Optional[uuid.UUID] = None) -> Case:
        """Persist a new Case entity."""
        case_number = await self.generate_next_code()

        case = Case(
            case_number=case_number,
            title=case_in.title,
            description=case_in.description,
            status=case_in.status,
            severity=case_in.severity,
            priority=case_in.priority,
            owner_id=case_in.owner_id,
            created_by_id=created_by_id,
            opened_at=datetime.now(timezone.utc),
            due_date=case_in.due_date,
            sla_target_at=case_in.sla_target_at,
            tags=case_in.tags,
            case_metadata=case_in.case_metadata,
            related_incidents=case_in.related_incidents,
            related_investigations=case_in.related_investigations,
            related_evidence=case_in.related_evidence,
            related_timeline_events=case_in.related_timeline_events,
            related_mitre_techniques=case_in.related_mitre_techniques,
            related_threat_indicators=case_in.related_threat_indicators,
            related_rule_matches=case_in.related_rule_matches,
        )
        self.session.add(case)
        await self.session.commit()
        await self.session.refresh(case)
        return case

    async def get_by_id(self, case_id: uuid.UUID) -> Optional[Case]:
        """Fetch Case by primary key UUID."""
        stmt = select(Case).where(Case.id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_number(self, case_number: str) -> Optional[Case]:
        """Fetch Case by case reference number."""
        stmt = select(Case).where(Case.case_number == case_number)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_filtered(self, params: CaseFilterParams) -> Tuple[List[Case], int]:
        """List cases with dynamic search, filtering, sorting, and pagination."""
        stmt = select(Case)
        count_stmt = select(func.count(Case.id))
        conditions = []

        if params.query:
            pattern = f"%{params.query}%"
            conditions.append(
                or_(
                    Case.title.ilike(pattern),
                    Case.description.ilike(pattern),
                    Case.case_number.ilike(pattern),
                )
            )

        if params.status:
            conditions.append(Case.status == params.status)

        if params.severity:
            conditions.append(Case.severity == params.severity)

        if params.priority:
            conditions.append(Case.priority == params.priority)

        if params.owner_id:
            conditions.append(Case.owner_id == params.owner_id)

        if params.sla_breached is not None:
            conditions.append(Case.sla_breached == params.sla_breached)

        if params.assigned_user_id:
            # Filter by analyst assignment using subquery
            assigned_stmt = select(CaseAssignment.case_id).where(
                CaseAssignment.user_id == params.assigned_user_id
            )
            conditions.append(Case.id.in_(assigned_stmt))

        if conditions:
            stmt = stmt.where(and_(*conditions))
            count_stmt = count_stmt.where(and_(*conditions))

        total_result = await self.session.execute(count_stmt)
        total_count = total_result.scalar_one()

        # Dynamic Sorting
        sort_attr = getattr(Case, params.sort_by, Case.created_at)
        sort_fn = desc if params.sort_order.lower() == "desc" else asc
        stmt = stmt.order_by(sort_fn(sort_attr))

        # Pagination
        offset = (params.page - 1) * params.page_size
        stmt = stmt.offset(offset).limit(params.page_size)

        result = await self.session.execute(stmt)
        cases = list(result.scalars().all())

        return cases, total_count

    async def update(self, case: Case, update_data: Dict[str, Any]) -> Case:
        """Update existing Case entity fields."""
        for field, value in update_data.items():
            if value is not None and hasattr(case, field):
                setattr(case, field, value)

        self.session.add(case)
        await self.session.commit()
        await self.session.refresh(case)
        return case

    async def delete(self, case_id: uuid.UUID) -> bool:
        """Delete case entity."""
        case = await self.get_by_id(case_id)
        if not case:
            return False
        await self.session.delete(case)
        await self.session.commit()
        return True


class CaseCommentRepository:
    """Repository handling database operations for CaseComment entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        case_id: uuid.UUID,
        content: str,
        author_id: Optional[uuid.UUID] = None,
        author_name: Optional[str] = None,
        parent_id: Optional[uuid.UUID] = None,
        mentions: Optional[List[str]] = None,
    ) -> CaseComment:
        """Persist a new comment."""
        comment = CaseComment(
            case_id=case_id,
            content=content,
            author_id=author_id,
            author_name=author_name,
            parent_id=parent_id,
            mentions=mentions or [],
            edit_history=[],
        )
        self.session.add(comment)
        await self.session.commit()
        await self.session.refresh(comment)
        return comment

    async def get_by_id(self, comment_id: uuid.UUID) -> Optional[CaseComment]:
        """Fetch comment by UUID."""
        stmt = select(CaseComment).where(CaseComment.id == comment_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_case(self, case_id: uuid.UUID) -> List[CaseComment]:
        """List all comments for a case ordered by creation time."""
        stmt = (
            select(CaseComment)
            .where(CaseComment.case_id == case_id)
            .order_by(asc(CaseComment.created_at))
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_content(
        self, comment: CaseComment, new_content: str, updated_by_id: Optional[uuid.UUID] = None
    ) -> CaseComment:
        """Update comment content and record edit history entry."""
        history_entry = {
            "previous_content": comment.content,
            "edited_at": datetime.now(timezone.utc).isoformat(),
            "edited_by_id": str(updated_by_id) if updated_by_id else None,
        }
        updated_history = list(comment.edit_history or [])
        updated_history.append(history_entry)

        comment.content = new_content
        comment.edit_history = updated_history

        self.session.add(comment)
        await self.session.commit()
        await self.session.refresh(comment)
        return comment

    async def soft_delete(self, comment: CaseComment, deleted_by_id: Optional[uuid.UUID] = None) -> CaseComment:
        """Soft delete a comment preserving audit metadata."""
        comment.is_deleted = True
        comment.deleted_at = datetime.now(timezone.utc)
        comment.deleted_by_id = deleted_by_id

        self.session.add(comment)
        await self.session.commit()
        await self.session.refresh(comment)
        return comment


class CaseAttachmentRepository:
    """Repository handling case attachment metadata."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        case_id: uuid.UUID,
        attachment_type: str,
        filename: str,
        file_size_bytes: int,
        file_hash: str,
        mime_type: str = "application/octet-stream",
        storage_uri: Optional[str] = None,
        description: Optional[str] = None,
        uploaded_by_id: Optional[uuid.UUID] = None,
    ) -> CaseAttachment:
        """Persist attachment metadata."""
        attachment = CaseAttachment(
            case_id=case_id,
            attachment_type=attachment_type,
            filename=filename,
            file_size_bytes=file_size_bytes,
            file_hash=file_hash,
            mime_type=mime_type,
            storage_uri=storage_uri,
            description=description,
            uploaded_by_id=uploaded_by_id,
        )
        self.session.add(attachment)
        await self.session.commit()
        await self.session.refresh(attachment)
        return attachment

    async def get_by_id(self, attachment_id: uuid.UUID) -> Optional[CaseAttachment]:
        """Fetch attachment by UUID."""
        stmt = select(CaseAttachment).where(CaseAttachment.id == attachment_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_case(self, case_id: uuid.UUID) -> List[CaseAttachment]:
        """List attachments metadata for a case."""
        stmt = (
            select(CaseAttachment)
            .where(CaseAttachment.case_id == case_id)
            .order_by(desc(CaseAttachment.created_at))
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


class CaseTaskRepository:
    """Repository handling case task management database routines."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        case_id: uuid.UUID,
        title: str,
        description: Optional[str] = None,
        assigned_to_id: Optional[uuid.UUID] = None,
        priority: str = "MEDIUM",
        due_date: Optional[datetime] = None,
        notes: Optional[str] = None,
    ) -> CaseTask:
        """Persist a new task."""
        task = CaseTask(
            case_id=case_id,
            title=title,
            description=description,
            assigned_to_id=assigned_to_id,
            status=TaskStatus.PENDING,
            priority=priority,
            due_date=due_date,
            notes=notes,
        )
        self.session.add(task)
        await self.session.commit()
        await self.session.refresh(task)
        return task

    async def get_by_id(self, task_id: uuid.UUID) -> Optional[CaseTask]:
        """Fetch task by UUID."""
        stmt = select(CaseTask).where(CaseTask.id == task_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_case(self, case_id: uuid.UUID) -> List[CaseTask]:
        """List tasks for a case."""
        stmt = (
            select(CaseTask)
            .where(CaseTask.case_id == case_id)
            .order_by(asc(CaseTask.created_at))
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update(self, task: CaseTask, update_data: Dict[str, Any]) -> CaseTask:
        """Update existing task fields."""
        for field, value in update_data.items():
            if value is not None and hasattr(task, field):
                setattr(task, field, value)

        self.session.add(task)
        await self.session.commit()
        await self.session.refresh(task)
        return task


class CaseApprovalRepository:
    """Repository handling case approval workflows."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        case_id: uuid.UUID,
        title: str,
        description: Optional[str] = None,
        is_auto_approval: bool = False,
    ) -> CaseApproval:
        """Persist approval request."""
        approval = CaseApproval(
            case_id=case_id,
            title=title,
            description=description,
            status=ApprovalStatus.PENDING,
            is_auto_approval=is_auto_approval,
        )
        self.session.add(approval)
        await self.session.commit()
        await self.session.refresh(approval)
        return approval

    async def get_by_id(self, approval_id: uuid.UUID) -> Optional[CaseApproval]:
        """Fetch approval request by UUID."""
        stmt = select(CaseApproval).where(CaseApproval.id == approval_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_case(self, case_id: uuid.UUID) -> List[CaseApproval]:
        """List approvals for a case."""
        stmt = (
            select(CaseApproval)
            .where(CaseApproval.case_id == case_id)
            .order_by(desc(CaseApproval.created_at))
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_all_pending(self) -> List[CaseApproval]:
        """List all pending approval requests across all cases."""
        stmt = (
            select(CaseApproval)
            .where(CaseApproval.status == ApprovalStatus.PENDING)
            .order_by(desc(CaseApproval.created_at))
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


    async def update_decision(
        self,
        approval: CaseApproval,
        status: ApprovalStatus,
        approver_id: Optional[uuid.UUID],
        decision_notes: Optional[str],
    ) -> CaseApproval:
        """Record decision on approval request."""
        approval.status = status
        approval.approver_id = approver_id
        approval.decision_notes = decision_notes
        approval.decided_at = datetime.now(timezone.utc)

        self.session.add(approval)
        await self.session.commit()
        await self.session.refresh(approval)
        return approval


class CaseActivityRepository:
    """Repository handling case activity audit timeline events."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def log_activity(
        self,
        case_id: uuid.UUID,
        activity_type: ActivityType,
        summary: str,
        details: Optional[Dict[str, Any]] = None,
        actor_id: Optional[uuid.UUID] = None,
    ) -> CaseActivity:
        """Log an activity event to case timeline."""
        activity = CaseActivity(
            case_id=case_id,
            activity_type=activity_type,
            summary=summary,
            details=details or {},
            actor_id=actor_id,
            timestamp=datetime.now(timezone.utc),
        )
        self.session.add(activity)
        await self.session.commit()
        await self.session.refresh(activity)
        return activity

    async def list_by_case(self, case_id: uuid.UUID) -> List[CaseActivity]:
        """List all activity events for a case ordered chronologically desc."""
        stmt = (
            select(CaseActivity)
            .where(CaseActivity.case_id == case_id)
            .order_by(desc(CaseActivity.timestamp))
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


class CaseAssignmentRepository:
    """Repository handling SOC analyst case assignments."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def assign(
        self,
        case_id: uuid.UUID,
        user_id: uuid.UUID,
        role: AssignmentRole = AssignmentRole.CO_ANALYST,
        assigned_by_id: Optional[uuid.UUID] = None,
    ) -> CaseAssignment:
        """Assign analyst to case or update role if already assigned."""
        stmt = select(CaseAssignment).where(
            and_(CaseAssignment.case_id == case_id, CaseAssignment.user_id == user_id)
        )
        existing = (await self.session.execute(stmt)).scalar_one_or_none()

        if existing:
            existing.role = role
            existing.assigned_by_id = assigned_by_id
            existing.assigned_at = datetime.now(timezone.utc)
            self.session.add(existing)
            await self.session.commit()
            await self.session.refresh(existing)
            return existing

        assignment = CaseAssignment(
            case_id=case_id,
            user_id=user_id,
            role=role,
            assigned_by_id=assigned_by_id,
            assigned_at=datetime.now(timezone.utc),
        )
        self.session.add(assignment)
        await self.session.commit()
        await self.session.refresh(assignment)
        return assignment

    async def get_assignment(self, case_id: uuid.UUID, user_id: uuid.UUID) -> Optional[CaseAssignment]:
        """Fetch assignment by case and user."""
        stmt = select(CaseAssignment).where(
            and_(CaseAssignment.case_id == case_id, CaseAssignment.user_id == user_id)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_case(self, case_id: uuid.UUID) -> List[CaseAssignment]:
        """List assignments for a case."""
        stmt = select(CaseAssignment).where(CaseAssignment.case_id == case_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def remove(self, case_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Remove analyst assignment from case."""
        assignment = await self.get_assignment(case_id, user_id)
        if not assignment:
            return False
        await self.session.delete(assignment)
        await self.session.commit()
        return True
