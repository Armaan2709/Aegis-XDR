"""
Case Management Statistics Aggregation Submodule Engine.

Calculates enterprise case workspace operational metrics including total cases,
open/closed breakdown, SLA breach rates, MTTR, task completion, and approval velocity.
"""

from typing import List
from datetime import datetime, timezone
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.case_management.models import (
    Case,
    CaseTask,
    CaseApproval,
    CaseStatus,
    TaskStatus,
    ApprovalStatus,
    CaseSeverity,
    CasePriority,
)
from app.case_management.schemas import CaseSummaryStats


class CaseStatisticsCalculator:
    """Calculates summary statistics across all cases."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def calculate(self) -> CaseSummaryStats:
        """Aggregate workspace statistics."""
        # Total
        total_stmt = select(func.count(Case.id))
        total_cases = (await self.session.execute(total_stmt)).scalar_one()

        # Open cases
        open_stmt = select(func.count(Case.id)).where(
            Case.status.in_([CaseStatus.DRAFT, CaseStatus.OPEN, CaseStatus.IN_PROGRESS, CaseStatus.PENDING_APPROVAL])
        )
        open_cases = (await self.session.execute(open_stmt)).scalar_one()

        # Closed cases
        closed_stmt = select(func.count(Case.id)).where(
            Case.status.in_([CaseStatus.RESOLVED, CaseStatus.CLOSED, CaseStatus.ARCHIVED])
        )
        closed_cases = (await self.session.execute(closed_stmt)).scalar_one()

        # SLA Breach Count
        sla_stmt = select(func.count(Case.id)).where(Case.sla_breached.is_(True))
        sla_breached_count = (await self.session.execute(sla_stmt)).scalar_one()

        sla_breach_rate = (sla_breached_count / total_cases * 100.0) if total_cases > 0 else 0.0

        # Mean Time to Resolve (MTTR) in hours
        resolved_cases_stmt = select(Case).where(
            and_or(Case.closed_at.isnot(None), Case.status.in_([CaseStatus.CLOSED, CaseStatus.RESOLVED]))
        )
        resolved_result = await self.session.execute(resolved_cases_stmt)
        resolved_cases = list(resolved_result.scalars().all())

        total_hours = 0.0
        for c in resolved_cases:
            if c.closed_at and c.opened_at:
                delta = c.closed_at - c.opened_at
                total_hours += delta.total_seconds() / 3600.0
        avg_resolution_hours = (total_hours / len(resolved_cases)) if len(resolved_cases) > 0 else 0.0

        # Task completion rate
        total_tasks_stmt = select(func.count(CaseTask.id))
        total_tasks = (await self.session.execute(total_tasks_stmt)).scalar_one()

        completed_tasks_stmt = select(func.count(CaseTask.id)).where(CaseTask.status == TaskStatus.COMPLETED)
        completed_tasks = (await self.session.execute(completed_tasks_stmt)).scalar_one()

        task_completion_rate = (completed_tasks / total_tasks * 100.0) if total_tasks > 0 else 0.0

        # By severity
        sev_stmt = select(Case.severity, func.count(Case.id)).group_by(Case.severity)
        sev_res = await self.session.execute(sev_stmt)
        cases_by_severity = {s.value if hasattr(s, 'value') else str(s): cnt for s, cnt in sev_res.all()}

        # By status
        stat_stmt = select(Case.status, func.count(Case.id)).group_by(Case.status)
        stat_res = await self.session.execute(stat_stmt)
        cases_by_status = {st.value if hasattr(st, 'value') else str(st): cnt for st, cnt in stat_res.all()}

        # By priority
        prio_stmt = select(Case.priority, func.count(Case.id)).group_by(Case.priority)
        prio_res = await self.session.execute(prio_stmt)
        cases_by_priority = {p.value if hasattr(p, 'value') else str(p): cnt for p, cnt in prio_res.all()}

        # Approval counts
        appr_stmt = select(CaseApproval.status, func.count(CaseApproval.id)).group_by(CaseApproval.status)
        appr_res = await self.session.execute(appr_stmt)
        approval_counts = {ap.value if hasattr(ap, 'value') else str(ap): cnt for ap, cnt in appr_res.all()}

        return CaseSummaryStats(
            total_cases=total_cases,
            open_cases=open_cases,
            closed_cases=closed_cases,
            sla_breached_count=sla_breached_count,
            sla_breach_rate=round(sla_breach_rate, 2),
            avg_resolution_hours=round(avg_resolution_hours, 2),
            task_completion_rate=round(task_completion_rate, 2),
            cases_by_severity=cases_by_severity,
            cases_by_status=cases_by_status,
            cases_by_priority=cases_by_priority,
            approval_counts=approval_counts,
        )


def and_or(c1, c2):
    from sqlalchemy import or_
    return or_(c1, c2)
