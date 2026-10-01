"""
Detection Rule Engine Repository Layer.

Encapsulates Async SQLAlchemy 2.0 database queries for Detection Rules,
Version History, Rule Executions, and Performance Metrics.
"""

import uuid
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, update, delete, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection_engine.models import (
    DetectionRule,
    RuleVersion,
    RuleExecution,
    RuleStatistics,
    RuleStatus,
    RuleSeverity,
)
from app.detection_engine.schemas import (
    DetectionRuleCreate,
    DetectionRuleUpdate,
    RuleFilterParams,
)


class DetectionRuleRepository:
    """Async repository for Detection Rule Engine entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_rule(self, data: DetectionRuleCreate, validation_status: str = "VALID") -> DetectionRule:
        """Persist a new detection rule."""
        rule = DetectionRule(
            name=data.name,
            rule_type=data.rule_type,
            category=data.category,
            description=data.description,
            severity=data.severity,
            status=data.status,
            version=1,
            author=data.author,
            source=data.source,
            content=data.content,
            validation_status=validation_status,
            tags=data.tags,
            metadata_info=data.metadata_info,
        )
        self.session.add(rule)
        await self.session.commit()
        await self.session.refresh(rule)

        # Record initial version 1 snapshot
        version_snapshot = RuleVersion(
            rule_id=rule.id,
            version=1,
            content=rule.content,
            change_summary="Initial rule creation",
            created_by=rule.author,
        )
        self.session.add(version_snapshot)

        # Initialize statistics entry
        stats_entry = RuleStatistics(
            rule_id=rule.id,
            total_executions=0,
            total_matches=0,
            avg_execution_ms=0.0,
            false_positive_rate=0.0,
        )
        self.session.add(stats_entry)

        await self.session.commit()
        return rule

    async def get_rule_by_id(self, rule_id: uuid.UUID) -> Optional[DetectionRule]:
        """Fetch a rule by primary key UUID."""
        stmt = select(DetectionRule).where(DetectionRule.id == rule_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_rule_by_name(self, name: str) -> Optional[DetectionRule]:
        """Fetch a rule by exact name."""
        stmt = select(DetectionRule).where(DetectionRule.name == name)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_rules(self, params: RuleFilterParams) -> Tuple[List[DetectionRule], int]:
        """Search and list rules with filtering and pagination."""
        stmt = select(DetectionRule)

        if params.rule_type:
            stmt = stmt.where(DetectionRule.rule_type == params.rule_type)

        if params.status:
            stmt = stmt.where(DetectionRule.status == params.status)

        if params.severity:
            stmt = stmt.where(DetectionRule.severity == params.severity)

        if params.category:
            stmt = stmt.where(DetectionRule.category.ilike(f"%{params.category}%"))

        if params.query:
            term = f"%{params.query}%"
            stmt = stmt.where(
                or_(
                    DetectionRule.name.ilike(term),
                    DetectionRule.description.ilike(term),
                    DetectionRule.content.ilike(term),
                )
            )

        count_stmt = select(DetectionRule.id).select_from(stmt.subquery())
        count_res = await self.session.execute(count_stmt)
        total_count = len(count_res.scalars().all())

        stmt = stmt.order_by(DetectionRule.created_at.desc())
        stmt = stmt.offset((params.page - 1) * params.page_size).limit(params.page_size)

        result = await self.session.execute(stmt)
        return list(result.scalars().all()), total_count

    async def update_rule(self, rule_id: uuid.UUID, data: DetectionRuleUpdate, new_validation_status: Optional[str] = None) -> Optional[DetectionRule]:
        """Update an existing rule and create version snapshot if content changes."""
        rule = await self.get_rule_by_id(rule_id)
        if not rule:
            return None

        content_changed = data.content is not None and data.content != rule.content
        if content_changed:
            rule.version += 1

        update_dict = data.model_dump(exclude={"change_summary"}, exclude_unset=True)
        for field, val in update_dict.items():
            setattr(rule, field, val)

        if new_validation_status:
            rule.validation_status = new_validation_status

        await self.session.commit()

        if content_changed:
            version_snapshot = RuleVersion(
                rule_id=rule.id,
                version=rule.version,
                content=rule.content,
                change_summary=data.change_summary or f"Updated rule to version {rule.version}",
                created_by=rule.author,
            )
            self.session.add(version_snapshot)
            await self.session.commit()

        await self.session.refresh(rule)
        return rule

    async def delete_rule(self, rule_id: uuid.UUID) -> bool:
        """Delete a detection rule."""
        rule = await self.get_rule_by_id(rule_id)
        if not rule:
            return False

        await self.session.delete(rule)
        await self.session.commit()
        return True

    async def list_versions(self, rule_id: uuid.UUID) -> List[RuleVersion]:
        """Fetch version history for a rule."""
        stmt = select(RuleVersion).where(RuleVersion.rule_id == rule_id).order_by(RuleVersion.version.desc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_version_by_number(self, rule_id: uuid.UUID, version_num: int) -> Optional[RuleVersion]:
        """Fetch specific version snapshot by version number."""
        stmt = select(RuleVersion).where(and_(RuleVersion.rule_id == rule_id, RuleVersion.version == version_num))
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def record_execution(self, rule_id: uuid.UUID, matched: bool, exec_time_ms: float, matches_count: int, details: Dict[str, Any]) -> RuleExecution:
        """Record dry-run execution and update rule stats."""
        exec_record = RuleExecution(
            rule_id=rule_id,
            execution_type="DRY_RUN",
            matched=matched,
            execution_time_ms=exec_time_ms,
            matches_count=matches_count,
            details=details,
        )
        self.session.add(exec_record)

        rule = await self.get_rule_by_id(rule_id)
        if rule:
            rule.execution_count += 1
            if matched:
                rule.match_count += matches_count
                rule.last_triggered = func.now()

        await self.session.commit()
        return exec_record

    async def get_statistics_metrics(self) -> Dict[str, Any]:
        """Aggregate totals for Detection Rule Engine dashboard."""
        total_stmt = select(func.count(DetectionRule.id))
        total_res = await self.session.execute(total_stmt)
        total_rules = total_res.scalar() or 0

        active_stmt = select(func.count(DetectionRule.id)).where(DetectionRule.status == RuleStatus.ACTIVE)
        active_res = await self.session.execute(active_stmt)
        active_rules = active_res.scalar() or 0

        draft_stmt = select(func.count(DetectionRule.id)).where(DetectionRule.status == RuleStatus.DRAFT)
        draft_res = await self.session.execute(draft_stmt)
        draft_rules = draft_res.scalar() or 0

        testing_stmt = select(func.count(DetectionRule.id)).where(DetectionRule.status == RuleStatus.TESTING)
        testing_res = await self.session.execute(testing_stmt)
        testing_rules = testing_res.scalar() or 0

        return {
            "total_rules_count": total_rules,
            "active_rules_count": active_rules,
            "draft_rules_count": draft_rules,
            "testing_rules_count": testing_rules,
        }
