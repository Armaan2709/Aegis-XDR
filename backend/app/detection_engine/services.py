"""
Detection Rule Engine Service Layer.

Orchestrates detection rule lifecycle management, versioning, validation,
dry-run testing, version rollbacks, and statistics reporting.
"""

import uuid
from typing import List, Tuple, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection_engine.repositories import DetectionRuleRepository
from app.detection_engine.rule_validator import RuleValidator, RuleValidationResult
from app.detection_engine.rule_tester import RuleTester, RuleTestRequest, RuleTestResult
from app.detection_engine.rule_versions import RuleVersionManager, VersionDiffResult
from app.detection_engine.schemas import (
    DetectionRuleCreate,
    DetectionRuleUpdate,
    DetectionRuleRead,
    RuleFilterParams,
    RuleVersionRead,
    RollbackRequest,
    DetectionRuleStatisticsRead,
)
from app.core.exceptions import NotFoundError, ConflictError, ValidationError
from app.core.logging import get_logger

logger = get_logger("domain.detection_engine")


class DetectionRuleService:
    """Application Service for Detection Rule management."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = DetectionRuleRepository(session)

    async def create_rule(self, data: DetectionRuleCreate) -> DetectionRuleRead:
        """
        Validate syntax, check for duplicate title, and create rule.
        """
        existing = await self.repo.get_rule_by_name(data.name)
        if existing:
            raise ConflictError(f"Detection Rule with name '{data.name}' already exists.")

        val_res = RuleValidator.validate(name=data.name, content=data.content, rule_type=data.rule_type, severity=data.severity)
        val_status = "VALID" if val_res.is_valid else "INVALID"

        rule = await self.repo.create_rule(data, validation_status=val_status)
        logger.info("Detection Rule created", rule_id=str(rule.id), name=rule.name, type=rule.rule_type)
        return DetectionRuleRead.model_validate(rule)

    async def get_rule(self, rule_id: uuid.UUID) -> DetectionRuleRead:
        """Retrieve rule by primary key UUID."""
        rule = await self.repo.get_rule_by_id(rule_id)
        if not rule:
            raise NotFoundError(f"Detection Rule with ID '{rule_id}' was not found.")
        return DetectionRuleRead.model_validate(rule)

    async def list_rules(self, params: RuleFilterParams) -> Tuple[List[DetectionRuleRead], int]:
        """Search and list detection rules."""
        rules, total = await self.repo.list_rules(params)
        dtos = [DetectionRuleRead.model_validate(r) for r in rules]
        return dtos, total

    async def update_rule(self, rule_id: uuid.UUID, data: DetectionRuleUpdate) -> DetectionRuleRead:
        """Update an existing rule with version snapshotting."""
        rule = await self.repo.get_rule_by_id(rule_id)
        if not rule:
            raise NotFoundError(f"Detection Rule with ID '{rule_id}' was not found.")

        val_status = None
        if data.content:
            target_type = rule.rule_type
            target_sev = data.severity or rule.severity
            val_res = RuleValidator.validate(
                name=data.name or rule.name,
                content=data.content,
                rule_type=target_type,
                severity=target_sev,
            )
            val_status = "VALID" if val_res.is_valid else "INVALID"

        updated = await self.repo.update_rule(rule_id, data, new_validation_status=val_status)
        return DetectionRuleRead.model_validate(updated or rule)

    async def delete_rule(self, rule_id: uuid.UUID) -> bool:
        """Delete a detection rule."""
        success = await self.repo.delete_rule(rule_id)
        if not success:
            raise NotFoundError(f"Detection Rule with ID '{rule_id}' was not found.")
        return True

    async def validate_rule(self, data: DetectionRuleCreate) -> RuleValidationResult:
        """Validate detection rule syntax and metadata without saving."""
        return RuleValidator.validate(
            name=data.name,
            content=data.content,
            rule_type=data.rule_type,
            severity=data.severity,
        )

    async def test_rule(self, rule_id: uuid.UUID, sample_data: str) -> RuleTestResult:
        """Perform dry-run test of a rule against sample data."""
        rule = await self.repo.get_rule_by_id(rule_id)
        if not rule:
            raise NotFoundError(f"Detection Rule with ID '{rule_id}' was not found.")

        req = RuleTestRequest(rule_type=rule.rule_type, rule_content=rule.content, sample_data=sample_data)
        result = RuleTester.test_rule(req)

        await self.repo.record_execution(
            rule_id=rule.id,
            matched=result.matched,
            exec_time_ms=result.execution_time_ms,
            matches_count=result.matches_count,
            details=result.details,
        )
        return result

    async def list_versions(self, rule_id: uuid.UUID) -> List[RuleVersionRead]:
        """Fetch version history for a rule."""
        rule = await self.repo.get_rule_by_id(rule_id)
        if not rule:
            raise NotFoundError(f"Detection Rule with ID '{rule_id}' was not found.")

        versions = await self.repo.list_versions(rule_id)
        return [RuleVersionRead.model_validate(v) for v in versions]

    async def compare_versions(self, rule_id: uuid.UUID, version_a: int, version_b: int) -> VersionDiffResult:
        """Compare two rule versions line by line."""
        ver_a = await self.repo.get_version_by_number(rule_id, version_a)
        ver_b = await self.repo.get_version_by_number(rule_id, version_b)

        if not ver_a or not ver_b:
            raise NotFoundError("One or both requested version numbers were not found.")

        return RuleVersionManager.compare_contents(ver_a.content, ver_b.content, version_a, version_b)

    async def rollback_rule(self, rule_id: uuid.UUID, target_version: int) -> DetectionRuleRead:
        """Rollback rule content to specified version number."""
        target = await self.repo.get_version_by_number(rule_id, target_version)
        if not target:
            raise NotFoundError(f"Version {target_version} for rule '{rule_id}' was not found.")

        update_dto = DetectionRuleUpdate(
            content=target.content,
            change_summary=f"Rolled back to version {target_version}",
        )
        return await self.update_rule(rule_id, update_dto)

    async def get_statistics(self) -> DetectionRuleStatisticsRead:
        """Fetch dashboard statistics for Detection Engine."""
        raw_stats = await self.repo.get_statistics_metrics()
        return DetectionRuleStatisticsRead.model_validate(raw_stats)
