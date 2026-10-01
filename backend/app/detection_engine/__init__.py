"""
Detection Rule Engine Package.

Provides multi-format parsing (Sigma, YARA, Suricata, Custom), deterministic validation,
version control diffs & rollbacks, dry-run testing, registry search, and REST API routes.
"""

from app.detection_engine.models import (
    RuleType,
    RuleStatus,
    RuleSeverity,
    RuleCategory,
    RuleTag,
    DetectionRule,
    RuleVersion,
    RuleExecution,
    RuleStatistics,
    RuleValidation,
    RuleTemplate,
)
from app.detection_engine.schemas import (
    DetectionRuleCreate,
    DetectionRuleUpdate,
    DetectionRuleRead,
    RuleFilterParams,
    RuleVersionRead,
    RollbackRequest,
    DetectionRuleStatisticsRead,
)
from app.detection_engine.rule_parser import RuleParser, ParsedRuleResult
from app.detection_engine.rule_validator import RuleValidator, RuleValidationResult
from app.detection_engine.rule_versions import RuleVersionManager, VersionDiffResult
from app.detection_engine.rule_tester import RuleTester, RuleTestRequest, RuleTestResult
from app.detection_engine.rule_registry import RuleRegistry, DEFAULT_RULE_TEMPLATES
from app.detection_engine.repositories import DetectionRuleRepository
from app.detection_engine.services import DetectionRuleService

__all__ = [
    "RuleType",
    "RuleStatus",
    "RuleSeverity",
    "RuleCategory",
    "RuleTag",
    "DetectionRule",
    "RuleVersion",
    "RuleExecution",
    "RuleStatistics",
    "RuleValidation",
    "RuleTemplate",
    "DetectionRuleCreate",
    "DetectionRuleUpdate",
    "DetectionRuleRead",
    "RuleFilterParams",
    "RuleVersionRead",
    "RollbackRequest",
    "DetectionRuleStatisticsRead",
    "RuleParser",
    "ParsedRuleResult",
    "RuleValidator",
    "RuleValidationResult",
    "RuleVersionManager",
    "VersionDiffResult",
    "RuleTester",
    "RuleTestRequest",
    "RuleTestResult",
    "RuleRegistry",
    "DEFAULT_RULE_TEMPLATES",
    "DetectionRuleRepository",
    "DetectionRuleService",
]

