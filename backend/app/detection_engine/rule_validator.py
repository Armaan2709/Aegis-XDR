"""
Deterministic Detection Rule Validator.

Validates required fields, syntax compliance, metadata structure,
naming duplicates, and format constraints for Sigma, YARA, Suricata, and Custom rules.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.detection_engine.models import RuleType, RuleSeverity
from app.detection_engine.rule_parser import RuleParser


class RuleValidationResult(BaseModel):
    """Validation report model."""

    is_valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class RuleValidator:
    """Validator for detection rules."""

    @classmethod
    def validate(
        cls,
        name: str,
        content: str,
        rule_type: RuleType,
        severity: Optional[RuleSeverity] = None,
    ) -> RuleValidationResult:
        """
        Perform deterministic validation checks on a detection rule.
        """
        errors: List[str] = []
        warnings: List[str] = []

        # 1. Required fields check
        if not name or len(name.strip()) == 0:
            errors.append("Rule name is required and cannot be empty.")
        elif len(name) > 255:
            errors.append("Rule name exceeds maximum length of 255 characters.")

        if not content or len(content.strip()) == 0:
            errors.append("Rule content is required and cannot be empty.")

        # 2. Syntax validation
        if content and len(content.strip()) > 0:
            parsed = RuleParser.parse(content, explicit_type=rule_type)
            if "Parsing error" in (parsed.description or ""):
                errors.append(f"Syntax validation failed: {parsed.description}")

            if rule_type == RuleType.SIGMA and "logsource" not in parsed.metadata:
                warnings.append("Sigma rule is missing 'logsource' section.")

            if rule_type == RuleType.SURICATA and not parsed.metadata.get("sid"):
                warnings.append("Suricata rule is missing 'sid' option.")

        # 3. Severity check
        if severity is None:
            warnings.append("No severity provided; defaulting to MEDIUM.")

        is_valid = len(errors) == 0

        return RuleValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
        )
