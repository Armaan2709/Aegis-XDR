"""
Detection Rule Quality Analyzer and Duplicate Detector.

Evaluates candidate rule quality (0-100 score), checks for duplicates in existing rule registries,
and runs dry-run test validations using Sprint 8 RuleValidator and RuleTester.
"""

from typing import List, Dict, Any, Optional
from app.detection_engine.rule_validator import RuleValidator
from app.detection_engine.rule_tester import RuleTester, RuleTestRequest
from app.ai.agents.detection_generator.schemas import (
    DetectionRuleCandidate,
    RuleQualityScore,
    RuleQualityLevel,
)


class DetectionRuleQualityAnalyzer:
    """Quality analyzer and duplicate detector delegating checks to Sprint 8 Detection Engine."""

    def evaluate_quality(
        self,
        candidate: DetectionRuleCandidate,
        existing_rules: Optional[List[Dict[str, Any]]] = None,
        sample_log: Optional[str] = None,
    ) -> RuleQualityScore:
        """Evaluate candidate rule syntax, duplicate status, and dry-run execution quality."""
        warnings: List[str] = []
        recommendations: List[str] = []
        is_dup = False
        dup_name = None

        # 1. Delegate validation to Sprint 8 RuleValidator
        val_res = RuleValidator.validate(
            name=candidate.title,
            content=candidate.detection_logic,
            rule_type=candidate.rule_type,
            severity=candidate.severity,
        )

        if not val_res.is_valid:
            return RuleQualityScore(
                quality_score=0.0,
                quality_level=RuleQualityLevel.REJECTED,
                warnings=val_res.errors,
                recommendations=["Fix syntax errors in rule detection logic."],
                is_duplicate=False,
            )

        warnings.extend(val_res.warnings)

        # 2. Check for Duplicates in existing rules
        if existing_rules:
            logic_lower = candidate.detection_logic.lower()
            for ex in existing_rules:
                ex_content = ex.get("content", "").lower()
                ex_name = ex.get("name", "Existing Rule")
                if ex_content and (logic_lower in ex_content or ex_content in logic_lower):
                    is_dup = True
                    dup_name = ex_name
                    warnings.append(f"Existing detection rule '{ex_name}' covers matching logic.")
                    break

        # 3. Perform Dry-Run test using Sprint 8 RuleTester
        test_sample = sample_log or candidate.detection_logic
        test_req = RuleTestRequest(
            rule_type=candidate.rule_type,
            rule_content=candidate.detection_logic,
            sample_data=test_sample,
        )
        test_res = RuleTester.test_rule(test_req)

        # 4. Calculate Quality Score (0-100)
        base_score = 80.0
        if candidate.mitre_techniques:
            base_score += 10.0
        if candidate.false_positive_notes and len(candidate.false_positive_notes) > 10:
            base_score += 5.0
        if test_res.matched:
            base_score += 5.0

        if is_dup:
            base_score -= 30.0
        if warnings:
            base_score -= len(warnings) * 5.0

        final_score = round(max(0.0, min(100.0, base_score)), 1)

        if final_score >= 85.0:
            q_level = RuleQualityLevel.EXCELLENT
        elif final_score >= 70.0:
            q_level = RuleQualityLevel.GOOD
        elif final_score >= 50.0:
            q_level = RuleQualityLevel.ACCEPTABLE
        elif final_score >= 30.0:
            q_level = RuleQualityLevel.WEAK
        else:
            q_level = RuleQualityLevel.REJECTED

        if not candidate.mitre_techniques:
            recommendations.append("Attach relevant MITRE ATT&CK technique tags.")
        if is_dup:
            recommendations.append(f"Consider updating existing rule '{dup_name}' instead of deploying duplicate.")

        return RuleQualityScore(
            quality_score=final_score,
            quality_level=q_level,
            warnings=warnings,
            recommendations=recommendations,
            is_duplicate=is_dup,
            duplicate_rule_name=dup_name,
        )
