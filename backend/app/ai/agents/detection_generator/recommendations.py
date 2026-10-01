"""
Detection Rule Recommendation Generator.

Generates human-governed advisory recommendations for candidate rule deployment, review, or enhancement.
STRICT HUMAN GOVERNANCE: Enforces requires_human_approval = True for all deployment/activation recommendations.
"""

from typing import List
from app.ai.agents.detection_generator.schemas import (
    DetectionRuleCandidate,
    RuleGenerationResult,
    DetectionRuleRecommendation,
)


class DetectionRuleRecommendationGenerator:
    """Generator for human-governed detection rule deployment recommendations."""

    def generate_recommendations(
        self, gen_result: RuleGenerationResult
    ) -> List[DetectionRuleRecommendation]:
        """Generate human-governed advisory deployment recommendations."""
        recommendations: List[DetectionRuleRecommendation] = []

        for cand in gen_result.candidates:
            q_info = gen_result.quality_scores.get(cand.candidate_id, {})
            score = q_info.get("quality_score", 70.0)
            is_dup = q_info.get("is_duplicate", False)
            dup_name = q_info.get("duplicate_rule_name")

            if is_dup:
                recommendations.append(
                    DetectionRuleRecommendation(
                        title=f"Review Existing Rule '{dup_name}' for Enhancement",
                        description=f"Candidate rule '{cand.title}' overlaps with existing rule '{dup_name}'. Recommend updating existing rule version.",
                        priority="MEDIUM",
                        rationale="Prevent duplicate detection rules in production registry.",
                        candidate_rule_id=cand.candidate_id,
                        validation_status="DUPLICATE_DETECTED",
                        quality_score=score,
                        suggested_action="Review and update existing detection rule version",
                        requires_human_approval=True,  # STRICT HUMAN GOVERNANCE
                    )
                )
            elif score >= 70.0:
                recommendations.append(
                    DetectionRuleRecommendation(
                        title=f"Approve & Deploy Candidate Rule: {cand.title}",
                        description=f"Candidate rule '{cand.title}' passed syntax validation and dry-run testing with quality score {score}/100.",
                        priority="HIGH",
                        rationale=cand.generation_rationale,
                        candidate_rule_id=cand.candidate_id,
                        validation_status="VALIDATED",
                        quality_score=score,
                        suggested_action=f"Promote candidate rule {cand.candidate_id} to TESTING/ACTIVE status",
                        requires_human_approval=True,  # STRICT HUMAN GOVERNANCE
                    )
                )

        if not recommendations:
            recommendations.append(
                DetectionRuleRecommendation(
                    title="Detection Engineering Baseline Review",
                    description="Standard review of detection telemetry and rule repository performance.",
                    priority="LOW",
                    rationale="Maintain detection engineering operational baseline.",
                    validation_status="BASELINE",
                    quality_score=50.0,
                    suggested_action="Review telemetry data sources for expanded rule coverage",
                    requires_human_approval=False,
                )
            )

        return recommendations
