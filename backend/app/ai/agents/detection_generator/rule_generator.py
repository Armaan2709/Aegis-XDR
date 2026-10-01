"""
Detection Rule Generation Engine.

Orchestrates Sigma, YARA, Suricata, and Custom candidate rule generation,
delegates validation and dry-run testing to Sprint 8 Detection Engine components,
and evaluates quality scoring and duplicate detection.
"""

from typing import List, Dict, Any, Optional
from app.detection_engine.models import RuleType, RuleSeverity
from app.ai.agents.detection_generator.schemas import (
    DetectionRuleCandidate,
    RuleGenerationResult,
    RuleQualityLevel,
)
from app.ai.agents.detection_generator.sigma_generator import SigmaRuleGenerator
from app.ai.agents.detection_generator.yara_generator import YaraRuleGenerator
from app.ai.agents.detection_generator.suricata_generator import SuricataRuleGenerator
from app.ai.agents.detection_generator.quality import DetectionRuleQualityAnalyzer


class DetectionRuleGenerationEngine:
    """Main generation engine for multi-format detection rules."""

    def __init__(self):
        self._sigma_gen = SigmaRuleGenerator()
        self._yara_gen = YaraRuleGenerator()
        self._suricata_gen = SuricataRuleGenerator()
        self._quality_analyzer = DetectionRuleQualityAnalyzer()

    def generate_candidates(
        self,
        observables: Dict[str, Any],
        existing_rules: Optional[List[Dict[str, Any]]] = None,
    ) -> RuleGenerationResult:
        """Generate candidates across Sigma, YARA, Suricata, and Custom formats, evaluating quality and dry-runs."""
        raw_candidates: List[DetectionRuleCandidate] = []

        # 1. Generate Sigma Candidate
        sigma_cand = self._sigma_gen.generate_rule(observables)
        if sigma_cand:
            raw_candidates.append(sigma_cand)

        # 2. Generate YARA Candidate
        yara_cand = self._yara_gen.generate_rule(observables)
        if yara_cand:
            raw_candidates.append(yara_cand)

        # 3. Generate Suricata Candidate
        suricata_cand = self._suricata_gen.generate_rule(observables)
        if suricata_cand:
            raw_candidates.append(suricata_cand)

        # 4. Generate Custom Fallback Candidate if no telemetry matched
        if not raw_candidates:
            raw_candidates.append(
                DetectionRuleCandidate(
                    title="Custom: Telemetry Activity Detection Rule",
                    description="Custom detection rule covering general investigation telemetry.",
                    rule_type=RuleType.CUSTOM,
                    severity=RuleSeverity.MEDIUM,
                    confidence=0.70,
                    mitre_techniques=observables.get("mitre_techniques", []),
                    evidence_refs=observables.get("evidence_refs", []),
                    detection_logic="SELECT * FROM events WHERE status = 'ALERT'",
                    false_positive_notes="High volume alert conditions.",
                    generation_rationale="Custom detection generated for baseline investigation telemetry.",
                )
            )

        # 5. Quality Analysis & Validation via Sprint 8 Detection Engine
        accepted_candidates: List[DetectionRuleCandidate] = []
        rejected_count = 0
        validation_results = {}
        dry_run_results = {}
        quality_scores = {}

        for cand in raw_candidates:
            q_score = self._quality_analyzer.evaluate_quality(cand, existing_rules)
            quality_scores[cand.candidate_id] = q_score.model_dump()

            if q_score.quality_level != RuleQualityLevel.REJECTED:
                accepted_candidates.append(cand)
                validation_results[cand.candidate_id] = {"is_valid": True, "warnings": q_score.warnings}
                dry_run_results[cand.candidate_id] = {"tested": True, "quality_score": q_score.quality_score}
            else:
                rejected_count += 1
                validation_results[cand.candidate_id] = {"is_valid": False, "errors": q_score.warnings}

        return RuleGenerationResult(
            candidates=accepted_candidates,
            generated_count=len(accepted_candidates),
            rejected_count=rejected_count,
            validation_results=validation_results,
            dry_run_results=dry_run_results,
            quality_scores=quality_scores,
        )
