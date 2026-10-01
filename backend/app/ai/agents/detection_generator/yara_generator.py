"""
YARA Rule Generator.

Generates YARA memory and artifact detection rule candidates from observed file hashes and binary strings.
Reuses Sprint 8 Detection Engine validation.
"""

from typing import Dict, Any, Optional
from app.detection_engine.models import RuleType, RuleSeverity
from app.ai.agents.detection_generator.schemas import DetectionRuleCandidate


class YaraRuleGenerator:
    """Deterministic generator for YARA detection rules."""

    def generate_rule(self, observables: Dict[str, Any]) -> Optional[DetectionRuleCandidate]:
        """Generate YARA rule candidate if binary hashes or artifact strings exist."""
        hashes = observables.get("hashes", [])
        procs = observables.get("processes", [])
        mitre_techs = observables.get("mitre_techniques", [])
        ev_refs = observables.get("evidence_refs", [])

        if not hashes and not procs:
            return None

        target_val = hashes[0] if hashes else (procs[0] if procs else "suspicious_binary")
        rule_name = f"AegisAI_Artifact_Detect_{target_val[:12].replace('-', '_')}"

        content = f"""rule {rule_name} {{
    meta:
        description = "Detects binary artifact or memory string pattern matching {target_val}"
        author = "AegisAI DetectionRuleGeneratorAgent"
    strings:
        $s1 = "{target_val}"
    condition:
        $s1
}}
"""

        return DetectionRuleCandidate(
            title=f"YARA: Memory & File Artifact ({rule_name})",
            description=f"YARA memory/file signature rule matching binary string artifact {target_val}.",
            rule_type=RuleType.YARA,
            severity=RuleSeverity.CRITICAL if hashes else RuleSeverity.HIGH,
            confidence=0.90 if hashes else 0.75,
            mitre_techniques=mitre_techs,
            evidence_refs=ev_refs,
            detection_logic=content,
            false_positive_notes="Valid system binaries sharing similar common string patterns.",
            generation_rationale="Generated from SHA256 file hash and binary process artifacts identified in evidence.",
        )
