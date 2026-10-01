"""
Suricata Rule Generator.

Generates Suricata network IDS rule candidates from observed malicious IPs, domains, and URLs.
Reuses Sprint 8 Detection Engine validation.
"""

from typing import Dict, Any, Optional
from app.detection_engine.models import RuleType, RuleSeverity
from app.ai.agents.detection_generator.schemas import DetectionRuleCandidate


class SuricataRuleGenerator:
    """Deterministic generator for Suricata network IDS rules."""

    _sid_counter = 1000100

    def generate_rule(self, observables: Dict[str, Any]) -> Optional[DetectionRuleCandidate]:
        """Generate Suricata IDS rule candidate if malicious IPs or domains exist."""
        ips = observables.get("ips", [])
        domains = observables.get("domains", [])
        mitre_techs = observables.get("mitre_techniques", [])
        ev_refs = observables.get("evidence_refs", [])

        if not ips and not domains:
            return None

        target = ips[0] if ips else domains[0]
        SuricataRuleGenerator._sid_counter += 1
        sid = SuricataRuleGenerator._sid_counter

        content = f'alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"AegisAI IDS Alert: Malicious C2 Traffic to {target}"; content:"{target}"; sid:{sid}; rev:1;)'

        return DetectionRuleCandidate(
            title=f"Suricata: Network C2 Signature ({target})",
            description=f"Suricata network signature detecting outbound C2 traffic to {target}.",
            rule_type=RuleType.SURICATA,
            severity=RuleSeverity.HIGH,
            confidence=0.88,
            mitre_techniques=mitre_techs,
            evidence_refs=ev_refs,
            detection_logic=content,
            false_positive_notes="Legitimate network traffic targeting shared hosting or CDN infrastructure.",
            generation_rationale="Generated from network telemetry and IOC IPs/domains observed during investigation.",
        )
