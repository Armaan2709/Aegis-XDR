"""
Severity and Priority Engine.

Calculates deterministic risk score (0-100), confidence score (0.0-1.0),
severity level (LOW, MEDIUM, HIGH, CRITICAL), and priority (P1, P2, P3, P4).
"""

from typing import Tuple
from app.ai.orchestrator.state import InvestigationState


class SeverityPriorityEngine:
    """Deterministic severity, priority, risk, and confidence calculation engine."""

    def calculate_scores(self, state: InvestigationState) -> Tuple[float, float, str, str]:
        """
        Calculate deterministic scores from InvestigationState.

        Returns:
            Tuple of (risk_score, confidence_score, severity, priority)
        """
        base_risk = 30.0

        # Alert count & severities
        if state.alerts:
            base_risk += min(30.0, len(state.alerts) * 10.0)
            high_alts = [a for a in state.alerts if str(a.get("severity", "")).upper() in ("HIGH", "CRITICAL")]
            if high_alts:
                base_risk += 15.0

        # Evidence count
        if state.evidence:
            base_risk += min(20.0, len(state.evidence) * 10.0)

        # Agent results & findings
        agent_confs = []
        for r in state.agent_results.values():
            conf = getattr(r, "confidence_score", 0.8)
            agent_confs.append(conf)
            findings = getattr(r, "findings", []) or []
            if len(findings) > 2:
                base_risk += 10.0

        risk_score = round(max(0.0, min(100.0, base_risk)), 1)

        # Confidence Score (Average of executing agent confidence or 0.85 baseline)
        confidence_score = round(sum(agent_confs) / len(agent_confs), 2) if agent_confs else 0.85

        # Severity mapping
        if risk_score >= 85.0:
            severity = "CRITICAL"
            priority = "P1"
        elif risk_score >= 65.0:
            severity = "HIGH"
            priority = "P2"
        elif risk_score >= 40.0:
            severity = "MEDIUM"
            priority = "P3"
        else:
            severity = "LOW"
            priority = "P4"

        return risk_score, confidence_score, severity, priority
