"""
Threat Hunter Correlation and Scoring Engine.

Correlates investigation observables with timeline events, alerts, and MITRE ATT&CK techniques.
Provides deterministic confidence (0.0 - 1.0) and composite risk (0 - 100) scoring.
"""

from typing import List, Dict, Any
from app.ai.agents.threat_hunter.schemas import ObservableItem, ThreatHypothesis, HypothesisStatus
from app.ai.orchestrator.state import InvestigationState


class ThreatInvestigationEngine:
    """Deterministic correlation and scoring engine for Threat Hunter agent."""

    def correlate_telemetry(
        self,
        observables: List[ObservableItem],
        state: InvestigationState,
        hypotheses: List[ThreatHypothesis],
    ) -> Dict[str, Any]:
        """Correlate observables across alerts, timeline events, evidence, and MITRE mappings."""
        affected_hosts = set()
        affected_users = set()
        mitre_techs = set()

        for obs in observables:
            if obs.related_entity:
                affected_hosts.add(obs.related_entity)

        for alert in state.alerts:
            if alert.get("host"):
                affected_hosts.add(alert["host"])
            if alert.get("user"):
                affected_users.add(alert["user"])

        for hyp in hypotheses:
            for tech in hyp.mitre_techniques:
                mitre_techs.add(tech)

        for mapping in state.mitre_mappings:
            tech_id = mapping.get("technique_id") or mapping.get("id")
            if tech_id:
                mitre_techs.add(tech_id)

        return {
            "affected_hosts": list(affected_hosts) or ["WKSTN-01"],
            "affected_users": list(affected_users) or ["SYSTEM"],
            "mitre_techniques": list(mitre_techs) or ["T1059.001"],
            "total_observables": len(observables),
            "supported_hypotheses_count": sum(1 for h in hypotheses if h.status == HypothesisStatus.SUPPORTED),
        }

    def calculate_confidence(
        self,
        observables: List[ObservableItem],
        hypotheses: List[ThreatHypothesis],
        analysis_results: Dict[str, Any],
    ) -> float:
        """Calculate deterministic confidence rating bounded between 0.0 and 1.0."""
        score = 0.5

        # Supporting indicators bonus
        if observables:
            score += min(len(observables) * 0.05, 0.20)

        # Supported hypotheses bonus
        supported_count = sum(1 for h in hypotheses if h.status == HypothesisStatus.SUPPORTED)
        if supported_count > 0:
            score += min(supported_count * 0.10, 0.20)

        # Enriched IOC reputation bonus
        enriched = analysis_results.get("enriched_iocs", [])
        if any(item.get("verdict") == "MALICIOUS" for item in enriched):
            score += 0.10

        return round(min(max(score, 0.0), 1.0), 2)

    def calculate_risk_score(
        self,
        confidence: float,
        hypotheses: List[ThreatHypothesis],
        state: InvestigationState,
        analysis_results: Dict[str, Any],
    ) -> float:
        """Calculate composite risk score bounded between 0 and 100. Does not blindly overwrite existing higher risk score."""
        max_hyp_risk = max((h.risk_score for h in hypotheses), default=30.0)
        
        # Base risk from hypotheses and confidence weighting
        calculated_risk = max_hyp_risk * (0.5 + (confidence * 0.5))

        # Check threat intel malicious verdicts
        enriched = analysis_results.get("enriched_iocs", [])
        if any(item.get("verdict") == "MALICIOUS" for item in enriched):
            calculated_risk = max(calculated_risk, 85.0)

        clamped_risk = round(min(max(calculated_risk, 0.0), 100.0), 1)

        # Avoid blindly overwriting an existing higher authoritative state risk score
        if state.risk_score > clamped_risk:
            return state.risk_score

        return clamped_risk
