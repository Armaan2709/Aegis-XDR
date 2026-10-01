"""
Threat Hunter Findings and Recommendations Generator.

Generates structured ThreatFinding and ThreatRecommendation outputs based on observable evidence,
hypotheses, and correlation context.
Enforces requires_human_approval = True for all SOAR response recommendations.
"""

from typing import List, Dict, Any, Tuple
from app.ai.agents.threat_hunter.schemas import (
    ObservableItem,
    ThreatHypothesis,
    ThreatFinding,
    ThreatRecommendation,
    HypothesisStatus,
)
from app.ai.orchestrator.state import InvestigationState


class ThreatRecommendationGenerator:
    """Generator for structured findings and human-governed security recommendations."""

    def generate_findings_and_recommendations(
        self,
        observables: List[ObservableItem],
        hypotheses: List[ThreatHypothesis],
        correlation: Dict[str, Any],
        confidence: float,
        risk_score: float,
        state: InvestigationState,
    ) -> Tuple[List[ThreatFinding], List[ThreatRecommendation]]:
        """Generate traceable findings and human-governed advisory recommendations."""
        findings: List[ThreatFinding] = []
        recommendations: List[ThreatRecommendation] = []

        # 1. Generate Findings from Hypotheses
        for hyp in hypotheses:
            if hyp.status in (HypothesisStatus.SUPPORTED, HypothesisStatus.INVESTIGATING):
                severity = "HIGH" if hyp.risk_score >= 70.0 else "MEDIUM"
                ioc_values = [o.value for o in observables]
                
                finding = ThreatFinding(
                    title=hyp.title,
                    description=hyp.description,
                    severity=severity,
                    confidence=hyp.confidence,
                    risk_score=hyp.risk_score,
                    evidence=hyp.evidence,
                    related_iocs=ioc_values,
                    mitre_techniques=hyp.mitre_techniques,
                    affected_entities=correlation.get("affected_hosts", ["WKSTN-01"]),
                    reasoning_summary=f"Formulated hypothesis based on {len(hyp.evidence)} supporting evidence items.",
                )
                findings.append(finding)

                # 2. Generate Recommendations for Findings
                if "PowerShell" in hyp.title:
                    recommendations.append(
                        ThreatRecommendation(
                            title="Collect Forensic Endpoint Dump & Review Script Logging",
                            description="Execute script block logging audit and collect memory dump from target host.",
                            priority="HIGH",
                            rationale="Obfuscated PowerShell execution detected; verify payload injection.",
                            related_finding=finding.finding_id,
                            suggested_playbook="PB-COLLECT-DIAGNOSTICS",
                            requires_human_approval=True, # STRICT HUMAN GOVERNANCE
                        )
                    )
                if "Credential" in hyp.title or "LSASS" in hyp.title:
                    recommendations.append(
                        ThreatRecommendation(
                            title="Request Endpoint Isolation & Credential Reset",
                            description="Isolate compromised endpoint and initiate privileged credential rotation.",
                            priority="URGENT",
                            rationale="Potential LSASS memory dumping detected; risk of lateral movement.",
                            related_finding=finding.finding_id,
                            suggested_playbook="PB-CONTAIN-ENDPOINT",
                            requires_human_approval=True, # STRICT HUMAN GOVERNANCE
                        )
                    )
                if "C2" in hyp.title or "Command and Control" in hyp.title:
                    recommendations.append(
                        ThreatRecommendation(
                            title="Block Malicious C2 IP Address at Perimeter Firewall",
                            description="Add identified C2 IP addresses to perimeter blocklists.",
                            priority="HIGH",
                            rationale="Active C2 beaconing pattern identified in telemetry.",
                            related_finding=finding.finding_id,
                            suggested_playbook="PB-BLOCK-IOC",
                            requires_human_approval=True, # STRICT HUMAN GOVERNANCE
                        )
                    )

        # Baseline Recommendation if empty
        if not recommendations:
            recommendations.append(
                ThreatRecommendation(
                    title="Monitor Endpoint Behavioral Telemetry",
                    description="Continue passive monitoring of process execution and network traffic.",
                    priority="LOW",
                    rationale="No definitive malicious threshold breached during hunt iteration.",
                    suggested_playbook=None,
                    requires_human_approval=False,
                )
            )

        return findings, recommendations
