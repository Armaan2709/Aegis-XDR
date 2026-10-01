"""
Threat Intelligence Findings and Intelligence Gap Detector.

Generates evidence-backed ThreatIntelligenceFinding objects and identifies intelligence gaps.
"""

from typing import List, Dict, Any, Tuple
from app.ai.agents.threat_intel.schemas import (
    IOCObservation,
    IntelligenceConsensus,
    ThreatCluster,
    AttributionAssessment,
    ThreatIntelligenceFinding,
    IntelligenceGap,
)
from app.ai.orchestrator.state import InvestigationState


class ThreatIntelFindingGenerator:
    """Generator for threat intelligence findings and intelligence gap analysis."""

    def generate_findings_and_gaps(
        self,
        iocs: List[IOCObservation],
        consensuses: List[IntelligenceConsensus],
        clusters: List[ThreatCluster],
        attribution: AttributionAssessment,
        state: InvestigationState,
    ) -> Tuple[List[ThreatIntelligenceFinding], List[IntelligenceGap]]:
        """Produce structured threat findings and detect intelligence gaps."""
        findings: List[ThreatIntelligenceFinding] = []
        gaps: List[IntelligenceGap] = []

        mitre_techs = [
            m.get("technique_id") or m.get("id")
            for m in state.mitre_mappings
            if m.get("technique_id") or m.get("id")
        ]

        # 1. Findings from Consensuses
        for cons in consensuses:
            if cons.consolidated_threat_score >= 50.0:
                severity = "CRITICAL" if cons.consolidated_threat_score >= 80.0 else "HIGH"
                finding = ThreatIntelligenceFinding(
                    title=f"Suspicious/Malicious IOC Verdict for {cons.ioc_value}",
                    description=f"Multi-provider enrichment generated consolidated threat score of {cons.consolidated_threat_score}/100.",
                    severity=severity,
                    confidence=cons.confidence,
                    threat_score=cons.consolidated_threat_score,
                    ioc_values=[cons.ioc_value],
                    ioc_types=[i.ioc_type.value for i in iocs if i.normalized_value == cons.ioc_value],
                    provider_evidence={
                        "malicious_count": cons.malicious_count,
                        "benign_count": cons.benign_count,
                        "unknown_count": cons.unknown_count,
                        "agreement_ratio": cons.agreement_ratio,
                    },
                    mitre_techniques=mitre_techs,
                    related_entities=["WKSTN-01"],
                    relationship_refs=[state.investigation_id],
                    reasoning_summary=f"Evaluated provider consensus across {len(cons.provider_assessments)} threat intelligence sources.",
                )
                findings.append(finding)

        # Baseline finding if none high risk
        if not findings:
            avg_score = sum(c.consolidated_threat_score for c in consensuses) / len(consensuses) if consensuses else 0.0
            findings.append(
                ThreatIntelligenceFinding(
                    title="Threat Intelligence Evaluation Baseline",
                    description=f"Evaluated {len(iocs)} indicators across registered threat intelligence providers.",
                    severity="INFORMATIONAL",
                    confidence=0.80,
                    threat_score=round(avg_score, 1),
                    ioc_values=[i.normalized_value for i in iocs],
                    ioc_types=list({i.ioc_type.value for i in iocs}),
                    provider_evidence={"status": "EVALUATED"},
                    mitre_techniques=mitre_techs,
                    related_entities=["WKSTN-01"],
                    relationship_refs=[state.investigation_id],
                    reasoning_summary="Standard threat intelligence baseline analysis.",
                )
            )

        # 2. Intelligence Gap Detection
        for cons in consensuses:
            if cons.disagreement_ratio > 0.4:
                gaps.append(
                    IntelligenceGap(
                        description=f"Significant provider disagreement detected for IOC: {cons.ioc_value}",
                        importance="HIGH",
                        priority="HIGH",
                        recommended_next_step=f"Perform manual analyst review or sandbox detonation for {cons.ioc_value}",
                    )
                )
            if cons.unknown_count >= 3:
                gaps.append(
                    IntelligenceGap(
                        description=f"Missing reputation data across providers for IOC: {cons.ioc_value}",
                        importance="MEDIUM",
                        priority="MEDIUM",
                        recommended_next_step=f"Submit {cons.ioc_value} to OTX / VirusTotal for fresh enrichment scan",
                    )
                )

        if not iocs:
            gaps.append(
                IntelligenceGap(
                    description="No valid Indicators of Compromise (IOCs) identified in current state telemetry",
                    importance="HIGH",
                    priority="HIGH",
                    recommended_next_step="Collect additional endpoint event logs and network capture telemetry",
                )
            )

        return findings, gaps
