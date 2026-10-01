"""
DFIR Findings and Evidence Gap Detector.

Generates evidence-backed DFIRFinding objects and identifies missing forensic telemetry gaps.
"""

from typing import List, Dict, Any, Tuple
from app.ai.agents.dfir.schemas import (
    NormalizedArtifact,
    ArtifactCategory,
    RootCauseHypothesis,
    DFIRFinding,
    EvidenceGap,
)
from app.ai.orchestrator.state import InvestigationState


class DFIRFindingGenerator:
    """Generator for evidence-backed DFIR findings and telemetry gap analysis."""

    def generate_findings_and_gaps(
        self,
        artifacts: List[NormalizedArtifact],
        root_causes: List[RootCauseHypothesis],
        proc_obs: List[Dict[str, Any]],
        cmd_obs: List[Dict[str, Any]],
        mitre_techs: List[str],
        state: InvestigationState,
    ) -> Tuple[List[DFIRFinding], List[EvidenceGap]]:
        """Produce traceable forensic findings and identify telemetry evidence gaps."""
        findings: List[DFIRFinding] = []
        gaps: List[EvidenceGap] = []

        ev_ids = [str(e.get("evidence_id") or e.get("id")) for e in state.evidence if e.get("evidence_id") or e.get("id")]
        tl_ids = [str(t.get("event_id") or t.get("id")) for t in state.timeline if t.get("event_id") or t.get("id")]
        entities = list({a.entity for a in artifacts if a.entity}) or ["WKSTN-01"]

        # 1. Findings from Root Cause Hypotheses
        for rc in root_causes:
            severity = "CRITICAL" if rc.confidence >= 0.85 else "HIGH"
            finding = DFIRFinding(
                title=rc.title,
                description=rc.description,
                severity=severity,
                confidence=rc.confidence,
                evidence_ids=ev_ids,
                timeline_event_ids=tl_ids,
                affected_entities=entities,
                mitre_techniques=mitre_techs,
                root_cause=rc.title,
                reasoning_summary=f"Reconstructed attack sequence from {len(artifacts)} forensic artifacts.",
            )
            findings.append(finding)

        # 2. Detect Evidence Telemetry Gaps
        categories_present = {a.category for a in artifacts}

        if ArtifactCategory.MEMORY not in categories_present:
            gaps.append(
                EvidenceGap(
                    description="Missing volatile memory image (RAM dump) for process inspection",
                    importance="HIGH",
                    recommended_collection="Acquire RAM image using WinPmem / LiME",
                    priority="HIGH",
                )
            )

        if ArtifactCategory.AUTHENTICATION not in categories_present:
            gaps.append(
                EvidenceGap(
                    description="Missing domain authentication security event logs (Security.evtx / Event ID 4624/4625)",
                    importance="MEDIUM",
                    recommended_collection="Retrieve Windows Security Event Logs from DC / Host",
                    priority="MEDIUM",
                )
            )

        if ArtifactCategory.NETWORK not in categories_present:
            gaps.append(
                EvidenceGap(
                    description="Missing full packet capture (PCAP) or NetFlow network telemetry",
                    importance="MEDIUM",
                    recommended_collection="Collect firewall/proxy traffic logs for target entity",
                    priority="LOW",
                )
            )

        return findings, gaps
