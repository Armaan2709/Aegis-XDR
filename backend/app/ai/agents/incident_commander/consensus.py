"""
Incident Consensus Engine.

Evaluates multi-agent agreement, partial agreement, disagreement, and evidence support score.
Identifies contradictory agent verdicts and computes agent agreement score.
"""

from typing import List, Dict, Any, Tuple
from app.ai.orchestrator.state import InvestigationState


class IncidentConsensusEngine:
    """Consensus and conflict evaluation engine for multi-agent investigation outputs."""

    def evaluate_consensus(
        self, state: InvestigationState
    ) -> Tuple[float, int, float, str, List[Dict[str, Any]]]:
        """
        Evaluate multi-agent consensus across state.agent_results.

        Returns:
            Tuple of (agent_agreement_score, conflict_count, evidence_support_score, consensus_status, conflicts)
        """
        results = list(state.agent_results.values())
        if not results:
            return 1.0, 0, 0.50, "INSUFFICIENT_EVIDENCE", []

        if len(results) == 1:
            return 1.0, 0, 0.75, "AGREEMENT", []

        conflicts: List[Dict[str, Any]] = []
        verdicts: Dict[str, Tuple[str, str]] = {}  # key -> (agent_name, verdict)

        for r in results:
            agent_name = getattr(r, "agent_name", "Agent")
            findings = getattr(r, "findings", []) or []
            for f in findings:
                if isinstance(f, dict):
                    key = f.get("category") or f.get("title") or f.get("candidate_id")
                    verdict = f.get("verdict") or f.get("rule_type") or f.get("severity")
                    if key and verdict:
                        if key in verdicts and verdicts[key][1] != verdict:
                            conflicts.append({
                                "finding_key": key,
                                "agent_a": verdicts[key][0],
                                "verdict_a": verdicts[key][1],
                                "agent_b": agent_name,
                                "verdict_b": verdict,
                            })
                        else:
                            verdicts[key] = (agent_name, str(verdict))

        conflict_count = len(conflicts)
        agreement_score = round(max(0.0, 1.0 - (conflict_count * 0.25)), 2)

        ev_count = len(state.evidence)
        evidence_support_score = round(min(1.0, 0.40 + (ev_count * 0.20)), 2)

        if conflict_count == 0:
            status = "AGREEMENT"
        elif conflict_count <= 2:
            status = "PARTIAL_AGREEMENT"
        else:
            status = "DISAGREEMENT"

        return agreement_score, conflict_count, evidence_support_score, status, conflicts
