"""
Forensic Timeline Analyzer and Attack Phase Mapper.

Reconstructs chronological attack timelines and maps artifacts to kill-chain AttackPhase phases.
"""

from typing import List, Dict, Any
from app.ai.agents.dfir.schemas import NormalizedArtifact, ArtifactCategory, AttackPhase


class ForensicTimelineAnalyzer:
    """Chronological timeline reconstruction and attack phase mapping engine."""

    def reconstruct_timeline(self, artifacts: List[NormalizedArtifact]) -> List[Dict[str, Any]]:
        """Order artifacts chronologically and associate with attack kill-chain phases."""
        timeline_events: List[Dict[str, Any]] = []

        # Sort artifacts (by timestamp if available, preserving relative order)
        sorted_artifacts = sorted(
            artifacts,
            key=lambda a: a.timestamp if a.timestamp else "9999-12-31T23:59:59Z"
        )

        for art in sorted_artifacts:
            phase = self._determine_attack_phase(art)
            timeline_events.append({
                "artifact_id": art.artifact_id,
                "timestamp": art.timestamp,
                "entity": art.entity,
                "category": art.category.value,
                "value": art.value,
                "source": art.source,
                "attack_phase": phase.value if phase else None,
                "related_evidence_id": art.related_evidence_id,
                "related_timeline_event_id": art.related_timeline_event_id,
            })

        return timeline_events

    def _determine_attack_phase(self, artifact: NormalizedArtifact) -> AttackPhase:
        """Determine kill-chain AttackPhase based on artifact value and metadata."""
        val_lower = artifact.value.lower()

        if "lsass" in val_lower or "mimikatz" in val_lower or "credential" in val_lower:
            return AttackPhase.CREDENTIAL_ACCESS
        elif "powershell" in val_lower or "cmd.exe" in val_lower or "-enc" in val_lower:
            return AttackPhase.EXECUTION
        elif "schtasks" in val_lower or "reg.exe" in val_lower or "run key" in val_lower:
            return AttackPhase.PERSISTENCE
        elif "wmic" in val_lower or "psexec" in val_lower or "smb" in val_lower:
            return AttackPhase.LATERAL_MOVEMENT
        elif artifact.category == ArtifactCategory.NETWORK:
            return AttackPhase.COMMAND_AND_CONTROL
        elif "whoami" in val_lower or "net group" in val_lower:
            return AttackPhase.DISCOVERY
        elif artifact.category == ArtifactCategory.AUTHENTICATION:
            return AttackPhase.INITIAL_ACCESS

        return AttackPhase.EXECUTION
