"""
DFIR Artifact Normalizer and Classifier.

Normalizes forensic evidence, timeline events, alerts, and threat intelligence into
standardized NormalizedArtifact objects without creating duplicate database entities.
"""

from typing import List, Set
from app.ai.agents.dfir.schemas import NormalizedArtifact, ArtifactCategory
from app.ai.orchestrator.state import InvestigationState


class ArtifactNormalizer:
    """Normalizes and classifies raw state telemetry into structured forensic artifacts."""

    def normalize(self, state: InvestigationState) -> List[NormalizedArtifact]:
        """Extract and categorize normalized forensic artifacts from investigation state."""
        artifacts: List[NormalizedArtifact] = []
        seen_keys: Set[str] = set()

        def add_art(
            val: str,
            cat: ArtifactCategory,
            source: str,
            ts: str = None,
            ent: str = None,
            ev_id: str = None,
            tl_id: str = None,
            meta: dict = None,
        ):
            val_clean = val.strip()
            if not val_clean:
                return
            key = f"{cat.value}:{val_clean.lower()}"
            if key not in seen_keys:
                seen_keys.add(key)
                artifacts.append(
                    NormalizedArtifact(
                        value=val_clean,
                        category=cat,
                        source=source,
                        timestamp=ts,
                        entity=ent,
                        related_evidence_id=ev_id,
                        related_timeline_event_id=tl_id,
                        metadata=meta or {},
                    )
                )

        # 1. Normalize Evidence
        for ev in state.evidence:
            ev_id = str(ev.get("evidence_id") or ev.get("id") or "evidence")
            ts = ev.get("timestamp") or ev.get("created_at")
            ent = ev.get("host") or ev.get("hostname")
            
            if "sha256" in ev:
                add_art(ev["sha256"], ArtifactCategory.FILE, source=f"evidence:{ev_id}", ts=ts, ent=ent, ev_id=ev_id, meta=ev)
            if "file_name" in ev:
                add_art(ev["file_name"], ArtifactCategory.FILE, source=f"evidence:{ev_id}", ts=ts, ent=ent, ev_id=ev_id, meta=ev)
            if "file_path" in ev:
                add_art(ev["file_path"], ArtifactCategory.FILE, source=f"evidence:{ev_id}", ts=ts, ent=ent, ev_id=ev_id, meta=ev)
            if "process_name" in ev:
                add_art(ev["process_name"], ArtifactCategory.PROCESS, source=f"evidence:{ev_id}", ts=ts, ent=ent, ev_id=ev_id, meta=ev)

        # 2. Normalize Timeline Events
        for te in state.timeline:
            tl_id = str(te.get("event_id") or te.get("id") or "timeline")
            ts = te.get("timestamp")
            ent = te.get("entity") or te.get("host")
            summary = te.get("summary") or te.get("description") or ""

            category = ArtifactCategory.LOG
            sum_lower = summary.lower()
            if "process" in sum_lower or "powershell" in sum_lower or "cmd" in sum_lower:
                category = ArtifactCategory.PROCESS
            elif "login" in sum_lower or "auth" in sum_lower:
                category = ArtifactCategory.AUTHENTICATION
            elif "network" in sum_lower or "ip" in sum_lower or "connection" in sum_lower:
                category = ArtifactCategory.NETWORK
            elif "registry" in sum_lower or "hklm" in sum_lower:
                category = ArtifactCategory.REGISTRY

            add_art(summary, category, source=f"timeline:{tl_id}", ts=ts, ent=ent, tl_id=tl_id, meta=te)

        # 3. Normalize Alerts
        for alert in state.alerts:
            alt_id = str(alert.get("alert_id") or alert.get("id") or "alert")
            ts = alert.get("timestamp")
            ent = alert.get("host") or alert.get("user")

            if "process_name" in alert:
                add_art(alert["process_name"], ArtifactCategory.PROCESS, source=f"alert:{alt_id}", ts=ts, ent=ent, meta=alert)
            if "command_line" in alert:
                add_art(alert["command_line"], ArtifactCategory.PROCESS, source=f"alert:{alt_id}", ts=ts, ent=ent, meta=alert)
            if "ip" in alert or "src_ip" in alert or "dst_ip" in alert:
                ip_val = alert.get("ip") or alert.get("dst_ip") or alert.get("src_ip")
                add_art(ip_val, ArtifactCategory.NETWORK, source=f"alert:{alt_id}", ts=ts, ent=ent, meta=alert)

        return artifacts
