"""
Threat Hunter Observable Extractor and Analyzer.

Extracts security observables (IPs, domains, hashes, processes, command lines, registry keys, users)
from InvestigationState and enriches them via registered read-only security tools.
"""

import re
from typing import List, Dict, Any, Set
from app.ai.agents.threat_hunter.schemas import ObservableItem, ObservableType
from app.ai.orchestrator.state import InvestigationState
from app.ai.tools.registry import ToolRegistry


class ObservableAnalyzer:
    """Extractor and analyzer for security observables in investigation state."""

    IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    HASH_SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
    HASH_MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
    DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b")
    PROCESS_PATTERNS = {"powershell.exe", "cmd.exe", "lsass.exe", "rundll32.exe", "reg.exe", "wmic.exe", "certutil.exe", "schtasks.exe"}

    def extract_observables(self, state: InvestigationState) -> List[ObservableItem]:
        """Extract structured observables from investigation state alerts, evidence, timeline, and threat intel."""
        observables: List[ObservableItem] = []
        seen_keys: Set[str] = set()

        def add_obs(val: str, o_type: ObservableType, source: str, entity: str = None, meta: dict = None):
            val_clean = val.strip()
            key = f"{o_type.value}:{val_clean.lower()}"
            if key not in seen_keys and val_clean:
                seen_keys.add(key)
                observables.append(
                    ObservableItem(
                        value=val_clean,
                        type=o_type,
                        source=source,
                        related_entity=entity,
                        metadata=meta or {},
                    )
                )

        # 1. Extract from Alerts
        for alert in state.alerts:
            source_id = alert.get("alert_id") or alert.get("id") or "alert"
            entity = alert.get("host") or alert.get("hostname") or alert.get("user")
            
            # String search in alert fields
            raw_text = str(alert)
            for ip in self.IP_REGEX.findall(raw_text):
                if ip not in ("127.0.0.1", "0.0.0.0"):
                    add_obs(ip, ObservableType.IP_ADDRESS, source=f"alert:{source_id}", entity=entity)
            for h in self.HASH_SHA256_REGEX.findall(raw_text):
                add_obs(h, ObservableType.HASH, source=f"alert:{source_id}", entity=entity)

            # Specific fields
            if "process_name" in alert:
                add_obs(alert["process_name"], ObservableType.PROCESS, source=f"alert:{source_id}", entity=entity)
            if "command_line" in alert:
                add_obs(alert["command_line"], ObservableType.COMMAND_LINE, source=f"alert:{source_id}", entity=entity)
            if "user" in alert:
                add_obs(alert["user"], ObservableType.USER_ACCOUNT, source=f"alert:{source_id}", entity=entity)

        # 2. Extract from Evidence
        for ev in state.evidence:
            ev_id = ev.get("evidence_id") or ev.get("id") or "evidence"
            if "sha256" in ev:
                add_obs(ev["sha256"], ObservableType.HASH, source=f"evidence:{ev_id}")
            if "file_name" in ev:
                add_obs(ev["file_name"], ObservableType.PROCESS, source=f"evidence:{ev_id}")

        # 3. Extract from Timeline Events
        for event in state.timeline:
            evt_id = event.get("event_id") or event.get("id") or "timeline"
            summary = str(event.get("summary") or event.get("description") or "")
            for proc in self.PROCESS_PATTERNS:
                if proc in summary.lower():
                    add_obs(proc, ObservableType.PROCESS, source=f"timeline:{evt_id}")

        # 4. Extract from Threat Intel
        for ti in state.threat_intelligence:
            ioc = ti.get("ioc_value") or ti.get("ioc")
            if ioc:
                ioc_type = ObservableType.IP_ADDRESS if self.IP_REGEX.match(ioc) else ObservableType.DOMAIN
                add_obs(ioc, ioc_type, source="threat_intelligence", meta=ti)

        return observables

    async def analyze_observables(
        self, observables: List[ObservableItem], tool_registry: ToolRegistry
    ) -> Dict[str, Any]:
        """Query registered read-only security tools to enrich observables."""
        results: Dict[str, Any] = {"enriched_iocs": [], "siem_matches": [], "tool_runs": 0}

        ti_tool = tool_registry.get("query_threat_intel")
        siem_tool = tool_registry.get("query_siem_logs")

        for obs in observables:
            if obs.type in (ObservableType.IP_ADDRESS, ObservableType.DOMAIN, ObservableType.HASH) and ti_tool:
                try:
                    res = await ti_tool.execute({"ioc_value": obs.value, "ioc_type": obs.type.value})
                    results["enriched_iocs"].append({
                        "observable": obs.value,
                        "type": obs.type.value,
                        "reputation": res.get("reputation_score", 0.0),
                        "verdict": res.get("verdict", "UNKNOWN"),
                        "threat_actor": res.get("associated_threat_actor"),
                    })
                    results["tool_runs"] += 1
                except Exception:
                    pass

            if obs.type == ObservableType.COMMAND_LINE and siem_tool:
                try:
                    res = await siem_tool.execute({"query": f"command_line:{obs.value}"})
                    results["siem_matches"].append({
                        "command_line": obs.value,
                        "matched_events": res.get("matched_events_count", 0),
                    })
                    results["tool_runs"] += 1
                except Exception:
                    pass

        return results
