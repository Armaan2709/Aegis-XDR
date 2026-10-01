"""
IOC Analyzer and Normalization Engine.

Extracts, validates, and normalizes Indicators of Compromise (IOCs) from investigation state,
alerts, evidence, timeline, Threat Hunter findings, and DFIR findings.

REUSES: app.threat_intelligence.ioc.IOCValidator
"""

from typing import List, Set
from app.threat_intelligence.ioc import IOCValidator
from app.threat_intelligence.models import IOCType
from app.ai.agents.threat_intel.schemas import IOCObservation
from app.ai.orchestrator.state import InvestigationState


class IOCAnalyzer:
    """IOC extraction, validation, and normalization engine reusing domain IOCValidator."""

    def extract_and_normalize(self, state: InvestigationState) -> List[IOCObservation]:
        """Extract indicators from state telemetry and normalize via IOCValidator."""
        observations: List[IOCObservation] = []
        seen_keys: Set[str] = set()

        def add_candidate(raw: str, source: str, meta: dict = None):
            if not raw or not isinstance(raw, str):
                return
            val_clean = raw.strip()
            if not val_clean or len(val_clean) < 3:
                return

            try:
                ioc_type, normalized = IOCValidator.detect_and_normalize(val_clean)
                key = f"{ioc_type.value}:{normalized}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    observations.append(
                        IOCObservation(
                            raw_value=val_clean,
                            normalized_value=normalized,
                            ioc_type=ioc_type,
                            source=source,
                            confidence=0.95 if ioc_type in (IOCType.SHA256, IOCType.IPV4, IOCType.DOMAIN) else 0.80,
                            metadata=meta or {},
                        )
                    )
            except Exception:
                # Safely ignore malformed inputs without crashing
                pass

        # 1. Extract from Evidence
        for ev in state.evidence:
            ev_id = str(ev.get("evidence_id") or ev.get("id") or "evidence")
            for field in ("sha256", "sha1", "md5", "ip", "domain", "url", "process_name", "file_name"):
                if field in ev and ev[field]:
                    add_candidate(str(ev[field]), source=f"evidence:{ev_id}", meta=ev)

        # 2. Extract from Alerts
        for alt in state.alerts:
            alt_id = str(alt.get("alert_id") or alt.get("id") or "alert")
            for field in ("ip", "src_ip", "dst_ip", "domain", "hash", "sha256", "process_name"):
                if field in alt and alt[field]:
                    add_candidate(str(alt[field]), source=f"alert:{alt_id}", meta=alt)

        # 3. Extract from Threat Intelligence domain state
        for ti in state.threat_intelligence:
            val = ti.get("value") or ti.get("ioc_value")
            if val:
                add_candidate(str(val), source="state:threat_intelligence", meta=ti)

        # 4. Extract from Agent Results (Threat Hunter & DFIR Agent)
        for agent_res in state.agent_results.values():
            findings = []
            if isinstance(agent_res, dict):
                findings = agent_res.get("findings", [])
                agent_name = agent_res.get("agent_name", "agent")
            elif hasattr(agent_res, "findings"):
                findings = agent_res.findings
                agent_name = getattr(agent_res, "agent_name", "agent")
            else:
                agent_name = "agent"

            for f in findings:
                if isinstance(f, dict):
                    # Check observables / ioc_values
                    for val in f.get("observables", []) + f.get("ioc_values", []) + f.get("evidence", []):
                        if isinstance(val, str):
                            add_candidate(val, source=f"agent:{agent_name}")
                        elif isinstance(val, dict) and "value" in val:
                            add_candidate(str(val["value"]), source=f"agent:{agent_name}")

        return observations
