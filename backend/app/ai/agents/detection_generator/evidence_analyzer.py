"""
Detection Evidence Analyzer.

Extracts detection-worthy observables, behaviors, commands, process trees, and MITRE techniques
from investigation state telemetry, Threat Hunter findings, DFIR findings, and Threat Intel findings.
"""

from typing import List, Dict, Any, Set
from app.ai.orchestrator.state import InvestigationState


class DetectionEvidenceAnalyzer:
    """Extracts detection-worthy observables from investigation state."""

    def analyze_evidence(self, state: InvestigationState) -> Dict[str, Any]:
        """Extract structured observables and behaviors from state telemetry."""
        observables = {
            "ips": set(),
            "domains": set(),
            "hashes": set(),
            "processes": set(),
            "commands": set(),
            "mitre_techniques": set(),
            "evidence_refs": set(),
        }

        # 1. Evidence Extraction
        for ev in state.evidence:
            ev_id = str(ev.get("evidence_id") or ev.get("id") or "evidence")
            observables["evidence_refs"].add(ev_id)
            if ev.get("ip"):
                observables["ips"].add(str(ev["ip"]).strip())
            if ev.get("domain"):
                observables["domains"].add(str(ev["domain"]).strip())
            if ev.get("sha256"):
                observables["hashes"].add(str(ev["sha256"]).strip().lower())
            if ev.get("process_name"):
                observables["processes"].add(str(ev["process_name"]).strip())
            if ev.get("command_line"):
                observables["commands"].add(str(ev["command_line"]).strip())

        # 2. Alerts Extraction
        for alt in state.alerts:
            alt_id = str(alt.get("alert_id") or alt.get("id") or "alert")
            observables["evidence_refs"].add(alt_id)
            if alt.get("ip") or alt.get("src_ip"):
                observables["ips"].add(str(alt.get("ip") or alt.get("src_ip")).strip())
            if alt.get("domain"):
                observables["domains"].add(str(alt["domain"]).strip())
            if alt.get("command_line"):
                observables["commands"].add(str(alt["command_line"]).strip())
            if alt.get("process_name"):
                observables["processes"].add(str(alt["process_name"]).strip())

        # 3. MITRE Mappings
        for m in state.mitre_mappings:
            tech = m.get("technique_id") or m.get("id")
            if tech:
                observables["mitre_techniques"].add(str(tech))

        # 4. Agent Results (Threat Hunter, DFIR, Threat Intel)
        for agent_res in state.agent_results.values():
            findings = []
            if isinstance(agent_res, dict):
                findings = agent_res.get("findings", [])
            elif hasattr(agent_res, "findings"):
                findings = agent_res.findings

            for f in findings:
                if isinstance(f, dict):
                    for tech in f.get("mitre_techniques", []):
                        observables["mitre_techniques"].add(str(tech))
                    for obs in f.get("observables", []) + f.get("ioc_values", []):
                        if isinstance(obs, str):
                            if "." in obs and not obs.endswith(".exe"):
                                observables["domains"].add(obs)
                            elif len(obs) == 64:
                                observables["hashes"].add(obs.lower())

        return {
            "ips": sorted(list(observables["ips"])),
            "domains": sorted(list(observables["domains"])),
            "hashes": sorted(list(observables["hashes"])),
            "processes": sorted(list(observables["processes"])),
            "commands": sorted(list(observables["commands"])),
            "mitre_techniques": sorted(list(observables["mitre_techniques"])),
            "evidence_refs": sorted(list(observables["evidence_refs"])),
        }
