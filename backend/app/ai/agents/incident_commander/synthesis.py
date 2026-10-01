"""
Incident Synthesis Engine.

Synthesizes multi-agent outputs from ThreatHunterAgent, DFIRInvestigatorAgent,
ThreatIntelligenceAnalystAgent, and DetectionRuleGeneratorAgent. Evaluates evidence backing
versus agent hypotheses and identifies evidence gaps and root causes.
"""

from typing import List, Dict, Any, Tuple
from app.ai.orchestrator.state import InvestigationState
from app.ai.agents.incident_commander.schemas import CommanderFinding


class IncidentSynthesisEngine:
    """Multi-agent synthesis engine combining evidence and specialized agent results."""

    def synthesize(self, state: InvestigationState) -> Tuple[List[CommanderFinding], List[CommanderFinding], List[str], str]:
        """
        Synthesize findings from InvestigationState.

        Returns:
            Tuple of (confirmed_findings, suspected_findings, evidence_gaps, likely_root_cause)
        """
        confirmed: List[CommanderFinding] = []
        suspected: List[CommanderFinding] = []
        gaps: List[str] = []
        contributing_agents: List[str] = list(state.agent_results.keys())

        # 1. Process Evidence Items
        has_file_ev = False
        has_net_ev = False
        has_auth_ev = False

        for ev in state.evidence:
            ev_id = str(ev.get("evidence_id") or ev.get("id") or "evidence")
            if ev.get("sha256") or ev.get("file_path"):
                has_file_ev = True
                confirmed.append(
                    CommanderFinding(
                        title=f"Forensic File Evidence ({ev.get('file_path') or 'Binary'})",
                        description=f"Confirmed forensic file artifact identified with hash {ev.get('sha256', 'N/A')}.",
                        severity="HIGH",
                        confidence=0.95,
                        evidence_refs=[ev_id],
                        supporting_agents=["DFIRInvestigatorAgent"] if "DFIRInvestigatorAgent" in contributing_agents else ["InvestigationState"],
                    )
                )
            if ev.get("ip") or ev.get("domain"):
                has_net_ev = True
                confirmed.append(
                    CommanderFinding(
                        title=f"Network Indicator ({ev.get('ip') or ev.get('domain')})",
                        description=f"Confirmed network connection indicator to {ev.get('ip') or ev.get('domain')}.",
                        severity="MEDIUM",
                        confidence=0.90,
                        evidence_refs=[ev_id],
                        supporting_agents=["ThreatIntelligenceAnalystAgent"] if "ThreatIntelligenceAnalystAgent" in contributing_agents else ["InvestigationState"],
                    )
                )

        # 2. Process Agent Results
        for agent_name, agent_res in state.agent_results.items():
            findings = getattr(agent_res, "findings", []) or []
            conf = getattr(agent_res, "confidence_score", 0.8)

            for f in findings:
                if isinstance(f, dict):
                    f_title = f.get("title") or f.get("category") or f"Finding from {agent_name}"
                    f_desc = f.get("verdict") or f.get("description") or f"Finding recorded by {agent_name}"
                    f_sev = f.get("severity") or "MEDIUM"

                    cmd_f = CommanderFinding(
                        title=f_title,
                        description=f_desc,
                        severity=f_sev,
                        confidence=conf,
                        supporting_agents=[agent_name],
                    )

                    if conf >= 0.85 and (state.evidence or len(contributing_agents) > 1):
                        confirmed.append(cmd_f)
                    else:
                        suspected.append(cmd_f)

        # 3. Identify Evidence Gaps
        if not has_file_ev:
            gaps.append("Missing host memory/file forensic artifacts.")
        if not has_net_ev:
            gaps.append("Missing external firewall / DNS network log telemetry.")
        if not has_auth_ev:
            gaps.append("Missing centralized domain authentication logs (EventID 4624/4625).")

        # 4. Determine Root Cause Conservatively
        likely_root_cause = "Unknown / Inconclusive"

        cmds_str = " ".join([str(alt.get("command_line", "")).lower() for alt in state.alerts])
        if "powershell" in cmds_str or "cmd.exe" in cmds_str:
            likely_root_cause = "Strong evidence suggests malicious command execution / script interpreter abuse."
        elif has_net_ev and has_file_ev:
            likely_root_cause = "Strong evidence suggests external C2 payload delivery and execution."
        elif has_net_ev:
            likely_root_cause = "Most likely unauthorized remote network access or exposed service exploitation."
        elif has_file_ev:
            likely_root_cause = "Most likely endpoint malware execution or untrusted binary dropping."

        return confirmed, suspected, gaps, likely_root_cause
