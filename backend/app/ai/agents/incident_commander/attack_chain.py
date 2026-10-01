"""
Attack Chain Analyzer.

Reconstructs 12-stage MITRE ATT&CK attack chain lifecycle using telemetry,
alerts, and multi-agent findings.
Statuses: OBSERVED, INFERRED, NOT_OBSERVED, UNKNOWN.
"""

from typing import List, Dict, Any
from app.ai.orchestrator.state import InvestigationState
from app.ai.agents.incident_commander.schemas import AttackChainStage, AttackStageStatus


class AttackChainAnalyzer:
    """Reconstructs observed and inferred attack lifecycle stages across 12 tactics."""

    STAGE_TACTICS = [
        "INITIAL_ACCESS",
        "EXECUTION",
        "PERSISTENCE",
        "PRIVILEGE_ESCALATION",
        "DEFENSE_EVASION",
        "CREDENTIAL_ACCESS",
        "DISCOVERY",
        "LATERAL_MOVEMENT",
        "COMMAND_AND_CONTROL",
        "COLLECTION",
        "EXFILTRATION",
        "IMPACT",
    ]

    def reconstruct_attack_chain(self, state: InvestigationState) -> List[AttackChainStage]:
        """Reconstruct 12-stage attack chain based strictly on evidence and findings."""
        stages: List[AttackChainStage] = []
        observed_mitre = set()

        for m in state.mitre_mappings:
            tech = str(m.get("technique_id") or m.get("id") or "")
            if tech:
                observed_mitre.add(tech)

        for agent_res in state.agent_results.values():
            findings = getattr(agent_res, "findings", []) or []
            for f in findings:
                if isinstance(f, dict):
                    for tech in f.get("mitre_techniques", []):
                        observed_mitre.add(str(tech))

        cmds_str = " ".join([str(alt.get("command_line", "")).lower() for alt in state.alerts])
        ips_list = [alt.get("ip") or alt.get("src_ip") for alt in state.alerts if alt.get("ip") or alt.get("src_ip")]

        for tactic in self.STAGE_TACTICS:
            status = AttackStageStatus.NOT_OBSERVED
            desc = f"No observed evidence for tactical stage {tactic}."
            techs: List[str] = []
            confidence = 0.0

            if tactic == "INITIAL_ACCESS":
                if ips_list or any("T1190" in t or "T1566" in t for t in observed_mitre):
                    status = AttackStageStatus.OBSERVED
                    desc = "Observed external network connection or alert ingestion."
                    confidence = 0.85
                else:
                    status = AttackStageStatus.INFERRED
                    desc = "Inferred initial access prior to alert ingestion."
                    confidence = 0.50

            elif tactic == "EXECUTION":
                if "powershell" in cmds_str or "cmd.exe" in cmds_str or any("T1059" in t for t in observed_mitre):
                    status = AttackStageStatus.OBSERVED
                    desc = "Observed script host or command-line interpreter execution."
                    techs = [t for t in observed_mitre if "T1059" in t] or ["T1059.001"]
                    confidence = 0.90

            elif tactic == "COMMAND_AND_CONTROL":
                if ips_list or any("T1071" in t for t in observed_mitre):
                    status = AttackStageStatus.OBSERVED
                    desc = "Observed outbound network communication to remote infrastructure."
                    techs = [t for t in observed_mitre if "T1071" in t] or ["T1071.001"]
                    confidence = 0.88

            elif tactic == "CREDENTIAL_ACCESS":
                if "lsass" in cmds_str or any("T1003" in t for t in observed_mitre):
                    status = AttackStageStatus.OBSERVED
                    desc = "Observed credential dumping or LSASS process interaction."
                    techs = ["T1003"]
                    confidence = 0.92

            elif tactic == "PERSISTENCE":
                if "schtasks" in cmds_str or "reg add" in cmds_str or any("T1053" in t or "T1547" in t for t in observed_mitre):
                    status = AttackStageStatus.OBSERVED
                    desc = "Observed scheduled task or registry persistence modification."
                    techs = ["T1053.005"]
                    confidence = 0.85

            stages.append(
                AttackChainStage(
                    stage=tactic,
                    status=status,
                    description=desc,
                    mitre_techniques=techs,
                    confidence=confidence,
                )
            )

        return stages
