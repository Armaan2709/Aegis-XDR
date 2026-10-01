"""
DFIR Forensic Process Tree, Command Line, and Root Cause Analysis Engine.

Analyzes parent-child process hierarchies, command-line obfuscation, network artifacts,
and formulates evidence-backed root-cause hypotheses.

STRICT GUARANTEE:
- Zero shell execution, zero arbitrary Python execution, zero payload decoding execution.
- Read-only static analysis and correlation.
"""

from typing import List, Dict, Any, Tuple
from app.ai.agents.dfir.schemas import (
    NormalizedArtifact,
    ArtifactCategory,
    RootCauseHypothesis,
    RootCauseStatus,
)
from app.ai.orchestrator.state import InvestigationState


class ProcessTreeAnalyzer:
    """Analyzes parent-child process relationships and identifies execution anomalies."""

    SUSPICIOUS_PARENTS = {
        "winword.exe": ["powershell.exe", "cmd.exe", "cscript.exe", "wscript.exe"],
        "excel.exe": ["powershell.exe", "cmd.exe", "mshta.exe"],
        "chrome.exe": ["powershell.exe", "cmd.exe"],
        "services.exe": ["powershell.exe", "rundll32.exe"],
    }

    def analyze_process_trees(self, artifacts: List[NormalizedArtifact]) -> List[Dict[str, Any]]:
        """Identify suspicious process execution hierarchies from process artifacts."""
        observations: List[Dict[str, Any]] = []

        proc_artifacts = [a for a in artifacts if a.category == ArtifactCategory.PROCESS]

        for proc in proc_artifacts:
            val_lower = proc.value.lower()
            if "powershell" in val_lower and ("winword" in val_lower or "excel" in val_lower or "cmd" in val_lower):
                observations.append({
                    "pattern": "Office/Script Parent -> PowerShell Execution",
                    "process": proc.value,
                    "source": proc.source,
                    "confidence": 0.85,
                    "mitre_technique": "T1059.001",
                })
            elif "lsass" in val_lower:
                observations.append({
                    "pattern": "LSASS Memory Inspection / Access",
                    "process": proc.value,
                    "source": proc.source,
                    "confidence": 0.90,
                    "mitre_technique": "T1003.001",
                })

        return observations


class CommandLineAnalyzer:
    """Analyzes process command lines for obfuscation, encoding, and download strings."""

    def analyze_command_lines(self, artifacts: List[NormalizedArtifact]) -> List[Dict[str, Any]]:
        """Detect encoded commands and suspicious flags without executing them."""
        results: List[Dict[str, Any]] = []

        for proc in artifacts:
            if proc.category == ArtifactCategory.PROCESS:
                val = proc.value
                val_lower = val.lower()

                if "-enc" in val_lower or "-e " in val_lower or "base64" in val_lower:
                    results.append({
                        "indicator": "Encoded Command Line Flag Detected",
                        "command": val,
                        "risk": "HIGH",
                        "mitre_technique": "T1027",
                    })
                if "downloadstring" in val_lower or "curl" in val_lower or "wget" in val_lower:
                    results.append({
                        "indicator": "Remote Payload Download Attempt",
                        "command": val,
                        "risk": "HIGH",
                        "mitre_technique": "T1105",
                    })

        return results


class AttackReconstructionEngine:
    """Correlates evidence, timeline, and Threat Hunter context to reconstruct root cause."""

    def reconstruct_attack_and_root_cause(
        self,
        artifacts: List[NormalizedArtifact],
        proc_observations: List[Dict[str, Any]],
        cmd_observations: List[Dict[str, Any]],
        state: InvestigationState,
    ) -> Tuple[List[RootCauseHypothesis], List[str]]:
        """Formulate evidence-backed root cause hypotheses and map MITRE techniques."""
        root_causes: List[RootCauseHypothesis] = []
        mitre_techs: List[str] = []

        # Consume Threat Hunter Agent findings if present in state.agent_results
        hunter_findings = []
        for agent_res in state.agent_results.values():
            if isinstance(agent_res, dict):
                if agent_res.get("agent_name") == "ThreatHunterAgent":
                    hunter_findings.extend(agent_res.get("findings", []))
            elif hasattr(agent_res, "agent_name") and agent_res.agent_name == "ThreatHunterAgent":
                hunter_findings.extend(agent_res.findings if hasattr(agent_res, "findings") else [])


        # Check for spearphishing / document macro initial access evidence
        has_office_parent = any("Office" in obs.get("pattern", "") for obs in proc_observations)
        has_cmd_encoded = bool(cmd_observations)

        if has_office_parent or has_cmd_encoded:
            status = RootCauseStatus.SUPPORTED if (has_office_parent and has_cmd_encoded) else RootCauseStatus.INCONCLUSIVE
            evidence_items = [{"observable": obs["command"], "indicator": obs["indicator"]} for obs in cmd_observations]
            
            root_causes.append(
                RootCauseHypothesis(
                    title="Initial Access via Malicious Document / Obfuscated Script",
                    description="Adversary gained initial access via spearphishing attachment executing obfuscated script payload.",
                    supporting_evidence=evidence_items,
                    confidence=0.88 if status == RootCauseStatus.SUPPORTED else 0.60,
                    status=status,
                )
            )
            mitre_techs.extend(["T1566.001", "T1059.001", "T1027"])

        # Check for credential theft root cause
        has_lsass = any("LSASS" in obs.get("pattern", "") for obs in proc_observations)
        if has_lsass:
            root_causes.append(
                RootCauseHypothesis(
                    title="Credential Access via LSASS Memory Access",
                    description="Adversary executed memory dumping tool targeting Local Security Authority Subsystem Service.",
                    supporting_evidence=[{"pattern": "LSASS Memory Inspection"}],
                    confidence=0.92,
                    status=RootCauseStatus.SUPPORTED,
                )
            )
            mitre_techs.append("T1003.001")

        # Baseline fallback root cause if inconclusive
        if not root_causes:
            root_causes.append(
                RootCauseHypothesis(
                    title="Undetermined Initial Compromise Vector",
                    description="Insufficient forensic artifacts available to confirm exact initial access vector.",
                    supporting_evidence=[],
                    confidence=0.30,
                    status=RootCauseStatus.INCONCLUSIVE,
                )
            )

        # Include Threat Hunter techniques
        for map_item in state.mitre_mappings:
            tech_id = map_item.get("technique_id") or map_item.get("id")
            if tech_id and tech_id not in mitre_techs:
                mitre_techs.append(tech_id)

        return root_causes, list(set(mitre_techs))
