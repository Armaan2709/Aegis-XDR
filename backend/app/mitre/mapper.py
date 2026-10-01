"""
Deterministic MITRE ATT&CK Artifact Mapping Engine.

Evaluates security alerts, evidence artifacts, timeline events, and correlation results
against deterministic pattern signatures to assign MITRE Tactics, Techniques, Sub-Techniques,
and Confidence Scores.
"""

from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field
from app.mitre.models import MitreTacticEnum


class MitreMappingMatch(BaseModel):
    """Result of a deterministic MITRE ATT&CK mapping evaluation."""

    technique_id: str = Field(..., description="Mapped MITRE Technique ID (e.g. T1059)")
    subtechnique_id: Optional[str] = Field(None, description="Mapped Sub-Technique ID (e.g. T1059.001)")
    tactic: MitreTacticEnum = Field(..., description="Associated Tactic Enum")
    confidence_score: float = Field(..., ge=0.0, le=100.0, description="Mapping confidence score")
    matched_rule: str = Field(..., description="Deterministic pattern or rule title matched")
    evidence_refs: List[str] = Field(default_factory=list)
    timeline_refs: List[str] = Field(default_factory=list)


class MitreMapper:
    """Deterministic MITRE ATT&CK Mapping Engine."""

    # Static signature rules database mapping process names, keywords, and payload patterns to techniques
    SIGNATURE_RULES = [
        {
            "id": "sig-powershell",
            "technique_id": "T1059",
            "subtechnique_id": "T1059.001",
            "tactic": MitreTacticEnum.EXECUTION,
            "confidence": 95.0,
            "match_processes": ["powershell.exe", "pwsh.exe", "powershell_ise.exe"],
            "match_keywords": ["-enc", "-encodedcommand", "downloadstring", "invoke-expression", "iex"],
        },
        {
            "id": "sig-cmd",
            "technique_id": "T1059",
            "subtechnique_id": "T1059.003",
            "tactic": MitreTacticEnum.EXECUTION,
            "confidence": 90.0,
            "match_processes": ["cmd.exe"],
            "match_keywords": ["/c", "cmd.exe /c", "whoami", "ipconfig"],
        },
        {
            "id": "sig-lsass-dump",
            "technique_id": "T1003",
            "subtechnique_id": "T1003.001",
            "tactic": MitreTacticEnum.CREDENTIAL_ACCESS,
            "confidence": 98.0,
            "match_processes": ["mimikatz.exe", "procdump.exe", "lsass.exe", "comsvcs.dll"],
            "match_keywords": ["lsass", "sekurlsa", "minidump", "sam", "lsadump"],
        },
        {
            "id": "sig-scheduled-task",
            "technique_id": "T1053",
            "subtechnique_id": "T1053.005",
            "tactic": MitreTacticEnum.PERSISTENCE,
            "confidence": 92.0,
            "match_processes": ["schtasks.exe", "at.exe"],
            "match_keywords": ["/create", "schtasks", "cron", "systemd-timer"],
        },
        {
            "id": "sig-ransomware-encryption",
            "technique_id": "T1486",
            "subtechnique_id": None,
            "tactic": MitreTacticEnum.IMPACT,
            "confidence": 95.0,
            "match_processes": ["vssadmin.exe", "wbadmin.exe"],
            "match_keywords": ["delete shadows", "resize shadowstorage", ".locked", "README_TO_DECRYPT"],
        },
        {
            "id": "sig-c2-beaconing",
            "technique_id": "T1071",
            "subtechnique_id": "T1071.001",
            "tactic": MitreTacticEnum.COMMAND_AND_CONTROL,
            "confidence": 85.0,
            "match_processes": [],
            "match_keywords": ["c2 beacon", "dns tunneling", "http beacon", "meterpreter"],
        },
    ]

    @classmethod
    def map_artifact(cls, artifact_payload: Dict[str, Any]) -> List[MitreMappingMatch]:
        """
        Evaluate an arbitrary artifact dictionary (Alert, Evidence, Timeline Event, or Correlation Result)
        and return deterministic MITRE ATT&CK matches.
        """
        matches: List[MitreMappingMatch] = []
        seen_techniques: Set[str] = set()

        text_content = str(artifact_payload).lower()

        process_name = str(artifact_payload.get("process_name") or artifact_payload.get("process") or "").lower()
        title = str(artifact_payload.get("title") or artifact_payload.get("description") or "").lower()

        for rule in cls.SIGNATURE_RULES:
            matched = False

            # Process name match
            for proc in rule["match_processes"]:
                if proc in process_name or proc in text_content:
                    matched = True
                    break

            # Keyword match
            if not matched:
                for kw in rule["match_keywords"]:
                    if kw in text_content or kw in title:
                        matched = True
                        break

            if matched and rule["technique_id"] not in seen_techniques:
                seen_techniques.add(rule["technique_id"])
                matches.append(
                    MitreMappingMatch(
                        technique_id=rule["technique_id"],
                        subtechnique_id=rule["subtechnique_id"],
                        tactic=rule["tactic"],
                        confidence_score=rule["confidence"],
                        matched_rule=rule["id"],
                        evidence_refs=[str(artifact_payload.get("id"))] if artifact_payload.get("id") else [],
                    )
                )

        # Fallback category mapping if no process signature matched
        if not matches:
            category = str(artifact_payload.get("category") or artifact_payload.get("event_category") or "").upper()
            if "MALWARE" in category or "EXECUTION" in category:
                matches.append(
                    MitreMappingMatch(
                        technique_id="T1059",
                        subtechnique_id="T1059.001",
                        tactic=MitreTacticEnum.EXECUTION,
                        confidence_score=75.0,
                        matched_rule="fallback-category-execution",
                    )
                )
            elif "CREDENTIAL" in category or "EXFILTRATION" in category:
                matches.append(
                    MitreMappingMatch(
                        technique_id="T1003",
                        subtechnique_id="T1003.001",
                        tactic=MitreTacticEnum.CREDENTIAL_ACCESS,
                        confidence_score=75.0,
                        matched_rule="fallback-category-credential",
                    )
                )

        return matches
