"""
Local MITRE ATT&CK Knowledge Base.

Provides offline enterprise ATT&CK Matrix catalog of Tactics, Techniques, and Sub-Techniques,
with support for importing official MITRE ATT&CK STIX/TAXII JSON datasets.
"""

from typing import List, Dict, Any, Optional, Tuple
from app.mitre.models import MitreTacticEnum


DEFAULT_MITRE_TACTICS = [
    {"tactic_id": "TA0001", "name": "Initial Access", "description": "The adversary is trying to get into your network."},
    {"tactic_id": "TA0002", "name": "Execution", "description": "The adversary is trying to run malicious code."},
    {"tactic_id": "TA0003", "name": "Persistence", "description": "The adversary is trying to maintain their foothold."},
    {"tactic_id": "TA0004", "name": "Privilege Escalation", "description": "The adversary is trying to gain higher-level permissions."},
    {"tactic_id": "TA0005", "name": "Defense Evasion", "description": "The adversary is trying to avoid being detected."},
    {"tactic_id": "TA0006", "name": "Credential Access", "description": "The adversary is trying to steal account names and passwords."},
    {"tactic_id": "TA0007", "name": "Discovery", "description": "The adversary is trying to figure out your environment."},
    {"tactic_id": "TA0008", "name": "Lateral Movement", "description": "The adversary is trying to move through your environment."},
    {"tactic_id": "TA0009", "name": "Collection", "description": "The adversary is trying to gather data of interest to their goal."},
    {"tactic_id": "TA0011", "name": "Command and Control", "description": "The adversary is trying to communicate with compromised systems."},
    {"tactic_id": "TA0010", "name": "Exfiltration", "description": "The adversary is trying to steal data."},
    {"tactic_id": "TA0040", "name": "Impact", "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data."},
]


DEFAULT_MITRE_TECHNIQUES = [
    {
        "technique_id": "T1059",
        "tactic": MitreTacticEnum.EXECUTION,
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "platforms": ["Windows", "Linux", "macOS"],
        "detection_notes": "Monitor process execution for powershell.exe, cmd.exe, bash, or zsh with suspicious flags.",
        "data_sources": ["Process: Process Creation", "Command: Command Execution"],
        "mitigation_notes": "Restrict command shell access to authorized administrators.",
    },
    {
        "technique_id": "T1003",
        "tactic": MitreTacticEnum.CREDENTIAL_ACCESS,
        "name": "OS Credential Dumping",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
        "platforms": ["Windows", "Linux"],
        "detection_notes": "Monitor memory access to lsass.exe or reading SAM/SECURITY hives.",
        "data_sources": ["Process: Process Access", "File: File Access"],
        "mitigation_notes": "Enable LSA Protection (LSASS Guard) and Credential Guard.",
    },
    {
        "technique_id": "T1053",
        "tactic": MitreTacticEnum.PERSISTENCE,
        "name": "Scheduled Task/Job",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
        "platforms": ["Windows", "Linux", "macOS"],
        "detection_notes": "Monitor task schtasks.exe, crontab, or systemd timers for new jobs.",
        "data_sources": ["Scheduled Job: Scheduled Job Creation"],
        "mitigation_notes": "Configure permissions to limit task creation privileges.",
    },
    {
        "technique_id": "T1071",
        "tactic": MitreTacticEnum.COMMAND_AND_CONTROL,
        "name": "Application Layer Protocol",
        "description": "Adversaries may communicate using application layer protocols to avoid detection/filtering by blending in with existing traffic.",
        "platforms": ["Windows", "Linux", "macOS"],
        "detection_notes": "Inspect HTTP/HTTPS/DNS traffic for abnormal beacons or high frequency requests.",
        "data_sources": ["Network Traffic: Network Traffic Flow"],
        "mitigation_notes": "Implement web proxies and TLS decryption inspection.",
    },
    {
        "technique_id": "T1486",
        "tactic": MitreTacticEnum.IMPACT,
        "name": "Data Encrypted for Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability to system and network resources.",
        "platforms": ["Windows", "Linux", "macOS"],
        "detection_notes": "Detect high-volume file modification and renaming activity accompanied by volume shadow copy deletion.",
        "data_sources": ["File: File Modification", "Process: Process Creation"],
        "mitigation_notes": "Maintain offline backups and restrict vssadmin access.",
    },
]


DEFAULT_MITRE_SUBTECHNIQUES = [
    {
        "subtechnique_id": "T1059.001",
        "parent_technique_id": "T1059",
        "name": "PowerShell",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "platforms": ["Windows"],
        "detection_notes": "Monitor ScriptBlock Logging (Event ID 4104) for obfuscated base64 code.",
    },
    {
        "subtechnique_id": "T1059.003",
        "parent_technique_id": "T1059",
        "name": "Windows Command Shell",
        "description": "Adversaries may abuse cmd.exe to execute commands.",
        "platforms": ["Windows"],
        "detection_notes": "Monitor cmd.exe spawned by web servers, office applications, or unusual parent processes.",
    },
    {
        "subtechnique_id": "T1003.001",
        "parent_technique_id": "T1003",
        "name": "LSASS Memory",
        "description": "Adversaries may attempt to access and dump memory contents of LSASS.",
        "platforms": ["Windows"],
        "detection_notes": "Monitor procdump.exe, rundll32.exe, or mimikatz accessing LSASS process handle.",
    },
]


class MitreKnowledgeBase:
    """Local repository management layer for MITRE ATT&CK catalog datasets."""

    @staticmethod
    def get_tactics() -> List[Dict[str, Any]]:
        """Retrieve static catalog of tactics."""
        return DEFAULT_MITRE_TACTICS

    @staticmethod
    def get_techniques() -> List[Dict[str, Any]]:
        """Retrieve static catalog of techniques."""
        return DEFAULT_MITRE_TECHNIQUES

    @staticmethod
    def get_subtechniques() -> List[Dict[str, Any]]:
        """Retrieve static catalog of sub-techniques."""
        return DEFAULT_MITRE_SUBTECHNIQUES

    @classmethod
    def load_from_json(cls, json_payload: Dict[str, Any]) -> Tuple[int, int]:
        """Placeholder for importing custom official ATT&CK STIX/TAXII JSON dataset."""
        techniques_count = len(json_payload.get("techniques", []))
        tactics_count = len(json_payload.get("tactics", []))
        return tactics_count, techniques_count
