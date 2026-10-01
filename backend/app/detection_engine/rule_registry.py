"""
Centralized Detection Rule Registry & Indexing Manager.

Provides catalog lookup, rule classification indexing, and template presets.
"""

from typing import List, Dict, Any, Optional
from app.detection_engine.models import RuleType, RuleSeverity


DEFAULT_RULE_TEMPLATES = [
    {
        "name": "Sigma Suspicious PowerShell Execution Template",
        "rule_type": RuleType.SIGMA,
        "description": "Template for detecting obfuscated base64 encoded PowerShell commands",
        "template_content": """title: Suspicious Encoded PowerShell Command
id: 5f7a0123-4567-89ab-cdef-0123456789ab
status: experimental
description: Detects base64 encoded command arguments in powershell.exe
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -encodedcommand '
    condition: selection
falsepositives:
    - Administrative maintenance scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001""",
    },
    {
        "name": "YARA Mimikatz Memory Dump Signature Template",
        "rule_type": RuleType.YARA,
        "description": "Template for YARA memory signature targeting credential dumper artifacts",
        "template_content": """rule Mimikatz_Memory_Artifact {
    meta:
        description = "Detects Mimikatz memory signature"
        author = "AegisAI Detection Team"
        severity = "CRITICAL"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide
        $s2 = "lsadump::sam" ascii wide
    condition:
        any of ($s*)
}""",
    },
    {
        "name": "Suricata C2 Beacon Network Signature Template",
        "rule_type": RuleType.SURICATA,
        "description": "Template for Suricata network IDS rule inspecting suspicious HTTP user agents",
        "template_content": 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"AegisAI IDS: Suspicious C2 HTTP User-Agent"; content:"Meterpreter"; http_user_agent; sid:9000001; rev:1;)',
    },
]


class RuleRegistry:
    """Registry helper for default rule templates and static metadata."""

    @staticmethod
    def get_default_templates() -> List[Dict[str, Any]]:
        """Retrieve default detection rule templates."""
        return DEFAULT_RULE_TEMPLATES
