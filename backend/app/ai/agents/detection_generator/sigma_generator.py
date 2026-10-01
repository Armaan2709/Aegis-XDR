"""
Sigma Rule Generator.

Generates structured Sigma YAML detection candidates based on process creation,
PowerShell commands, and endpoint event telemetry. Reuses Sprint 8 Detection Engine validation.
"""

import uuid
from typing import Dict, Any, Optional
from app.detection_engine.models import RuleType, RuleSeverity
from app.ai.agents.detection_generator.schemas import DetectionRuleCandidate


class SigmaRuleGenerator:
    """Deterministic generator for Sigma YAML detection rules."""

    def generate_rule(self, observables: Dict[str, Any]) -> Optional[DetectionRuleCandidate]:
        """Generate Sigma YAML rule candidate if process/command telemetry exists."""
        cmds = observables.get("commands", [])
        procs = observables.get("processes", [])
        mitre_techs = observables.get("mitre_techniques", [])
        ev_refs = observables.get("evidence_refs", [])

        if not cmds and not procs:
            return None

        rule_id = str(uuid.uuid4())
        proc_str = procs[0] if procs else "powershell.exe"
        cmd_str = cmds[0] if cmds else "powershell.exe -enc"

        tags_yaml = "\n".join([f"    - attack.{tech.lower().replace('.', '_')}" for tech in mitre_techs]) if mitre_techs else "    - attack.execution"

        content = f"""title: Suspicious Process Execution - {proc_str}
id: {rule_id}
status: experimental
description: Detects suspicious process creation or command execution matching {proc_str}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\{proc_str}'
        CommandLine|contains: '{cmd_str}'
    condition: selection
falsepositives:
    - Administrative maintenance scripts
    - Authorized IT management software
level: high
tags:
{tags_yaml}
"""

        return DetectionRuleCandidate(
            title=f"Sigma: Suspicious Process Execution ({proc_str})",
            description=f"Sigma rule detecting process creation for {proc_str} and associated command parameters.",
            rule_type=RuleType.SIGMA,
            severity=RuleSeverity.HIGH,
            confidence=0.85,
            mitre_techniques=mitre_techs,
            evidence_refs=ev_refs,
            detection_logic=content,
            false_positive_notes="Administrative maintenance scripts or legitimate remote administration.",
            generation_rationale="Generated from suspicious process and command line telemetry observed during investigation.",
        )
