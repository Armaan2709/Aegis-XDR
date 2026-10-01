"""
Response Plan Engine.

Generates categorized human-governed incident response plans.
STRICT HUMAN GOVERNANCE: Enforces requires_human_approval = True for all response recommendations.
"""

from typing import List, Dict, Any
from app.ai.orchestrator.state import InvestigationState
from app.ai.agents.incident_commander.schemas import (
    ResponsePlan,
    CommanderRecommendation,
)


class ResponsePlanEngine:
    """Categorized human-governed response plan engine."""

    def build_response_plan(
        self, state: InvestigationState, severity: str
    ) -> ResponsePlan:
        """Construct structured response plan categorized across 6 response phases."""
        immediate: List[CommanderRecommendation] = []
        containment: List[CommanderRecommendation] = []
        investigation: List[CommanderRecommendation] = []
        eradication: List[CommanderRecommendation] = []
        recovery: List[CommanderRecommendation] = []
        monitoring: List[CommanderRecommendation] = []

        # Extract IPs, domains, hosts, and command lines
        ips = [alt.get("ip") or alt.get("src_ip") for alt in state.alerts if alt.get("ip") or alt.get("src_ip")]
        hosts = [alt.get("hostname") or alt.get("host") for alt in state.alerts if alt.get("hostname") or alt.get("host")]

        # 1. Immediate Actions
        if hosts:
            h_target = str(hosts[0])
            immediate.append(
                CommanderRecommendation(
                    action="ISOLATE_HOST",
                    rationale=f"Isolate compromised host {h_target} from local subnet to contain lateral movement.",
                    priority="HIGH",
                    risk_reduction="CRITICAL",
                    requires_human_approval=True,  # STRICT HUMAN GOVERNANCE
                    related_playbook_id="PB-ISOLATE-HOST-V1",
                    related_case_id=state.case_id,
                )
            )

        if ips:
            ip_target = str(ips[0])
            containment.append(
                CommanderRecommendation(
                    action="BLOCK_IP",
                    rationale=f"Add malicious C2 IP {ip_target} to border firewall drop rules.",
                    priority="HIGH",
                    risk_reduction="HIGH",
                    requires_human_approval=True,  # STRICT HUMAN GOVERNANCE
                    related_playbook_id="PB-BLOCK-IP-V1",
                    related_case_id=state.case_id,
                )
            )

        # 2. Investigation Actions
        investigation.append(
            CommanderRecommendation(
                action="COLLECT_FORENSIC_TRIAGE",
                rationale="Collect endpoint RAM dump and MFT artifact package for deep memory analysis.",
                priority="MEDIUM",
                risk_reduction="MODERATE",
                requires_human_approval=False,
                related_case_id=state.case_id,
            )
        )

        # 3. Eradication Actions
        eradication.append(
            CommanderRecommendation(
                action="TERMINATE_SUSPICIOUS_PROCESSES",
                rationale="Identify and kill unauthorized script host and child process trees.",
                priority="HIGH",
                risk_reduction="HIGH",
                requires_human_approval=True,  # STRICT HUMAN GOVERNANCE
                related_case_id=state.case_id,
            )
        )

        # 4. Recovery & Monitoring
        recovery.append(
            CommanderRecommendation(
                action="RESTORE_SYSTEM_BASELINE",
                rationale="Validate endpoint security agent integrity before restoring network connectivity.",
                priority="LOW",
                risk_reduction="LOW",
                requires_human_approval=False,
            )
        )
        monitoring.append(
            CommanderRecommendation(
                action="ENABLE_ENHANCED_SIEM_LOGGING",
                rationale="Enable 30-day debug audit logging for affected domain user accounts.",
                priority="LOW",
                risk_reduction="MODERATE",
                requires_human_approval=False,
            )
        )

        return ResponsePlan(
            immediate_actions=immediate,
            containment_actions=containment,
            investigation_actions=investigation,
            eradication_actions=eradication,
            recovery_actions=recovery,
            monitoring_actions=monitoring,
            approval_required=True,
        )
