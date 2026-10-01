"""
Scenario 1: Credential Compromise & LSASS Memory Dump Simulation.

Synthetic Scenario Sequence:
1. Initial Access: Suspicious Authentication Anomaly from External IP (198.51.100.44).
2. Credential Theft: LSASS process memory reading via encoded PowerShell payload.
3. Lateral Movement: Remote WMI execution towards internal workstation WS-FINANCE-04.
"""

from app.demo.schemas import ScenarioID, ScenarioDefinition
from app.demo.generators import generate_credential_compromise_telemetry
from app.ai.pipeline.schemas import PipelineStage


def get_credential_compromise_scenario() -> ScenarioDefinition:
    """Return scenario definition for Credential Compromise."""
    return ScenarioDefinition(
        scenario_id=ScenarioID.CREDENTIAL_COMPROMISE,
        name="Credential Compromise & LSASS Memory Dump",
        description=(
            "Simulates initial access via compromised backup service credentials, memory dumping of "
            "LSASS via encoded PowerShell, followed by remote WMI lateral movement across Domain Controllers."
        ),
        attack_phases=[
            "Initial Access (Suspicious Login)",
            "Credential Access (LSASS Memory Dump)",
            "Execution (Encoded PowerShell)",
            "Lateral Movement (Remote WMI Execution)",
        ],
        synthetic_alerts=generate_credential_compromise_telemetry(),
        expected_mitre_techniques=["T1078", "T1110", "T1003.001", "T1059.001", "T1021.002", "T1047"],
        expected_risk_range=[75.0, 100.0],
        expected_severity="CRITICAL",
        expected_governance_state="AWAITING_APPROVAL",
        expected_final_stage=PipelineStage.COMPLETED,
    )
