"""
Scenario 3: Multi-Gigabyte Data Exfiltration via C2 Channel.

Synthetic Scenario Sequence:
1. Collection: Multi-part encrypted 7z archive creation under public temp directory.
2. Command & Control / Exfiltration: High volume HTTPS outbound transfer to suspicious external domain.
"""

from app.demo.schemas import ScenarioID, ScenarioDefinition
from app.demo.generators import generate_data_exfiltration_telemetry
from app.ai.pipeline.schemas import PipelineStage


def get_data_exfiltration_scenario() -> ScenarioDefinition:
    """Return scenario definition for Data Exfiltration."""
    return ScenarioDefinition(
        scenario_id=ScenarioID.DATA_EXFILTRATION,
        name="Encrypted Data Staging & C2 Exfiltration Burst",
        description=(
            "Simulates unauthorized staging of sensitive intellectual property into encrypted 7z archives "
            "followed by exfiltration over HTTPS to an external malicious Command & Control node."
        ),
        attack_phases=[
            "Discovery (Directory Scanning)",
            "Collection (Encrypted Archive Creation)",
            "Command & Control (External Malicious Domain)",
            "Exfiltration (High-Volume HTTPS Burst)",
        ],
        synthetic_alerts=generate_data_exfiltration_telemetry(),
        expected_mitre_techniques=["T1560.001", "T1071.001", "T1041"],
        expected_risk_range=[80.0, 100.0],
        expected_severity="CRITICAL",
        expected_governance_state="AWAITING_APPROVAL",
        expected_final_stage=PipelineStage.COMPLETED,
    )
