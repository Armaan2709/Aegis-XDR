"""
Scenario 2: Ransomware Activity & Recovery Disablement Simulation.

Synthetic Scenario Sequence:
1. Execution & Defense Evasion: Shadow copy deletion via vssadmin.exe.
2. Impact: High-volume encryption burst altering file extensions to .lockbit_enc.
3. Defense Evasion: Windows recovery subsystem disablement via bcdedit.exe.
"""

from app.demo.schemas import ScenarioID, ScenarioDefinition
from app.demo.generators import generate_ransomware_telemetry
from app.ai.pipeline.schemas import PipelineStage


def get_ransomware_simulation_scenario() -> ScenarioDefinition:
    """Return scenario definition for Ransomware Simulation."""
    return ScenarioDefinition(
        scenario_id=ScenarioID.RANSOMWARE_SIMULATION,
        name="Ransomware Outbreak & System Recovery Disablement",
        description=(
            "Simulates high-speed ransomware infection on a network file server, including automated shadow copy "
            "deletion, high-entropy file mutation bursts, and recovery subsystem tampering."
        ),
        attack_phases=[
            "Execution (Parent-Child Spawn)",
            "Defense Evasion (Volume Shadow Copy Deletion)",
            "Impact (Mass Encryption & High Entropy)",
            "Defense Evasion (BCD Recovery Disablement)",
        ],
        synthetic_alerts=generate_ransomware_telemetry(),
        expected_mitre_techniques=["T1490", "T1059", "T1486"],
        expected_risk_range=[85.0, 100.0],
        expected_severity="CRITICAL",
        expected_governance_state="AWAITING_APPROVAL",
        expected_final_stage=PipelineStage.COMPLETED,
    )
