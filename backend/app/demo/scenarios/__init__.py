"""
Deterministic Attack Scenarios Repository.

Provides structured scenario configurations for Credential Compromise,
Ransomware Simulation, and Data Exfiltration.
"""

from app.demo.scenarios.credential_compromise import get_credential_compromise_scenario
from app.demo.scenarios.ransomware_simulation import get_ransomware_simulation_scenario
from app.demo.scenarios.data_exfiltration import get_data_exfiltration_scenario

__all__ = [
    "get_credential_compromise_scenario",
    "get_ransomware_simulation_scenario",
    "get_data_exfiltration_scenario",
]
