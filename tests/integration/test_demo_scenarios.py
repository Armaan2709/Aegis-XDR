"""
End-to-End Demonstration Scenario Integration Test Suite.

Validates end-to-end synthetic scenario execution across Credential Compromise,
Ransomware Simulation, and Data Exfiltration scenarios, failure recovery paths,
and REST API endpoints.
"""

import pytest
from app.demo.schemas import ScenarioID, ScenarioRunRequest
from app.demo.runner import DemoScenarioRunner


@pytest.mark.anyio
async def test_credential_compromise_scenario_execution(async_session):
    """Test full execution of Credential Compromise scenario."""
    runner = DemoScenarioRunner()
    result = await runner.run_scenario(
        async_session,
        ScenarioID.CREDENTIAL_COMPROMISE,
        ScenarioRunRequest(auto_approve=True),
    )

    assert result.scenario_id == ScenarioID.CREDENTIAL_COMPROMISE
    assert result.assertions_passed == 20
    assert len(result.created_alert_ids) == 3
    assert result.created_incident_id is not None
    assert result.created_investigation_id is not None
    assert result.created_case_id is not None
    assert result.approval_status == "APPROVED"
    assert result.soar_execution_mode == "SAFE_MOCK_EXECUTION"


@pytest.mark.anyio
async def test_ransomware_simulation_scenario_execution(async_session):
    """Test full execution of Ransomware Simulation scenario."""
    runner = DemoScenarioRunner()
    result = await runner.run_scenario(
        async_session,
        ScenarioID.RANSOMWARE_SIMULATION,
        ScenarioRunRequest(auto_approve=False),
    )

    assert result.scenario_id == ScenarioID.RANSOMWARE_SIMULATION
    assert result.assertions_passed == 20
    assert len(result.created_alert_ids) == 3
    assert result.approval_status == "PENDING"


@pytest.mark.anyio
async def test_data_exfiltration_scenario_execution(async_session):
    """Test full execution of Data Exfiltration scenario."""
    runner = DemoScenarioRunner()
    result = await runner.run_scenario(
        async_session,
        ScenarioID.DATA_EXFILTRATION,
        ScenarioRunRequest(auto_approve=True),
    )

    assert result.scenario_id == ScenarioID.DATA_EXFILTRATION
    assert result.assertions_passed == 20
    assert len(result.created_alert_ids) == 2
    assert result.approval_status == "APPROVED"


@pytest.mark.anyio
async def test_scenario_report_generation(async_session):
    """Test structured demonstration report generation distinguishing OBSERVED, INFERRED, SIMULATED, RECOMMENDED."""
    runner = DemoScenarioRunner()
    result = await runner.run_scenario(
        async_session,
        ScenarioID.CREDENTIAL_COMPROMISE,
        ScenarioRunRequest(auto_approve=True),
    )
    report = runner.generate_report(result)

    assert report.scenario_id == ScenarioID.CREDENTIAL_COMPROMISE
    assert len(report.observed_telemetry) == 3
    assert report.soar_execution_result["mode"] == "SAFE_MOCK_EXECUTION"
    assert report.approval_decision["mandatory_gate"] is True


@pytest.mark.anyio
async def test_scenario_cleanup(async_session):
    """Test cleanup of synthetic scenario telemetry."""
    runner = DemoScenarioRunner()
    await runner.run_scenario(
        async_session,
        ScenarioID.CREDENTIAL_COMPROMISE,
        ScenarioRunRequest(auto_approve=False),
    )
    deleted_count = await runner.cleanup_scenario(async_session, ScenarioID.CREDENTIAL_COMPROMISE)
    assert deleted_count == 3
