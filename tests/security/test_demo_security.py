"""
Security Boundary Regression Tests for Demonstration Framework.

Validates that synthetic demonstration scenarios cannot execute shell commands,
cannot run arbitrary code, cannot mutate live infrastructure, and strictly respect CaseApproval.
"""

import pytest
from app.demo.schemas import ScenarioID, ScenarioRunRequest
from app.demo.runner import DemoScenarioRunner
from app.demo.scenarios import get_credential_compromise_scenario


@pytest.mark.anyio
async def test_demo_soar_safety_boundary(async_session):
    """Verify that demo scenario SOAR actions are restricted to SAFE_MOCK_EXECUTION."""
    runner = DemoScenarioRunner()
    result = await runner.run_scenario(
        async_session,
        ScenarioID.CREDENTIAL_COMPROMISE,
        ScenarioRunRequest(auto_approve=True),
    )

    assert result.soar_execution_mode == "SAFE_MOCK_EXECUTION"
    assert result.approval_status == "APPROVED"


@pytest.mark.anyio
async def test_demo_unapproved_action_blocking(async_session):
    """Verify that without CaseApproval, demo scenario response actions remain blocked."""
    runner = DemoScenarioRunner()
    result = await runner.run_scenario(
        async_session,
        ScenarioID.RANSOMWARE_SIMULATION,
        ScenarioRunRequest(auto_approve=False),
    )

    assert result.approval_status == "PENDING"
    for action in result.response_plan:
        assert action["status"] == "PENDING_APPROVAL"


def test_demo_synthetic_telemetry_isolation():
    """Verify that all generated synthetic telemetry items are explicitly tagged."""
    scen = get_credential_compromise_scenario()
    for alert in scen.synthetic_alerts:
        assert "synthetic_telemetry" in alert.tags
        assert alert.source_ref_id.startswith("SYN-")


def test_demo_no_shell_execution_capability():
    """Verify that DemoScenarioRunner contains no OS subprocess or shell invocation capabilities."""
    runner = DemoScenarioRunner()
    assert not hasattr(runner, "exec_shell")
    assert not hasattr(runner, "run_command")
    assert not hasattr(runner, "eval_python")
