"""
API Router for End-to-End Security Validation & SOC Demonstration.

Mounts endpoints for scenario listing, scenario execution, results retrieval,
structured report generation, and synthetic telemetry cleanup.
"""

from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.demo.schemas import (
    ScenarioID,
    ScenarioDefinition,
    ScenarioRunRequest,
    ScenarioExecutionResult,
    ScenarioReport,
)
from app.demo.runner import DemoScenarioRunner

router = APIRouter(prefix="/demo", tags=["SOC Demonstration & Security Validation"])
runner = DemoScenarioRunner()


@router.get("/scenarios", response_model=List[ScenarioDefinition])
async def list_scenarios() -> List[ScenarioDefinition]:
    """List all available synthetic security demonstration scenarios."""
    return runner.list_scenarios()


@router.get("/scenarios/{scenario_id}", response_model=ScenarioDefinition)
async def get_scenario(scenario_id: ScenarioID) -> ScenarioDefinition:
    """Retrieve metadata for a specific attack scenario."""
    return runner.get_scenario(scenario_id)


@router.post("/scenarios/{scenario_id}/run", response_model=ScenarioExecutionResult)
async def run_scenario(
    scenario_id: ScenarioID,
    req: ScenarioRunRequest = ScenarioRunRequest(),
    session: AsyncSession = Depends(get_db),
) -> ScenarioExecutionResult:
    """Execute a deterministic end-to-end synthetic scenario."""
    return await runner.run_scenario(session, scenario_id, req)


@router.get("/scenarios/{scenario_id}/result", response_model=ScenarioExecutionResult)
async def get_scenario_result(
    scenario_id: ScenarioID,
    session: AsyncSession = Depends(get_db),
) -> ScenarioExecutionResult:
    """Get latest execution result for a scenario."""
    return await runner.get_result(session, scenario_id)


@router.get("/scenarios/{scenario_id}/report", response_model=ScenarioReport)
async def get_scenario_report(
    scenario_id: ScenarioID,
    session: AsyncSession = Depends(get_db),
) -> ScenarioReport:
    """Generate structured demonstration report for a scenario."""
    result = await runner.get_result(session, scenario_id)
    return runner.generate_report(result)


@router.delete("/scenarios/{scenario_id}", status_code=status.HTTP_200_OK)
async def cleanup_scenario(
    scenario_id: ScenarioID,
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Purge synthetic scenario alerts and telemetry from database."""
    deleted_count = await runner.cleanup_scenario(session, scenario_id)
    return {
        "status": "SUCCESS",
        "message": f"Purged synthetic telemetry for scenario '{scenario_id.value}'.",
        "deleted_count": deleted_count,
    }
