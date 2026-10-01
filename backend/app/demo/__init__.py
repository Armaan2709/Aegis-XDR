"""
AegisAI XDR End-to-End Security Validation & Demonstration Engine.

Provides deterministic synthetic attack scenario generators, scenario runners,
validation assertion checkers, structured demonstration reporting, and API routes.
"""

from app.demo.schemas import (
    ScenarioID,
    ScenarioDefinition,
    ScenarioExecutionResult,
    ScenarioReport,
    DemonstrationMetrics,
)
from app.demo.runner import DemoScenarioRunner

__all__ = [
    "ScenarioID",
    "ScenarioDefinition",
    "ScenarioExecutionResult",
    "ScenarioReport",
    "DemonstrationMetrics",
    "DemoScenarioRunner",
]
