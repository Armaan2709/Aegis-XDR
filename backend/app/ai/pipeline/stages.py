"""
Modular Pipeline Stage Implementations.

Defines BasePipelineStage abstract base class and 11 concrete stage executors:
AlertTriageStage, CorrelationStage, InvestigationInitializationStage, ThreatHuntingStage,
DFIRAnalysisStage, ThreatIntelligenceStage, DetectionGenerationStage, IncidentSynthesisStage,
HumanReviewGateStage, ResponseExecutionStage, and FinalizationStage.
"""

import abc
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from app.ai.pipeline.schemas import (
    PipelineStage,
    StageStatus,
    StageResult,
    PipelineContext,
    PipelineTimelineEntry,
)
from app.ai.agents.threat_hunter import ThreatHunterAgent
from app.ai.agents.dfir import DFIRInvestigatorAgent
from app.ai.agents.threat_intel import ThreatIntelligenceAnalystAgent
from app.ai.agents.detection_generator import DetectionRuleGeneratorAgent
from app.ai.agents.incident_commander import IncidentCommanderAgent
from app.case_management.models import ApprovalStatus


class BasePipelineStage(abc.ABC):
    """Abstract base class for autonomous investigation pipeline stages."""

    @property
    @abc.abstractmethod
    def stage(self) -> PipelineStage:
        """Stage enum identifier."""
        pass

    def validate(self, context: PipelineContext) -> bool:
        """Validate context requirements for stage execution."""
        return context is not None and bool(context.investigation_id)

    def health_check(self) -> bool:
        """Stage health check."""
        return True

    @abc.abstractmethod
    async def execute(self, context: PipelineContext) -> StageResult:
        """Execute stage logic over context."""
        pass


class AlertTriageStage(BasePipelineStage):
    """Stage 1: Ingests and triages initial alert telemetry."""

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.TRIAGING

    async def execute(self, context: PipelineContext) -> StageResult:
        start_t = time.time()
        alts = context.investigation_state.alerts
        exec_ms = round((time.time() - start_t) * 1000, 2)
        return StageResult(
            stage=self.stage,
            status=StageStatus.SUCCESS,
            completed_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=exec_ms,
            output={"ingested_alerts_count": len(alts)},
        )


class CorrelationStage(BasePipelineStage):
    """Stage 2: Runs correlation logic over alerts and links/creates incident."""

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.CORRELATING

    async def execute(self, context: PipelineContext) -> StageResult:
        start_t = time.time()
        inc_id = context.incident_id or context.investigation_state.incident_id or f"INC-{context.investigation_id[:8]}"
        context.incident_id = inc_id
        context.investigation_state.incident_id = inc_id
        exec_ms = round((time.time() - start_t) * 1000, 2)
        return StageResult(
            stage=self.stage,
            status=StageStatus.SUCCESS,
            completed_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=exec_ms,
            output={"correlated_incident_id": inc_id},
        )


class InvestigationInitializationStage(BasePipelineStage):
    """Stage 3: Initializes shared InvestigationState and case parameters."""

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.INVESTIGATION_STARTED

    async def execute(self, context: PipelineContext) -> StageResult:
        start_t = time.time()
        case_id = context.case_id or context.investigation_state.case_id or f"CASE-{context.investigation_id[:8]}"
        context.case_id = case_id
        context.investigation_state.case_id = case_id
        context.investigation_state.current_phase = "AI_INVESTIGATION_RUNNING"
        exec_ms = round((time.time() - start_t) * 1000, 2)
        return StageResult(
            stage=self.stage,
            status=StageStatus.SUCCESS,
            completed_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=exec_ms,
            output={"initialized_case_id": case_id},
        )


class ThreatHuntingStage(BasePipelineStage):
    """Stage 4: Executes ThreatHunterAgent over shared InvestigationState."""

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.THREAT_HUNTING

    async def execute(self, context: PipelineContext) -> StageResult:
        start_t = time.time()
        agent = ThreatHunterAgent()
        res = await agent.execute(context.investigation_state)
        context.investigation_state.add_agent_result(res)
        exec_ms = round((time.time() - start_t) * 1000, 2)
        status = StageStatus.SUCCESS if res.status.value == "SUCCESS" else StageStatus.PARTIAL_SUCCESS
        return StageResult(
            stage=self.stage,
            status=status,
            completed_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=exec_ms,
            output={"findings_count": len(res.findings)},
        )


class DFIRAnalysisStage(BasePipelineStage):
    """Stage 5: Executes DFIRInvestigatorAgent over shared InvestigationState."""

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.DFIR_ANALYSIS

    async def execute(self, context: PipelineContext) -> StageResult:
        start_t = time.time()
        agent = DFIRInvestigatorAgent()
        res = await agent.execute(context.investigation_state)
        context.investigation_state.add_agent_result(res)
        exec_ms = round((time.time() - start_t) * 1000, 2)
        status = StageStatus.SUCCESS if res.status.value == "SUCCESS" else StageStatus.PARTIAL_SUCCESS
        return StageResult(
            stage=self.stage,
            status=status,
            completed_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=exec_ms,
            output={"evidence_items_count": len(res.evidence)},
        )


class ThreatIntelligenceStage(BasePipelineStage):
    """Stage 6: Executes ThreatIntelligenceAnalystAgent over shared InvestigationState."""

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.THREAT_INTELLIGENCE

    async def execute(self, context: PipelineContext) -> StageResult:
        start_t = time.time()
        agent = ThreatIntelligenceAnalystAgent()
        res = await agent.execute(context.investigation_state)
        context.investigation_state.add_agent_result(res)
        exec_ms = round((time.time() - start_t) * 1000, 2)
        status = StageStatus.SUCCESS if res.status.value == "SUCCESS" else StageStatus.PARTIAL_SUCCESS
        return StageResult(
            stage=self.stage,
            status=status,
            completed_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=exec_ms,
            output={"ioc_matches_count": len(res.findings)},
        )


class DetectionGenerationStage(BasePipelineStage):
    """Stage 7: Executes DetectionRuleGeneratorAgent over shared InvestigationState."""

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.DETECTION_GENERATION

    async def execute(self, context: PipelineContext) -> StageResult:
        start_t = time.time()
        agent = DetectionRuleGeneratorAgent()
        res = await agent.execute(context.investigation_state)
        context.investigation_state.add_agent_result(res)
        exec_ms = round((time.time() - start_t) * 1000, 2)
        status = StageStatus.SUCCESS if res.status.value == "SUCCESS" else StageStatus.PARTIAL_SUCCESS
        return StageResult(
            stage=self.stage,
            status=status,
            completed_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=exec_ms,
            output={"candidate_rules_count": len(res.findings)},
        )


class IncidentSynthesisStage(BasePipelineStage):
    """Stage 8: Executes IncidentCommanderAgent for final synthesis and response plan formulation."""

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.INCIDENT_SYNTHESIS

    async def execute(self, context: PipelineContext) -> StageResult:
        start_t = time.time()
        agent = IncidentCommanderAgent()
        res = await agent.execute(context.investigation_state)
        context.investigation_state.add_agent_result(res)

        meta = res.metadata or {}
        context.final_assessment = meta.get("assessment")
        context.response_plan = meta.get("response_plan")

        exec_ms = round((time.time() - start_t) * 1000, 2)
        return StageResult(
            stage=self.stage,
            status=StageStatus.SUCCESS,
            completed_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=exec_ms,
            output={
                "risk_score": context.investigation_state.risk_score,
                "confidence_score": context.investigation_state.confidence_score,
            },
        )


class HumanReviewGateStage(BasePipelineStage):
    """Stage 9: Enforces CaseApproval governance gate for SOAR response actions."""

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.AWAITING_REVIEW

    async def execute(self, context: PipelineContext) -> StageResult:
        start_t = time.time()
        plan = context.response_plan or {}
        requires_approval = plan.get("approval_required", True)

        context.approval_required = requires_approval
        if not context.approval_id:
            context.approval_id = f"APP-GATE-{context.investigation_id[:8]}"

        exec_ms = round((time.time() - start_t) * 1000, 2)
        status = StageStatus.SUCCESS if context.approval_status in ("APPROVED", "AUTO_APPROVED") else StageStatus.PENDING

        return StageResult(
            stage=self.stage,
            status=status,
            completed_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=exec_ms,
            output={
                "approval_id": context.approval_id,
                "approval_status": context.approval_status,
                "requires_approval": requires_approval,
            },
        )


class ResponseExecutionStage(BasePipelineStage):
    """Stage 10: Executes approved response actions via safe mock Playbook Engine."""

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.RESPONSE_EXECUTING

    async def execute(self, context: PipelineContext) -> StageResult:
        start_t = time.time()

        # STRICT GOVERNANCE CHECK: Approval MUST be APPROVED or AUTO_APPROVED
        if context.approval_status not in ("APPROVED", "AUTO_APPROVED"):
            raise PermissionError(
                f"Cannot execute response actions: CaseApproval status is '{context.approval_status}', expected APPROVED."
            )

        plan = context.response_plan or {}
        exec_actions = []
        for cat in ("immediate_actions", "containment_actions", "eradication_actions"):
            for item in plan.get(cat, []):
                act_name = item.get("action") or "UNKNOWN_ACTION"
                exec_actions.append(f"SAFE_MOCK_EXECUTION: {act_name}")

        exec_ms = round((time.time() - start_t) * 1000, 2)
        return StageResult(
            stage=self.stage,
            status=StageStatus.SUCCESS,
            completed_at=datetime.now(timezone.utc).isoformat(),
            execution_time_ms=exec_ms,
            output={"executed_actions_count": len(exec_actions), "actions": exec_actions},
        )


class FinalizationStage(BasePipelineStage):
    """Stage 11: Finalizes investigation, updates case, records metrics and completion timestamp."""

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.COMPLETED

    async def execute(self, context: PipelineContext) -> StageResult:
        start_t = time.time()
        context.completed_at = datetime.now(timezone.utc).isoformat()
        context.investigation_state.current_phase = "INVESTIGATION_COMPLETED"
        exec_ms = round((time.time() - start_t) * 1000, 2)
        return StageResult(
            stage=self.stage,
            status=StageStatus.SUCCESS,
            completed_at=context.completed_at,
            execution_time_ms=exec_ms,
            output={"final_status": "COMPLETED"},
        )
