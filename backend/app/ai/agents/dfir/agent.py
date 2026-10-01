"""
DFIR Investigator Agent Implementation.

Specialized Digital Forensics and Incident Response AI Agent for AegisAI XDR.
Inherits from BaseAgent. Executes read-only forensic analysis over InvestigationState.

STRICT SAFETY GUARANTEE:
- Strictly read-only forensic investigation.
- No binary execution, malware execution, active scanning, shell/Python execution, or file/system modifications.
- Human approval explicitly enforced for all response recommendations.
"""

import time
from typing import List, Dict, Any, Optional
from app.ai.agents.base import BaseAgent, AgentResult, AgentStatus
from app.ai.orchestrator.state import InvestigationState
from app.ai.tools.registry import ToolRegistry
from app.ai.tools.security_tools import (
    QuerySIEMTool,
    QueryThreatIntelTool,
    QueryMitreTool,
    QueryEvidenceTool,
)
from app.ai.agents.dfir.schemas import DFIRFinding, DFIRRecommendation, EvidenceGap
from app.ai.agents.dfir.artifacts import ArtifactNormalizer
from app.ai.agents.dfir.timeline import ForensicTimelineAnalyzer
from app.ai.agents.dfir.analysis import (
    ProcessTreeAnalyzer,
    CommandLineAnalyzer,
    AttackReconstructionEngine,
)
from app.ai.agents.dfir.findings import DFIRFindingGenerator
from app.ai.agents.dfir.recommendations import DFIRRecommendationGenerator
from app.ai.memory.short_term import ShortTermMemory
from app.ai.memory.case_memory import CaseMemory


class DFIRInvestigatorAgent(BaseAgent):
    """Specialized Digital Forensics and Incident Response AI Agent for AegisAI XDR."""

    def __init__(self, tool_registry: Optional[ToolRegistry] = None):
        self._tool_registry = tool_registry or ToolRegistry()
        if not self._tool_registry.get("query_evidence_metadata"):
            self._tool_registry.register(QueryEvidenceTool())
        if not self._tool_registry.get("query_siem_logs"):
            self._tool_registry.register(QuerySIEMTool())

        self._normalizer = ArtifactNormalizer()
        self._timeline_analyzer = ForensicTimelineAnalyzer()
        self._proc_analyzer = ProcessTreeAnalyzer()
        self._cmd_analyzer = CommandLineAnalyzer()
        self._reconstruction_engine = AttackReconstructionEngine()
        self._finding_generator = DFIRFindingGenerator()
        self._recommendation_generator = DFIRRecommendationGenerator()
        self._short_memory = ShortTermMemory()
        self._case_memory = CaseMemory()

    @property
    def name(self) -> str:
        return "DFIRInvestigatorAgent"

    @property
    def description(self) -> str:
        return (
            "Specialized Digital Forensics and Incident Response agent that reconstructs timelines, "
            "analyzes process trees, identifies evidence gaps, and performs root-cause analysis."
        )

    @property
    def capabilities(self) -> List[str]:
        return [
            "Digital Forensics",
            "Evidence Analysis",
            "Timeline Reconstruction",
            "Process Analysis",
            "File Analysis",
            "Network Artifact Analysis",
            "Authentication Analysis",
            "Attack Reconstruction",
            "Evidence Correlation",
            "Root Cause Analysis",
        ]

    def validate_input(self, state: InvestigationState) -> bool:
        """Validate state contains required investigation identifier."""
        return state is not None and bool(state.investigation_id)

    def health_check(self) -> bool:
        """Verify agent health."""
        return True

    async def execute(self, state: InvestigationState) -> AgentResult:
        """Execute DFIR forensic investigation pipeline over InvestigationState."""
        start_time = time.time()

        if not self.validate_input(state):
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.FAILURE,
                metadata={"error": "Invalid input InvestigationState"},
            )

        try:
            # 1. Normalize state evidence, timeline, and alerts
            artifacts = self._normalizer.normalize(state)

            # 2. Reconstruct forensic timeline & attack kill-chain phases
            timeline_events = self._timeline_analyzer.reconstruct_timeline(artifacts)

            # 3. Process tree & command line analysis
            proc_obs = self._proc_analyzer.analyze_process_trees(artifacts)
            cmd_obs = self._cmd_analyzer.analyze_command_lines(artifacts)

            # 4. Attack reconstruction & root cause analysis (consuming Threat Hunter context)
            root_causes, mitre_techs = self._reconstruction_engine.reconstruct_attack_and_root_cause(
                artifacts, proc_obs, cmd_obs, state
            )

            # 5. Generate Findings and Evidence Telemetry Gaps
            findings, gaps = self._finding_generator.generate_findings_and_gaps(
                artifacts, root_causes, proc_obs, cmd_obs, mitre_techs, state
            )

            # 6. Generate Human-Governed Recommendations
            recommendations = self._recommendation_generator.generate_recommendations(findings, gaps)

            # 7. Memory Integration
            self._short_memory.store(
                f"dfir:{state.investigation_id}:timeline", timeline_events
            )
            if state.case_id:
                self._case_memory.store_for_case(
                    state.case_id, f"dfir:{state.investigation_id}:findings", [f.model_dump() for f in findings]
                )

            # 8. State Updates
            avg_confidence = (
                sum(f.confidence for f in findings) / len(findings) if findings else 0.5
            )
            state.confidence_score = round(max(state.confidence_score, avg_confidence), 2)

            for rec in recommendations:
                state.add_recommendation(rec.title)

            # 9. Format AgentResult
            exec_time = round((time.time() - start_time) * 1000, 2)
            result = AgentResult(
                agent_name=self.name,
                status=AgentStatus.SUCCESS,
                confidence_score=avg_confidence,
                findings=[f.model_dump() for f in findings],
                evidence=[{"artifact_id": a.artifact_id, "category": a.category.value, "value": a.value} for a in artifacts],
                recommendations=[r.title for r in recommendations],
                execution_time_ms=exec_time,
                metadata={
                    "artifacts_count": len(artifacts),
                    "timeline_events_count": len(timeline_events),
                    "root_causes": [rc.model_dump() for rc in root_causes],
                    "evidence_gaps": [g.model_dump() for g in gaps],
                    "mitre_techniques": mitre_techs,
                    "detailed_recommendations": [r.model_dump() for r in recommendations],
                },
            )

            return result

        except Exception as e:
            exec_time = round((time.time() - start_time) * 1000, 2)
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.FAILURE,
                execution_time_ms=exec_time,
                metadata={"error": str(e)},
            )
