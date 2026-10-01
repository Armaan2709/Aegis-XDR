"""
AI Orchestrator Standard Investigation Workflow.

Defines the standard multi-stage security investigation workflow DAG:
Triage -> Threat Intel -> Threat Hunting -> DFIR -> Detection -> Incident Commander.
"""

from app.ai.workflows.base import BaseWorkflow
from app.ai.orchestrator.graph import WorkflowGraph, WorkflowStep, AgentNode


class InvestigationWorkflow(BaseWorkflow):
    """Standard security investigation multi-agent workflow DAG."""

    @property
    def name(self) -> str:
        return "standard_investigation_workflow"

    @property
    def description(self) -> str:
        return "Sequential multi-agent investigation workflow from Triage to Incident Commander synthesis."

    def build_graph(self) -> WorkflowGraph:
        """Construct the investigation workflow DAG."""
        graph = WorkflowGraph(name=self.name)

        # Nodes
        graph.add_node(AgentNode(node_id="node_triage", agent_name="TriageAgent", description="Initial alert triage"))
        graph.add_node(AgentNode(node_id="node_threat_intel", agent_name="ThreatIntelAgent", description="Enrich IOC reputation"))
        graph.add_node(AgentNode(node_id="node_threat_hunter", agent_name="ThreatHunterAgent", description="Telemetry hunting"))
        graph.add_node(AgentNode(node_id="node_dfir", agent_name="DFIRInvestigatorAgent", description="Forensic evidence analysis"))
        graph.add_node(AgentNode(node_id="node_detection", agent_name="DetectionRuleGeneratorAgent", description="Detection rule matching"))
        graph.add_node(AgentNode(node_id="node_commander", agent_name="IncidentCommanderAgent", description="Final synthesis and recommendations"))

        # Steps with dependencies
        graph.add_step(WorkflowStep(step_id="step_triage", agent_name="TriageAgent", dependencies=[]))
        graph.add_step(WorkflowStep(step_id="step_threat_intel", agent_name="ThreatIntelAgent", dependencies=["step_triage"]))
        graph.add_step(WorkflowStep(step_id="step_threat_hunter", agent_name="ThreatHunterAgent", dependencies=["step_threat_intel"]))
        graph.add_step(WorkflowStep(step_id="step_dfir", agent_name="DFIRInvestigatorAgent", dependencies=["step_threat_hunter"]))
        graph.add_step(WorkflowStep(step_id="step_detection", agent_name="DetectionRuleGeneratorAgent", dependencies=["step_dfir"]))
        graph.add_step(WorkflowStep(step_id="step_commander", agent_name="IncidentCommanderAgent", dependencies=["step_detection"]))

        graph.validate_dag()
        return graph
