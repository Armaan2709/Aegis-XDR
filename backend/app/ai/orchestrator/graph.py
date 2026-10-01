"""
AI Orchestrator Workflow Graph Engine.

LangGraph-ready Direct Acyclic Graph (DAG) abstraction supporting workflow step resolution,
topological ordering, cycle detection, dependency validation, and conditional branching.
"""

from typing import Dict, List, Optional, Set, Any
from pydantic import BaseModel, Field
from app.ai.orchestrator.state import InvestigationState
from app.core.exceptions import ValidationError, ConflictError


class WorkflowStep(BaseModel):
    """Workflow step definition node within a workflow DAG."""
    step_id: str = Field(..., description="Unique step identifier string")
    agent_name: str = Field(..., description="Name of agent to execute at this step")
    dependencies: List[str] = Field(default_factory=list, description="Step IDs that must complete prior to this step")
    condition_rule: Optional[Dict[str, Any]] = Field(default=None, description="Optional condition rule for step execution")


class AgentNode(BaseModel):
    """Visual/Graph representation node for an agent."""
    node_id: str = Field(..., description="Unique node ID")
    agent_name: str = Field(..., description="Target agent name")
    description: Optional[str] = Field(default=None, description="Node description")


class WorkflowGraph:
    """Directed Acyclic Graph (DAG) structure for orchestrating agent workflow steps."""

    def __init__(self, name: str = "default_workflow_graph"):
        self.name = name
        self.nodes: Dict[str, AgentNode] = {}
        self.steps: Dict[str, WorkflowStep] = {}

    def add_node(self, node: AgentNode) -> None:
        """Add graph node. Raises ConflictError on duplicate node_id."""
        if node.node_id in self.nodes:
            raise ConflictError(f"Node '{node.node_id}' already exists in workflow graph.")
        self.nodes[node.node_id] = node

    def add_step(self, step: WorkflowStep) -> None:
        """Add workflow step. Raises ConflictError on duplicate step_id."""
        if step.step_id in self.steps:
            raise ConflictError(f"Step '{step.step_id}' already exists in workflow graph.")
        self.steps[step.step_id] = step

    def validate_dag(self) -> None:
        """Validate DAG integrity: check missing dependencies and cycles."""
        # 1. Missing dependency check
        for step in self.steps.values():
            for dep in step.dependencies:
                if dep not in self.steps:
                    raise ValidationError(f"Step '{step.step_id}' references non-existent dependency '{dep}'.")

        # 2. Cycle detection via Khan's / Depth-First Search cycle detection
        visited: Set[str] = set()
        rec_stack: Set[str] = set()

        def dfs(step_id: str):
            visited.add(step_id)
            rec_stack.add(step_id)

            step = self.steps[step_id]
            for dep in step.dependencies:
                if dep not in visited:
                    dfs(dep)
                elif dep in rec_stack:
                    raise ValidationError(f"Cycle detected in workflow graph involving step '{step_id}' and '{dep}'.")

            rec_stack.remove(step_id)

        for s_id in self.steps:
            if s_id not in visited:
                dfs(s_id)

    def get_execution_order(self) -> List[WorkflowStep]:
        """Return steps in topological execution order."""
        self.validate_dag()
        
        # Calculate in-degrees
        in_degree = {s_id: 0 for s_id in self.steps}
        graph = {s_id: [] for s_id in self.steps}

        for step in self.steps.values():
            for dep in step.dependencies:
                graph[dep].append(step.step_id)
                in_degree[step.step_id] += 1

        queue = [s_id for s_id, deg in in_degree.items() if deg == 0]
        order = []

        while queue:
            curr = queue.pop(0)
            order.append(self.steps[curr])

            for neighbor in graph[curr]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        return order

    def evaluate_step_condition(self, step: WorkflowStep, state: InvestigationState) -> bool:
        """Evaluate if step execution conditions are met based on investigation state."""
        if not step.condition_rule:
            return True

        rule = step.condition_rule
        field = rule.get("field")
        op = rule.get("operator", "==")
        target_val = rule.get("value")

        if not field:
            return True

        state_dict = state.to_dict()
        actual_val = state_dict.get(field)

        if op == "==":
            return actual_val == target_val
        elif op == "!=":
            return actual_val != target_val
        elif op == ">":
            return float(actual_val or 0) > float(target_val or 0)
        elif op == ">=":
            return float(actual_val or 0) >= float(target_val or 0)

        return True


class WorkflowExecution(BaseModel):
    """Tracks execution run progress for a workflow graph."""
    execution_id: str = Field(..., description="Unique execution instance UUID string")
    graph_name: str = Field(..., description="Name of executed workflow graph")
    completed_steps: List[str] = Field(default_factory=list, description="List of successfully completed step IDs")
    failed_steps: List[str] = Field(default_factory=list, description="List of failed step IDs")
    skipped_steps: List[str] = Field(default_factory=list, description="List of skipped step IDs")
    status: str = Field(default="PENDING", description="Status: PENDING, RUNNING, COMPLETED, FAILED")
