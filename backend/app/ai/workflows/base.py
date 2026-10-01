"""
AI Orchestrator Workflow Base Abstraction.

Defines BaseWorkflow interface for constructing WorkflowGraph DAG structures.
"""

from abc import ABC, abstractmethod
from app.ai.orchestrator.graph import WorkflowGraph


class BaseWorkflow(ABC):
    """Abstract Base Class for AI security investigation workflow definitions."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique workflow name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Description of workflow objective."""
        pass

    @abstractmethod
    def build_graph(self) -> WorkflowGraph:
        """Construct and return validated WorkflowGraph DAG."""
        pass
