"""
Security Correlation Graph Representation.

Provides node and edge definitions to model relationships between Alerts, Incidents,
Hosts, Users, IP addresses, Processes, and Evidence artifacts for attack graph reconstruction.
"""

import enum
from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field


class CorrelationNodeType(str, enum.Enum):
    """Categories of graph nodes in correlation networks."""
    ALERT = "ALERT"
    INCIDENT = "INCIDENT"
    HOST = "HOST"
    USER = "USER"
    IP = "IP"
    HASH = "HASH"
    PROCESS = "PROCESS"
    EVIDENCE = "EVIDENCE"


class CorrelationEdgeType(str, enum.Enum):
    """Relationship categories connecting graph nodes."""
    BELONGS_TO = "BELONGS_TO"
    CORRELATED_WITH = "CORRELATED_WITH"
    TRIGGERED_ON = "TRIGGERED_ON"
    EXECUTED_BY = "EXECUTED_BY"
    COMMUNICATED_WITH = "COMMUNICATED_WITH"
    ASSOCIATED_EVIDENCE = "ASSOCIATED_EVIDENCE"


class GraphNode(BaseModel):
    """Node in the correlation relationship graph."""
    id: str = Field(..., description="Unique node identifier")
    label: str = Field(..., description="Display label for node")
    node_type: CorrelationNodeType = Field(..., description="Node category classification")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary attributes")


class GraphEdge(BaseModel):
    """Directed or undirected edge in the correlation relationship graph."""
    source_id: str = Field(..., description="Source node ID")
    target_id: str = Field(..., description="Target node ID")
    relationship: CorrelationEdgeType = Field(..., description="Relationship category")
    weight: float = Field(1.0, description="Edge weight rating")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Edge metadata")


class CorrelationGraph(BaseModel):
    """Graph structure managing entity nodes and correlation edges."""

    nodes: Dict[str, GraphNode] = Field(default_factory=dict)
    edges: List[GraphEdge] = Field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        """Add or update a node in the graph."""
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge connecting two nodes if both exist or after adding them."""
        self.edges.append(edge)

    def build_from_alerts(self, alerts: List[Any], incident_id: Optional[str] = None) -> None:
        """Construct graph nodes and edges from a collection of alert entities."""
        if incident_id:
            incident_node_id = f"incident:{incident_id}"
            self.add_node(
                GraphNode(
                    id=incident_node_id,
                    label=f"Incident {incident_id[:8]}",
                    node_type=CorrelationNodeType.INCIDENT,
                    properties={"incident_id": incident_id},
                )
            )

        for alert in alerts:
            alert_id_str = str(getattr(alert, "id", alert.get("id") if isinstance(alert, dict) else ""))
            title = str(getattr(alert, "title", alert.get("title") if isinstance(alert, dict) else "Alert"))
            alert_node_id = f"alert:{alert_id_str}"

            self.add_node(
                GraphNode(
                    id=alert_node_id,
                    label=title,
                    node_type=CorrelationNodeType.ALERT,
                    properties={
                        "severity": str(getattr(alert, "severity", "MEDIUM")),
                        "source": str(getattr(alert, "source", "SIEM")),
                    },
                )
            )

            if incident_id:
                self.add_edge(
                    GraphEdge(
                        source_id=alert_node_id,
                        target_id=f"incident:{incident_id}",
                        relationship=CorrelationEdgeType.BELONGS_TO,
                        weight=1.0,
                    )
                )

            # Extract IOCs & Host attributes
            raw_payload = getattr(alert, "raw_payload", {}) or (alert.get("raw_payload", {}) if isinstance(alert, dict) else {})
            iocs = getattr(alert, "iocs", {}) or (alert.get("iocs", {}) if isinstance(alert, dict) else {})

            hostname = raw_payload.get("hostname") or raw_payload.get("host")
            if hostname:
                host_node_id = f"host:{hostname}"
                self.add_node(
                    GraphNode(
                        id=host_node_id,
                        label=str(hostname),
                        node_type=CorrelationNodeType.HOST,
                    )
                )
                self.add_edge(
                    GraphEdge(
                        source_id=alert_node_id,
                        target_id=host_node_id,
                        relationship=CorrelationEdgeType.TRIGGERED_ON,
                    )
                )

            username = raw_payload.get("username") or raw_payload.get("user")
            if username:
                user_node_id = f"user:{username}"
                self.add_node(
                    GraphNode(
                        id=user_node_id,
                        label=str(username),
                        node_type=CorrelationNodeType.USER,
                    )
                )
                self.add_edge(
                    GraphEdge(
                        source_id=alert_node_id,
                        target_id=user_node_id,
                        relationship=CorrelationEdgeType.EXECUTED_BY,
                    )
                )

            ip_address = iocs.get("ip") or iocs.get("source_ip") or raw_payload.get("source_ip")
            if ip_address:
                ip_node_id = f"ip:{ip_address}"
                self.add_node(
                    GraphNode(
                        id=ip_node_id,
                        label=str(ip_address),
                        node_type=CorrelationNodeType.IP,
                    )
                )
                self.add_edge(
                    GraphEdge(
                        source_id=alert_node_id,
                        target_id=ip_node_id,
                        relationship=CorrelationEdgeType.COMMUNICATED_WITH,
                    )
                )

    def find_connected_components(self) -> List[Set[str]]:
        """Find connected clusters of node IDs using graph traversal."""
        adj: Dict[str, Set[str]] = {node_id: set() for node_id in self.nodes}
        for edge in self.edges:
            if edge.source_id in adj and edge.target_id in adj:
                adj[edge.source_id].add(edge.target_id)
                adj[edge.target_id].add(edge.source_id)

        visited: Set[str] = set()
        components: List[Set[str]] = []

        for node_id in self.nodes:
            if node_id not in visited:
                component: Set[str] = set()
                queue = [node_id]
                visited.add(node_id)
                while queue:
                    curr = queue.pop(0)
                    component.add(curr)
                    for nxt in adj.get(curr, set()):
                        if nxt not in visited:
                            visited.add(nxt)
                            queue.append(nxt)
                components.append(component)

        return components
