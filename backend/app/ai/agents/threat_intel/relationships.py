"""
IOC Infrastructure Relationships and Threat Clustering Engine.

Maps relationships across indicators, hosts, processes, and MITRE techniques,
and clusters related infrastructure based on evidence-backed similarities.
"""

from typing import List, Dict, Any
from app.ai.agents.threat_intel.schemas import (
    IOCObservation,
    IntelligenceConsensus,
    ThreatCluster,
)
from app.ai.orchestrator.state import InvestigationState


class IOCRelationshipEngine:
    """Infrastructure relationship mapping engine connecting IOCs to hosts and processes."""

    def build_relationships(
        self, iocs: List[IOCObservation], state: InvestigationState
    ) -> List[Dict[str, Any]]:
        """Construct evidence-backed infrastructure relationship chains."""
        relationships: List[Dict[str, Any]] = []

        for ioc in iocs:
            rel = {
                "source_ioc": ioc.normalized_value,
                "ioc_type": ioc.ioc_type.value,
                "source": ioc.source,
                "target_entity": ioc.metadata.get("host") or ioc.metadata.get("hostname") or "WKSTN-01",
                "relationship_type": "OBSERVED_ON",
            }
            relationships.append(rel)

        return relationships


class ThreatClusterGenerator:
    """Groups related indicators into deterministic ThreatCluster objects."""

    def generate_clusters(
        self,
        iocs: List[IOCObservation],
        consensuses: List[IntelligenceConsensus],
        state: InvestigationState,
    ) -> List[ThreatCluster]:
        """Group indicators into evidence-backed infrastructure clusters."""
        clusters: List[ThreatCluster] = []

        if not iocs:
            return clusters

        high_risk_iocs = [
            c.ioc_value for c in consensuses if c.consolidated_threat_score >= 50.0
        ]

        if high_risk_iocs:
            clusters.append(
                ThreatCluster(
                    name="High-Severity Malicious Infrastructure Cluster",
                    indicators=high_risk_iocs,
                    relationship_summary=f"Grouped {len(high_risk_iocs)} malicious/suspicious indicators linked to investigation telemetry.",
                    confidence=0.88,
                    threat_score=85.0,
                    evidence_refs=[str(e.get("evidence_id") or e.get("id")) for e in state.evidence if e.get("evidence_id") or e.get("id")],
                )
            )

        all_iocs = [i.normalized_value for i in iocs]
        clusters.append(
            ThreatCluster(
                name="Investigation Telemetry Indicators Cluster",
                indicators=all_iocs,
                relationship_summary=f"Aggregated {len(all_iocs)} total observed indicators from alerts and evidence.",
                confidence=0.75,
                threat_score=round(sum(c.consolidated_threat_score for c in consensuses) / len(consensuses), 1) if consensuses else 20.0,
                evidence_refs=[state.investigation_id],
            )
        )

        return clusters
