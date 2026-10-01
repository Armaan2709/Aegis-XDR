"""
MITRE ATT&CK Coverage & Matrix Heatmap Calculator.

Calculates coverage percentages across all 14 tactics, mapped techniques metrics,
missing high-risk tactics, and matrix heatmap representations for SOC dashboards.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.mitre.models import MitreTacticEnum
from app.mitre.knowledge_base import DEFAULT_MITRE_TACTICS


class TacticCoverageMetric(BaseModel):
    """Coverage metric summary for a single MITRE tactic."""

    tactic_id: str
    tactic_name: str
    mapped_techniques_count: int
    coverage_score: float = Field(..., ge=0.0, le=100.0)


class MitreCoverageReport(BaseModel):
    """Comprehensive MITRE ATT&CK enterprise/incident matrix coverage report."""

    scope: str = Field("ENVIRONMENT", description="Scope of report (ENVIRONMENT, INCIDENT, INVESTIGATION)")
    total_tactics_count: int = Field(12)
    covered_tactics_count: int = Field(0)
    overall_coverage_percentage: float = Field(0.0, ge=0.0, le=100.0)
    total_techniques_mapped: int = Field(0)
    tactic_metrics: List[TacticCoverageMetric] = Field(default_factory=list)
    heatmap_matrix: Dict[str, int] = Field(default_factory=dict)
    uncovered_tactics: List[str] = Field(default_factory=list)


class MitreCoverageCalculator:
    """Calculator for generating MITRE ATT&CK matrix coverage metrics."""

    @classmethod
    def calculate_coverage(
        cls, mappings: List[Any], scope: str = "ENVIRONMENT"
    ) -> MitreCoverageReport:
        """
        Calculate coverage report based on a collection of MitreMapping entities or dictionaries.
        """
        technique_counts: Dict[str, int] = {}
        tactic_counts: Dict[str, Set[str]] = {t["tactic_id"]: set() for t in DEFAULT_MITRE_TACTICS}

        for m in mappings:
            tech_id = str(getattr(m, "technique_id", m.get("technique_id") if isinstance(m, dict) else ""))
            tactic_val = str(getattr(m, "tactic", m.get("tactic") if isinstance(m, dict) else "")).upper()

            if tech_id:
                technique_counts[tech_id] = technique_counts.get(tech_id, 0) + 1

            # Match tactic to static tactics catalog
            for t_info in DEFAULT_MITRE_TACTICS:
                t_name_upper = t_info["name"].upper().replace(" ", "_")
                if t_name_upper in tactic_val or t_info["tactic_id"] in tactic_val:
                    tactic_counts[t_info["tactic_id"]].add(tech_id)

        metrics: List[TacticCoverageMetric] = []
        covered_count = 0
        uncovered: List[str] = []

        for t_info in DEFAULT_MITRE_TACTICS:
            t_id = t_info["tactic_id"]
            mapped_set = tactic_counts.get(t_id, set())
            tech_cnt = len(mapped_set)
            if tech_cnt > 0:
                covered_count += 1
                coverage_score = min(100.0, round((tech_cnt / 5.0) * 100.0, 1))
            else:
                uncovered.append(t_info["name"])
                coverage_score = 0.0

            metrics.append(
                TacticCoverageMetric(
                    tactic_id=t_id,
                    tactic_name=t_info["name"],
                    mapped_techniques_count=tech_cnt,
                    coverage_score=coverage_score,
                )
            )

        total_tactics = len(DEFAULT_MITRE_TACTICS)
        pct = round((covered_count / total_tactics) * 100.0, 1) if total_tactics > 0 else 0.0

        return MitreCoverageReport(
            scope=scope,
            total_tactics_count=total_tactics,
            covered_tactics_count=covered_count,
            overall_coverage_percentage=pct,
            total_techniques_mapped=len(technique_counts),
            tactic_metrics=metrics,
            heatmap_matrix=technique_counts,
            uncovered_tactics=uncovered,
        )
