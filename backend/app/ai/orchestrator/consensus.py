"""
AI Orchestrator Multi-Agent Consensus Engine.

Aggregates structured AgentResult outputs deterministically.
Calculates aggregate confidence, composite risk scores, flags conflicting findings,
and ranks recommendations without LLM inference.
"""

from typing import List, Dict, Any
from pydantic import BaseModel, Field
from app.ai.agents.base import AgentResult, AgentStatus


class ConsensusResult(BaseModel):
    """Structured result produced by consensus aggregation of multi-agent execution outputs."""
    aggregated_findings: List[Dict[str, Any]] = Field(default_factory=list)
    aggregated_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    composite_confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    composite_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    conflicting_findings: List[Dict[str, Any]] = Field(default_factory=list)
    ranked_recommendations: List[str] = Field(default_factory=list)
    participating_agents: List[str] = Field(default_factory=list)


class ConsensusEngine:
    """Deterministic consensus engine for multi-agent findings aggregation."""

    def aggregate(self, results: List[AgentResult]) -> ConsensusResult:
        """Aggregate a list of AgentResult objects into a unified ConsensusResult."""
        if not results:
            return ConsensusResult()

        successful_results = [r for r in results if r.status == AgentStatus.SUCCESS]
        if not successful_results:
            successful_results = results

        participating_agents = [r.agent_name for r in results]

        # 1. Aggregate Findings & Evidence
        all_findings = []
        all_evidence = []
        for r in successful_results:
            all_findings.extend(r.findings)
            all_evidence.extend(r.evidence)

        # 2. Composite Confidence Score (Average of successful agents)
        conf_sum = sum(r.confidence_score for r in successful_results)
        comp_conf = round(conf_sum / len(successful_results), 2) if successful_results else 0.0

        # 3. Composite Risk Score (Weighted by confidence scores)
        # Extract risk ratings from findings or calculate base score from confidence
        total_weighted_risk = 0.0
        total_weights = 0.0

        for r in successful_results:
            weight = r.confidence_score or 1.0
            agent_risk = 50.0 # Default baseline
            for f in r.findings:
                if "risk_score" in f:
                    agent_risk = float(f["risk_score"])
            total_weighted_risk += agent_risk * weight
            total_weights += weight

        comp_risk = round(total_weighted_risk / total_weights, 1) if total_weights > 0 else 0.0

        # 4. Conflicting Findings Detection
        conflicts = []
        verdicts = {}
        for r in successful_results:
            for f in r.findings:
                key = f.get("category") or f.get("title")
                verdict = f.get("verdict")
                if key and verdict:
                    if key in verdicts and verdicts[key]["verdict"] != verdict:
                        conflicts.append({
                            "key": key,
                            "agent_a": verdicts[key]["agent"],
                            "verdict_a": verdicts[key]["verdict"],
                            "agent_b": r.agent_name,
                            "verdict_b": verdict,
                        })
                    else:
                        verdicts[key] = {"agent": r.agent_name, "verdict": verdict}

        # 5. Recommendation Ranking (by frequency & confidence)
        rec_scores: Dict[str, float] = {}
        for r in successful_results:
            for rec in r.recommendations:
                rec_scores[rec] = rec_scores.get(rec, 0.0) + (r.confidence_score or 1.0)

        sorted_recs = sorted(rec_scores.keys(), key=lambda k: rec_scores[k], reverse=True)

        return ConsensusResult(
            aggregated_findings=all_findings,
            aggregated_evidence=all_evidence,
            composite_confidence_score=comp_conf,
            composite_risk_score=comp_risk,
            conflicting_findings=conflicts,
            ranked_recommendations=sorted_recs,
            participating_agents=participating_agents,
        )
