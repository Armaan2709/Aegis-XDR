# AegisAI XDR — Incident Commander Agent Module

## Overview

The **Incident Commander Agent** is the sixth and final core specialized AI agent in the AegisAI XDR autonomous SOC architecture. It serves as the master decision-making and coordination layer. It synthesizes findings from `ThreatHunterAgent`, `DFIRInvestigatorAgent`, `ThreatIntelligenceAnalystAgent`, and `DetectionRuleGeneratorAgent`, evaluates evidence backing versus agent-only claims, calculates multi-agent consensus and conflict counts, reconstructs observed 12-tactic attack chains, determines root causes conservatively, computes risk/severity/priority scores, builds categorized response plans, and generates management-level executive summaries.

---

## Security Boundaries & Human Governance

> [!IMPORTANT]
> - **Synthesis & Coordination Only**: The Incident Commander does NOT execute destructive shell commands, active network scans, host isolations, account disablements, firewall rule modifications, or SOAR playbook runs directly.
> - **Human Approval Boundary**: Every response recommendation capable of altering production security state (such as `BLOCK_IP`, `ISOLATE_HOST`, `DISABLE_ACCOUNT`, `DEPLOY_RULE`, `EXECUTE_PLAYBOOK`) explicitly sets `requires_human_approval = True`.
> - **Zero External Dependencies**: Executes completely deterministically without external cloud LLM APIs, external network dependencies, or cloud provider API keys.

---

## Submodule Architecture

- `agent.py`: `IncidentCommanderAgent` implementing `BaseAgent`.
- `schemas.py`: Pydantic v2 DTOs (`IncidentAssessment`, `AttackChainStage`, `CommanderFinding`, `CommanderRecommendation`, `ResponsePlan`, `ExecutiveIncidentSummary`).
- `synthesis.py`: `IncidentSynthesisEngine` combining evidence items and multi-agent findings, identifying evidence gaps and root causes.
- `attack_chain.py`: `AttackChainAnalyzer` reconstructing 12 MITRE ATT&CK tactic stages (`OBSERVED`, `INFERRED`, `NOT_OBSERVED`, `UNKNOWN`).
- `severity.py`: `SeverityPriorityEngine` calculating risk (0-100), confidence (0.0-1.0), severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and priority (`P1`, `P2`, `P3`, `P4`).
- `consensus.py`: `IncidentConsensusEngine` computing agent agreement scores, conflict counts, and evidence support ratings.
- `response_plan.py`: `ResponsePlanEngine` constructing categorized response plans (`IMMEDIATE`, `CONTAINMENT`, `INVESTIGATION`, `ERADICATION`, `RECOVERY`, `MONITORING`).
- `executive_summary.py`: `ExecutiveSummaryGenerator` producing non-technical SOC management reporting payloads.

---

## Workflow Integration

The `IncidentCommanderAgent` executes as the final node in `InvestigationWorkflow`:

```
Ingestion -> Triage -> Threat Intel -> Threat Hunter -> DFIR Investigator -> Detection Rule Generator -> Incident Commander -> Case Management (Human Approval) -> SOAR Playbook Engine
```
