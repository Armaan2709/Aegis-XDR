# AegisAI XDR — Threat Hunter Agent Module

## Overview

The **Threat Hunter Agent** is the first specialized autonomous AI security agent implemented for AegisAI XDR. It inspects security evidence and observables (IPs, domains, hashes, process executions, command lines, registry keys, user activity), formulates threat hypotheses, correlates attack patterns with MITRE ATT&CK and Threat Intelligence, calculates deterministic confidence and composite risk scores, and generates human-governed security recommendations.

---

## Capabilities & Responsibilities

- **Threat Hunting**: Proactive detection of attacker activity across endpoints and network telemetry.
- **Behavioral Analysis**: Process execution tree and obfuscated command line inspection.
- **IOC Analysis**: Reputation lookup for suspicious IP addresses, domains, and payload hashes.
- **Attack Pattern Detection**: Correlating multi-stage behavior to adversary TTPs.
- **MITRE ATT&CK Analysis**: Mapping observed behavior to ATT&CK tactics, techniques, and sub-techniques.
- **Hypothesis Generation**: Formulating structured hypotheses (Credential Theft, PowerShell Execution, Persistence, Lateral Movement, C2, Data Exfiltration).
- **Risk Assessment**: Calculating deterministic composite risk (0-100) and confidence ratings (0.0-1.0).

---

## Security Boundaries & Human Governance

> [!IMPORTANT]
> - **Strictly Read-Only Execution**: The Threat Hunter Agent executes only controlled read-only queries via registered security tools (`QuerySIEMTool`, `QueryThreatIntelTool`, `QueryMitreTool`, `QueryEvidenceTool`). No shell execution, arbitrary Python code execution, system modifications, account disabling, or host isolation are permitted.
> - **Human Approval Enforcement**: All recommendations involving SOAR response playbooks (e.g. `PB-CONTAIN-ENDPOINT`, `PB-BLOCK-IOC`) explicitly set `requires_human_approval = True`. No automated response actions execute without Case Management supervisor review.

---

## Submodule Architecture

- `agent.py`: `ThreatHunterAgent` implementing `BaseAgent`.
- `schemas.py`: Pydantic v2 models for `ObservableItem`, `ThreatHypothesis`, `ThreatFinding`, and `ThreatRecommendation`.
- `analyzers.py`: `ObservableAnalyzer` for regex/pattern extraction and tool enrichment.
- `hypotheses.py`: `HypothesisEngine` for evidence-backed threat hypothesis generation.
- `investigation.py`: `ThreatInvestigationEngine` for telemetry correlation and deterministic scoring.
- `recommendations.py`: `ThreatRecommendationGenerator` for findings and human-governed recommendations.

---

## AI Orchestrator Integration

The `ThreatHunterAgent` registers with `AgentRegistry` and executes as a core node in `InvestigationWorkflow`:

```
InvestigationState -> ThreatHunterAgent -> AgentResult -> ConsensusEngine -> Updated InvestigationState
```
