# AegisAI XDR — DFIR Investigator Agent Module

## Overview

The **DFIR Investigator Agent** is the specialized Digital Forensics and Incident Response AI agent implemented for AegisAI XDR. It inspects forensic evidence, normalizes artifacts across process, file, network, registry, and authentication categories, reconstructs chronological attack timelines and kill-chain phases, evaluates parent-child process trees, identifies evidence gaps, formulates root-cause hypotheses, and generates human-governed security recommendations.

---

## Capabilities & Responsibilities

- **Digital Forensics**: Inspection and classification of raw host, memory, process, and file evidence.
- **Artifact Normalization**: Normalizing evidence, timeline events, and alerts into `NormalizedArtifact` objects.
- **Timeline Reconstruction**: Chronological event ordering and kill-chain `AttackPhase` mapping.
- **Process & Command-Line Analysis**: Detecting suspicious parent-child process relationships (Office -> PowerShell, Browser -> script, Service -> unusual binary) and obfuscated command line flags (`-enc`).
- **Attack Reconstruction & Root Cause**: Formulating evidence-backed `RootCauseHypothesis` statuses (`SUPPORTED`, `INCONCLUSIVE`, `REFUTED`).
- **Threat Hunter Integration**: Consuming prior findings from `ThreatHunterAgent` when present in state.
- **Evidence Gap Detection**: Identifying missing telemetry (RAM dump, auth logs, PCAP) to guide collectors.

---

## Security Boundaries & Human Governance

> [!IMPORTANT]
> - **Strictly Read-Only Execution**: The DFIR Investigator Agent is strictly read-only. No binary execution, malware execution, active scanning, shell/Python execution, host isolation, or system modifications are permitted.
> - **Human Approval Enforcement**: All recommendations involving SOAR response playbooks (e.g. `PB-CONTAIN-ENDPOINT`, `PB-COLLECT-DIAGNOSTICS`, `PB-FORENSIC-TRIAGE`) explicitly set `requires_human_approval = True`. No automated response actions execute without Case Management supervisor review.

---

## Submodule Architecture

- `agent.py`: `DFIRInvestigatorAgent` implementing `BaseAgent`.
- `schemas.py`: Pydantic v2 models for `NormalizedArtifact`, `RootCauseHypothesis`, `EvidenceGap`, `DFIRFinding`, and `DFIRRecommendation`.
- `artifacts.py`: `ArtifactNormalizer` categorizing evidence into process, file, network, registry, auth, memory, and log types.
- `timeline.py`: `ForensicTimelineAnalyzer` ordering events and mapping attack phases.
- `analysis.py`: `ProcessTreeAnalyzer`, `CommandLineAnalyzer`, and `AttackReconstructionEngine`.
- `findings.py`: `DFIRFindingGenerator` producing findings and detecting evidence gaps.
- `recommendations.py`: `DFIRRecommendationGenerator` generating human-governed advisory recommendations.

---

## AI Orchestrator Integration

The `DFIRInvestigatorAgent` registers with `AgentRegistry` and executes following `ThreatHunterAgent` in `InvestigationWorkflow`:

```
InvestigationState -> ThreatHunterAgent -> DFIRInvestigatorAgent -> ConsensusEngine -> Updated InvestigationState
```
