# AegisAI XDR — Threat Intelligence Analyst Agent Module

## Overview

The **Threat Intelligence Analyst Agent** is the third specialized autonomous AI security agent implemented for AegisAI XDR. It extracts Indicators of Compromise (IOCs) from investigation state telemetry (alerts, evidence, timeline, Threat Hunter findings, and DFIR findings), normalizes them using domain `IOCValidator`, evaluates provider consensus across VirusTotal, AbuseIPDB, AlienVault OTX, MISP, and GreyNoise, calculates consolidated threat and confidence scores, maps indicator infrastructure relationships, clusters related indicators into `ThreatCluster` objects, formulates conservative attribution assessments, detects intelligence gaps, and issues human-governed security recommendations.

---

## Capabilities & Responsibilities

- **Threat Intelligence Analysis**: Full-spectrum indicator analysis and provider reputation query parsing.
- **IOC Normalization**: Normalizing IPv4, IPv6, Domain, URL, Hashes (MD5/SHA1/SHA256), Email, Registry Keys, and Processes using domain `IOCValidator`.
- **Provider Consensus Evaluation**: Calculating malicious, benign, and unknown verdict ratios, agreement/disagreement metrics, and consolidated threat scores (0-100).
- **Threat Clustering**: Deterministic grouping of indicators based on common infrastructure, hosts, or threat categories.
- **Conservative Attribution**: Non-definitive attribution levels (`UNKNOWN`, `POTENTIAL_CAMPAIGN`, `POSSIBLE_THREAT_GROUP`, `INFRASTRUCTURE_RELATIONSHIP`).
- **Intelligence Gap Detection**: Identifying provider disagreement or missing reputation telemetry.

---

## Security Boundaries & Human Governance

> [!IMPORTANT]
> - **Analysis-Only Execution**: The Threat Intelligence Analyst Agent is strictly read-only. No network probing, port scanning, outbound connections to suspicious infrastructure, active scanning, or system modifications are performed.
> - **Human Approval Enforcement**: All recommendations involving SOAR response playbooks (e.g. `PB-CONTAIN-ENDPOINT`, `PB-COLLECT-DIAGNOSTICS`, `PB-FORENSIC-TRIAGE`) explicitly set `requires_human_approval = True`. No automated response actions execute without Case Management supervisor review.

---

## Submodule Architecture

- `agent.py`: `ThreatIntelligenceAnalystAgent` implementing `BaseAgent`.
- `schemas.py`: Pydantic v2 models for `IOCObservation`, `ProviderAssessment`, `IntelligenceConsensus`, `ThreatCluster`, `AttributionAssessment`, `ThreatIntelligenceFinding`, `IntelligenceGap`, and `ThreatIntelligenceRecommendation`.
- `ioc_analysis.py`: `IOCAnalyzer` extracting and normalizing indicators reusing `IOCValidator`.
- `enrichment.py`: `ThreatEnrichmentConsensusEngine` computing provider consensus and consolidated scores.
- `relationships.py`: `IOCRelationshipEngine` and `ThreatClusterGenerator`.
- `attribution.py`: `ConservativeAttributionEngine` formulating non-definitive attribution statements.
- `findings.py`: `ThreatIntelFindingGenerator` producing findings and detecting intelligence gaps.
- `recommendations.py`: `ThreatIntelRecommendationGenerator` generating human-governed advisory recommendations.

---

## AI Orchestrator Integration

The `ThreatIntelligenceAnalystAgent` registers with `AgentRegistry` and executes following `ThreatHunterAgent` and `DFIRInvestigatorAgent` in `InvestigationWorkflow`:

```
InvestigationState -> ThreatHunterAgent -> DFIRInvestigatorAgent -> ThreatIntelligenceAnalystAgent -> ConsensusEngine -> Updated InvestigationState
```
