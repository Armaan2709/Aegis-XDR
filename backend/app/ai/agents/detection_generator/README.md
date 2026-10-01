# AegisAI XDR — Detection Rule Generator Agent Module

## Overview

The **Detection Rule Generator Agent** is the fourth specialized autonomous AI security agent implemented for AegisAI XDR. It extracts detection-worthy observables and behaviors from `InvestigationState` telemetry (alerts, evidence, timeline, Threat Hunter findings, DFIR findings, Threat Intel findings, and MITRE ATT&CK mappings) and synthesizes candidate defensive detection rules across **Sigma (YAML)**, **YARA (Memory/File)**, **Suricata (Network IDS)**, and **Custom** formats.

All generated candidates are validated, dry-run tested, versioned, and checked for duplicates by delegating directly to the existing Sprint 8 Detection Engine (`RuleParser`, `RuleValidator`, `RuleTester`, `RuleVersionManager`, `RuleRegistry`).

---

## Security Boundaries & Human Governance

> [!IMPORTANT]
> - **Generation & Dry-Run Mode Only**: The agent does not deploy rules to production SIEM, modify EDR policies, update firewall rules, or execute YARA/Suricata against production endpoints or network traffic.
> - **Human Approval Enforcement**: All recommendations to approve or deploy generated rules set `requires_human_approval = True`. No rule deployment occurs without Case Management supervisor review.

---

## Submodule Architecture

- `agent.py`: `DetectionRuleGeneratorAgent` implementing `BaseAgent`.
- `schemas.py`: Pydantic v2 models for `DetectionRuleCandidate`, `RuleQualityScore`, `RuleGenerationResult`, and `DetectionRuleRecommendation`.
- `evidence_analyzer.py`: `DetectionEvidenceAnalyzer` extracting processes, commands, hashes, IPs, domains, and MITRE technique IDs.
- `sigma_generator.py`: `SigmaRuleGenerator` producing structured Sigma YAML rules.
- `yara_generator.py`: `YaraRuleGenerator` producing YARA memory/file signature rules.
- `suricata_generator.py`: `SuricataRuleGenerator` producing Suricata network IDS rules.
- `rule_generator.py`: `DetectionRuleGenerationEngine` orchestrating rule synthesis and quality assessment.
- `quality.py`: `DetectionRuleQualityAnalyzer` evaluating quality scores (0-100), duplicate status, and dry-run performance via Sprint 8 components.
- `recommendations.py`: `DetectionRuleRecommendationGenerator` producing human-governed advisory deployment recommendations.

---

## AI Orchestrator Integration

The `DetectionRuleGeneratorAgent` registers with `AgentRegistry` (aliased as `"DetectionAgent"`) and executes in `InvestigationWorkflow`:

```
InvestigationState -> ThreatHunterAgent -> DFIRInvestigatorAgent -> ThreatIntelligenceAnalystAgent -> DetectionRuleGeneratorAgent -> ConsensusEngine -> Updated InvestigationState
```
