# AegisAI XDR — AI Multi-Agent Architecture Documentation

This document specifies the design, capabilities, inputs, outputs, security boundaries, and test coverage of all specialized AI agents in the **AegisAI XDR** platform.

---

## 📊 Agent Comparison Matrix

| Agent | Core Purpose | Primary Input | Primary Output | Security Boundary | Human Approval Req |
|-------|--------------|---------------|----------------|-------------------|--------------------|
| **AI Orchestrator** | Manages stage transitions & state flow | Alert / Pipeline Request | Updated `PipelineContext` | Read-only orchestration | No |
| **ThreatHunterAgent** | Analyzes alerts & lateral movement | Ingested Alerts | Investigative Hypotheses | Read-only telemetry analysis | No |
| **DFIRInvestigatorAgent** | Reconstructs process trees & timeline | Evidence & Process Logs | Process Tree & Chronology | Read-only forensic analysis | No |
| **ThreatIntelAnalystAgent** | Normalizes IOCs & checks reputation | Extracted IOCs | Reputation & Confidence Scores | Read-only API enrichment | No |
| **DetectionRuleGeneratorAgent**| Generates Sigma/YARA/Suricata rules | Verified Attack Evidence | Candidate Rule Specs | Candidate generation only | Candidate status only |
| **IncidentCommanderAgent** | Synthesizes report & response plan | Aggregate Agent Results | Executive Summary & Plan | Recommends actions | **YES (CaseApproval)** |

---

## 1. AI Orchestrator

- **Purpose**: Directs the 11-stage autonomous investigation graph, invoking agents sequentially and updating global pipeline state.
- **Capabilities**: Stage execution scheduling, retry management, error handling, state machine recovery.
- **Inputs**: `PipelineRunRequest` containing initial alerts, `investigation_id`, and `incident_id`.
- **Outputs**: `PipelineContext` containing stage status records and overall execution metrics.
- **`InvestigationState` Fields**: Initializes `investigation_id`, `incident_id`, `alerts`, and `current_phase`.
- **Tools Used**: `PipelineStage` execution handlers, state serializers.
- **Memory**: In-memory `PipelineContext` stored in PostgreSQL/Redis database records.
- **Security Boundary**: Strictly internal workflow orchestration logic. Cannot execute external commands.
- **Human Approval**: Not required for stage progression. Pauses workflow at Stage 9 (`AWAITING_REVIEW`) when response actions are recommended.
- **Failure Behavior**: On stage failure, retries up to 3 times before setting pipeline status to `PAUSED` or `FAILED`.
- **Test Coverage**: Tested in `tests/unit/test_ai_orchestrator.py` and `tests/unit/test_autonomous_pipeline.py`.

---

## 2. ThreatHunterAgent

- **Purpose**: Conducts threat hunting over ingested security alerts to detect suspicious process executions, authentication anomalies, and lateral movement attempts.
- **Capabilities**: Hypothesis formulation, MITRE ATT&CK technique mapping, threat scoring.
- **Inputs**: Alert list and raw host telemetry from `InvestigationState.alerts`.
- **Outputs**: `AgentResult` containing hypotheses list, mapped MITRE techniques, and updated risk score.
- **`InvestigationState` Fields**: Mutates `hypotheses`, `mitre_mappings`, `risk_score`.
- **Tools Used**: Telemetry parser, MITRE technique mapper.
- **Memory**: Ephemeral execution memory per investigation run.
- **Security Boundary**: Strictly read-only analysis of security telemetry.
- **Human Approval**: None required.
- **Failure Behavior**: Returns partial findings with error metadata if telemetry parsing fails.
- **Test Coverage**: Tested in `tests/unit/test_threat_hunter.py`.

---

## 3. DFIRInvestigatorAgent

- **Purpose**: Reconstructs digital forensics process trees, command execution arguments, registry modifications, and chronological timeline events.
- **Capabilities**: Parent-child process tree reconstruction, execution sequence analysis, forensic evidence linking.
- **Inputs**: `InvestigationState.evidence` and telemetry logs.
- **Outputs**: Reconstructed process trees, file modification sequences, and timeline event records.
- **`InvestigationState` Fields**: Mutates `timeline` and `evidence`.
- **Tools Used**: Process tree builder, timeline generator.
- **Memory**: Ephemeral execution context.
- **Security Boundary**: Read-only analysis of uploaded forensic artifacts. Does not modify evidence files.
- **Human Approval**: None required.
- **Failure Behavior**: Falls back to basic event ordering if complex process tree reconstruction fails.
- **Test Coverage**: Tested in `tests/unit/test_dfir_investigator.py`.

---

## 4. ThreatIntelAnalystAgent

- **Purpose**: Extracts IP addresses, domain names, file hashes (MD5/SHA256), and URLs from alerts and enriches them against threat intelligence providers.
- **Capabilities**: IOC normalization, reputation lookups, provider consensus calculation, confidence rating.
- **Inputs**: Extracted IOC list from alerts and forensic evidence.
- **Outputs**: Normalized IOC objects, threat reputation scores, provider consensus data.
- **`InvestigationState` Fields**: Mutates `threat_intelligence` and `confidence_score`.
- **Tools Used**: VirusTotal API mock connector, MISP threat feed parser, IOC extractor.
- **Memory**: Cached IOC reputation records stored in Redis.
- **Security Boundary**: External network reads only. No write actions.
- **Human Approval**: None required.
- **Failure Behavior**: Uses cached reputation values or returns default neutral reputation on provider timeouts.
- **Test Coverage**: Tested in `tests/unit/test_threat_intelligence_agent.py`.

---

## 5. DetectionRuleGeneratorAgent

- **Purpose**: Synthesizes structured detection rules (Sigma, YARA, Suricata) based on verified attack patterns and forensic evidence.
- **Capabilities**: Rule pattern generation, syntax validation, duplicate detection, quality scoring.
- **Inputs**: Mapped MITRE techniques, process command lines, and file indicators.
- **Outputs**: Candidate detection rule definitions with metadata and quality scores.
- **`InvestigationState` Fields**: Mutates `detection_matches`.
- **Tools Used**: Sigma rule syntax validator, YARA pattern generator.
- **Memory**: Rule repository cache.
- **Security Boundary**: Generated rules are saved in `CANDIDATE` status. Never automatically deployed to active sensors.
- **Human Approval**: Requires human review before rule activation.
- **Failure Behavior**: Rejects invalid syntax rule candidates and logs validation details.
- **Test Coverage**: Tested in `tests/unit/test_detection_rule_generator.py`.

---

## 6. IncidentCommanderAgent

- **Purpose**: Acts as the senior executive agent, synthesizing findings from all specialized agents into an actionable incident summary and proposed response plan.
- **Capabilities**: Aggregate risk scoring, executive reporting, response playbook recommendation, governance request creation.
- **Inputs**: Complete `InvestigationState` including findings from Threat Hunter, DFIR, Threat Intel, and Detection Generator.
- **Outputs**: Final executive summary, overall risk assessment, response plan, and `CaseApproval` request.
- **`InvestigationState` Fields**: Mutates `recommendations`, `risk_score`, and `current_phase`.
- **Tools Used**: Report generator, CaseApproval builder.
- **Memory**: Full investigation historical state context.
- **Security Boundary**: Recommends response playbooks only. **Must submit a `CaseApproval` request for human sign-off**. Cannot directly invoke SOAR playbooks.
- **Human Approval**: **Mandatory `CaseApproval` gate enforced**.
- **Failure Behavior**: Emits conservative safety recommendations if aggregate risk calculation encounters invalid data.
- **Test Coverage**: Tested in `tests/unit/test_incident_commander.py`.
