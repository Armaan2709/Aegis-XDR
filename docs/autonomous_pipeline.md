# AegisAI XDR — Autonomous Investigation Pipeline Documentation

This document details the 11-stage autonomous investigation pipeline operating within the **AegisAI XDR** platform.

---

## 🔄 11-Stage Investigation Lifecycle Overview

```
 [1] TRIAGING ──> [2] CORRELATING ──> [3] INVESTIGATION_STARTED ──> [4] THREAT_HUNTING
                                                                            │
 [8] INCIDENT_SYNTHESIS <── [7] DETECTION_GENERATION <── [6] THREAT_INTEL <── [5] DFIR_ANALYSIS
        │
        └──> [9] AWAITING_REVIEW (Human Gate) ──> [10] RESPONSE_EXECUTING ──> [11] COMPLETED
```

---

## 📑 Detailed Stage Specifications

### Stage 1: Alert Triage (`TRIAGING`)
- **Input**: Ingested raw security telemetry alerts (`AlertCreate` schemas).
- **Processing**: Normalizes alert attributes, calculates initial severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and assigns priority (`P1`–`P4`).
- **Output**: Validated `Alert` objects persisted to database.
- **State Transition**: `CREATED` → `TRIAGING` → `CORRELATING`.
- **Failure Behavior**: Retries ingestion up to 3 times; logs unparseable payloads to error queue.
- **Audit Event**: `ALERT_INGESTED`, `ALERT_TRIAGED`.
- **Security Boundary**: Input sanitization blocks SQL injection and XSS payloads.

---

### Stage 2: Alert Correlation (`CORRELATING`)
- **Input**: List of triaged alert UUIDs (`CorrelationRequest`).
- **Processing**: Evaluates temporal proximity, common hostnames/IPs, user context, and attack pattern similarity to group alerts into a unified Incident graph.
- **Output**: `Incident` entity created or linked with aggregated risk score.
- **State Transition**: `TRIAGING` → `CORRELATING` → `INVESTIGATION_STARTED`.
- **Failure Behavior**: Fallback logic creates single-alert Incident if graph correlation fails.
- **Audit Event**: `INCIDENT_CREATED`, `ALERTS_CORRELATED`.
- **Security Boundary**: Multi-tenant workspace isolation enforced during graph queries.

---

### Stage 3: Investigation Initialization (`INVESTIGATION_STARTED`)
- **Input**: `incident_id` and target investigation parameters.
- **Processing**: Instantiates an `Investigation` domain object and creates the shared `InvestigationState` container.
- **Output**: Initialized `Investigation` record in database and active `PipelineContext`.
- **State Transition**: `CORRELATING` → `INVESTIGATION_STARTED` → `THREAT_HUNTING`.
- **Failure Behavior**: Emits `NotFoundError` if associated incident UUID does not exist.
- **Audit Event**: `INVESTIGATION_INITIALIZED`.
- **Security Boundary**: Read-only state creation.

---

### Stage 4: Threat Hunting (`THREAT_HUNTING`)
- **Input**: Active `InvestigationState.alerts`.
- **Processing**: Invokes `ThreatHunterAgent` to formulate attack hypotheses, map tactics/techniques to MITRE ATT&CK, and calculate threat progression scores.
- **Output**: `AgentResult` populated with hypotheses and MITRE mappings.
- **State Transition**: `INVESTIGATION_STARTED` → `THREAT_HUNTING` → `DFIR_ANALYSIS`.
- **Failure Behavior**: Retries agent execution; records partial findings on persistent error.
- **Audit Event**: `THREAT_HUNTING_COMPLETED`.
- **Security Boundary**: Read-only telemetry analysis.

---

### Stage 5: DFIR Analysis (`DFIR_ANALYSIS`)
- **Input**: Forensic evidence records (`InvestigationState.evidence`).
- **Processing**: Invokes `DFIRInvestigatorAgent` to reconstruct parent-child process execution trees, inspect command-line arguments, and establish event chronologies.
- **Output**: Reconstructed process trees and forensic timeline event entries.
- **State Transition**: `THREAT_HUNTING` → `DFIR_ANALYSIS` → `THREAT_INTELLIGENCE`.
- **Failure Behavior**: Falls back to simple timestamp ordering if process tree reconstruction fails.
- **Audit Event**: `DFIR_ANALYSIS_COMPLETED`.
- **Security Boundary**: Read-only evidence inspection; evidence files are protected against modification.

---

### Stage 6: Threat Intelligence (`THREAT_INTELLIGENCE`)
- **Input**: Extracted IOCs (IPs, hashes, domain names) from alerts and evidence.
- **Processing**: Invokes `ThreatIntelAnalystAgent` to query threat reputation feeds, compute provider consensus, and assign confidence ratings.
- **Output**: Enriched `threat_intelligence` records attached to `InvestigationState`.
- **State Transition**: `DFIR_ANALYSIS` → `THREAT_INTELLIGENCE` → `DETECTION_GENERATION`.
- **Failure Behavior**: Uses local cache or default neutral ratings on network timeout.
- **Audit Event**: `THREAT_INTEL_ENRICHED`.
- **Security Boundary**: Read-only external API calls over TLS.

---

### Stage 7: Detection Generation (`DETECTION_GENERATION`)
- **Input**: Mapped MITRE techniques, command lines, and verified IOCs.
- **Processing**: Invokes `DetectionRuleGeneratorAgent` to synthesize candidate Sigma, YARA, and Suricata detection rules.
- **Output**: Candidate detection rule definitions stored in database with `CANDIDATE` status.
- **State Transition**: `THREAT_INTELLIGENCE` → `DETECTION_GENERATION` → `INCIDENT_SYNTHESIS`.
- **Failure Behavior**: Rejects rules that fail syntax validation and logs error details.
- **Audit Event**: `DETECTION_RULE_GENERATED`.
- **Security Boundary**: Generated rules remain in `CANDIDATE` status and are **never automatically activated**.

---

### Stage 8: Incident Synthesis (`INCIDENT_SYNTHESIS`)
- **Input**: Aggregate findings from all preceding agent executions.
- **Processing**: Invokes `IncidentCommanderAgent` to compute final aggregate risk scores, formulate executive summaries, and generate a proposed response plan.
- **Output**: Executive investigation summary, proposed SOAR playbook execution request, and `CaseApproval` governance record.
- **State Transition**: `DETECTION_GENERATION` → `INCIDENT_SYNTHESIS` → `AWAITING_REVIEW`.
- **Failure Behavior**: Generates conservative fallback summary on missing agent findings.
- **Audit Event**: `INCIDENT_SYNTHESIS_COMPLETED`.
- **Security Boundary**: Submits response recommendations to human governance; cannot execute playbooks directly.

---

### Stage 9: Human Governance Review (`AWAITING_REVIEW`)
- **Input**: `CaseApproval` record in `PENDING` status.
- **Processing**: **Pipeline pauses execution**. Waits for a human SOC analyst or supervisor to grant approval or reject the response plan.
- **Output**: Approved (`APPROVED`) or Rejected (`REJECTED`) `CaseApproval` status.
- **State Transition**:
  - `AWAITING_REVIEW` → `RESPONSE_EXECUTING` (if approved)
  - `AWAITING_REVIEW` → `CANCELLED` / `FAILED` (if rejected/expired)
- **Failure Behavior**: Times out safely after configured SLA threshold, setting approval to `EXPIRED` and canceling response execution.
- **Audit Event**: `APPROVAL_REQUESTED`, `APPROVAL_DECIDED`.
- **Security Boundary**: Non-bypassable human-in-the-loop governance barrier.

---

### Stage 10: Response Execution (`RESPONSE_EXECUTING`)
- **Input**: Approved `CaseApproval` record and target SOAR playbook definition.
- **Processing**: Triggers `PlaybookService` in **`SAFE_MOCK_EXECUTION`** mode.
- **Output**: Simulated execution log records detailing host containment, IP blocking, or account status updates.
- **State Transition**: `AWAITING_REVIEW` → `RESPONSE_EXECUTING` → `RESPONSE_COMPLETED`.
- **Failure Behavior**: Logs execution error and flags playbook execution as `FAILED` without system damage.
- **Audit Event**: `PLAYBOOK_EXECUTED_MOCK`.
- **Security Boundary**: Strictly non-destructive simulation mode (`SAFE_MOCK_EXECUTION`).

---

### Stage 11: Investigation Finalization (`COMPLETED`)
- **Input**: Completed stage outputs and SOAR execution logs.
- **Processing**: Flushes final timeline events, updates `Investigation` status to `COMPLETED`, and generates structured executive report.
- **Output**: Finalized `Investigation` record, audit timeline, and demonstration report.
- **State Transition**: `RESPONSE_COMPLETED` → `COMPLETED`.
- **Failure Behavior**: Ensures database state is committed before closing pipeline context.
- **Audit Event**: `INVESTIGATION_COMPLETED`.
- **Security Boundary**: Read-only state finalization.

---

## 🛠️ Pipeline Resilience, Retries & State Recovery

1. **Automatic Retries**: Individual agent stages retry up to 3 times with exponential backoff on transient errors.
2. **State Machine Resumption**: If a pipeline run is interrupted or paused at `AWAITING_REVIEW`, the state is fully persisted in PostgreSQL (`pipeline_contexts` table). Calling `resume_pipeline()` restores `InvestigationState` from JSON and continues from the current stage.
3. **Cancellation**: Pipeline execution can be explicitly canceled by an analyst, immediately transitioning status to `CANCELLED` and logging an audit event.
