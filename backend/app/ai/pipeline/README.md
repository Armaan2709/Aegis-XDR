# AegisAI XDR — End-to-End Autonomous Investigation Pipeline

## Overview

The **Autonomous Investigation Pipeline** (`backend/app/ai/pipeline/`) unifies all AegisAI XDR core engines and specialized AI security agents into a single, deterministic 11-stage autonomous security operations workflow.

```
Security Alert
    ↓
Correlation Engine
    ↓
Incident
    ↓
Investigation
    ↓
Autonomous AI Investigation Pipeline
    ├── Threat Hunter
    ├── DFIR Investigator
    ├── Threat Intelligence Analyst
    ├── Detection Rule Generator
    └── Incident Commander
    ↓
Unified Assessment & Risk/Severity Scoring
    ↓
Human-Governed CaseApproval Gate
    ↓
Approved SOAR Playbook Execution (Safe Mock)
    ↓
Finalization & Auditable Reporting
```

---

## Security Boundaries & Governance

> [!IMPORTANT]
> - **Human Approval Boundary**: Response execution (`ResponseExecutionStage`) CANNOT execute unless `CaseApproval` is set to `APPROVED` or `AUTO_APPROVED`.
> - **Safe Mock SOAR Execution**: All playbook response actions remain simulated/mock. Zero live firewall modifications, host isolations, account disablements, or network blocks occur.
> - **Zero External Dependencies**: Operates 100% deterministically without external cloud LLM APIs, cloud provider keys, or external network calls.

---

## Submodule Architecture

- `schemas.py`: Pydantic v2 data models (`PipelineStage`, `PipelineStatus`, `StageStatus`, `StageResult`, `PipelineContext`, `PipelineTimelineEntry`, `PipelineRunRequest`).
- `state_manager.py`: `PipelineStateManager` enforcing valid state transitions and preventing illegal state machine jumps.
- `stages.py`: 11 concrete stage executors implementing `BasePipelineStage`.
- `pipeline.py`: `AutonomousInvestigationPipeline` coordinating stage execution, retries, cancellation, and metrics recording.
- `recovery.py`: `PipelineRecoveryEngine` allowing safe resumption from failed/paused stages without re-running completed stages.
- `audit.py`: `PipelineAuditLogger` writing auditable timeline entries.
- `metrics.py`: `PipelineMetricsCollector` tracking duration, failure counts, retry counts, and MTTR approximations.

---

## API Endpoints

- `POST /api/v1/ai/investigations/{investigation_id}/run`
- `GET /api/v1/ai/investigations/{investigation_id}/status`
- `GET /api/v1/ai/investigations/{investigation_id}/timeline`
- `POST /api/v1/ai/investigations/{investigation_id}/cancel`
- `GET /api/v1/ai/pipelines/{pipeline_id}`
