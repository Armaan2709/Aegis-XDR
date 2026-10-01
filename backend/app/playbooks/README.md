# AegisAI XDR — SOAR Playbook Engine Module

## Overview

The **SOAR (Security Orchestration, Automation, and Response) Playbook Engine** is the response execution layer for AegisAI XDR. It automates complex incident containment, threat hunting, evidence collection, and notification workflows using deterministic, sequential steps and composable logic.

---

## Key Architecture & Safety Guarantees

> [!IMPORTANT]
> **Deterministic Simulated Actions Only**:
> To guarantee zero collateral damage, all response action execution is delegated to **safe mock executors**. No real-world destructive infrastructure commands (e.g. firewall rule pushes, host isolations, process kills, system calls, or shell execution) are executed by this engine.

### Core Architecture Components

- **`models.py`**: SQLAlchemy 2.0 entities (`Playbook`, `PlaybookStep`, `PlaybookExecution`, `PlaybookStepExecution`) using `Mapped[]` type hints.
- **`schemas.py`**: Pydantic v2 DTOs for request validation, execution parameters, and API response formatting.
- **`repositories.py`**: Async SQLAlchemy 2.0 database repositories for CRUD operations, status queries, and pagination.
- **`actions.py`**: `BasePlaybookAction` abstract interface and safe mock executors for all 12 supported `ActionType` values.
- **`conditions.py`**: `ConditionEvaluator` for evaluating context variables using comparison (`==`, `!=`, `>=`, `>`, `<=`, `<`, `IN`, `CONTAINS`) and logical (`AND`, `OR`) operators.
- **`validators.py`**: `PlaybookValidator` for validating step ordering, missing configurations, timeouts, retries, and lifecycle state transitions.
- **`registry.py`**: `PlaybookRegistry` for runtime registration, searching, category/severity filtering, and version resolution.
- **`approvals.py`**: `PlaybookApprovalBridge` integrating playbook manual approval gates with the existing authoritative **Case Management `CaseApproval`** architecture.
- **`executions.py`**: `ExecutionTracker` for managing workflow context, propagating step outputs, and logging step execution history.
- **`engine.py`**: `PlaybookEngine` orchestrator driving step execution loops, retries, timeout enforcement, condition evaluation, and approval pauses/resumptions.
- **`services.py`**: `PlaybookService` domain service coordinating API requests, database persistence, validation, and engine runs.
- **`router.py`**: REST API routes mounted under `/api/v1/playbooks`.

---

## Playbook & Step Lifecycles

### Playbook Lifecycle States
1. `DRAFT`: Initial draft mode under configuration.
2. `TESTING`: Sandbox testing state for validation.
3. `ACTIVE`: Production ready; available for automated or manual triggering.
4. `DISABLED`: Temporarily deactivated.
5. `ARCHIVED`: Soft-deleted / historical record.

### Execution Workflow States
1. `QUEUED`: Execution initialized and queued for run.
2. `RUNNING`: Step execution loop active.
3. `WAITING_APPROVAL`: Execution paused pending supervisor decision in Case Management.
4. `COMPLETED`: All configured steps completed successfully.
5. `FAILED`: Step failed and retries exhausted without `continue_on_failure`.
6. `CANCELLED`: Execution cancelled by user or rejected during approval gate.
7. `PARTIALLY_COMPLETED`: Execution finished with non-critical step failures (`continue_on_failure=True`).

---

## Supported Action Types & Mock Output

Every action execution returns structured metadata explicitly indicating simulated output:

| ActionType | Mock Behavior & Description |
|---|---|
| `BLOCK_IP` | Simulates perimeter firewall IP blocking rule application |
| `ISOLATE_HOST` | Simulates EDR network isolation of compromised endpoint |
| `DISABLE_ACCOUNT` | Simulates Identity Directory user account deactivation |
| `COLLECT_EVIDENCE` | Simulates DFIR artifact (RAM/disk dump) collection trigger |
| `QUERY_THREAT_INTEL` | Simulates Threat Intel indicator reputation enrichment query |
| `CREATE_CASE` | Simulates Case Management workspace auto-creation |
| `CREATE_INCIDENT` | Simulates Incident entity auto-generation |
| `SEND_NOTIFICATION` | Simulates SOC chat (Slack/Teams) notification dispatch |
| `ADD_TAG` | Simulates security classification tag attachment |
| `UPDATE_INCIDENT` | Simulates Incident status / containment update |
| `RUN_DETECTION` | Simulates Detection Engine rule sweep trigger |
| `GENERATE_REPORT` | Simulates executive incident report compilation |

---

## Case Approval System Integration

Playbook step approvals integrate seamlessly with the existing `CaseApproval` domain in Case Management:
1. When a step has `requires_approval=True` (or global `playbook.requires_approval=True`), execution status transitions to `WAITING_APPROVAL`.
2. A formal `CaseApproval` request is submitted via `PlaybookApprovalBridge.request_step_approval(...)`.
3. Execution pauses until the approval is approved or rejected by a SOC supervisor.
4. Upon approval, `PlaybookEngine.resume_execution_after_approval(...)` resumes sequential execution from the paused step.

---

## REST API Endpoints

All endpoints are protected by project-standard authentication and mounted under `/api/v1/playbooks`:

- `POST /playbooks`: Create a new playbook definition
- `GET /playbooks`: List, filter, and search playbooks
- `GET /playbooks/{playbook_id}`: Retrieve playbook details and step hierarchy
- `PATCH /playbooks/{playbook_id}`: Update playbook metadata or status
- `DELETE /playbooks/{playbook_id}`: Delete playbook definition
- `POST /playbooks/{playbook_id}/steps`: Add a step to a playbook
- `PATCH /playbooks/{playbook_id}/steps/{step_id}`: Update a step configuration
- `DELETE /playbooks/{playbook_id}/steps/{step_id}`: Remove a step from a playbook
- `POST /playbooks/{playbook_id}/validate`: Validate playbook structure and rules
- `POST /playbooks/{playbook_id}/execute`: Trigger playbook execution run
- `GET /playbooks/executions`: List and filter playbook execution runs
- `GET /playbooks/executions/{execution_id}`: Get execution run details and step logs
- `POST /playbooks/executions/{execution_id}/cancel`: Cancel active or waiting execution run

---

## Future AI Agent Integration Hooks

The SOAR Playbook Engine is designed for seamless integration with specialized autonomous AI agents (e.g. Threat Hunter Agent, Incident Response Agent, Root Cause Analysis Agent):
- **Agent Action Triggering**: Autonomous AI agents can trigger playbooks programmatically via `PlaybookService.execute_playbook(...)` with initial context payload.
- **Dynamic Context Passing**: AI agents can inspect intermediate step outputs from `execution_context` and dynamically alter downstream playbook conditions or trigger sub-playbooks.
