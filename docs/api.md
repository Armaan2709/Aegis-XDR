# AegisAI XDR — OpenAPI REST API Documentation

This document provides a comprehensive reference for all REST API endpoints implemented in the **AegisAI XDR** FastAPI application (`backend/app/api/v1/`).

---

## 🔑 1. Authentication Endpoints (`/api/v1/auth`)

### `POST /api/v1/auth/login`
- **Description**: Authenticates user credentials and returns JWT access and refresh tokens.
- **Authentication**: None (Public).
- **Request Body**: `OAuth2PasswordRequestForm` (`username`, `password`).
- **Response (`200 OK`)**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
    "token_type": "bearer",
    "expires_in": 3600,
    "user": {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "username": "analyst1",
      "email": "analyst@aegisai.corp",
      "role": "SOC_ANALYST"
    }
  }
  ```
- **Error Responses**: `401 Unauthorized` (Invalid credentials).

---

## 🚨 2. Alert Management Endpoints (`/api/v1/alerts`)

### `GET /api/v1/alerts`
- **Description**: Lists security telemetry alerts with optional filtering and pagination.
- **Authentication**: Bearer Token.
- **Query Parameters**: `severity`, `source`, `status`, `page`, `page_size`.
- **Response (`200 OK`)**: List of `AlertRead` models.

### `POST /api/v1/alerts`
- **Description**: Ingests a new security telemetry alert.
- **Required Role**: `SOC_ANALYST`, `INCIDENT_COMMANDER`, `ADMIN`.
- **Request Body**: `AlertCreate` schema.

---

## 🔥 3. Incident Correlation Endpoints (`/api/v1/incidents`)

### `GET /api/v1/incidents`
- **Description**: Lists correlated security incidents.
- **Authentication**: Bearer Token.
- **Response (`200 OK`)**: List of `IncidentRead` models.

### `POST /api/v1/incidents/correlate`
- **Description**: Triggers graph threat correlation over unassociated alerts.
- **Required Role**: `SOC_ANALYST` or higher.
- **Request Body**: `CorrelationRequest` (`alert_ids: List[UUID]`).

---

## 🔬 4. Investigation Domain Endpoints (`/api/v1/investigations`)

### `GET /api/v1/investigations`
- **Description**: Lists active and completed security investigations.
- **Response (`200 OK`)**: List of `InvestigationRead` models.

### `POST /api/v1/investigations`
- **Description**: Initiates a new investigation for an incident.
- **Request Body**: `InvestigationCreate` schema.

---

## 🤖 5. AI Multi-Agent & Pipeline Endpoints (`/api/v1/ai`)

### `GET /api/v1/ai/agents/status`
- **Description**: Returns live status, tool list, and performance metrics for all 6 AI agents.
- **Response (`200 OK`)**: Dict of agent status objects.

### `POST /api/v1/ai/pipeline/run`
- **Description**: Triggers or resumes the 11-stage autonomous investigation pipeline.
- **Request Body**: `PipelineRunRequest` (`investigation_id`, `incident_id`, `auto_approve_routine`).
- **Response (`200 OK`)**: `PipelineContext` model.

---

## 🌐 6. Threat Intelligence Endpoints (`/api/v1/threat-intel`)

### `GET /api/v1/threat-intel/indicators`
- **Description**: Queries extracted and enriched IOC reputation records.
- **Response (`200 OK`)**: List of `ThreatIndicatorRead` models.

### `POST /api/v1/threat-intel/lookup`
- **Description**: Performs on-demand reputation lookup for a specific IP, hash, or domain.

---

## 🎯 7. MITRE ATT&CK Endpoints (`/api/v1/mitre`)

### `GET /api/v1/mitre/matrix`
- **Description**: Returns MITRE ATT&CK 14-column tactical matrix with technique mappings.

---

## 🛡️ 8. Detection Engine Endpoints (`/api/v1/detections`)

### `GET /api/v1/detections/rules`
- **Description**: Lists detection rules by format (`SIGMA`, `YARA`, `SURICATA`) and status (`CANDIDATE`, `ACTIVE`).

### `POST /api/v1/detections/rules/{id}/approve`
- **Description**: Approves a candidate detection rule for activation.
- **Required Role**: `INCIDENT_COMMANDER` or `ADMIN`.

---

## 💼 9. Case Management Endpoints (`/api/v1/cases`)

### `GET /api/v1/cases`
- **Description**: Lists SOC cases with SLA metrics and assigned analysts.

### `POST /api/v1/cases/{id}/comments`
- **Description**: Adds a threaded Markdown comment to a case workspace.

---

## 🛑 10. Governance & Approval Endpoints (`/api/v1/approvals`)

### `GET /api/v1/approvals`
- **Description**: Lists pending and decided `CaseApproval` human governance requests.

### `POST /api/v1/approvals/{id}/decide`
- **Description**: Grants (`APPROVED`) or denies (`REJECTED`) a governance approval request.
- **Required Role**: `INCIDENT_COMMANDER` or `ADMIN`.

---

## ⚡ 11. SOAR Playbook Endpoints (`/api/v1/playbooks`)

### `GET /api/v1/playbooks`
- **Description**: Lists registered SOAR playbooks and steps.

### `POST /api/v1/playbooks/execute`
- **Description**: Triggers a SOAR playbook in **`SAFE_MOCK_EXECUTION`** mode.
- **Required Role**: `INCIDENT_COMMANDER` or `ADMIN`. Valid `CaseApproval` required.

---

## ⏱️ 12. Timeline & Audit Endpoints (`/api/v1/timeline`)

### `GET /api/v1/timeline/events`
- **Description**: Returns chronological timeline event records for an investigation.

---

## 🏥 13. System Health & Observability Endpoints (`/api/v1/health`)

### `GET /api/v1/health/liveness`
- **Description**: Liveness probe returning `200 OK` if API server process is running.

### `GET /api/v1/health/readiness`
- **Description**: Readiness probe checking PostgreSQL, Redis, and Elasticsearch connectivity.

### `GET /api/v1/health/deps`
- **Description**: Component dependency health endpoint returning granular latencies for database, cache, and search engines.

---

## 🧪 14. Demonstration Framework Endpoints (`/api/v1/demo`)

### `GET /api/v1/demo/scenarios`
- **Description**: Lists available synthetic security demonstration scenarios (`credential_compromise`, `ransomware_simulation`, `data_exfiltration`).

### `POST /api/v1/demo/run`
- **Description**: Runs complete end-to-end synthetic scenario through domain services and 20-point assertion validator.

### `GET /api/v1/demo/results/{id}`
- **Description**: Retrieves scenario execution results, agent findings, and assertion details.

### `GET /api/v1/demo/report/{id}`
- **Description**: Generates structured demonstration report with telemetry classifications (`OBSERVED`, `INFERRED`, `SIMULATED`, `RECOMMENDED`).
