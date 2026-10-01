# AegisAI XDR

An AI-powered autonomous security operations and extended detection & response platform with multi-agent investigation, threat intelligence, DFIR, detection engineering, observability, and human-governed safe SOAR.

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Async_Backend-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict_0_Errors-3178C6.svg)](https://www.typescriptlang.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D.svg)](https://redis.io/)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8-005571.svg)](https://www.elastic.co/)
[![Pytest Suite](https://img.shields.io/badge/Tests-166%2F166_Passed-brightgreen.svg)]()
[![Security Tests](https://img.shields.io/badge/Security_Tests-23%2F23_Passed-brightgreen.svg)]()
[![Governance](https://img.shields.io/badge/Governance-CaseApproval_Enforced-blue.svg)]()
[![SOAR Mode](https://img.shields.io/badge/SOAR_Mode-SAFE__MOCK__EXECUTION-amber.svg)]()

---

## Executive Summary

**AegisAI XDR** represents an autonomous, human-governed Extended Detection & Response platform designed to alleviate modern Security Operations Center (SOC) challenges. It orchestrates a specialized cluster of **six AI agents** through an **11-stage autonomous investigation pipeline**, automating alert ingestion, threat correlation, digital forensics, threat intelligence synthesis, and detection engineering while enforcing strict human governance barriers on all containment actions.

---

## Problem Statement

Modern SOCs face four compounding operational crises:
1. **Severe Alert Fatigue**: Analysts are inundated with thousands of raw alerts daily, leading to missed true positives.
2. **Context Fragmentation**: Telemetry across network firewalls, endpoints, authentication providers, and cloud workloads is siloed.
3. **Investigation & DFIR Bottlenecks**: Reconstructing process parent-child relationships, decoding obfuscated command lines, and validating IOCs requires hours of manual analyst effort.
4. **Autonomous Execution Risk**: Traditional SOAR tools risk destructive misconfigurations if granted unconstrained autonomous containment capabilities.

AegisAI XDR solves this through **multi-agent collaborative investigation** combined with a mandatory **Human-in-the-Loop (`CaseApproval`) governance gate** and an immutable **`SAFE_MOCK_EXECUTION` safety boundary**.

---

## System Architecture

```
                      +-------------------------------------------------------+
                      |         React 18 / TypeScript SOC Command Center      |
                      |        (16 Operational Views & Real-Time Controls)    |
                      +-------------------------------------------------------+
                                                  |
                                                  | REST API (JWT Bearer / CORS)
                                                  v
                      +-------------------------------------------------------+
                      |              FastAPI Async Backend Core               |
                      |   - Request ID Tracing      - Security Headers (HSTS) |
                      |   - SlowAPI Rate Limiter    - Pydantic v2 Envelopes   |
                      |   - RBAC Authorization      - Alembic Migrations      |
                      +-------------------------------------------------------+
                               |                          |
             +-----------------+                          +-----------------+
             v                                                              v
+---------------------------+                                  +---------------------------+
|    Six AI Agent Cluster   |                                  |   Persistence Datastores  |
| - AI Orchestrator         |                                  | - PostgreSQL 16 (Relat.)  |
| - ThreatHunterAgent       |                                  | - Redis 7 (Cache/Broker)  |
| - DFIRInvestigatorAgent   |                                  | - Elasticsearch 8 (Logs)  |
| - ThreatIntelAnalystAgent |                                  +---------------------------+
| - DetectionRuleGenAgent   |                                                |
| - IncidentCommanderAgent  |                                                v
+---------------------------+                                  +---------------------------+
             |                                                 | Real-Time Observability   |
             v                                                 | - Prometheus Metrics Expose|
+---------------------------+                                  | - Component Latency Checks|
|  11-Stage Pipeline Engine |                                  | - MTTD / MTTR Engine      |
+---------------------------+                                  +---------------------------+
             |
             v
+------------------------------------------------------------------------------------------+
|                              Mandatory Human Governance Gate                             |
|                                                                                          |
|    AI Recommendation  --->  CaseApproval PENDING  --->  Execution BLOCKED                |
|                                                                                          |
|             [ Approved by Senior Analyst / Incident Commander ]                          |
|                                     |                                                    |
|                                     v                                                    |
|                   SAFE_MOCK_EXECUTION (Zero Destructive Impact)                           |
+------------------------------------------------------------------------------------------+
```

---

## Six Specialized AI Agents

AegisAI XDR deploys a coordinated cluster of six specialized agents operating under structured `InvestigationState` memory:

| Agent Name | Primary Operational Responsibility | Core Capabilities |
| :--- | :--- | :--- |
| **AI Orchestrator** | Central pipeline coordinator, state machine manager, and dispatch router | Lifecycle orchestration, agent failure recovery, state progression |
| **ThreatHunterAgent** | Hypothesis-driven threat hunting and anomaly detection | Observable extraction, behavioral pattern matching, MITRE mapping (`T1078`, `T1003`) |
| **DFIRInvestigatorAgent** | Digital forensics, process lineage, and artifact reconstruction | Process tree tracing (`PPID` → `PID`), PowerShell script decoding, SHA256 hashing |
| **ThreatIntelAnalystAgent** | Multi-provider threat intelligence enrichment and scoring | IOC extraction, reputation consensus (VirusTotal, AbuseIPDB, MISP), actor attribution |
| **DetectionRuleGeneratorAgent** | Automated detection rule synthesis and validation | Sigma rule generation, YARA scanning patterns, Suricata network signatures |
| **IncidentCommanderAgent** | Multi-agent synthesis, attack chain analysis, response planning | Root cause determination, severity assessment, `CaseApproval` proposal |

---

## 11-Stage Autonomous Investigation Pipeline

State machine transitions strictly enforce linear phase progression:

```
[1. TRIAGING]
      ↓
[2. CORRELATING]
      ↓
[3. INVESTIGATION_STARTED]
      ↓
[4. THREAT_HUNTING]
      ↓
[5. DFIR_ANALYSIS]
      ↓
[6. THREAT_INTELLIGENCE]
      ↓
[7. DETECTION_GENERATION]
      ↓
[8. INCIDENT_SYNTHESIS]
      ↓
[9. AWAITING_REVIEW] 🛑 (Execution Blocked — Mandatory Human Decision Point)
      ↓
      ├── REJECTED / CANCELLED  ──>  [Execution Remains BLOCKED]
      └── APPROVED              ──>  [10. RESPONSE_EXECUTING (SAFE_MOCK_EXECUTION)]
                                                 ↓
                                           [11. COMPLETED]
```

---

## Security & Governance Model

### Non-Negotiable Safety Invariants
1. **`SOAR_EXECUTION_MODE = SAFE_MOCK_EXECUTION`**: All SOAR actions (host isolation, user disablement, credential revocation, IP blocking) execute in simulated safe-mock mode. Real OS shells, destructive commands, and external network alterations are strictly prohibited.
2. **Mandatory `CaseApproval`**: No privileged containment playbook can execute autonomously.
   - `PENDING` $\rightarrow$ **BLOCKED**
   - `REJECTED` $\rightarrow$ **BLOCKED**
   - `CANCELLED` $\rightarrow$ **BLOCKED**
   - Only `APPROVED` or `AUTO_APPROVED` can reach `SAFE_MOCK_EXECUTION`.
3. **Role-Based Access Control (RBAC)**:
   - `READ_ONLY`: Observer access only; mutation endpoints (`POST`, `PUT`, `DELETE`) return `403 Forbidden`.
   - `SOC_ANALYST`: Triage alerts, review cases, inspect investigations. Blocked from privileged approval decisions (`403 Forbidden`).
   - `SENIOR_ANALYST` / `SOC_MANAGER` / `ADMIN`: Authorized to adjudicate `CaseApproval` requests.
4. **Synthetic Telemetry Isolation**: Synthetic demo data uses dedicated `SYN-*` reference IDs and `synthetic_telemetry = true` flags, preventing cross-contamination with operational records.

---

## Technology Stack

- **Backend**: Python 3.13 / 3.11+, FastAPI (Async), SQLAlchemy 2.0 (Asyncpg), Pydantic v2, Alembic, SlowAPI.
- **Frontend**: React 18, Vite 5, TypeScript 5, Tailwind CSS, Lucide React, Recharts, TanStack React Query.
- **Data Infrastructure**: PostgreSQL 16 (Relational Engine), Redis 7 (Caching & Pub/Sub), Elasticsearch 8.12 (Telemetry Search).
- **Testing**: Pytest, Pytest-AsyncIO, AnyIO (166 total tests).

---

## Repository Structure

```
AegisAI XDR/
├── backend/
│   ├── app/
│   │   ├── ai/                 # Multi-agent engines, tools, pipeline, prompts
│   │   ├── api/v1/             # Central router, health, overview
│   │   ├── case_management/    # Cases, CaseApproval governance, activities
│   │   ├── core/               # Configuration, security, database, redis, ES
│   │   ├── correlation/        # Cross-source alert correlation engine
│   │   ├── db/                 # Alembic migrations & migrations/env.py
│   │   ├── demo/               # Synthetic scenario runner & reports
│   │   ├── detection_engine/   # Sigma, YARA, Suricata rule management
│   │   ├── domains/            # Alerts, incidents, investigations, evidence, timeline, users
│   │   ├── mitre/              # ATT&CK knowledge base, mapping, coverage matrix
│   │   ├── observability/      # Health collectors, Prometheus exporter
│   │   ├── playbooks/          # Safe mock SOAR playbook engine
│   │   └── threat_intelligence/# IOC management, feeds, multi-provider enrichment
│   ├── Dockerfile              # Multi-stage hardened non-root container
│   └── pyproject.toml          # Backend package dependencies
├── frontend/
│   ├── src/
│   │   ├── api/                # Typed API client & endpoint definitions
│   │   ├── components/         # Reusable SOC layout, cards, badges, modals
│   │   ├── context/            # AuthContext (JWT session management)
│   │   ├── pages/              # 16 SOC Command Center page views
│   │   └── types/              # TypeScript interface definitions
│   ├── Dockerfile              # Multi-stage production web container
│   ├── package.json            # Node.js dependencies & scripts
│   └── vite.config.ts          # Vite build config with backend proxy
├── docs/                       # 23 comprehensive architectural & evaluation guides
├── tests/                      # 166 Pytest tests (23 security, 9 integration, 134 unit)
├── scripts/                    # Maintenance & database backup utilities
├── docker-compose.yml          # Containerized local environment
└── README.md                   # Master project documentation
```

---

## Quick Start (Local Evaluator Workflow)

### Prerequisites
- Python 3.11+ (Python 3.13 supported)
- Node.js 18+ & npm 9+
- Running PostgreSQL (port 5432), Redis (port 6379), Elasticsearch (port 9200)

### 1. Terminal 1: Backend
```bash
cd backend
source ../venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
*API Documentation will be live at `http://localhost:8000/docs`.*

### 2. Terminal 2: Frontend
```bash
cd frontend
npm run dev
```
*Frontend will be live at `http://localhost:3000`.*

### 3. Open in Browser
- URL: **`http://localhost:3000`**
- Default Analyst Credentials:
  - Username: **`analyst1`**
  - Password: **`password123`**
- Administrator / Commander Credentials:
  - Username: **`admin@aegis.ai`**
  - Password: **`password123`**

---

## Interactive End-to-End Demonstration

Navigate to **`http://localhost:3000/demo`** to execute three pre-configured synthetic security scenarios:

1. **Credential Compromise & LSASS Memory Dump** (`credential_compromise`)
   - Emulates brute force credential stuffing, lateral movement, and memory credential harvesting (`T1078`, `T1110`, `T1003.001`).
   - Asserts 20-point validation checklist and halts at `AWAITING_REVIEW` with a pending host isolation approval.
2. **Ransomware Outbreak & System Recovery Disablement** (`ransomware_simulation`)
   - Simulates shadow copy deletion via `vssadmin` and rapid file encryption (`T1490`, `T1486`).
3. **Encrypted Data Staging & C2 Exfiltration Burst** (`data_exfiltration`)
   - Demonstrates sensitive archive staging and encrypted outbound command-and-control communication (`T1560.001`, `T1041`).

### Demonstrating Human Governance
1. Log in as `analyst1` and run a synthetic scenario at `/demo`.
2. Notice the investigation pauses at Stage 9 (`AWAITING_REVIEW`) with `CaseApproval` in `PENDING` status.
3. Attempting to approve as `analyst1` demonstrates RBAC enforcement (tier-1 analyst cannot approve privileged containment).
4. Log in as `admin@aegis.ai` and visit `/approvals`.
5. Click **APPROVE**: The status transitions to `APPROVED`, proceeding to Stage 10 (`SAFE_MOCK_EXECUTION`).
6. Alternatively click **REJECT**: The status transitions to `REJECTED`, keeping execution **BLOCKED**.

---

## Test Execution & Verification

Run all test suites from the project root using the activated virtual environment:

```bash
# 1. Run Security Test Suite (23 Tests)
python3 -m pytest tests/security -v

# 2. Run Integration Test Suite (9 Tests)
python3 -m pytest tests/integration -v

# 3. Run Full Pytest Regression Suite (166 Tests)
python3 -m pytest -v

# 4. Verify Frontend TypeScript (0 Errors)
cd frontend && npx tsc --noEmit

# 5. Verify Frontend Production Build
cd frontend && npm run build
```

**Verification Results:**
- Pytest Suite: **166 passed** in 4.24s (0 failed, 0 errors).
- TypeScript: **0 errors**.
- Vite Production Build: **Successfully generated** in 1.53s.

---

## Documentation Index

Comprehensive documentation is provided in the [`docs/`](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs) directory:

- [docs/architecture.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/architecture.md) — Comprehensive system architecture & data flow
- [docs/ai_agents.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/ai_agents.md) — Six AI agents detailed design & prompt engineering
- [docs/autonomous_pipeline.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/autonomous_pipeline.md) — 11-stage autonomous state machine specifications
- [docs/security_architecture.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/security_architecture.md) — Cryptographic authentication & security controls
- [docs/governance.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/governance.md) — CaseApproval workflow and human-in-the-loop gates
- [docs/threat_model.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/threat_model.md) — STRIDE threat analysis and mitigation strategies
- [docs/detection_engine.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/detection_engine.md) — Sigma, YARA, and Suricata rule pipeline
- [docs/threat_intelligence.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/threat_intelligence.md) — IOC multi-provider enrichment and caching
- [docs/dfir.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/dfir.md) — Digital forensics, process tree, and timeline engine
- [docs/soc_command_center.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/soc_command_center.md) — Frontend UI component architecture & workflows
- [docs/api.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/api.md) — Full REST API specifications & schemas
- [docs/database.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/database.md) — Relational schema & Alembic migration guide
- [docs/clean_install.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/clean_install.md) — Step-by-step evaluator installation guide
- [docs/demo_runbook.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/demo_runbook.md) — Live evaluator demonstration runbook
- [docs/teacher_demo_script.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/teacher_demo_script.md) — Step-by-step instructor walkthrough script
- [docs/viva_questions.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/viva_questions.md) — 50 comprehensive technical viva Q&A pairs
- [docs/project_report.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/project_report.md) — Complete university capstone project report
- [docs/showcase_checklist.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/showcase_checklist.md) — Evaluation and presentation grading checklist
- [docs/final_release_report.md](file:///home/armaanjaat/Desktop/AegisAI%20XDR%20/docs/final_release_report.md) — Release audit verification report

---

## Known Limitations & Safety Boundaries

1. **Simulated SOAR Execution**: In compliance with enterprise safety standards, playbook actions are simulated (`SAFE_MOCK_EXECUTION`). No actual OS network isolation or endpoint modification takes place.
2. **Isolated Synthetic Telemetry**: The interactive demonstration utilizes synthetic event generators with explicit reference IDs to ensure determinism during live grading.
3. **Local LLM Fallback**: When external LLM inference providers are unconfigured, the system deterministically executes rule-based hypothesis generation without breaking pipeline execution.

---

## GitHub Release Instructions

To publish this verified release to your GitHub repository:

```bash
# Review repository status
git status --short

# Stage all verified release files
git add .

# Create the release commit
git commit -m "release: AegisAI XDR v1.0.0"

# Push to your remote repository
git push origin main
```
