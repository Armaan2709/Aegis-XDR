# AegisAI XDR — Academic Final Project Report

**Project Title**: AegisAI XDR: Autonomous Multi-Agent Cyber Defense Platform with Human-in-the-Loop Governance  
**Domain**: Cybersecurity, Artificial Intelligence, Distributed System Design  
**Author**: Engineering Team / Project Candidate  
**Target Environment**: Enterprise SOC / Academic Capstone Evaluation  

---

## 1. Abstract
Modern Security Operations Centers (SOCs) face escalating operational challenges driven by massive alert volume, fragmented security tooling, manual digital forensics, and high risk associated with unvalidated response automation. This report presents **AegisAI XDR**, an enterprise-grade Extended Detection & Response (XDR) platform powered by a 5-agent specialized AI cluster operating under a deterministic 11-stage autonomous investigation pipeline. AegisAI XDR combines automated threat hunting, DFIR process tree reconstruction, threat intelligence provider consensus, and detection rule synthesis with strict human-in-the-loop governance (`CaseApproval`) and safe simulation response playbooks (`SAFE_MOCK_EXECUTION`). Evaluated across 166 automated backend tests, 23 security regression benchmarks, and 3 end-to-end synthetic attack scenarios, AegisAI XDR achieves 100% test pass fidelity, zero TypeScript compilation errors, and complete operational readiness.

---

## 2. Introduction
Cyber defense teams encounter sophisticated multi-stage attack vectors operating at machine speed. Traditional Security Information and Event Management (SIEM) systems generate overwhelming numbers of alerts without context, forcing security analysts to manually correlate events, inspect command-line strings, query threat feeds, and write detection signatures. AegisAI XDR addresses this bottleneck by deploying autonomous AI agents that collaborate under a centralized state machine orchestrator to automate threat investigation while enforcing non-negotiable security and governance boundaries.

---

## 3. Problem Statement
1. **Alert Fatigue**: Security analysts spend up to 70% of their operational time manually triaging false-positive alerts.
2. **Context Fragmentation**: Disconnected logs across network, endpoint, and cloud sensors delay incident correlation.
3. **Forensic Reconstruction Overhead**: Manual parent-child process tree analysis and chronological event ordering increase Mean Time to Respond (MTTR).
4. **Automation Risk**: Unvalidated automated SOAR tools risk causing catastrophic operational outages by isolating critical production servers without human oversight.

---

## 4. Existing System Analysis
Current SOC solutions rely heavily on legacy SIEM correlation rules or simple LLM chatbot assistants. Legacy SIEMs require brittle rule syntax and lack adaptive threat hunting capabilities. Single-prompt LLM wrappers lack state persistence, struggle with multi-step reasoning, and possess no native security boundaries or governance gates.

---

## 5. Proposed AegisAI XDR System
AegisAI XDR introduces a tiered, domain-driven architecture integrating:
- **Multi-Agent Collaboration Graph**: 5 specialized AI agents (Threat Hunter, DFIR Investigator, Threat Intel Analyst, Detection Rule Generator, Incident Commander) led by an AI Orchestrator.
- **11-Stage Autonomous Pipeline**: A state-machine pipeline tracking investigation milestones from alert ingestion to final report generation.
- **Mandatory `CaseApproval` Governance**: A human review gate blocking privileged response actions until an analyst approves the plan.
- **`SAFE_MOCK_EXECUTION` Boundary**: Non-destructive SOAR playbook execution mode protecting production infrastructure.

---

## 6. Project Objectives
1. Architect an enterprise FastAPI backend using clean Architecture and Domain-Driven Design (DDD).
2. Develop a React 18 TypeScript frontend featuring 16 specialized SOC pages.
3. Construct a deterministic 11-stage pipeline capable of state persistence and failure recovery.
4. Implement RBAC, JWT authentication, and security headers middleware.
5. Create a 20-point assertion validation engine for synthetic security demonstrations.
6. Verify platform stability with 100% pass rates across security, integration, and unit tests.

---

## 7. Scope & Operational Boundaries
- **In Scope**: Ingestion of network/endpoint alerts, graph threat correlation, multi-agent AI analysis, process tree reconstruction, IOC reputation lookups, Sigma/YARA candidate rule generation, case management, approval governance, safe mock SOAR execution, and observability metrics.
- **Out of Scope**: Real destructive host containment commands, real physical malware execution, direct unapproved system modifications.

---

## 8. Requirements Specification

### Functional Requirements
- **FR-1**: Ingest security alerts with severity scoring (`LOW` to `CRITICAL`).
- **FR-2**: Group related alerts into correlated Incident graphs.
- **FR-3**: Formulate threat hunting hypotheses and map MITRE ATT&CK techniques.
- **FR-4**: Reconstruct parent-child process trees and DFIR execution timelines.
- **FR-5**: Normalize IOCs and calculate provider consensus threat scores.
- **FR-6**: Synthesize candidate Sigma, YARA, and Suricata detection rules.
- **FR-7**: Enforce `CaseApproval` human sign-off before response playbooks run.
- **FR-8**: Execute SOAR playbooks strictly in `SAFE_MOCK_EXECUTION` mode.

### Non-Functional Requirements
- **NFR-1**: Sub-100ms API response latency for standard domain queries.
- **NFR-2**: Cryptographically signed JWT tokens with algorithm protection.
- **NFR-3**: 100% test pass rate across unit, integration, and security regression suites.
- **NFR-4**: Strict TypeScript compilation (`0 errors`).
- **NFR-5**: Containerized non-root execution (`USER appuser`).

---

## 9. Platform Architecture & System Design
AegisAI XDR employs a 4-tier architecture:
1. **Presentation Tier**: React 18 SPA with Tailwind CSS and TanStack Query v5.
2. **API Tier**: Async FastAPI router with rate limiting, correlation IDs, and security headers.
3. **Domain Tier**: Domain services and repository abstractions (Alerts, Incidents, Cases, Playbooks).
4. **AI & Data Tier**: Multi-agent state graph, PostgreSQL 16, Redis 7, and Elasticsearch 8.

---

## 10. Technology Stack & Framework Selection
- **Languages**: Python 3.11+, TypeScript 5+, SQL, HTML/CSS.
- **Backend Framework**: FastAPI (Async), Pydantic v2, Structlog, SlowAPI.
- **Database & ORM**: PostgreSQL 16, Async SQLAlchemy 2.0, Alembic.
- **Cache & Message Broker**: Redis 7.
- **Frontend Framework**: React 18, Vite, Tailwind CSS, Lucide Icons.
- **Container Infrastructure**: Docker, Docker Compose, Alpine base images.

---

## 11. Database Design & Entity Relationships
The relational schema comprises 11 core tables (`users`, `alerts`, `incidents`, `investigations`, `evidence`, `timeline_events`, `cases`, `case_approvals`, `detection_rules`, `playbooks`, `audit_logs`). Relationships enforce referential integrity via foreign key constraints and cascade rules.

---

## 12. Multi-Agent AI & Autonomous Pipeline Design
The 11-stage pipeline progresses sequentially: `TRIAGING` → `CORRELATING` → `INVESTIGATION_STARTED` → `THREAT_HUNTING` → `DFIR_ANALYSIS` → `THREAT_INTELLIGENCE` → `DETECTION_GENERATION` → `INCIDENT_SYNTHESIS` → `AWAITING_REVIEW` → `RESPONSE_EXECUTING` → `COMPLETED`. Stage 9 enforces a pause until `CaseApproval` status transitions from `PENDING` to `APPROVED`.

---

## 13. Security Architecture & Governance Framework
Security controls are layered across authentication (JWT HS256/RS256), authorization (RBAC decorator enforcement), governance (`CaseApproval` state machine), safety (`SOAR_EXECUTION_MODE = SAFE_MOCK_EXECUTION`), input sanitization (SQLAlchemy ORM + Pydantic validation), and HTTP hardening (CSP, HSTS, rate limiting).

---

## 14. Implementation & Module Design
Modules are cleanly partitioned in `backend/app/`:
- `ai/`: Orchestrator, 5 specialized agents, tool registry, pipeline schemas.
- `case_management/`: Case entities, comments, `CaseApproval` governance models.
- `core/`: Config, async database engine, Redis connection factory, security routines.
- `demo/`: Synthetic scenario runner, scenario catalog, 20-point assertion validator.
- `domains/`: Alerts, incidents, evidence, timeline, threat intel, detection engine.
- `middleware/`: Correlation ID tracking and security response headers.

---

## 15. Testing Methodology & Security Suite
Testing follows a 3-tier strategy:
1. **Unit Tests** (`tests/unit/`): 134 tests validating domain logic, repository operations, and agent outputs.
2. **Integration Tests** (`tests/integration/`): 9 tests verifying autonomous pipeline execution, demo scenario runs, and observability endpoints.
3. **Security Regression Tests** (`tests/security/`): 23 tests verifying JWT security, RBAC enforcement, `CaseApproval` blocking, safe SOAR mode, and input validation.

---

## 16. Security Hardening & Threat Model Validation
Threat modeling against STRIDE identified 15 attack surfaces. All high/medium threats were mitigated:
- JWT algorithm confusion → Blocked via explicit `algorithms=[settings.ALGORITHM]` decoding.
- Privilege escalation → Blocked via `@require_role` decorators and `READ_ONLY` mutation guards.
- SOAR infrastructure damage → Blocked via hardcoded `SAFE_MOCK_EXECUTION` mode.
- Approval bypass → Verified that unapproved calls return `HTTP 403 Forbidden`.

---

## 17. Results, Assertions & Performance Evaluation

### Empirical Verification Benchmarks

| Metric / Benchmark | Target / Requirement | Observed Verified Result | Status |
|:---|:---|:---|:---|
| **Python Code Compilation** | 0 Syntax/Import Errors | 100% Clean Compilation | ✅ PASS |
| **Security Test Suite** | 100% Pass | 23 / 23 Passed | ✅ PASS |
| **Integration Test Suite** | 100% Pass | 9 / 9 Passed | ✅ PASS |
| **Full Pytest Suite** | 100% Pass | **166 / 166 Passed** | ✅ PASS |
| **TypeScript Typecheck** | 0 Errors | **0 Errors (`tsc --noEmit`)** | ✅ PASS |
| **Vite Production Build** | Successful `dist/` | **Built in 2.00s (`vite build`)**| ✅ PASS |
| **Demo Assertions** | 20 / 20 Passed | **20 / 20 Passed** | ✅ PASS |

---

## 18. System Limitations & Operational Constraints
1. **Mock Response Execution**: Playbooks run strictly in simulation mode; integration with production EDR agents (e.g. CrowdStrike) requires custom plugin development.
2. **Synthetic Telemetry Scope**: Demo scenarios utilize pre-configured synthetic payloads rather than live tap feeds.
3. **LLM Provider Dependency**: Local LLM inference requires Ollama running Llama 3 or equivalent models.

---

## 19. Future Scope & Enhancements
1. **Live EDR Plugin Connectors**: Develop production plugin bridges for CrowdStrike Falcon and SentinelOne.
2. **Multi-Tenant Workspace Partitioning**: Extend database schemas to support isolated enterprise tenant organizations.
3. **Graph Neural Network (GNN) Correlation**: Incorporate GNN models to improve non-linear alert correlation fidelity.

---

## 20. Conclusion & Academic Summary
AegisAI XDR successfully demonstrates that autonomous multi-agent AI can dramatically accelerate cyber threat detection and investigation without compromising enterprise safety. By enforcing mandatory human governance (`CaseApproval`) and safe response simulation (`SAFE_MOCK_EXECUTION`), AegisAI XDR delivers a technically robust, production-ready framework that meets all software engineering, cybersecurity, and academic evaluation standards.
