# AegisAI XDR — Comprehensive Technical Viva Question Bank (52 Questions)

This document contains 52 technical viva exam questions and concise, authoritative answers based on the actual source code implementation of **AegisAI XDR**.

---

## 🏛️ Category 1: Platform Architecture & System Design

#### Q1: What is the high-level architecture of AegisAI XDR?
> **Answer**: AegisAI XDR uses a domain-driven tiered architecture with a React 18 TypeScript frontend, an async FastAPI Python backend, PostgreSQL for relational/audit storage, Redis for caching/rate-limiting, Elasticsearch for log search, and a 5-agent state graph AI orchestrator.

#### Q2: How does domain-driven design (DDD) manifest in the codebase?
> **Answer**: Features are organized into isolated domain contexts (`backend/app/domains/` and `case_management/`) containing dedicated schemas, SQL models, repository abstractions, services, and API routers.

#### Q3: How does the system handle high API load and concurrency?
> **Answer**: FastAPI uses Python `asyncio` non-blocking I/O routines, SQLAlchemy 2.0 async session pools (`AsyncSession`), and Redis connection pooling.

#### Q4: What is the role of `InvestigationState`?
> **Answer**: It is a shared, mutable context object passed through the 11-stage autonomous pipeline, storing alerts, evidence, agent findings, risk scores, and recommendations.

#### Q5: How is state persistence achieved across pipeline stages?
> **Answer**: `PipelineContext` serializes `InvestigationState` to JSON and commits execution milestones to the `pipeline_contexts` table in PostgreSQL.

---

## 🔑 Category 2: Authentication, Authorization & Security Architecture

#### Q6: What authentication mechanism is implemented?
> **Answer**: Stateless JWT (JSON Web Tokens) signed with HS256 (dev) or RS256 (prod) containing `sub`, `exp`, `iat`, `type`, and `role` claims.

#### Q7: How does AegisAI XDR prevent algorithm confusion (e.g. `none` algorithm attacks)?
> **Answer**: `security.py` enforces explicit algorithm validation (`algorithms=[settings.ALGORITHM]`) during token decoding; missing or `none` algorithms raise `HTTP 401 Unauthorized`.

#### Q8: How is token revocation handled in a stateless JWT architecture?
> **Answer**: Blacklisted token JTI hashes are stored in Redis with TTL matching token expiry (`check_jwt_blacklisted`). On Redis failure, an in-memory fallback set preserves revocation security.

#### Q9: What roles exist in the RBAC matrix?
> **Answer**: `READ_ONLY`, `SOC_ANALYST`, `INCIDENT_COMMANDER`, and `ADMIN`.

#### Q10: How does RBAC restrict `READ_ONLY` users?
> **Answer**: `rbac.py` intercepts requests and raises `HTTP 403 Forbidden` if a `READ_ONLY` user attempts any `POST`, `PUT`, `PATCH`, or `DELETE` mutation endpoint.

#### Q11: What HTTP security headers are injected by middleware?
> **Answer**: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `X-XSS-Protection`.

#### Q12: How are database credentials protected in production?
> **Answer**: Production settings validation (`config.py`) rejects default development passwords and enforces >=32 character high-entropy secret keys.

---

## 🛑 Category 3: Governance & SOAR Safety Model

#### Q13: What is `CaseApproval`?
> **Answer**: A mandatory human-in-the-loop governance record required before any privileged SOAR response action can execute.

#### Q14: Can AI agents execute response playbooks independently?
> **Answer**: No. AI agent recommendations are strictly advisory. The pipeline halts at Stage 9 (`AWAITING_REVIEW`) until a human grants approval.

#### Q15: What happens if a `CaseApproval` record is `PENDING`, `REJECTED`, or `CANCELLED`?
> **Answer**: SOAR playbook execution remains strictly **BLOCKED**.

#### Q16: What is `SAFE_MOCK_EXECUTION`?
> **Answer**: A non-negotiable safety setting enforcing that SOAR playbooks generate simulated execution logs and audit records without invoking destructive OS commands.

#### Q17: How is `SOAR_EXECUTION_MODE` guarded against tampering?
> **Answer**: Field validator in `config.py` enforces `SOAR_EXECUTION_MODE == "SAFE_MOCK_EXECUTION"`, raising a startup error if changed to any non-mock value.

---

## 🤖 Category 4: AI Agents & Multi-Agent Orchestration

#### Q18: Name the 6 AI agents and their primary responsibilities.
> **Answer**: 
> 1. AI Orchestrator (workflow stage management)
> 2. ThreatHunterAgent (hypothesis formulation & MITRE mapping)
> 3. DFIRInvestigatorAgent (process tree & timeline reconstruction)
> 4. ThreatIntelAnalystAgent (IOC extraction & provider consensus)
> 5. DetectionRuleGeneratorAgent (Sigma/YARA/Suricata rule synthesis)
> 6. IncidentCommanderAgent (executive summary & CaseApproval request creation)

#### Q19: What design pattern models the multi-agent workflow?
> **Answer**: State graph DAG (Directed Acyclic Graph) pattern where agents execute sequentially over the shared `InvestigationState`.

#### Q20: How are AI prompt injection threats mitigated?
> **Answer**: Telemetry payload inputs are sanitized with structural delimiters, and agent outputs are parsed through strict Pydantic schemas.

#### Q21: What tools are available to AI agents?
> **Answer**: Isolated functions in `ToolRegistry` that operate strictly on in-memory state and database repositories.

#### Q22: Do AI tools have access to shell subprocess execution?
> **Answer**: No. Zero `os.system`, `subprocess`, or `eval` invocations exist in the AI tool registry.

---

## 🛡️ Category 5: Threat Detection & Detection Engineering

#### Q23: What rule formats are supported by the Detection Engine?
> **Answer**: Sigma (logs), YARA (binary/memory), and Suricata (network NIDS).

#### Q24: What is the lifecycle of a synthesized detection rule?
> **Answer**: Evidence → Candidate Synthesis → Parse → Validate → Dry-Run Test → Quality Analysis → Human Analyst Review → Activation.

#### Q25: Are generated detection rules automatically deployed to sensors?
> **Answer**: No. Synthesized rules remain in `CANDIDATE` status until a human analyst dry-runs and approves them.

---

## 🌐 Category 6: Threat Intelligence & DFIR

#### Q26: What IOC types does the platform extract?
> **Answer**: IPv4/IPv6 addresses, FQDN domains, MD5/SHA1/SHA256 file hashes, and URLs.

#### Q27: How is threat intel provider consensus calculated?
> **Answer**: Weighted average of maliciousness ratings across feeds (VirusTotal, MISP, AbuseIPDB) adjusted by provider reliability weights.

#### Q28: How does DFIR reconstruct process execution trees?
> **Answer**: Connects process logs by matching Parent Process IDs (PPID) to Process IDs (PID) in chronological sequence.

#### Q29: Is DFIR forensic analysis destructive to raw evidence?
> **Answer**: No. All forensic parsing is strictly read-only, and file SHA256 hashes are verified to preserve chain-of-custody.

---

## 🏥 Category 7: Databases, Observability & Deployment

#### Q30: What database ORM and migration tool are used?
> **Answer**: SQLAlchemy 2.0 (Async) and Alembic migration framework.

#### Q31: How is database resilience configured?
> **Answer**: Connection pool sizing, `pool_recycle=1800` (recycle connections every 30 mins), and pre-ping validation (`pool_pre_ping=True`).

#### Q32: What health probes are exposed?
> **Answer**: `/api/v1/health/liveness` (app process check), `/api/v1/health/readiness` (dependency check), and `/api/v1/health/deps` (latency metrics).

#### Q33: How is log correlation achieved across microservices?
> **Answer**: Correlation ID middleware injects a unique `X-Correlation-ID` header into every request and binds it to Structlog JSON logs.

#### Q34: What container security best practices are implemented in Dockerfiles?
> **Answer**: Multi-stage builds, minimal alpine base images, and non-root execution (`USER appuser`).

---

## 🧪 Category 8: Demonstration & Testing Framework

#### Q35: What 3 demo scenarios are built into the platform?
> **Answer**: `credential_compromise`, `ransomware_simulation`, and `data_exfiltration`.

#### Q36: How are demo assertions evaluated?
> **Answer**: The scenario runner evaluates a 20-point checklist verifying pipeline state, agent outputs, risk scores, approval blocking, and safe SOAR execution.

#### Q37: How many automated tests exist in the test suite?
> **Answer**: 166 total backend tests (23 security tests, 9 integration tests, 134 unit tests).

---

## ⚡ Category 9: Advanced Engineering & Evaluator Deep-Dives

#### Q38: How does FastAPI dependency injection work in AegisAI XDR?
> **Answer**: `Depends(get_db)` and `Depends(get_current_user)` manage async database sessions and extract authenticated user contexts per request lifecycle.

#### Q39: What is the function of Pydantic v2 schemas in the API layer?
> **Answer**: They enforce strict data type validation, field constraints (e.g. UUID formatting), and serialization envelopes for request/response payloads.

#### Q40: How does the system handle Redis disconnection without failing user authorization?
> **Answer**: If Redis becomes unreachable, `security.py` falls back to an in-memory token blacklist set while logging a warning.

#### Q41: How does `SlowAPI` enforce endpoint rate limiting?
> **Answer**: It tracks client IP addresses in Redis or memory, returning `HTTP 429 Too Many Requests` when limits (e.g. 100 req/min) are exceeded.

#### Q42: What is the difference between MITRE Tactics and Techniques?
> **Answer**: Tactics describe the adversary's tactical goal (e.g. `EXECUTION`), while Techniques describe the specific technical method used (e.g. `T1059.001 PowerShell`).

#### Q43: How does the correlation engine calculate incident risk scores?
> **Answer**: Aggregates base alert severities, asset criticality multipliers, and temporal alignment factors into a normalized 0–100 risk score.

#### Q44: What is the role of `Alembic` version tables in PostgreSQL?
> **Answer**: `alembic_version` tracks current database schema revisions (`5d18d07315a7`), preventing schema drift and enabling incremental DDL migrations.

#### Q45: How are CORS headers configured for production deployment?
> **Answer**: `CORS_ORIGINS` explicitly lists allowed frontend domain origins. Wildcard `*` is strictly rejected when `ENVIRONMENT=production`.

#### Q46: What is a Directed Acyclic Graph (DAG) in the context of AI orchestration?
> **Answer**: A workflow graph where state moves forward through execution nodes without cycles, guaranteeing deterministic pipeline termination.

#### Q47: How does `Structlog` format logs for enterprise SIEM ingestion?
> **Answer**: Formats all log entries as structured JSON objects containing timestamps, log levels, correlation IDs, user UUIDs, and caller module paths.

#### Q48: How are Base64 PowerShell commands analyzed by DFIRInvestigatorAgent?
> **Answer**: Identifies `-enc` or `-EncodedCommand` flags, decodes UTF-16LE Base64 strings, and inspects underlying script blocks for malicious API calls.

#### Q49: Why are non-root users enforced in Dockerfiles?
> **Answer**: Prevents container escape attacks from escalating to root privileges on the host Linux kernel (`USER appuser`).

#### Q50: How does the synthetic scenario runner guarantee isolation from real alerts?
> **Answer**: Telemetry objects generated by demo runs are tagged with `synthetic_telemetry: true` and prefixed with `SYN-` reference IDs.

#### Q51: What is the purpose of Prometheus metrics exposition?
> **Answer**: `/api/v1/health/metrics` exposes HTTP request counts, response latency histograms, and active investigation gauges in standard Prometheus format.

#### Q52: What guarantees that AegisAI XDR cannot cause real infrastructure damage?
> **Answer**: The non-negotiable hardcoded `SOAR_EXECUTION_MODE = "SAFE_MOCK_EXECUTION"` setting replaces all remote action APIs with safe simulation logging.
