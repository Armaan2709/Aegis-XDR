# AegisAI XDR — Platform Threat Model (STRIDE Framework)

This document provides a comprehensive threat model analysis for the **AegisAI XDR** platform using the STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) methodology.

---

## 🎯 STRIDE Analysis Matrix Across 15 Attack Surfaces

### 1. Authentication & JWT Engine
- **Threat**: JWT Signature Forgery / Algorithm Manipulation (`none` algorithm or key confusion).
- **Attack Surface**: `/api/v1/auth/token`, Authorization Header.
- **Impact**: Full authentication bypass; attacker impersonates any user.
- **Existing Control**: Cryptographic algorithm enforcement (`algorithms=[settings.ALGORITHM]`), strict claim verification in `security.py`.
- **Detection**: Audit log alert on `JWT_INVALID_ALGORITHM` or failed token decoding.
- **Mitigation**: Use RS256 asymmetric keys with private key stored in secret manager.
- **Residual Risk**: Low.

---

### 2. Authorization & RBAC Boundary
- **Threat**: Privilege Escalation / IDOR (Analyst or Read-Only user mutates data or grants approvals).
- **Attack Surface**: REST API mutation endpoints (`POST`, `PUT`, `DELETE`).
- **Impact**: Unauthorized data modification or unauthorized security response execution.
- **Existing Control**: `@require_role` decorator enforcement and `READ_ONLY` role mutation blocking in `rbac.py`.
- **Detection**: Log alert on `HTTP 403 Forbidden` authorization failures.
- **Mitigation**: Unit test coverage (`test_rbac.py`) for all restricted routes.
- **Residual Risk**: Low.

---

### 3. API Gateway & Endpoints
- **Threat**: Denial of Service (DoS) / Endpoint Flooding.
- **Attack Surface**: Public API endpoints (`/api/v1/*`).
- **Impact**: Service degradation or unavailability for SOC analysts.
- **Existing Control**: SlowAPI rate limiting (100 req/min per IP) in `main.py`.
- **Detection**: Prometheus metric `http_requests_total{status="429"}` spike.
- **Mitigation**: Upstream Web Application Firewall (WAF) / reverse proxy rate limiting.
- **Residual Risk**: Medium (distributed botnet volume).

---

### 4. AI Orchestrator Graph Engine
- **Threat**: Orchestrator State Manipulation / Stage Hijacking.
- **Attack Surface**: In-memory `PipelineContext` / `InvestigationState`.
- **Impact**: Bypassing investigation stages or corrupting aggregate risk calculations.
- **Existing Control**: Strongly typed Pydantic models (`PipelineContext`) and state transition validation in `orchestrator.py`.
- **Detection**: Log warning on unexpected state transitions or invalid stage outputs.
- **Mitigation**: Immutable audit logs of pipeline state transitions.
- **Residual Risk**: Low.

---

### 5. Specialized AI Agents
- **Threat**: Indirect Prompt Injection via Telemetry Data.
- **Attack Surface**: Malicious strings in ingested security alert payloads (e.g. process command lines).
- **Impact**: Agent outputs manipulated to misclassify threat severity or alter summary reports.
- **Existing Control**: Structured JSON extraction; LLM prompts sanitize telemetry inputs using delimiters and schema parsing.
- **Detection**: Anomaly detection on sudden shifts in agent risk scores.
- **Mitigation**: Strict schema validation on agent output JSON; agents operate strictly read-only.
- **Residual Risk**: Medium (inherent LLM prompt vulnerability).

---

### 6. AI Tool Registry
- **Threat**: Unauthorized System Command Execution via AI Tools.
- **Attack Surface**: Tool execution dispatch in `ToolRegistry`.
- **Impact**: Arbitrary shell command execution on host operating system.
- **Existing Control**: Tool isolation; **zero OS subprocess calls (`os.system`, `eval`, `subprocess.Popen`) exist in tool functions**.
- **Detection**: Monitoring tool invocation metrics in `tools/registry.py`.
- **Mitigation**: Static code analysis preventing addition of shell execution tools.
- **Residual Risk**: Low.

---

### 7. Detection Rule Generator Engine
- **Threat**: Automated Activation of Malicious or Invalid Detection Rules.
- **Attack Surface**: Generated Sigma / YARA rule candidates.
- **Impact**: Sensor disruption or massive false-positive alerts.
- **Existing Control**: Generated rules are stored strictly in `CANDIDATE` status. **Automated activation is prohibited**.
- **Detection**: Rule parser syntax validation during generation.
- **Mitigation**: Mandatory human SOC analyst review and dry-run validation before deployment.
- **Residual Risk**: Low.

---

### 8. CaseApproval Governance Gate
- **Threat**: Governance Bypass / Unauthorized SOAR Execution.
- **Attack Surface**: Direct API invocation of response playbooks.
- **Impact**: Unauthorized host isolation or network block.
- **Existing Control**: `PlaybookService.execute_playbook()` requires a valid `CaseApproval` record in `APPROVED` status.
- **Detection**: Security test `test_approval_bypass.py` verifies unapproved calls fail.
- **Mitigation**: Mandatory database foreign key link between playbook execution and approval ID.
- **Residual Risk**: Low.

---

### 9. SOAR Playbook Engine
- **Threat**: Destructive Infrastructure Containment Actions.
- **Attack Surface**: Playbook execution runner.
- **Impact**: Accidental shutdown of critical business infrastructure.
- **Existing Control**: Hardcoded **`SOAR_EXECUTION_MODE = "SAFE_MOCK_EXECUTION"`**. Real API execution calls are replaced with safe simulation logging.
- **Detection**: Audit log records `SOAR_MOCK_EXECUTED`.
- **Mitigation**: Non-mock execution mode requires code refactoring and multi-party cryptographic keys.
- **Residual Risk**: Low.

---

### 10. PostgreSQL Relational Store
- **Threat**: SQL Injection (SQLi) / Data Exfiltration.
- **Attack Surface**: Database query parameters.
- **Impact**: Database compromise, credential exfiltration, data tampering.
- **Existing Control**: SQLAlchemy 2.0 ORM parameterized queries across all repositories.
- **Detection**: Security test `test_input_validation.py` verifies SQLi payload handling.
- **Mitigation**: Database user operates under principle of least privilege.
- **Residual Risk**: Low.

---

### 11. Redis Cache Store
- **Threat**: Redis Unauthorized Access / Token Blacklist Tampering.
- **Attack Surface**: Redis TCP port (6379).
- **Impact**: Revoked JWT tokens accepted, cache poisoning.
- **Existing Control**: Redis password authentication; fallback in-memory blacklist on Redis failure.
- **Detection**: Redis connection health checks (`check_redis_health`).
- **Mitigation**: Bind Redis to internal Docker bridge network; enable TLS.
- **Residual Risk**: Low.

---

### 12. Elasticsearch Telemetry Search Engine
- **Threat**: Telemetry Data Tampering / Unauthenticated Querying.
- **Attack Surface**: Elasticsearch REST API (9200).
- **Impact**: Deletion or alteration of historical security logs.
- **Existing Control**: Internal network binding; credentials configured via environment variables.
- **Detection**: Elasticsearch health check endpoint (`check_elasticsearch_health`).
- **Mitigation**: Enable Elasticsearch Security (X-Pack Basic Auth + TLS).
- **Residual Risk**: Medium.

---

### 13. Frontend SPA Application
- **Threat**: Cross-Site Scripting (XSS) / Session Token Hijacking.
- **Attack Surface**: React UI component rendering of untrusted alert text.
- **Impact**: Execution of malicious JavaScript in analyst browser session.
- **Existing Control**: React auto-escaping DOM rendering; HTTP Content Security Policy (`CSP`) headers.
- **Detection**: CSP violation reports.
- **Mitigation**: Store JWT tokens in `HttpOnly` SameSite cookies rather than localStorage.
- **Residual Risk**: Low.

---

### 14. Docker Container Infrastructure
- **Threat**: Container Breakout / Privilege Escalation.
- **Attack Surface**: Docker runtime environment.
- **Impact**: Host machine compromise from container root user.
- **Existing Control**: Dockerfiles enforce non-root user execution (`USER appuser`).
- **Detection**: Container vulnerability scanning in CI/CD pipeline.
- **Mitigation**: Read-only container root file system with explicit tmpfs mounts.
- **Residual Risk**: Low.

---

### 15. CI/CD Pipeline & Supply Chain
- **Threat**: Malicious Dependency Injection / Secret Leakage.
- **Attack Surface**: GitHub Actions workflow (`ci.yml`), `pyproject.toml`, `package.json`.
- **Impact**: Production deployment of backdoored dependencies or exposed API keys.
- **Existing Control**: Automated CI/CD security test execution; no hardcoded secrets in repository.
- **Detection**: GitHub Secret Scanning and Dependabot alerts.
- **Mitigation**: Pin dependency versions with lockfiles (`package-lock.json`, lockhashes).
- **Residual Risk**: Low.
