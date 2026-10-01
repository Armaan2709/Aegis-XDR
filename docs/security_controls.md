# AegisAI XDR — Verified Security Control Matrix

This matrix maps implemented security controls in **AegisAI XDR** directly to their source code locations and automated verification test files.

---

## 📋 Security Controls Verification Table

| Control Category | Specific Security Control | Source Implementation Location | Verification Test File | Status |
|------------------|---------------------------|--------------------------------|------------------------|--------|
| **Authentication** | Cryptographic JWT Token Signing (HS256/RS256) | `backend/app/core/security.py` | `tests/security/test_auth_security.py` | ✅ VERIFIED |
| **Authentication** | Expiration & Claim Validation (`sub`, `exp`, `type`) | `backend/app/core/security.py` | `tests/security/test_auth_security.py` | ✅ VERIFIED |
| **Authentication** | Algorithm Manipulation Protection (`none` blocked) | `backend/app/core/security.py` | `tests/security/test_auth_security.py` | ✅ VERIFIED |
| **Authentication** | Revoked Token Blacklisting (Redis / Memory) | `backend/app/core/security.py` | `tests/security/test_auth_security.py` | ✅ VERIFIED |
| **Authorization** | Role-Based Access Control (`SOC_ANALYST`, `ADMIN`, etc.)| `backend/app/core/rbac.py` | `tests/security/test_rbac.py` | ✅ VERIFIED |
| **Authorization** | `READ_ONLY` Mutation Blocking (`POST`/`PUT`/`DELETE`) | `backend/app/core/rbac.py` | `tests/security/test_rbac.py` | ✅ VERIFIED |
| **Governance** | Mandatory `CaseApproval` Human Review Gate | `backend/app/case_management/models.py` | `tests/security/test_approval_bypass.py` | ✅ VERIFIED |
| **Governance** | Unapproved SOAR Action Execution Blocking | `backend/app/playbooks/services.py` | `tests/security/test_approval_bypass.py` | ✅ VERIFIED |
| **SOAR Safety** | `SAFE_MOCK_EXECUTION` Boundary Enforcement | `backend/app/core/config.py` | `tests/security/test_demo_security.py` | ✅ VERIFIED |
| **AI Tools** | Isolated Tool Registry without Subprocess Execution | `backend/app/ai/tools/registry.py` | `tests/security/test_ai_security.py` | ✅ VERIFIED |
| **AI Agents** | Read-Only Telemetry Analysis Constraints | `backend/app/ai/agents/base.py` | `tests/security/test_ai_security.py` | ✅ VERIFIED |
| **Detection Engine** | Rule Candidates Held in `CANDIDATE` Status | `backend/app/domains/detections/services.py` | `tests/unit/test_detection_engine.py` | ✅ VERIFIED |
| **Input Validation** | SQL Injection Prevention via SQLAlchemy ORM | `backend/app/repositories/base.py` | `tests/security/test_input_validation.py` | ✅ VERIFIED |
| **Input Validation** | XSS Payload Sanitization & React DOM Auto-Escaping | `frontend/src/pages/DemoScenarios.tsx` | `tests/security/test_input_validation.py` | ✅ VERIFIED |
| **HTTP Hardening** | Security Headers (CSP, HSTS, X-Frame, X-Content) | `backend/app/middleware/security_headers.py` | `tests/security/test_security_headers.py` | ✅ VERIFIED |
| **Rate Limiting** | SlowAPI Endpoint Rate Limiting (100 req/min) | `backend/app/main.py` | `tests/security/test_api_security.py` | ✅ VERIFIED |
| **Audit Logging** | Immutable Database Audit Logging & Structlog JSON | `backend/app/core/logging.py` | `tests/unit/test_case_management.py` | ✅ VERIFIED |
| **Tracing** | `X-Correlation-ID` Context Propagation | `backend/app/middleware/correlation.py` | `tests/security/test_security_headers.py` | ✅ VERIFIED |
| **Secret Protection**| Production Secret Entropy Enforcement | `backend/app/core/config.py` | Code Audit | ✅ VERIFIED |
| **Container Security**| Non-Root User Execution (`USER appuser`) | `backend/Dockerfile` | `docker compose config` | ✅ VERIFIED |
| **Health Checks** | Component Liveness/Readiness Endpoints | `backend/app/api/v1/health.py` | `tests/integration/test_observability_api.py` | ✅ VERIFIED |
| **Resilience** | DB Pre-Ping Pool Validation & Redis Timeout Fallback | `backend/app/core/database.py`, `redis.py` | `tests/integration/test_observability_api.py` | ✅ VERIFIED |
