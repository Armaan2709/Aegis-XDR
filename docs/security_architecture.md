# AegisAI XDR — Security Architecture Specifications

This document outlines the end-to-end security architecture, authentication controls, authorization rules, governance boundaries, and resilience mechanisms of the **AegisAI XDR** platform.

---

## 🔒 1. Authentication & JWT Hardening

- **JWT Engine**: Implemented in `backend/app/core/security.py` using `python-jose`.
- **Algorithms Supported**: `HS256` (default for dev) and `RS256` (production configuration).
- **Token Claims**: Subject (`sub` = user UUID), expiration (`exp`), issued-at (`iat`), token type (`type` = "access" / "refresh"), and role (`role`).
- **Token Validation Security**:
  - Missing claims (e.g. missing `sub` or `type`) are strictly rejected.
  - Expired tokens fail with `401 Unauthorized` (`JWT_EXPIRED`).
  - Algorithm manipulation (e.g., `none` algorithm attacks) is blocked by explicit `algorithms=[settings.ALGORITHM]` enforcement.
  - Revoked tokens are checked against a Redis blacklist (`check_jwt_blacklisted`).

---

## 🛡️ 2. Role-Based Access Control (RBAC) & API Authorization

Implemented in `backend/app/core/rbac.py` with 4 operational roles:

| Role | Permissions | Mutation Capabilities | Governance Actions |
|------|-------------|-----------------------|--------------------|
| `READ_ONLY` | View-only access across all dashboards & domains | Blocked (`403 Forbidden`) | Blocked |
| `SOC_ANALYST` | View dashboards, ingest alerts, add notes/tags, run investigations | Standard operational mutations | Can request approvals |
| `INCIDENT_COMMANDER` | Full operational control, rule management, playbook execution | Full domain mutations | Can grant/reject approvals |
| `ADMIN` | System configuration, user management, global settings | Administrative mutations | Full governance authority |

- **Role Normalization**: Normalizes role strings to uppercase enums.
- **READ_ONLY Mutation Block**: Decorators enforce that `READ_ONLY` users cannot execute `POST`, `PUT`, `PATCH`, or `DELETE` requests.

---

## 🛑 3. CaseApproval & Governance Control Boundary

Implemented in `backend/app/case_management/models.py` and `backend/app/playbooks/services.py`:

```
 [AI Recommendation] ──> [CaseApproval Created (PENDING)] ──> [Human Review Gate]
                                                                      │
                                                ┌─────────────────────┴─────────────────────┐
                                                ▼                                           ▼
                                    [Analyst Grants Approval]                   [Analyst Rejects Approval]
                                                │                                           │
                                                ▼                                           ▼
                                [SAFE_MOCK_EXECUTION Triggered]                 [Execution Blocked & Logged]
```

- Response actions (e.g., IP blocking, host isolation, account disabling) **must** create a `CaseApproval` record in `PENDING` status.
- Unapproved playbooks remain safely blocked.
- Resuming a pipeline without an approved `CaseApproval` raises `ForbiddenError`.

---

## 🛡️ 4. SOAR Execution Safety Boundary

Implemented in `backend/app/playbooks/services.py` and `backend/app/core/config.py`:

- **Constraint**: `SOAR_EXECUTION_MODE = "SAFE_MOCK_EXECUTION"`.
- **Validation**: Enforced at settings initialization. Attempting to set `SOAR_EXECUTION_MODE` to any non-mock value raises a configuration `ValueError`.
- **Execution Boundary**: Playbook steps produce simulated result objects and immutable audit logs. **Zero remote shell or operating system commands are executed**.

---

## 🤖 5. AI Tool Isolation & Security Boundary

Implemented in `backend/app/ai/tools/registry.py`:

- AI agents execute tools registered in an explicit, isolated `ToolRegistry`.
- Tools operate strictly over in-memory `InvestigationState` and domain database repositories.
- **No OS Subprocess Execution**: Tools have no access to `os.system()`, `subprocess.Popen()`, or `eval()`.
- Input validation sanitizes tool parameters against injection attacks.

---

## 🌐 6. Input Validation & HTTP Hardening

- **Pydantic Schemas**: Request payloads pass through strict Pydantic v2 schemas (`backend/app/schemas/`).
- **SQL Injection Prevention**: SQLAlchemy 2.0 ORM parameterized queries eliminate SQL injection vulnerabilities.
- **XSS Payload Handling**: Text fields sanitize script tags and HTML entities.
- **Security Headers Middleware**: `backend/app/middleware/security_headers.py` injects:
  - `Content-Security-Policy: default-src 'self'`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-XSS-Protection: 1; mode=block`
- **Rate Limiting**: `SlowAPI` enforces rate limits (default: 100 requests/minute per IP).

---

## 📊 7. Observability, Correlation IDs & Audit Trail

- **Correlation ID Middleware**: Injects a unique `X-Correlation-ID` header into every request/response lifecycle.
- **Structured JSON Logging**: Structlog formats logs in JSON with correlation IDs, timestamps, user IDs, and request paths.
- **Immutable Audit Trail**: Database `audit_logs` table records authentication attempts, approval decisions, user role changes, and SOAR execution events.

---

## 🔐 8. Infrastructure & Container Resilience

- **Secrets Management**: Default development keys are rejected in `ENVIRONMENT=production`. Production secrets are read exclusively from environment variables.
- **Docker Hardening**: Multi-stage Docker builds run containers under non-root service users.
- **PostgreSQL Resilience**: Connection pooling with `pool_recycle=1800` and pre-ping validation.
- **Redis Resilience**: Explicit connection timeouts with fallback to in-memory JWT blacklist on connection loss.
- **Elasticsearch Resilience**: Configured request timeouts and error retries.
