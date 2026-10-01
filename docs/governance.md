# AegisAI XDR — Human-in-the-Loop Governance & CaseApproval Specifications

This document specifies the human governance framework and `CaseApproval` lifecycle implemented within the **AegisAI XDR** platform.

---

## 🏛️ Governance Philosophy: AI Recommendation vs. Authorized Action

AegisAI XDR establishes a non-negotiable boundary between **AI Recommendation** and **Authorized Security Response**:

> ⚠️ **Key Security Principle**: An AI agent (including `IncidentCommanderAgent`) has **zero authority** to execute response actions independently. AI outputs are classified strictly as **advisory recommendations**. Privileged response playbooks can only be triggered after a human SOC analyst or supervisor grants explicit authorization via a `CaseApproval` record.

---

## 🔄 State Machine & Execution Decision Flow

```
                      +-----------------------------------+
                      |      IncidentCommanderAgent       |
                      |   Generates Recommended Action    |
                      +-----------------------------------+
                                        |
                                        v
                      +-----------------------------------+
                      |      CaseApproval Created         |
                      |        Status: PENDING            |
                      +-----------------------------------+
                                        |
                      +-----------------+-----------------+
                      |                                   |
                      v                                   v
             [No Approval Granted]               [Human Analyst Review]
                      |                                   |
           +----------+----------+               +--------+--------+
           |                     |               |                 |
           v                     v               v                 v
     Status: PENDING      Status: REJECTED  Status: APPROVED  Status: CANCELLED
           |                     |               |                 |
           v                     v               v                 v
   🚫 EXECUTION BLOCKED  🚫 EXECUTION BLOCKED  ✅ SAFE MOCK SOAR   🚫 EXECUTION BLOCKED
                                                   EXECUTED
```

---

## 📊 Detailed Approval Status Rules

| Approval Status | Execution State | SOAR Playbook Action | System Behavior |
|-----------------|-----------------|----------------------|-----------------|
| `PENDING` | **BLOCKED** | Suspended | Pipeline pauses at Stage 9 (`AWAITING_REVIEW`). Playbook cannot execute. |
| `REJECTED` | **BLOCKED** | Terminated | Execution canceled. Incident Commander recommendation flagged as rejected. |
| `CANCELLED` | **BLOCKED** | Terminated | Operation aborted by analyst or system timeout SLA. |
| `APPROVED` | **EXECUTING** | `SAFE_MOCK_EXECUTION` | Triggered strictly within safe simulation boundary. Audit log created. |

---

## 📜 Auditability & Governance Traceability

Every `CaseApproval` transition logs an immutable record in the PostgreSQL `audit_logs` table containing:
- `approval_id`: Unique UUID identifier.
- `case_id`: Associated SOC Case UUID.
- `requester_agent`: Agent making the recommendation (e.g. `IncidentCommanderAgent`).
- `action_type`: Specific playbook action requested (e.g. `ISOLATE_HOST_AND_BLOCK_IOC`).
- `approver_id`: User UUID of approving human analyst (or `SYSTEM` for automated synthetic test flags).
- `status`: `PENDING`, `APPROVED`, `REJECTED`, or `EXPIRED`.
- `decided_at`: UTC timestamp of approval decision.

---

## 🧪 Verification in Security Tests

The governance boundary is verified by automated pytest routines:
- `tests/security/test_approval_bypass.py`: Verifies that calling `execute_playbook()` or resuming a pipeline without an `APPROVED` record raises `ForbiddenError` (HTTP 403).
- `tests/security/test_demo_security.py::test_demo_unapproved_action_blocking`: Verifies that running a demo scenario with `auto_approve=False` safely halts response execution.
