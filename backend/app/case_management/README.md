# AegisAI XDR — Enterprise Case Management System (Sprint 9)

## Overview
The **Case Management System** serves as the central collaboration operational workspace for SOC analysts and AI orchestration agents. It aggregates Incidents, Investigations, DFIR Evidence, Forensic Timelines, MITRE ATT&CK techniques, Threat Intelligence IOCs, and Detection Rule matches into a unified, auditable workspace.

---

## Domain Models
1. **Case**: Central case workspace entity (`CASE-YYYY-NNNN` auto-generated reference code).
2. **CaseComment**: Threaded Markdown comments with mentions, edit audit history, and soft deletion.
3. **CaseAttachment**: Metadata catalog for forensic artifacts (Reports, Screenshots, PCAPs, Memory Dumps, Log Files, IOC Lists). Storage metadata only.
4. **CaseTask**: Operational tasks with state machine validations (`PENDING` -> `IN_PROGRESS` -> `COMPLETED`/`CANCELLED`).
5. **CaseApproval**: Governance approval system with manual and `AutoApprovalPolicy` placeholder engine.
6. **CaseActivity**: Append-only audit trail logging all case lifecycle operations.
7. **CaseAssignment**: Analyst role assignment tracking (Primary Lead, Co-Analyst, Reviewer, Observer).
8. **CaseStatistics**: Aggregated operational workspace metrics (MTTR, SLA breaches, task completion rates).

---

## Architecture & Design Patterns
- **Clean Architecture & DDD**: Strict separation of database entities (`models.py`), Pydantic schemas (`schemas.py`), async data access repositories (`repositories.py`), core domain services (`services.py`), specialized submodules (`comments.py`, `attachments.py`, `tasks.py`, `approvals.py`, `activity.py`, `statistics.py`), and REST API endpoints (`router.py`).
- **Async SQLAlchemy 2.0**: Typed `Mapped[]` type hints.
- **Pydantic v2**: `ConfigDict(from_attributes=True)` and strict field validations.

---

## REST API Endpoints

Mounted under `/api/v1/cases`:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/cases` | Create a new Case |
| `GET` | `/cases` | List, search, filter, sort, and paginate cases |
| `GET` | `/cases/statistics` | Retrieve aggregated case statistics |
| `GET` | `/cases/{case_id}` | Get detailed case info |
| `PATCH` | `/cases/{case_id}` | Update case properties |
| `POST` | `/cases/{case_id}/close` | Close case with closure notes |
| `POST` | `/cases/{case_id}/assignments` | Assign an analyst |
| `DELETE` | `/cases/{case_id}/assignments/{user_id}` | Unassign an analyst |
| `POST` | `/cases/{case_id}/links` | Link domain entity (Incident, Evidence, MITRE, Threat IOC, etc.) |
| `GET` | `/cases/{case_id}/comments` | List comments |
| `POST` | `/cases/{case_id}/comments` | Post comment / threaded reply |
| `PATCH` | `/cases/{case_id}/comments/{comment_id}` | Edit comment |
| `DELETE` | `/cases/{case_id}/comments/{comment_id}` | Soft delete comment |
| `GET` | `/cases/{case_id}/attachments` | List attachment metadata |
| `POST` | `/cases/{case_id}/attachments` | Add attachment metadata |
| `GET` | `/cases/{case_id}/tasks` | List case tasks |
| `POST` | `/cases/{case_id}/tasks` | Create task |
| `PATCH` | `/cases/{case_id}/tasks/{task_id}` | Update task status / assignment |
| `GET` | `/cases/{case_id}/approvals` | List approval requests |
| `POST` | `/cases/{case_id}/approvals` | Request approval |
| `POST` | `/cases/{case_id}/approvals/{approval_id}/decision` | Submit approval decision |
| `GET` | `/cases/{case_id}/activity` | Retrieve case activity audit log |
