# AegisAI XDR — Database Architecture & Schema Specifications

This document specifies the database models, relations, indexes, migrations, backup routines, and Entity-Relationship (ER) diagram for the **AegisAI XDR** PostgreSQL relational store.

---

## 📐 1. Entity-Relationship (ER) Diagram

```mermaid
erDiagram
    USERS ||--o{ CASES : owns
    USERS ||--o{ CASE_COMMENTS : authors
    USERS ||--o{ CASE_APPROVALS : decides
    INCIDENTS ||--o{ ALERTS : contains
    INCIDENTS ||--o{ INVESTIGATIONS : originates
    INVESTIGATIONS ||--o{ EVIDENCE : collects
    INVESTIGATIONS ||--o{ TIMELINE_EVENTS : records
    INVESTIGATIONS ||--o{ DETECTION_RULES : synthesizes
    CASES ||--o{ CASE_COMMENTS : threads
    CASES ||--o{ CASE_APPROVALS : requires
    CASES ||--o{ CASE_ACTIVITIES : audits

    USERS {
        uuid id PK
        string username UK
        string email UK
        string hashed_password
        string role
        boolean is_active
        datetime created_at
    }

    ALERTS {
        uuid id PK
        string title
        string description
        string source
        string severity
        json mitre_tactics
        json mitre_techniques
        json iocs
        uuid incident_id FK
        datetime created_at
    }

    INCIDENTS {
        uuid id PK
        string title
        string description
        string severity
        string priority
        string status
        float risk_score
        datetime created_at
    }

    INVESTIGATIONS {
        uuid id PK
        uuid incident_id FK
        string name
        string status
        string priority
        string phase
        float risk_score
        float confidence_score
        json findings
        datetime started_at
    }

    EVIDENCE {
        uuid id PK
        uuid investigation_id FK
        string artifact_name
        string artifact_type
        string file_path
        string sha256_hash
        json evidence_metadata
        datetime collected_at
    }

    TIMELINE_EVENTS {
        uuid id PK
        uuid investigation_id FK
        uuid incident_id FK
        string event_type
        string event_category
        string description
        datetime timestamp
    }

    CASES {
        uuid id PK
        string case_number UK
        string title
        string status
        string severity
        uuid owner_id FK
        json related_incidents
        json related_investigations
        datetime opened_at
    }

    CASE_APPROVALS {
        uuid id PK
        uuid case_id FK
        string title
        string description
        string status
        boolean is_auto_approval
        uuid approver_id FK
        datetime decided_at
    }

    PLAYBOOKS {
        uuid id PK
        string name
        string category
        json steps
        datetime created_at
    }

    AUDIT_LOGS {
        uuid id PK
        uuid user_id FK
        string action
        string resource_type
        string resource_id
        json details
        datetime timestamp
    }
```

---

## 🗄️ 2. Domain Entity Specifications

Implemented in `backend/app/models/` and `backend/app/case_management/models.py`:

1. **`users`**: User account credentials, hashed passwords, roles (`SOC_ANALYST`, `ADMIN`, etc.).
2. **`alerts`**: Ingested security telemetry events with MITRE tactics and IOC lists.
3. **`incidents`**: Correlated incident graphs grouping related alerts.
4. **`investigations`**: Multi-agent investigation lifecycle state and risk scores.
5. **`evidence`**: Forensic artifacts with SHA256 cryptographic hash validation.
6. **`timeline_events`**: Chronological reconstruction events.
7. **`cases`**: Enterprise SOC case workspace records.
8. **`case_approvals`**: Human governance approval records (`PENDING`, `APPROVED`, `REJECTED`).
9. **`detection_rules`**: Generated Sigma, YARA, and Suricata candidate rules.
10. **`playbooks`**: SOAR playbook steps and mock execution configurations.
11. **`audit_logs`**: Immutable audit logs capturing platform activity.

---

## ⚙️ 3. Database Migration Management (Alembic)

- **Registry**: `backend/app/db/base.py` imports all SQLAlchemy models to ensure complete metadata tracking.
- **Migration Configuration**: `backend/alembic.ini` and `backend/app/db/migrations/env.py`.
- **Baseline Migration**: Baseline migration `5d18d07315a7_initial_schema_sprint21.py` contains DDL table definitions.
- **Commands**:
  ```bash
  # Check current revision
  alembic current

  # Run pending migrations
  alembic upgrade head
  ```

---

## 💾 4. Automated Backup & Recovery

- **Script**: `scripts/db_backup.sh`.
- **Functionality**:
  - PostgreSQL `pg_dump` binary execution.
  - MD5 integrity checksum generation.
  - `gzip` compression.
  - Rolling retention policy (prunes backups older than 7 days).
- **Disaster Recovery Guide**: Documented in `docs/backup_and_recovery.md`.
