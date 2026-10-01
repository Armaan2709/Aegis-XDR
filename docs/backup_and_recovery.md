# AegisAI XDR Disaster Recovery & Production Backup Runbook

## Overview
This runbook documents operational procedures for PostgreSQL relational state backups, Redis snapshot persistence, Elasticsearch telemetry index recovery, and platform restoration following disaster events.

---

## Service Level Objectives (RPO & RTO)
- **Recovery Point Objective (RPO)**: < 1 Hour (Point-in-Time Recovery via PostgreSQL WAL archiving and hourly snapshots).
- **Recovery Time Objective (RTO)**: < 15 Minutes (Containerized restoration and DB migration replay).

---

## 1. PostgreSQL Database Backup & Restore

### Automatic / Scheduled Backup Creation
Run the included backup script:
```bash
./scripts/db_backup.sh /var/backups/aegis
```

Or execute directly via Docker:
```bash
docker exec -t aegis_postgres pg_dump -U aegis_user aegis_xdr_db | gzip -9 > /var/backups/aegis/aegis_xdr_$(date +%Y%m%d_%H%M%S).sql.gz
```

### Verification
Validate the backup file non-destructively:
```bash
gzip -t /var/backups/aegis/aegis_xdr_latest.sql.gz
```

### Database Restore Procedure
> [!CAUTION]
> Restoring a database replaces existing relational tables. Always create a safety snapshot before restoring.

1. Drop existing connections and restore database:
```bash
gunzip -c /var/backups/aegis/aegis_xdr_latest.sql.gz | docker exec -i aegis_postgres psql -U aegis_user -d aegis_xdr_db
```
2. Verify table integrity and run migrations:
```bash
PYTHONPATH=backend python3 -m alembic -c backend/app/db/alembic.ini upgrade head
```

---

## 2. Redis Persistence & Cache Recovery

### Configuration Requirements
In `redis.conf`, enforce RDB snapshots + AOF persistence:
```ini
save 900 1
save 300 10
appendonly yes
appendfsync everysec
```

### Backup & Restoration
- Copy the appendonly file (`appendonly.aof`) or snapshot (`dump.rdb`) to `/data/dump.rdb`.
- Start Redis; Redis will automatically load persistent keys into memory upon startup.
- In-memory JWT revocation token blacklists fall back seamlessly if Redis storage is cleared.

---

## 3. Elasticsearch Telemetry Recovery

### Snapshot Lifecycle Management (SLM)
Create a repository and snapshot:
```bash
curl -X PUT "localhost:9200/_snapshot/aegis_backup_repo" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/usr/share/elasticsearch/snapshots"
  }
}'
```

Trigger an on-demand snapshot:
```bash
curl -X PUT "localhost:9200/_snapshot/aegis_backup_repo/snapshot_1?wait_for_completion=true"
```

### Telemetry Index Restoration
Restore indices from a snapshot:
```bash
curl -X POST "localhost:9200/_snapshot/aegis_backup_repo/snapshot_1/_restore"
```

---

## 4. Disaster Recovery Procedure Checklist
1. Deploy platform infrastructure using hardened Docker Compose configuration.
2. Verify environment configuration variables and mandatory production secrets.
3. Execute PostgreSQL restore and apply Alembic migrations.
4. Start Redis and Elasticsearch services.
5. Verify `/api/v1/health/readiness` and `/api/v1/health/deps` endpoints.
6. Verify CaseApproval and RBAC governance controls.
