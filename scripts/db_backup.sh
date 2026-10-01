#!/usr/bin/env bash
# ==============================================================================
# AegisAI XDR Enterprise Production Backup & Disaster Recovery Script
# ==============================================================================
# SAFE EXECUTION: Never overwrites existing production backups or databases automatically.
# Usage: ./scripts/db_backup.sh [backup_dir]

set -euo pipefail

BACKUP_DIR="${1:-/tmp/aegis_backups}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
POSTGRES_BACKUP_FILE="${BACKUP_DIR}/aegis_xdr_postgres_${TIMESTAMP}.sql.gz"

POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-aegis_user}"
POSTGRES_DB="${POSTGRES_DB:-aegis_xdr_db}"

echo "======================================================================"
echo "AegisAI XDR Backup Script - Timestamp: ${TIMESTAMP}"
echo "======================================================================"
echo "Target Backup Directory: ${BACKUP_DIR}"

mkdir -p "${BACKUP_DIR}"

if command -v pg_dump &> /dev/null; then
    echo "[+] Creating PostgreSQL database backup..."
    PGPASSWORD="${POSTGRES_PASSWORD:-aegis_secure_password}" pg_dump \
        -h "${POSTGRES_HOST}" \
        -p "${POSTGRES_PORT}" \
        -U "${POSTGRES_USER}" \
        -d "${POSTGRES_DB}" \
        --clean --if-exists --no-owner --no-privileges \
        | gzip -9 > "${POSTGRES_BACKUP_FILE}"
    echo "[+] PostgreSQL backup completed: ${POSTGRES_BACKUP_FILE}"
    echo "[+] Verification size: $(du -sh "${POSTGRES_BACKUP_FILE}" | cut -f1)"
else
    echo "[!] pg_dump command not found in PATH. Skipping direct pg_dump execution."
    echo "[!] Run pg_dump within container: docker exec -t aegis_postgres pg_dump -U aegis_user aegis_xdr_db | gzip > backup.sql.gz"
fi

echo "[+] Backup execution completed safely."
