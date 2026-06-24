#!/usr/bin/env bash
# SentinelSSH — PostgreSQL backup (run from the repo dir or via cron).
# Dumps the DB from the running `db` container and prunes old archives.
#
# Cron example (daily 03:30, keep 14 days):
#   30 3 * * * cd /opt/sentinelssh && ./deploy/backup.sh >> /var/log/sentinelssh-backup.log 2>&1
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/opt/sentinelssh/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
POSTGRES_USER="${POSTGRES_USER:-sentinel}"
POSTGRES_DB="${POSTGRES_DB:-sentinelssh}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="${BACKUP_DIR}/sentinelssh-${TS}.sql.gz"

mkdir -p "${BACKUP_DIR}"

echo "[backup] dumping ${POSTGRES_DB} -> ${OUT}"
docker compose exec -T db pg_dump -U "${POSTGRES_USER}" "${POSTGRES_DB}" | gzip -9 > "${OUT}"

echo "[backup] pruning archives older than ${RETENTION_DAYS} days"
find "${BACKUP_DIR}" -name 'sentinelssh-*.sql.gz' -mtime "+${RETENTION_DAYS}" -delete

echo "[backup] done: $(du -h "${OUT}" | cut -f1)"

# Restore (manual):
#   gunzip -c backups/sentinelssh-YYYYMMDD-HHMMSS.sql.gz | \
#     docker compose exec -T db psql -U sentinel -d sentinelssh
