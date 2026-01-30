#!/usr/bin/env sh
# Backup vulnerability_db from RDS (Mumbai) to S3 vul-db-backup folder.
# The .sql file in S3 can be used to recover the database: psql -h HOST -U postgres -d vulnerability_db -f <downloaded>.sql
# Usage: set VUL_DB_PASSWORD (or PGPASSWORD), then run. Optional: VUL_DB_HOST, S3_BUCKET, USE_DOCKER=1.
# RDS server is PostgreSQL 15; use USE_DOCKER=1 if local pg_dump is not 15.x.
# Example: VUL_DB_PASSWORD='xxx' ./backup-vul-db-to-s3.sh

set -e

VUL_HOST="${VUL_DB_HOST:-postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com}"
VUL_PORT="${VUL_DB_PORT:-5432}"
VUL_USER="${VUL_DB_USER:-postgres}"
VUL_DB="${VUL_DB_NAME:-vulnerability_db}"
export PGPASSWORD="${VUL_DB_PASSWORD:-$PGPASSWORD}"
export PGSSLMODE="${PGSSLMODE:-require}"
BUCKET="${S3_BUCKET:-cspm-lgtech}"
REGION="${AWS_REGION:-ap-south-1}"
S3_PREFIX="vul-db-backup"
STAMP=$(date -u +%Y%m%d_%H%M%S)
BACKUP_FILE="vulnerability_db_${STAMP}.sql"

if [ -z "$PGPASSWORD" ]; then
  echo "ERROR: set VUL_DB_PASSWORD or PGPASSWORD"
  exit 1
fi

echo "Backing up $VUL_DB on $VUL_HOST to S3 $BUCKET/$S3_PREFIX/..."

if [ "$USE_DOCKER" = "1" ]; then
  docker run --rm \
    -e PGPASSWORD \
    -e PGSSLMODE \
    postgres:15-alpine \
    pg_dump -h "$VUL_HOST" -p "$VUL_PORT" -U "$VUL_USER" -d "$VUL_DB" --no-owner --no-acl -F p \
    > "$BACKUP_FILE"
else
  pg_dump -h "$VUL_HOST" -p "$VUL_PORT" -U "$VUL_USER" -d "$VUL_DB" --no-owner --no-acl -F p -f "$BACKUP_FILE"
fi

echo "Uploading to s3://$BUCKET/$S3_PREFIX/$BACKUP_FILE"
aws s3 cp "$BACKUP_FILE" "s3://$BUCKET/$S3_PREFIX/$BACKUP_FILE" --region "$REGION"
rm -f "$BACKUP_FILE"
echo "Done. Backup at s3://$BUCKET/$S3_PREFIX/$BACKUP_FILE"
