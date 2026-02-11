#!/bin/bash

###############################################################################
# Complete RDS Database Backup Script
# Backs up ALL databases from RDS instance using Docker (to avoid version mismatch)
###############################################################################

set -e

# Configuration
REGION="ap-south-1"
S3_BUCKET="anup-backup"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DATE=$(date +%Y-%m-%d)
BACKUP_DIR="/tmp/rds-backups-${TIMESTAMP}"
S3_PREFIX="rds-backups/${BACKUP_DATE}"

# Database connection details
DB_HOST="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
DB_USER="postgres"
DB_PASSWORD="jtv2BkJF8qoFtAKP"
DB_PORT="5432"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Create backup directory
mkdir -p "${BACKUP_DIR}"
log_info "Created backup directory: ${BACKUP_DIR}"

# Get list of all databases (excluding templates and rdsadmin)
log_info "Fetching list of databases..."

DATABASES=$(PGPASSWORD="${DB_PASSWORD}" psql -h ${DB_HOST} -U ${DB_USER} -d postgres -t -c "
    SELECT datname FROM pg_database
    WHERE datistemplate = false
    AND datname NOT IN ('rdsadmin')
    ORDER BY datname;
" | grep -v '^$' | xargs)

if [ -z "$DATABASES" ]; then
    log_error "No databases found!"
    exit 1
fi

log_info "Found databases: ${DATABASES}"
log_info ""

# Backup each database using Docker (to match server version)
TOTAL_SIZE=0
SUCCESS_COUNT=0
FAILED_COUNT=0

for DB_NAME in $DATABASES; do
    log_info "=========================================="
    log_info "Backing up database: ${DB_NAME}"
    log_info "=========================================="

    BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}-${TIMESTAMP}.sql"
    BACKUP_FILE_COMPRESSED="${BACKUP_FILE}.gz"

    # Use Docker with PostgreSQL 15 to match server version
    log_info "Running pg_dump via Docker..."

    docker run --rm \
        -e PGPASSWORD="${DB_PASSWORD}" \
        postgres:15 \
        pg_dump -h ${DB_HOST} \
        -U ${DB_USER} \
        -p ${DB_PORT} \
        -d ${DB_NAME} \
        --no-owner \
        --no-acl \
        --clean \
        --if-exists \
        > "${BACKUP_FILE}" 2>&1

    if [ $? -eq 0 ] && [ -s "${BACKUP_FILE}" ]; then
        BACKUP_SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
        log_info "✓ Backup created: ${BACKUP_SIZE}"

        # Compress
        log_info "Compressing..."
        gzip "${BACKUP_FILE}"

        COMPRESSED_SIZE=$(du -h "${BACKUP_FILE_COMPRESSED}" | cut -f1)
        COMPRESSED_BYTES=$(stat -f%z "${BACKUP_FILE_COMPRESSED}")
        TOTAL_SIZE=$((TOTAL_SIZE + COMPRESSED_BYTES))

        log_info "Compressed size: ${COMPRESSED_SIZE}"

        # Upload to S3
        S3_PATH="s3://${S3_BUCKET}/${S3_PREFIX}/${DB_NAME}-${TIMESTAMP}.sql.gz"
        log_info "Uploading to S3..."

        aws s3 cp "${BACKUP_FILE_COMPRESSED}" "${S3_PATH}" --region ${REGION}

        if [ $? -eq 0 ]; then
            log_info "✓ Upload successful: ${S3_PATH}"
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            log_error "✗ Upload failed"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    else
        log_error "✗ Backup failed for ${DB_NAME}"
        FAILED_COUNT=$((FAILED_COUNT + 1))

        # Check if file exists and show its content for debugging
        if [ -f "${BACKUP_FILE}" ]; then
            log_warn "Backup file exists but might be empty:"
            head -20 "${BACKUP_FILE}"
        fi
    fi

    log_info ""
done

# Create backup manifest
log_info "Creating backup manifest..."
MANIFEST_FILE="${BACKUP_DIR}/backup-manifest-${TIMESTAMP}.json"

cat > "${MANIFEST_FILE}" <<EOF
{
  "backup_date": "${BACKUP_DATE}",
  "backup_timestamp": "${TIMESTAMP}",
  "region": "${REGION}",
  "rds_instance": "postgres-vulnerability-db",
  "s3_bucket": "${S3_BUCKET}",
  "s3_prefix": "${S3_PREFIX}",
  "total_databases": $(echo $DATABASES | wc -w),
  "successful_backups": ${SUCCESS_COUNT},
  "failed_backups": ${FAILED_COUNT},
  "total_size_bytes": ${TOTAL_SIZE},
  "databases": [
EOF

FIRST=true
for DB_NAME in $DATABASES; do
    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        echo "," >> "${MANIFEST_FILE}"
    fi

    BACKUP_EXISTS="false"
    if [ -f "${BACKUP_DIR}/${DB_NAME}-${TIMESTAMP}.sql.gz" ]; then
        BACKUP_EXISTS="true"
    fi

    cat >> "${MANIFEST_FILE}" <<EOF
    {
      "database_name": "${DB_NAME}",
      "backup_file": "${DB_NAME}-${TIMESTAMP}.sql.gz",
      "s3_path": "s3://${S3_BUCKET}/${S3_PREFIX}/${DB_NAME}-${TIMESTAMP}.sql.gz",
      "backup_successful": ${BACKUP_EXISTS}
    }
EOF
done

cat >> "${MANIFEST_FILE}" <<EOF

  ]
}
EOF

# Upload manifest
aws s3 cp "${MANIFEST_FILE}" \
    "s3://${S3_BUCKET}/${S3_PREFIX}/backup-manifest-${TIMESTAMP}.json" \
    --region ${REGION}

# Summary
log_info ""
log_info "=========================================="
log_info "           BACKUP SUMMARY"
log_info "=========================================="
log_info "Backup Date: ${BACKUP_DATE}"
log_info "Timestamp: ${TIMESTAMP}"
log_info "Total Databases: $(echo $DATABASES | wc -w)"
log_info "Successful: ${SUCCESS_COUNT}"
log_info "Failed: ${FAILED_COUNT}"
log_info "Total Size: $(numfmt --to=iec ${TOTAL_SIZE}) (${TOTAL_SIZE} bytes)"
log_info "S3 Location: s3://${S3_BUCKET}/${S3_PREFIX}/"
log_info ""
log_info "Databases backed up:"
for DB_NAME in $DATABASES; do
    if [ -f "${BACKUP_DIR}/${DB_NAME}-${TIMESTAMP}.sql.gz" ]; then
        SIZE=$(du -h "${BACKUP_DIR}/${DB_NAME}-${TIMESTAMP}.sql.gz" | cut -f1)
        log_info "  ✓ ${DB_NAME} (${SIZE})"
    else
        log_error "  ✗ ${DB_NAME} (failed)"
    fi
done
log_info ""

# List S3 files
log_info "Files uploaded to S3:"
aws s3 ls "s3://${S3_BUCKET}/${S3_PREFIX}/" --region ${REGION} --human-readable --summarize

log_info ""
log_info "=========================================="
log_info "Backup completed!"
log_info "=========================================="
log_info "Local backups: ${BACKUP_DIR}"
log_info "S3 location: s3://${S3_BUCKET}/${S3_PREFIX}/"
