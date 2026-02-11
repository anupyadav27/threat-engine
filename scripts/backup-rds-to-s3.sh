#!/bin/bash

###############################################################################
# RDS Database Backup Script
# Purpose: Backup all RDS databases and upload to S3 with timestamp
# Author: Vulnerability Engine Deployment
# Date: 2026-02-11
###############################################################################

set -e  # Exit on any error

# Configuration
REGION="ap-south-1"
S3_BUCKET="anup-backup"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DATE=$(date +%Y-%m-%d)
BACKUP_DIR="/tmp/rds-backups-${TIMESTAMP}"
S3_PREFIX="rds-backups/${BACKUP_DATE}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Create backup directory
mkdir -p "${BACKUP_DIR}"
log_info "Created backup directory: ${BACKUP_DIR}"

# Get list of all RDS instances
log_info "Fetching list of RDS instances in region ${REGION}..."
RDS_INSTANCES=$(aws rds describe-db-instances \
    --region ${REGION} \
    --query 'DBInstances[*].DBInstanceIdentifier' \
    --output text)

if [ -z "$RDS_INSTANCES" ]; then
    log_error "No RDS instances found in region ${REGION}"
    exit 1
fi

log_info "Found RDS instances: ${RDS_INSTANCES}"

# Backup each RDS instance
for DB_INSTANCE in $RDS_INSTANCES; do
    log_info "=========================================="
    log_info "Processing database: ${DB_INSTANCE}"
    log_info "=========================================="

    # Get database details
    DB_INFO=$(aws rds describe-db-instances \
        --db-instance-identifier ${DB_INSTANCE} \
        --region ${REGION} \
        --query 'DBInstances[0].{Endpoint:Endpoint.Address,Engine:Engine,DBName:DBName,MasterUsername:MasterUsername}' \
        --output json)

    DB_ENDPOINT=$(echo $DB_INFO | jq -r '.Endpoint')
    DB_ENGINE=$(echo $DB_INFO | jq -r '.Engine')
    DB_NAME=$(echo $DB_INFO | jq -r '.DBName')
    DB_USER=$(echo $DB_INFO | jq -r '.MasterUsername')

    log_info "Database Engine: ${DB_ENGINE}"
    log_info "Database Name: ${DB_NAME}"
    log_info "Endpoint: ${DB_ENDPOINT}"

    # Get database password from secret or use environment variable
    if [ "${DB_INSTANCE}" = "postgres-vulnerability-db" ]; then
        DB_PASSWORD="jtv2BkJF8qoFtAKP"  # Known password
    else
        log_warn "Password not configured for ${DB_INSTANCE}, skipping..."
        continue
    fi

    # Backup based on database engine
    if [[ "${DB_ENGINE}" == "postgres" ]]; then
        log_info "Creating PostgreSQL backup..."

        BACKUP_FILE="${BACKUP_DIR}/${DB_INSTANCE}-${TIMESTAMP}.sql"
        BACKUP_FILE_COMPRESSED="${BACKUP_FILE}.gz"

        # Create pg_dump backup
        export PGPASSWORD="${DB_PASSWORD}"

        log_info "Running pg_dump..."
        pg_dump -h ${DB_ENDPOINT} \
            -U ${DB_USER} \
            -d ${DB_NAME} \
            --no-owner \
            --no-acl \
            --clean \
            --if-exists \
            > "${BACKUP_FILE}" 2>&1

        if [ $? -eq 0 ]; then
            log_info "✓ Backup created successfully"

            # Get backup size
            BACKUP_SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
            log_info "Backup size: ${BACKUP_SIZE}"

            # Compress backup
            log_info "Compressing backup..."
            gzip "${BACKUP_FILE}"

            COMPRESSED_SIZE=$(du -h "${BACKUP_FILE_COMPRESSED}" | cut -f1)
            log_info "Compressed size: ${COMPRESSED_SIZE}"

            # Upload to S3
            S3_PATH="s3://${S3_BUCKET}/${S3_PREFIX}/${DB_INSTANCE}-${TIMESTAMP}.sql.gz"
            log_info "Uploading to S3: ${S3_PATH}"

            aws s3 cp "${BACKUP_FILE_COMPRESSED}" "${S3_PATH}" --region ${REGION}

            if [ $? -eq 0 ]; then
                log_info "✓ Upload successful"

                # Verify upload
                S3_SIZE=$(aws s3 ls "${S3_PATH}" --region ${REGION} | awk '{print $3}')
                log_info "S3 file size: ${S3_SIZE} bytes"
            else
                log_error "✗ Upload failed"
            fi
        else
            log_error "✗ Backup failed for ${DB_INSTANCE}"
        fi

        unset PGPASSWORD

    elif [[ "${DB_ENGINE}" == "mysql" ]] || [[ "${DB_ENGINE}" == "mariadb" ]]; then
        log_info "Creating MySQL/MariaDB backup..."

        BACKUP_FILE="${BACKUP_DIR}/${DB_INSTANCE}-${TIMESTAMP}.sql"
        BACKUP_FILE_COMPRESSED="${BACKUP_FILE}.gz"

        # Create mysqldump backup
        log_info "Running mysqldump..."
        mysqldump -h ${DB_ENDPOINT} \
            -u ${DB_USER} \
            -p"${DB_PASSWORD}" \
            --single-transaction \
            --routines \
            --triggers \
            --events \
            ${DB_NAME} \
            > "${BACKUP_FILE}" 2>&1

        if [ $? -eq 0 ]; then
            log_info "✓ Backup created successfully"

            # Compress and upload
            gzip "${BACKUP_FILE}"

            S3_PATH="s3://${S3_BUCKET}/${S3_PREFIX}/${DB_INSTANCE}-${TIMESTAMP}.sql.gz"
            aws s3 cp "${BACKUP_FILE_COMPRESSED}" "${S3_PATH}" --region ${REGION}

            if [ $? -eq 0 ]; then
                log_info "✓ Upload successful"
            fi
        else
            log_error "✗ Backup failed for ${DB_INSTANCE}"
        fi
    else
        log_warn "Unsupported database engine: ${DB_ENGINE}"
    fi

    echo ""
done

# Create backup manifest
MANIFEST_FILE="${BACKUP_DIR}/backup-manifest-${TIMESTAMP}.json"
log_info "Creating backup manifest..."

cat > "${MANIFEST_FILE}" <<EOF
{
  "backup_date": "${BACKUP_DATE}",
  "backup_timestamp": "${TIMESTAMP}",
  "region": "${REGION}",
  "s3_bucket": "${S3_BUCKET}",
  "s3_prefix": "${S3_PREFIX}",
  "databases": [
EOF

FIRST=true
for DB_INSTANCE in $RDS_INSTANCES; do
    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        echo "," >> "${MANIFEST_FILE}"
    fi

    cat >> "${MANIFEST_FILE}" <<EOF
    {
      "db_instance": "${DB_INSTANCE}",
      "backup_file": "${DB_INSTANCE}-${TIMESTAMP}.sql.gz",
      "s3_path": "s3://${S3_BUCKET}/${S3_PREFIX}/${DB_INSTANCE}-${TIMESTAMP}.sql.gz"
    }
EOF
done

cat >> "${MANIFEST_FILE}" <<EOF

  ],
  "created_by": "rds-backup-script",
  "version": "1.0"
}
EOF

# Upload manifest
log_info "Uploading manifest to S3..."
aws s3 cp "${MANIFEST_FILE}" \
    "s3://${S3_BUCKET}/${S3_PREFIX}/backup-manifest-${TIMESTAMP}.json" \
    --region ${REGION}

# Summary
log_info "=========================================="
log_info "Backup Summary"
log_info "=========================================="
log_info "Backup Date: ${BACKUP_DATE}"
log_info "Backup Timestamp: ${TIMESTAMP}"
log_info "S3 Bucket: ${S3_BUCKET}"
log_info "S3 Path: s3://${S3_BUCKET}/${S3_PREFIX}/"
log_info ""
log_info "Backed up databases:"
for DB_INSTANCE in $RDS_INSTANCES; do
    log_info "  - ${DB_INSTANCE}"
done
log_info ""
log_info "Local backup directory: ${BACKUP_DIR}"
log_info ""

# List uploaded files
log_info "Files in S3:"
aws s3 ls "s3://${S3_BUCKET}/${S3_PREFIX}/" --region ${REGION} --human-readable

# Cleanup local backups
log_info ""
read -p "Do you want to delete local backup files? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "${BACKUP_DIR}"
    log_info "✓ Local backup files deleted"
else
    log_info "Local backup files retained at: ${BACKUP_DIR}"
fi

log_info ""
log_info "=========================================="
log_info "Backup completed successfully!"
log_info "=========================================="
