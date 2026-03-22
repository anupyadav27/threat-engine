#!/bin/bash

# Migration Script: Add account_id Column to discovery_findings Table
# This script adds explicit account_id tracking for multi-account discovery analysis

DB_HOST="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
DB_USER="postgres"
DB_PASSWORD="jtv2BkJF8qoFtAKP"
DB_NAME="threat_engine_discoveries"
SQL_FILE="04_add_account_column.sql"

echo "======================================================================="
echo "ADDING account_id COLUMN TO discovery_findings TABLE"
echo "======================================================================="
echo ""
echo "Database: $DB_NAME"
echo "Host: $DB_HOST"
echo ""

# Check if SQL file exists
if [ ! -f "$SQL_FILE" ]; then
    echo "❌ Error: SQL file '$SQL_FILE' not found"
    exit 1
fi

# Execute SQL migration
echo "Executing migration..."
echo "-----------------------------------------------------------------------"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -f "$SQL_FILE"

if [ $? -eq 0 ]; then
    echo ""
    echo "======================================================================="
    echo "✅ MIGRATION COMPLETED SUCCESSFULLY"
    echo "======================================================================="
    echo ""
    echo "Verifying account_id column..."
    echo "-----------------------------------------------------------------------"
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "\d discovery_findings" | grep -A 1 "account_id"
    echo ""
    echo "Done! The account_id column has been added to discovery_findings table."
else
    echo ""
    echo "======================================================================="
    echo "❌ MIGRATION FAILED"
    echo "======================================================================="
    exit 1
fi
