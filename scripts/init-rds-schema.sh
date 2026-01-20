#!/bin/bash
# Initialize PostgreSQL schema in RDS
# Usage: ./init-rds-schema.sh

set -e

# RDS Connection Details
# Try both users - threatengine (from secret) and postgres (from handover doc)
RDS_HOST="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
RDS_PORT="5432"
RDS_DB="vulnerability_db"

# Try threatengine first (from Kubernetes secret)
RDS_USER="${RDS_USER:-threatengine}"
RDS_PASSWORD="${RDS_PASSWORD:-v-nKrqSta17I8UA1IPzIgoiJHPIE-zPm20V7D857yVU}"

# Alternative: postgres user (from handover doc)
# RDS_USER="postgres"
# RDS_PASSWORD="apXuHV%2OSyRWK62"

# Schema file
SCHEMA_FILE="onboarding/database/schema.sql"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     RDS PostgreSQL Schema Initialization                         ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Check if psql is available
if ! command -v psql &> /dev/null; then
    echo "❌ psql not found. Installing postgresql client..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install postgresql@14 || brew install postgresql
    else
        echo "Please install postgresql client manually"
        exit 1
    fi
fi

# Check if schema file exists
if [ ! -f "$SCHEMA_FILE" ]; then
    echo "❌ Schema file not found: $SCHEMA_FILE"
    exit 1
fi

echo "📋 Connection Details:"
echo "   Host: $RDS_HOST"
echo "   Port: $RDS_PORT"
echo "   Database: $RDS_DB"
echo "   User: $RDS_USER"
echo ""

# Test connection
echo "🔍 Testing connection..."
export PGPASSWORD="$RDS_PASSWORD"
if psql -h "$RDS_HOST" -p "$RDS_PORT" -U "$RDS_USER" -d "$RDS_DB" -c "SELECT version();" > /dev/null 2>&1; then
    echo "✅ Connection successful!"
else
    echo "❌ Connection failed. Please check:"
    echo "   - RDS security group allows your IP"
    echo "   - Credentials are correct"
    echo "   - RDS instance is running"
    exit 1
fi

# Check if tables already exist
echo ""
echo "🔍 Checking existing tables..."
TABLE_COUNT=$(psql -h "$RDS_HOST" -p "$RDS_PORT" -U "$RDS_USER" -d "$RDS_DB" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('tenants', 'providers', 'accounts', 'schedules', 'executions', 'scan_results');" | tr -d ' ')

if [ "$TABLE_COUNT" -gt 0 ]; then
    echo "⚠️  Found $TABLE_COUNT existing table(s)."
    read -p "Do you want to recreate tables? This will DROP existing tables! (yes/no): " -r
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "🗑️  Dropping existing tables..."
        psql -h "$RDS_HOST" -p "$RDS_PORT" -U "$RDS_USER" -d "$RDS_DB" <<EOF
DROP TABLE IF EXISTS scan_results CASCADE;
DROP TABLE IF EXISTS executions CASCADE;
DROP TABLE IF EXISTS schedules CASCADE;
DROP TABLE IF EXISTS accounts CASCADE;
DROP TABLE IF EXISTS providers CASCADE;
DROP TABLE IF EXISTS tenants CASCADE;
EOF
        echo "✅ Tables dropped"
    else
        echo "ℹ️  Keeping existing tables. Skipping schema creation."
        exit 0
    fi
fi

# Create schema
echo ""
echo "📝 Creating schema..."
psql -h "$RDS_HOST" -p "$RDS_PORT" -U "$RDS_USER" -d "$RDS_DB" -f "$SCHEMA_FILE"

if [ $? -eq 0 ]; then
    echo "✅ Schema created successfully!"
else
    echo "❌ Schema creation failed"
    exit 1
fi

# Verify tables
echo ""
echo "🔍 Verifying tables..."
TABLE_LIST=$(psql -h "$RDS_HOST" -p "$RDS_PORT" -U "$RDS_USER" -d "$RDS_DB" -t -c "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name;" | tr -d ' ')

echo "Created tables:"
echo "$TABLE_LIST" | while read -r table; do
    if [ ! -z "$table" ]; then
        echo "  ✅ $table"
    fi
done

# Count rows (should be 0 for new tables)
echo ""
echo "📊 Table status:"
for table in tenants providers accounts schedules executions scan_results; do
    COUNT=$(psql -h "$RDS_HOST" -p "$RDS_PORT" -U "$RDS_USER" -d "$RDS_DB" -t -c "SELECT COUNT(*) FROM $table;" 2>/dev/null | tr -d ' ' || echo "0")
    echo "  $table: $COUNT rows"
done

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     ✅ RDS Schema Initialization Complete!                      ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

unset PGPASSWORD

