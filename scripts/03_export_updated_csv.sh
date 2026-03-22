#!/bin/bash

# CSV Export Script - Export Updated Tables to Local CSV Files
# This script exports rule_discoveries and resource_inventory tables after schema changes

DB_HOST="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
DB_USER="postgres"
DB_PASSWORD="jtv2BkJF8qoFtAKP"

# Output directory
OUTPUT_DIR="/Users/apple/.claude-worktrees/threat-engine/nervous-burnell/rds_backup_updated"

echo "======================================================================="
echo "EXPORTING UPDATED CSV FILES FROM RDS"
echo "======================================================================="

# Create output directories
echo ""
echo "Creating output directories..."
mkdir -p "$OUTPUT_DIR/check"
mkdir -p "$OUTPUT_DIR/pythonsdk"

# Step 1: Export rule_discoveries (Check DB)
echo ""
echo "Step 1: Exporting threat_engine_check.rule_discoveries..."
echo "-----------------------------------------------------------------------"

PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d threat_engine_check -c "\COPY (
    SELECT
        id,
        service,
        provider,
        version,
        boto3_client_name,
        arn_identifier,
        arn_identifier_independent_methods,
        arn_identifier_dependent_methods,
        discoveries_data,
        customer_id,
        tenant_id,
        source,
        generated_by,
        is_active,
        created_at,
        updated_at
    FROM rule_discoveries
    ORDER BY provider, service, id
) TO '$OUTPUT_DIR/check/rule_discoveries_updated.csv' WITH CSV HEADER;"

if [ $? -eq 0 ]; then
    FILE_SIZE=$(du -h "$OUTPUT_DIR/check/rule_discoveries_updated.csv" | cut -f1)
    RECORD_COUNT=$(tail -n +2 "$OUTPUT_DIR/check/rule_discoveries_updated.csv" | wc -l | tr -d ' ')
    echo "✅ rule_discoveries exported successfully"
    echo "   File: $OUTPUT_DIR/check/rule_discoveries_updated.csv"
    echo "   Size: $FILE_SIZE"
    echo "   Records: $RECORD_COUNT"
else
    echo "❌ Failed to export rule_discoveries"
    exit 1
fi

# Step 2: Export resource_inventory (Python SDK DB)
echo ""
echo "Step 2: Exporting threat_engine_pythonsdk.resource_inventory..."
echo "-----------------------------------------------------------------------"

PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d threat_engine_pythonsdk -c "\COPY (
    SELECT
        id,
        service_id,
        service_name,
        boto3_client_name,
        inventory_data,
        arn_identifiers_summary,
        total_resource_types,
        total_operations,
        discovery_operations,
        version,
        created_at,
        updated_at
    FROM resource_inventory
    ORDER BY service_id
) TO '$OUTPUT_DIR/pythonsdk/resource_inventory_updated.csv' WITH CSV HEADER;"

if [ $? -eq 0 ]; then
    FILE_SIZE=$(du -h "$OUTPUT_DIR/pythonsdk/resource_inventory_updated.csv" | cut -f1)
    RECORD_COUNT=$(tail -n +2 "$OUTPUT_DIR/pythonsdk/resource_inventory_updated.csv" | wc -l | tr -d ' ')
    echo "✅ resource_inventory exported successfully"
    echo "   File: $OUTPUT_DIR/pythonsdk/resource_inventory_updated.csv"
    echo "   Size: $FILE_SIZE"
    echo "   Records: $RECORD_COUNT"
else
    echo "❌ Failed to export resource_inventory"
    exit 1
fi

# Summary
echo ""
echo "======================================================================="
echo "CSV EXPORT COMPLETED SUCCESSFULLY"
echo "======================================================================="
echo ""
echo "Exported files:"
echo "  1. $OUTPUT_DIR/check/rule_discoveries_updated.csv"
echo "  2. $OUTPUT_DIR/pythonsdk/resource_inventory_updated.csv"
echo ""
echo "Next steps:"
echo "  - Review CSV files for data accuracy"
echo "  - Verify new columns are populated correctly"
echo "  - Use these files for analysis and development"
