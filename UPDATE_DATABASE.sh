#!/bin/bash
#
# Multi-Cloud Database Update Script
# Updates RDS Mumbai with multi-cloud metadata
#

set -e

SCRIPT_DIR="/Users/apple/Desktop/threat-engine/consolidated_services/database/scripts"

echo "================================================================================"
echo "MULTI-CLOUD DATABASE UPDATE - RDS MUMBAI"
echo "================================================================================"
echo ""
echo "This will update the threat_engine_shared database with:"
echo "  - 1,350+ services across 6 CSPs"
echo "  - Discovery & enrichment operations"
echo "  - Resource classifications"
echo ""
echo "================================================================================"
echo ""

# Prompt for RDS credentials
read -p "RDS Host (e.g., xxx.rds.amazonaws.com): " RDS_HOST
read -p "RDS Port [5432]: " RDS_PORT
RDS_PORT=${RDS_PORT:-5432}
read -p "Database Name [threat_engine_shared]: " DB_NAME
DB_NAME=${DB_NAME:-threat_engine_shared}
read -p "Username [shared_user]: " DB_USER
DB_USER=${DB_USER:-shared_user}
read -sp "Password: " DB_PASSWORD
echo ""
echo ""

# Test connection
echo "Testing connection to RDS..."
export PGPASSWORD="$DB_PASSWORD"
if psql -h "$RDS_HOST" -p "$RDS_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null 2>&1; then
    echo "✅ Connection successful!"
else
    echo "❌ Connection failed. Please check credentials."
    exit 1
fi

echo ""
echo "================================================================================"
echo "DRY RUN - Testing Update"
echo "================================================================================"
echo ""

# Run dry-run
python3 "$SCRIPT_DIR/update_pythonsdk_simple.py" \
    --dry-run \
    --host "$RDS_HOST" \
    --port "$RDS_PORT" \
    --database "$DB_NAME" \
    --user "$DB_USER" \
    --password "$DB_PASSWORD"

echo ""
echo "================================================================================"
read -p "Proceed with LIVE update? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "❌ Update cancelled"
    exit 0
fi

echo ""
echo "================================================================================"
echo "LIVE UPDATE - Updating RDS Database"
echo "================================================================================"
echo ""

# Run live update
python3 "$SCRIPT_DIR/update_pythonsdk_simple.py" \
    --host "$RDS_HOST" \
    --port "$RDS_PORT" \
    --database "$DB_NAME" \
    --user "$DB_USER" \
    --password "$DB_PASSWORD"

echo ""
echo "================================================================================"
echo "VERIFYING UPDATE"
echo "================================================================================"
echo ""

# Verify updates
echo "Checking CSP coverage..."
psql -h "$RDS_HOST" -p "$RDS_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
SELECT csp_id, COUNT(*) as total_services,
       COUNT(CASE WHEN independent_methods IS NOT NULL THEN 1 END) as with_discovery
FROM services
GROUP BY csp_id
ORDER BY csp_id;
"

echo ""
echo "Checking S3 metadata..."
psql -h "$RDS_HOST" -p "$RDS_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
SELECT
    service_id,
    ARRAY_LENGTH(independent_methods, 1) as discovery_ops,
    ARRAY_LENGTH(dependent_methods, 1) as enrichment_ops,
    data_quality,
    primary_arn_pattern
FROM services
WHERE service_id = 'aws.s3';
"

echo ""
echo "================================================================================"
echo "✅ DATABASE UPDATE COMPLETE!"
echo "================================================================================"
echo ""
echo "Next steps:"
echo "  1. Update inventory engine code"
echo "  2. Test locally"
echo "  3. Deploy to EKS"
echo ""
