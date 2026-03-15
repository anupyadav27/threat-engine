#!/bin/bash

# Database Schema Changes - Add ARN Identifier Columns
# This script adds new columns to rule_discoveries and resource_inventory tables

DB_HOST="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
DB_USER="postgres"
DB_PASSWORD="jtv2BkJF8qoFtAKP"

echo "======================================================================="
echo "APPLYING SCHEMA CHANGES TO RDS DATABASES"
echo "======================================================================="

# Step 1: Update rule_discoveries table (Check DB)
echo ""
echo "Step 1: Updating threat_engine_check.rule_discoveries..."
echo "-----------------------------------------------------------------------"

PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d threat_engine_check << 'EOF'
-- Add new columns to rule_discoveries
ALTER TABLE rule_discoveries
ADD COLUMN IF NOT EXISTS boto3_client_name VARCHAR(100),
ADD COLUMN IF NOT EXISTS arn_identifier VARCHAR(255),
ADD COLUMN IF NOT EXISTS arn_identifier_independent_methods TEXT[],
ADD COLUMN IF NOT EXISTS arn_identifier_dependent_methods TEXT[];

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_rule_discoveries_boto3_client
ON rule_discoveries(boto3_client_name);

CREATE INDEX IF NOT EXISTS idx_rule_discoveries_arn_identifier
ON rule_discoveries(arn_identifier);

-- Add column comments
COMMENT ON COLUMN rule_discoveries.boto3_client_name
IS 'Boto3 client name (e.g., iam, cognito-idp, s3)';

COMMENT ON COLUMN rule_discoveries.arn_identifier
IS 'ARN identifier field from Python SDK resource_inventory (e.g., iam.user_detail_list_arn)';

COMMENT ON COLUMN rule_discoveries.arn_identifier_independent_methods
IS 'Independent methods (root_operations) - Priority 1';

COMMENT ON COLUMN rule_discoveries.arn_identifier_dependent_methods
IS 'Dependent methods (dependent_operations) - Priority 2 fallback';

-- Verify schema
\d rule_discoveries
EOF

if [ $? -eq 0 ]; then
    echo "✅ rule_discoveries schema updated successfully"
else
    echo "❌ Failed to update rule_discoveries schema"
    exit 1
fi

# Step 2: Update resource_inventory table (Python SDK DB)
echo ""
echo "Step 2: Updating threat_engine_pythonsdk.resource_inventory..."
echo "-----------------------------------------------------------------------"

PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d threat_engine_pythonsdk << 'EOF'
-- Add new columns to resource_inventory
ALTER TABLE resource_inventory
ADD COLUMN IF NOT EXISTS service_name VARCHAR(100),
ADD COLUMN IF NOT EXISTS boto3_client_name VARCHAR(100),
ADD COLUMN IF NOT EXISTS arn_identifiers_summary JSONB;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_resource_inventory_service_name
ON resource_inventory(service_name);

CREATE INDEX IF NOT EXISTS idx_resource_inventory_boto3_client
ON resource_inventory(boto3_client_name);

CREATE INDEX IF NOT EXISTS idx_resource_inventory_arn_summary_gin
ON resource_inventory USING GIN (arn_identifiers_summary);

-- Add column comments
COMMENT ON COLUMN resource_inventory.service_name
IS 'Service name extracted from service_id (e.g., iam from aws.iam)';

COMMENT ON COLUMN resource_inventory.boto3_client_name
IS 'Boto3 client name (may differ from service_name, e.g., cognito-idp)';

COMMENT ON COLUMN resource_inventory.arn_identifiers_summary
IS 'Summary of ARN identifiers by resource type: {resource_type: {arn_entity, independent_methods, dependent_methods}}';

-- Verify schema
\d resource_inventory
EOF

if [ $? -eq 0 ]; then
    echo "✅ resource_inventory schema updated successfully"
else
    echo "❌ Failed to update resource_inventory schema"
    exit 1
fi

echo ""
echo "======================================================================="
echo "SCHEMA CHANGES COMPLETED SUCCESSFULLY"
echo "======================================================================="
echo ""
echo "Next step: Run 02_populate_columns.py to populate the new columns"
