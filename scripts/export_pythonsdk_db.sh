#!/bin/bash
# Export Python SDK Database Schema and Sample Data

DB_HOST="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
DB_NAME="threat_engine_pythonsdk"
DB_USER="postgres"
DB_PASSWORD="jtv2BkJF8qoFtAKP"  # From service_metadata_loader.py line 77
OUTPUT_DIR="/Users/apple/Desktop/threat-engine/database_exports/pythonsdk"

mkdir -p "$OUTPUT_DIR"

echo "Exporting Python SDK database schema and data..."

# Export full schema
echo "1. Exporting database schema..."
PGPASSWORD="$DB_PASSWORD" pg_dump \
  -h "$DB_HOST" \
  -U "$DB_USER" \
  -d "$DB_NAME" \
  --schema-only \
  -f "$OUTPUT_DIR/pythonsdk_schema.sql"

echo "✅ Schema exported to: $OUTPUT_DIR/pythonsdk_schema.sql"

# Export table summaries (counts, structure)
echo ""
echo "2. Exporting table summaries..."
PGPASSWORD="$DB_PASSWORD" psql \
  -h "$DB_HOST" \
  -U "$DB_USER" \
  -d "$DB_NAME" \
  -o "$OUTPUT_DIR/table_summaries.txt" << 'EOF'
-- Table counts
SELECT 'CSP Count' as metric, COUNT(*) as count FROM csp
UNION ALL
SELECT 'Services Count', COUNT(*) FROM services
UNION ALL
SELECT 'Operations Count', COUNT(*) FROM operations
UNION ALL
SELECT 'Fields Count', COUNT(*) FROM fields
UNION ALL
SELECT 'Resource Inventory Records', COUNT(*) FROM resource_inventory
UNION ALL
SELECT 'Relationship Rules', COUNT(*) FROM relationship_rules;

-- CSP breakdown
SELECT '\n--- CSP Breakdown ---' as section;
SELECT csp_id, csp_name, total_services, sdk_version
FROM csp
ORDER BY total_services DESC;

-- Service counts per CSP
SELECT '\n--- Services Per CSP ---' as section;
SELECT csp_id, COUNT(*) as service_count
FROM services
GROUP BY csp_id
ORDER BY service_count DESC;

-- Sample AWS services with SDK module and ARN patterns
SELECT '\n--- Sample AWS Services (First 20 with ARN patterns) ---' as section;
SELECT
    service_id,
    service_name,
    sdk_module,
    metadata->>'primary_arn_pattern' as arn_pattern,
    total_operations
FROM services
WHERE csp_id = 'aws'
  AND metadata->>'primary_arn_pattern' IS NOT NULL
LIMIT 20;
EOF

echo "✅ Table summaries exported to: $OUTPUT_DIR/table_summaries.txt"

# Export AWS services data (for discoveries engine refactoring)
echo ""
echo "3. Exporting AWS services data..."
PGPASSWORD="$DB_PASSWORD" psql \
  -h "$DB_HOST" \
  -U "$DB_USER" \
  -d "$DB_NAME" \
  -c "\COPY (
    SELECT
        service_id,
        csp_id,
        service_name,
        service_full_name,
        sdk_module,
        total_operations,
        metadata
    FROM services
    WHERE csp_id = 'aws'
    ORDER BY service_name
) TO '$OUTPUT_DIR/aws_services.csv' CSV HEADER"

echo "✅ AWS services exported to: $OUTPUT_DIR/aws_services.csv"

# Export operations for key AWS services
echo ""
echo "4. Exporting operations for key AWS services..."
PGPASSWORD="$DB_PASSWORD" psql \
  -h "$DB_HOST" \
  -U "$DB_USER" \
  -d "$DB_NAME" \
  -c "\COPY (
    SELECT
        service_id,
        operation_name,
        python_method,
        is_discovery,
        main_output_field,
        metadata
    FROM operations
    WHERE service_id IN ('aws.ec2', 'aws.s3', 'aws.iam', 'aws.lambda', 'aws.rds')
      AND is_discovery = TRUE
    ORDER BY service_id, operation_name
    LIMIT 100
) TO '$OUTPUT_DIR/aws_discovery_operations_sample.csv' CSV HEADER"

echo "✅ Operations sample exported to: $OUTPUT_DIR/aws_discovery_operations_sample.csv"

# Export resource inventory classifications
echo ""
echo "5. Exporting resource inventory classifications..."
PGPASSWORD="$DB_PASSWORD" psql \
  -h "$DB_HOST" \
  -U "$DB_USER" \
  -d "$DB_NAME" \
  -c "\COPY (
    SELECT
        service_id,
        inventory_data,
        total_resource_types,
        total_operations,
        discovery_operations
    FROM resource_inventory
    WHERE service_id LIKE 'aws.%'
    ORDER BY service_id
    LIMIT 50
) TO '$OUTPUT_DIR/aws_resource_inventory_sample.csv' CSV HEADER"

echo "✅ Resource inventory sample exported to: $OUTPUT_DIR/aws_resource_inventory_sample.csv"

# Export relationship rules for AWS
echo ""
echo "6. Exporting relationship rules for AWS..."
PGPASSWORD="$DB_PASSWORD" psql \
  -h "$DB_HOST" \
  -U "$DB_USER" \
  -d "$DB_NAME" \
  -c "\COPY (
    SELECT
        rule_id,
        csp_id,
        service_id,
        from_type,
        relation_type,
        to_type,
        source_field,
        target_uid_pattern
    FROM relationship_rules
    WHERE csp_id = 'aws'
    ORDER BY service_id, from_type
    LIMIT 100
) TO '$OUTPUT_DIR/aws_relationship_rules_sample.csv' CSV HEADER"

echo "✅ Relationship rules sample exported to: $OUTPUT_DIR/aws_relationship_rules_sample.csv"

# Create a summary report
echo ""
echo "7. Creating summary report..."
cat > "$OUTPUT_DIR/EXPORT_SUMMARY.md" << 'EOFMD'
# Python SDK Database Export Summary

## Export Date
$(date)

## Database Details
- **Host**: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
- **Database**: threat_engine_pythonsdk
- **Location**: AWS RDS ap-south-1 (Mumbai)

## Exported Files

### 1. Schema
- `pythonsdk_schema.sql` - Full database schema with all tables, indexes, comments

### 2. Summary Statistics
- `table_summaries.txt` - Table counts, CSP breakdown, sample service data

### 3. AWS Services Data
- `aws_services.csv` - All AWS services with SDK module names, ARN patterns, metadata
- `aws_discovery_operations_sample.csv` - Sample discovery operations (first 100)
- `aws_resource_inventory_sample.csv` - Sample resource classifications (first 50)
- `aws_relationship_rules_sample.csv` - Sample relationship rules (first 100)

## Key Findings for Discoveries Engine Refactoring

### Services Table Structure
```sql
CREATE TABLE services (
    service_id VARCHAR(100) PRIMARY KEY,
    csp_id VARCHAR(50) NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    service_full_name VARCHAR(200),
    description TEXT,
    sdk_module VARCHAR(200),  -- ✅ This is the boto3 client name!
    total_operations INTEGER,
    discovery_operations INTEGER,
    metadata JSONB DEFAULT '{}'  -- ✅ Contains primary_arn_pattern, resource_identifier_type
);
```

### Metadata JSONB Field
The `metadata` field contains:
- `primary_arn_pattern` - ARN pattern for generating resource ARNs
- `resource_identifier_type` - Type (arn, resource_id, etc.)
- `primary_resource_id_pattern` - Alternative ID pattern for non-ARN resources

### How Discoveries Engine Should Use This

1. **Replace `discovery_helper.py` hardcoded mapping:**
   ```python
   # OLD: Hardcoded dictionary
   SERVICE_TO_BOTO3_CLIENT = {'cognito': 'cognito-idp', ...}

   # NEW: Query database
   SELECT sdk_module FROM services WHERE service_name = 'cognito' AND csp_id = 'aws'
   # Returns: 'cognito-idp'
   ```

2. **Replace `discovery_resource_mapper.py` JSON file loading:**
   ```python
   # OLD: Load from service_list.json file
   config_path = os.path.join(_config_dir(), "service_list.json")

   # NEW: Query database
   SELECT metadata->>'primary_arn_pattern', metadata->>'resource_identifier_type'
   FROM services
   WHERE service_name = 'ec2' AND csp_id = 'aws'
   # Returns: ARN pattern and identifier type
   ```

3. **Replace `reporting_manager.py` ARN generation:**
   ```python
   # OLD: Load ARN pattern from static JSON
   arn_pattern = service_config.get("arn_pattern")

   # NEW: Query database for ARN pattern
   SELECT metadata->>'primary_arn_pattern' FROM services
   WHERE service_id = 'aws.ec2'
   ```

## Database Connection Details (from existing code)

**Environment Variables:**
- `PYTHONSDK_DB_HOST` = postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
- `PYTHONSDK_DB_PORT` = 5432
- `PYTHONSDK_DB_NAME` = threat_engine_pythonsdk
- `PYTHONSDK_DB_USER` = postgres
- `PYTHONSDK_DB_PASSWORD` = (stored in Secrets Manager)

**Default Connection:**
See `/Users/apple/Desktop/threat-engine/consolidated_services/database/config/database_config.py`
EOFMD

echo "✅ Summary report created: $OUTPUT_DIR/EXPORT_SUMMARY.md"

echo ""
echo "============================================"
echo "✅ Python SDK Database Export Complete!"
echo "============================================"
echo "Output directory: $OUTPUT_DIR"
echo ""
echo "Files created:"
ls -lh "$OUTPUT_DIR"
