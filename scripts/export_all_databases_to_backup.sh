#!/bin/bash
# Export all databases (Check, PythonSDK, Discoveries) to RDS backup location

DB_HOST="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
DB_USER="postgres"
DB_PASSWORD="jtv2BkJF8qoFtAKP"
OUTPUT_BASE="/Users/apple/.claude-worktrees/threat-engine/nervous-burnell/rds_backup"

# Create output directories
mkdir -p "$OUTPUT_BASE/check"
mkdir -p "$OUTPUT_BASE/pythonsdk"
mkdir -p "$OUTPUT_BASE/discoveries"

echo "================================================================================"
echo "EXPORTING ALL DATABASES TO: $OUTPUT_BASE"
echo "================================================================================"
echo ""

# =============================================================================
# 1. CHECK DATABASE (threat_engine_check)
# =============================================================================
echo "1. Exporting CHECK database (threat_engine_check)..."
echo "--------------------------------------------------------------------------------"

DB_NAME="threat_engine_check"
OUTPUT_DIR="$OUTPUT_BASE/check"

# Export check_report
echo "  - check_report"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM check_report ORDER BY scan_timestamp DESC) TO '$OUTPUT_DIR/check_report.csv' CSV HEADER"

# Export check_findings
echo "  - check_findings"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM check_findings ORDER BY id) TO '$OUTPUT_DIR/check_findings.csv' CSV HEADER"

# Export rule_checks
echo "  - rule_checks"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM rule_checks ORDER BY service, rule_id) TO '$OUTPUT_DIR/rule_checks.csv' CSV HEADER"

# Export rule_metadata
echo "  - rule_metadata"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM rule_metadata ORDER BY service, rule_id) TO '$OUTPUT_DIR/rule_metadata.csv' CSV HEADER"

# Export rule_discoveries (IMPORTANT)
echo "  - rule_discoveries (PRIMARY SOURCE)"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM rule_discoveries ORDER BY provider, service) TO '$OUTPUT_DIR/rule_discoveries.csv' CSV HEADER"

# Export schemas
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ check_report" > "$OUTPUT_DIR/schema_check_report.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ check_findings" > "$OUTPUT_DIR/schema_check_findings.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ rule_checks" > "$OUTPUT_DIR/schema_rule_checks.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ rule_metadata" > "$OUTPUT_DIR/schema_rule_metadata.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ rule_discoveries" > "$OUTPUT_DIR/schema_rule_discoveries.txt"

# Summary stats
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -o "$OUTPUT_DIR/summary_stats.txt" << 'EOF'
SELECT 'check_report' as table_name, COUNT(*) as count FROM check_report
UNION ALL SELECT 'check_findings', COUNT(*) FROM check_findings
UNION ALL SELECT 'rule_checks', COUNT(*) FROM rule_checks
UNION ALL SELECT 'rule_metadata', COUNT(*) FROM rule_metadata
UNION ALL SELECT 'rule_discoveries', COUNT(*) FROM rule_discoveries;
EOF

echo "  ✅ Check database exported to: $OUTPUT_DIR"
echo ""

# =============================================================================
# 2. PYTHON SDK DATABASE (threat_engine_pythonsdk)
# =============================================================================
echo "2. Exporting PYTHON SDK database (threat_engine_pythonsdk)..."
echo "--------------------------------------------------------------------------------"

DB_NAME="threat_engine_pythonsdk"
OUTPUT_DIR="$OUTPUT_BASE/pythonsdk"

# Export csp
echo "  - csp"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM csp ORDER BY csp_id) TO '$OUTPUT_DIR/csp.csv' CSV HEADER"

# Export services
echo "  - services"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM services ORDER BY csp_id, service_name) TO '$OUTPUT_DIR/services.csv' CSV HEADER"

# Export operations
echo "  - operations"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM operations ORDER BY service_id, operation_name) TO '$OUTPUT_DIR/operations.csv' CSV HEADER"

# Export fields
echo "  - fields"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM fields ORDER BY service_id, operation_name, field_name) TO '$OUTPUT_DIR/fields.csv' CSV HEADER"

# Export resource_inventory
echo "  - resource_inventory"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM resource_inventory ORDER BY service_id) TO '$OUTPUT_DIR/resource_inventory.csv' CSV HEADER"

# Export dependency_index
echo "  - dependency_index"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM dependency_index ORDER BY service_id) TO '$OUTPUT_DIR/dependency_index.csv' CSV HEADER"

# Export direct_vars
echo "  - direct_vars"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM direct_vars ORDER BY service_id) TO '$OUTPUT_DIR/direct_vars.csv' CSV HEADER"

# Export enhancement_indexes
echo "  - enhancement_indexes"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM enhancement_indexes ORDER BY csp_id, index_type) TO '$OUTPUT_DIR/enhancement_indexes.csv' CSV HEADER"

# Export relation_types
echo "  - relation_types"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM relation_types ORDER BY relation_id) TO '$OUTPUT_DIR/relation_types.csv' CSV HEADER"

# Export relationship_rules
echo "  - relationship_rules"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM relationship_rules ORDER BY csp_id, from_type, to_type) TO '$OUTPUT_DIR/relationship_rules.csv' CSV HEADER"

# Export schemas
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ csp" > "$OUTPUT_DIR/schema_csp.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ services" > "$OUTPUT_DIR/schema_services.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ operations" > "$OUTPUT_DIR/schema_operations.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ fields" > "$OUTPUT_DIR/schema_fields.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ resource_inventory" > "$OUTPUT_DIR/schema_resource_inventory.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ relationship_rules" > "$OUTPUT_DIR/schema_relationship_rules.txt"

# Summary stats
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -o "$OUTPUT_DIR/summary_stats.txt" << 'EOF'
SELECT 'csp' as table_name, COUNT(*) as count FROM csp
UNION ALL SELECT 'services', COUNT(*) FROM services
UNION ALL SELECT 'operations', COUNT(*) FROM operations
UNION ALL SELECT 'fields', COUNT(*) FROM fields
UNION ALL SELECT 'resource_inventory', COUNT(*) FROM resource_inventory
UNION ALL SELECT 'dependency_index', COUNT(*) FROM dependency_index
UNION ALL SELECT 'direct_vars', COUNT(*) FROM direct_vars
UNION ALL SELECT 'enhancement_indexes', COUNT(*) FROM enhancement_indexes
UNION ALL SELECT 'relation_types', COUNT(*) FROM relation_types
UNION ALL SELECT 'relationship_rules', COUNT(*) FROM relationship_rules;
EOF

echo "  ✅ Python SDK database exported to: $OUTPUT_DIR"
echo ""

# =============================================================================
# 3. DISCOVERIES DATABASE (threat_engine_discoveries)
# =============================================================================
echo "3. Exporting DISCOVERIES database (threat_engine_discoveries)..."
echo "--------------------------------------------------------------------------------"

DB_NAME="threat_engine_discoveries"
OUTPUT_DIR="$OUTPUT_BASE/discoveries"

# Export customers
echo "  - customers"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM customers ORDER BY customer_id) TO '$OUTPUT_DIR/customers.csv' CSV HEADER"

# Export tenants
echo "  - tenants"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM tenants ORDER BY tenant_id) TO '$OUTPUT_DIR/tenants.csv' CSV HEADER"

# Export discovery_report
echo "  - discovery_report"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM discovery_report ORDER BY scan_timestamp DESC) TO '$OUTPUT_DIR/discovery_report.csv' CSV HEADER"

# Export discovery_findings
echo "  - discovery_findings"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM discovery_findings ORDER BY scan_timestamp DESC) TO '$OUTPUT_DIR/discovery_findings.csv' CSV HEADER"

# Export discovery_history
echo "  - discovery_history"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM discovery_history ORDER BY scan_timestamp DESC) TO '$OUTPUT_DIR/discovery_history.csv' CSV HEADER"

# Check if rule_definitions table exists and export if it does
echo "  - rule_definitions (if exists)"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM rule_definitions ORDER BY id) TO '$OUTPUT_DIR/rule_definitions.csv' CSV HEADER" 2>/dev/null || echo "    (table does not exist, skipping)"

# Export schemas
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ customers" > "$OUTPUT_DIR/schema_customers.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ tenants" > "$OUTPUT_DIR/schema_tenants.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ discovery_report" > "$OUTPUT_DIR/schema_discovery_report.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ discovery_findings" > "$OUTPUT_DIR/schema_discovery_findings.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ discovery_history" > "$OUTPUT_DIR/schema_discovery_history.txt"

# Summary stats
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -o "$OUTPUT_DIR/summary_stats.txt" << 'EOF'
SELECT 'customers' as table_name, COUNT(*) as count FROM customers
UNION ALL SELECT 'tenants', COUNT(*) FROM tenants
UNION ALL SELECT 'discovery_report', COUNT(*) FROM discovery_report
UNION ALL SELECT 'discovery_findings', COUNT(*) FROM discovery_findings
UNION ALL SELECT 'discovery_history', COUNT(*) FROM discovery_history;
EOF

echo "  ✅ Discoveries database exported to: $OUTPUT_DIR"
echo ""

# =============================================================================
# SUMMARY
# =============================================================================
echo "================================================================================"
echo "EXPORT COMPLETE!"
echo "================================================================================"
echo ""
echo "All databases exported to: $OUTPUT_BASE"
echo ""
echo "Directory structure:"
du -sh "$OUTPUT_BASE"/* 2>/dev/null
echo ""
echo "Total size:"
du -sh "$OUTPUT_BASE"
echo ""
echo "Files created:"
echo "  Check DB:        $(ls -1 $OUTPUT_BASE/check/*.csv 2>/dev/null | wc -l) CSV files"
echo "  Python SDK DB:   $(ls -1 $OUTPUT_BASE/pythonsdk/*.csv 2>/dev/null | wc -l) CSV files"
echo "  Discoveries DB:  $(ls -1 $OUTPUT_BASE/discoveries/*.csv 2>/dev/null | wc -l) CSV files"
echo ""
echo "================================================================================"
