#!/bin/bash
# Complete export of Check database

DB_HOST="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
DB_NAME="threat_engine_check"
DB_USER="postgres"
DB_PASSWORD="jtv2BkJF8qoFtAKP"
OUTPUT_DIR="/Users/apple/Desktop/threat-engine/database_exports/check"

mkdir -p "$OUTPUT_DIR"

echo "Exporting Check database (complete)..."

# Export check_report table
echo "Exporting check_report table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM check_report ORDER BY scan_timestamp DESC LIMIT 500) TO '$OUTPUT_DIR/check_report.csv' CSV HEADER"

# Export check_findings table
echo "Exporting check_findings table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM check_findings ORDER BY scan_timestamp DESC LIMIT 5000) TO '$OUTPUT_DIR/check_findings.csv' CSV HEADER"

# Export rule_checks table
echo "Exporting rule_checks table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM rule_checks ORDER BY service, rule_id) TO '$OUTPUT_DIR/rule_checks.csv' CSV HEADER"

# Export rule_metadata table
echo "Exporting rule_metadata table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM rule_metadata ORDER BY service, rule_id) TO '$OUTPUT_DIR/rule_metadata.csv' CSV HEADER"

# Export rule_discoveries table (KEY TABLE)
echo "Exporting rule_discoveries table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM rule_discoveries ORDER BY service, provider) TO '$OUTPUT_DIR/rule_discoveries.csv' CSV HEADER"

echo ""
echo "Exporting database schemas..."

# Export database schemas
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

echo ""
echo "Generating summary statistics..."

# Generate summary statistics
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -o "$OUTPUT_DIR/summary_stats.txt" << 'EOF'
-- Table counts
SELECT 'check_report' as table_name, COUNT(*) as count FROM check_report
UNION ALL
SELECT 'check_findings', COUNT(*) FROM check_findings
UNION ALL
SELECT 'rule_checks', COUNT(*) FROM rule_checks
UNION ALL
SELECT 'rule_metadata', COUNT(*) FROM rule_metadata
UNION ALL
SELECT 'rule_discoveries', COUNT(*) FROM rule_discoveries;

-- Services in rule_discoveries
SELECT service, provider, COUNT(*) as discovery_count
FROM rule_discoveries
GROUP BY service, provider
ORDER BY provider, service;

-- Sample discovery IDs from rule_discoveries
SELECT service,
       jsonb_array_length(discoveries_data->'discovery') as discovery_count,
       jsonb_path_query_array(discoveries_data, '$.discovery[*].discovery_id') as discovery_ids
FROM rule_discoveries
ORDER BY service
LIMIT 20;

-- Recent check scans
SELECT check_scan_id, provider, service, region, discovery_scan_id, scan_timestamp
FROM check_report
ORDER BY scan_timestamp DESC
LIMIT 20;
EOF

echo ""
echo "✅ Check database export complete"
echo "Output directory: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"
