#!/bin/bash
# Complete export of Discoveries database

DB_HOST="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
DB_NAME="threat_engine_discoveries"
DB_USER="postgres"
DB_PASSWORD="jtv2BkJF8qoFtAKP"  # Same password
OUTPUT_DIR="/Users/apple/Desktop/threat-engine/database_exports/discoveries"

mkdir -p "$OUTPUT_DIR"

echo "Exporting Discoveries database (complete)..."

# Export discovery_report table (scan metadata)
echo "Exporting discovery_report table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM discovery_report ORDER BY scan_timestamp DESC LIMIT 500) TO '$OUTPUT_DIR/discovery_report.csv' CSV HEADER"

# Export discovery_findings table (resource findings)
echo "Exporting discovery_findings table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM discovery_findings ORDER BY scan_timestamp DESC LIMIT 5000) TO '$OUTPUT_DIR/discovery_findings.csv' CSV HEADER"

# Export discovery_history table (drift detection)
echo "Exporting discovery_history table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM discovery_history ORDER BY scan_timestamp DESC LIMIT 2000) TO '$OUTPUT_DIR/discovery_history.csv' CSV HEADER"

# Export customers table
echo "Exporting customers table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM customers ORDER BY customer_id) TO '$OUTPUT_DIR/customers.csv' CSV HEADER"

# Export tenants table
echo "Exporting tenants table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM tenants ORDER BY tenant_id) TO '$OUTPUT_DIR/tenants.csv' CSV HEADER"

echo ""
echo "Exporting database schemas..."

# Export database schema
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ discovery_report" > "$OUTPUT_DIR/schema_discovery_report.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ discovery_findings" > "$OUTPUT_DIR/schema_discovery_findings.txt"
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\d+ discovery_history" > "$OUTPUT_DIR/schema_discovery_history.txt"

echo ""
echo "Generating summary statistics..."

# Generate summary statistics
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -o "$OUTPUT_DIR/summary_stats.txt" << 'EOF'
-- Table counts
SELECT 'discovery_report' as table_name, COUNT(*) as count FROM discovery_report
UNION ALL
SELECT 'discovery_findings', COUNT(*) FROM discovery_findings
UNION ALL
SELECT 'discovery_history', COUNT(*) FROM discovery_history
UNION ALL
SELECT 'customers', COUNT(*) FROM customers
UNION ALL
SELECT 'tenants', COUNT(*) FROM tenants;

-- Recent scans
SELECT discovery_scan_id, provider, service, region, status, scan_timestamp
FROM discovery_report
ORDER BY scan_timestamp DESC
LIMIT 20;

-- Services scanned
SELECT service, COUNT(*) as finding_count
FROM discovery_findings
GROUP BY service
ORDER BY finding_count DESC
LIMIT 30;

-- Discovery IDs used
SELECT discovery_id, COUNT(*) as usage_count
FROM discovery_findings
GROUP BY discovery_id
ORDER BY usage_count DESC
LIMIT 30;
EOF

echo ""
echo "✅ Discoveries database export complete"
echo "Output directory: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"
