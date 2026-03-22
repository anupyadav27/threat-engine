#!/bin/bash
# Complete export of Python SDK database

DB_HOST="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
DB_NAME="threat_engine_pythonsdk"
DB_USER="postgres"
DB_PASSWORD="jtv2BkJF8qoFtAKP"  # From service_metadata_loader.py
OUTPUT_DIR="/Users/apple/Desktop/threat-engine/database_exports/pythonsdk"

mkdir -p "$OUTPUT_DIR"

echo "Exporting Python SDK database (complete)..."

# Export all services (all CSPs)
echo "Exporting services table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM services ORDER BY csp_id, service_name) TO '$OUTPUT_DIR/services_all.csv' CSV HEADER"

# Export all operations
echo "Exporting operations table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM operations ORDER BY service_id, operation_name) TO '$OUTPUT_DIR/operations_all.csv' CSV HEADER"

# Export all fields
echo "Exporting fields table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM fields ORDER BY service_id, operation_name, field_name) TO '$OUTPUT_DIR/fields_all.csv' CSV HEADER"

# Export resource inventory
echo "Exporting resource_inventory table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM resource_inventory ORDER BY service_id) TO '$OUTPUT_DIR/resource_inventory_all.csv' CSV HEADER"

# Export relationship rules
echo "Exporting relationship_rules table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM relationship_rules ORDER BY csp_id, from_type, to_type) TO '$OUTPUT_DIR/relationship_rules_all.csv' CSV HEADER"

# Export CSP metadata
echo "Exporting csp table..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
  -c "\COPY (SELECT * FROM csp ORDER BY csp_id) TO '$OUTPUT_DIR/csp.csv' CSV HEADER"

echo ""
echo "✅ Python SDK database export complete"
echo "Output directory: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"
