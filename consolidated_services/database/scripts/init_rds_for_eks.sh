#!/usr/bin/env sh
# Init RDS for EKS: create threat-engine DBs, apply base schemas, run migrations.
# Uses PGHOST/PGPORT/PGUSER/PGPASSWORD, or RDS_HOST/RDS_PORT/RDS_SUPERUSER/RDS_SUPERUSER_PASSWORD.
# Set TE_DB_ROOT to consolidated_services/database (default: parent of scripts/).

set -e

# Path to schemas and migrations (repo root relative or absolute)
if [ -n "$TE_DB_ROOT" ]; then
  ROOT="$TE_DB_ROOT"
else
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi
SCHEMAS_DIR="${ROOT}/schemas"
MIGRATIONS_DIR="${ROOT}/migrations"

if [ ! -d "$SCHEMAS_DIR" ] || [ ! -d "$MIGRATIONS_DIR" ]; then
  echo "ERROR: schemas or migrations dir missing (TE_DB_ROOT=$ROOT)"
  exit 1
fi

# Connection: prefer RDS_* for K8s secret, else PG*
export PGHOST="${RDS_HOST:-$PGHOST}"
export PGPORT="${RDS_PORT:-${PGPORT:-5432}}"
export PGUSER="${RDS_SUPERUSER:-$PGUSER}"
export PGPASSWORD="${RDS_SUPERUSER_PASSWORD:-$PGPASSWORD}"
export PGSSLMODE="${PGSSLMODE:-require}"

if [ -z "$PGHOST" ] || [ -z "$PGUSER" ]; then
  echo "ERROR: set RDS_HOST/RDS_SUPERUSER (or PGHOST/PGUSER) and password"
  exit 1
fi

psql_() { psql -v ON_ERROR_STOP=1 "$@"; }

echo "Creating databases on $PGHOST..."
for db in threat_engine_shared threat_engine_configscan threat_engine_compliance threat_engine_inventory threat_engine_threat; do
  psql_ -d postgres -c "SELECT 1 FROM pg_database WHERE datname = '$db'" | grep -q 1 || psql_ -d postgres -c "CREATE DATABASE $db;"
done

echo "Applying base schemas..."
psql_ -d threat_engine_shared    -f "$SCHEMAS_DIR/shared_schema.sql"
psql_ -d threat_engine_configscan -f "$SCHEMAS_DIR/configscan_schema.sql"
# Compliance, inventory, threat reference tenants; create minimal tenants in each (split-DB)
psql_ -d threat_engine_compliance -c "CREATE TABLE IF NOT EXISTS tenants (tenant_id VARCHAR(255) PRIMARY KEY, tenant_name VARCHAR(255), created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());"
psql_ -d threat_engine_compliance -f "$SCHEMAS_DIR/compliance_schema.sql"
psql_ -d threat_engine_inventory -c "CREATE TABLE IF NOT EXISTS tenants (tenant_id VARCHAR(255) PRIMARY KEY, tenant_name VARCHAR(255), created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());"
psql_ -d threat_engine_inventory -f "$SCHEMAS_DIR/inventory_schema.sql"
psql_ -d threat_engine_threat   -c "CREATE TABLE IF NOT EXISTS tenants (tenant_id VARCHAR(255) PRIMARY KEY, tenant_name VARCHAR(255), created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());"
psql_ -d threat_engine_threat   -f "$SCHEMAS_DIR/threat_schema.sql"

echo "Running migrations..."
# configscan
psql_ -d threat_engine_configscan -f "$MIGRATIONS_DIR/002_add_rule_metadata.sql"
psql_ -d threat_engine_configscan -f "$MIGRATIONS_DIR/004_add_threat_metadata.sql"
psql_ -d threat_engine_configscan -f "$MIGRATIONS_DIR/008_iam_datasec_views.sql"
# threat (003 expects threat_reports; ensure it exists so backup/drop succeed)
psql_ -d threat_engine_threat -c "CREATE TABLE IF NOT EXISTS threat_reports (id SERIAL PRIMARY KEY, tenant_id VARCHAR(255), data JSONB);" 2>/dev/null || true
psql_ -d threat_engine_threat    -f "$MIGRATIONS_DIR/003_normalize_threat_schema.sql"
# compliance
psql_ -d threat_engine_compliance -f "$MIGRATIONS_DIR/005_compliance_output_tables.sql"
psql_ -d threat_engine_compliance -f "$MIGRATIONS_DIR/006_compliance_control_mappings.sql"
psql_ -d threat_engine_compliance -f "$MIGRATIONS_DIR/007_compliance_analysis_views.sql"

echo "Done. DBs: threat_engine_shared, threat_engine_configscan, threat_engine_compliance, threat_engine_inventory, threat_engine_threat"
