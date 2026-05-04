-- DI-14: inventory — drift detection indexes
-- NOTE: inventory_drift is a dedicated table (drift_id, change_type, previous_state, current_state, etc.)
-- inventory_findings is the main asset table; add drift summary columns for BFF queries
-- Apply via:
--   kubectl cp DI-14-inventory-drift.sql threat-engine-engines/<inventory-pod>:/tmp/
--   kubectl exec -n threat-engine-engines deployment/engine-inventory -- \
--       psql -h $INVENTORY_DB_HOST -U $INVENTORY_DB_USER -d $INVENTORY_DB_NAME \
--       -f /tmp/DI-14-inventory-drift.sql

BEGIN;

-- Index for drift queries on dedicated inventory_drift table
CREATE INDEX IF NOT EXISTS idx_inventory_drift_tenant_asset
    ON inventory_drift(tenant_id, asset_id);

CREATE INDEX IF NOT EXISTS idx_inventory_drift_severity
    ON inventory_drift(tenant_id, severity, detected_at DESC);

-- Index for main inventory_findings table (BFF asset list queries)
CREATE INDEX IF NOT EXISTS idx_inventory_findings_tenant_scan
    ON inventory_findings(tenant_id, scan_run_id);

CREATE INDEX IF NOT EXISTS idx_inventory_findings_resource_type
    ON inventory_findings(tenant_id, resource_type, provider);

COMMIT;
