-- =============================================================================
-- Migration 013: Add parent relationship columns to resource_inventory_identifier
-- =============================================================================
-- Database:  threat_engine_inventory
-- Purpose:   Add parent_service / parent_resource_type columns so the inventory
--            engine knows which parent resource to use when fetching sub-resources.
--
--            The enrich_ops JSONB entries now include a "param_sources" field that
--            tells the engine HOW to resolve each required_param from the parent
--            asset's discovery fields at scan time.
--
-- Background:
--   Sub-resources (e.g. bucket_versioning, security_group, role_policy) cannot
--   be listed independently — they require the parent resource's identifier.
--   By storing parent_resource_type the inventory engine can:
--     1. Find the parent asset in the assets index (Pass 1)
--     2. Extract the required_param value from the parent's emitted_fields
--     3. Match the enrichment record to the parent asset (Pass 2)
--
-- Apply with:
--   psql -h <RDS_HOST> -U postgres -d threat_engine_inventory \
--     -f 013_add_rii_parent_columns.sql
--
-- Safe to re-run: all DDL uses ADD COLUMN IF NOT EXISTS.
-- =============================================================================

-- ── 1. Add parent relationship columns ────────────────────────────────────────
--
-- parent_service:       service name of the parent resource (NULL for root resources)
--                       e.g. "s3" for bucket_versioning, "ec2" for security_group
--
-- parent_resource_type: resource_type of the parent within that service (NULL for roots)
--                       e.g. "bucket" for bucket_versioning, "vpc" for security_group

ALTER TABLE resource_inventory_identifier
    ADD COLUMN IF NOT EXISTS parent_service       VARCHAR(100),
    ADD COLUMN IF NOT EXISTS parent_resource_type VARCHAR(255);

-- ── 2. Parent relationship index ──────────────────────────────────────────────
-- Used by the inventory engine to look up all sub-resources owned by a given
-- parent resource type. The partial WHERE clause keeps the index small.

CREATE INDEX IF NOT EXISTS idx_rii_parent
    ON resource_inventory_identifier(csp, parent_service, parent_resource_type)
    WHERE parent_resource_type IS NOT NULL;

-- ── 3. Update column comments ─────────────────────────────────────────────────
-- Document the full enrich_ops entry shape including param_sources.

COMMENT ON COLUMN resource_inventory_identifier.parent_service IS
    'Service name of the parent resource (NULL for root resources). '
    'e.g. "s3" for bucket_versioning, "ec2" for security_group. '
    'Populated by load_resource_inventory_identifier.py from step5 catalog.';

COMMENT ON COLUMN resource_inventory_identifier.parent_resource_type IS
    'resource_type of the parent within parent_service (NULL for root resources). '
    'e.g. "bucket" for bucket_versioning, "vpc" for security_group, "role" for role_policy. '
    'The inventory engine uses this to locate the parent Asset in Pass 2 enrichment.';

COMMENT ON COLUMN resource_inventory_identifier.enrich_ops IS
    'Dependent operations that enrich assets (require params from root resource). '
    'Each record shape: { '
    '  "operation":       "get_bucket_versioning",     '
    '  "independent":     false,                        '
    '  "required_params": ["Bucket"],                   '
    '  "python_method":   "get_bucket_versioning",      '
    '  "param_sources": {                               '
    '    "Bucket": {                                    '
    '      "from_field":         "resource_id",         '
    '      "from_asset_field":   "name",                '
    '      "parent_resource_type": "bucket"             '
    '    }                                              '
    '  }                                                '
    '}. '
    'param_sources tells the engine HOW to resolve each required_param from the '
    'parent asset''s discovery fields at scan time (Pass 2 Strategy 2).';

-- ── Verify ────────────────────────────────────────────────────────────────────
-- Check that columns were added successfully (informational only, not enforced):
DO $$
DECLARE
    col_count INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO   col_count
    FROM   information_schema.columns
    WHERE  table_name = 'resource_inventory_identifier'
      AND  column_name IN ('parent_service', 'parent_resource_type');

    IF col_count = 2 THEN
        RAISE NOTICE 'Migration 013: parent_service and parent_resource_type columns confirmed on resource_inventory_identifier.';
    ELSE
        RAISE WARNING 'Migration 013: Expected 2 new columns but found %. Check DDL output above.', col_count;
    END IF;
END;
$$;
