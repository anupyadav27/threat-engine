-- =============================================================================
-- DI-003: Rebuild asset_inventory unique key + extend resource_inventory_identifier
-- =============================================================================
-- Database: threat_engine_di (asset_inventory)
--           threat_engine_inventory (resource_inventory_identifier)
--
-- Changes:
--   asset_inventory:
--     - DROP old UNIQUE(resource_uid, scan_run_id, tenant_id, provider)
--     - ADD  UNIQUE(resource_uid, discovery_id, scan_run_id, tenant_id, provider)
--       One resource now produces N rows — one per discovery op that emits it.
--       Enrichment rows (e.g. get_bucket_acl) get their own row alongside the
--       root enumeration row (list_buckets).
--
--   resource_inventory_identifier:
--     - ADD uid_template       VARCHAR  — template string for canonical UID
--         Syntax: {item.Field}, {context.region}, {context.account_id},
--                 {context.partition}, {parent.Field}
--         Example: "arn:aws:s3:::{item.Name}"
--         Example: "arn:aws:ec2:{context.region}:{context.account_id}:instance/{item.InstanceId}"
--     - ADD uid_source         VARCHAR  — 'template' | 'field' | 'heuristic'
--     - ADD discovery_id       VARCHAR  — root op discovery_id stored explicitly
--         (matches what check rules put in for_each for the root op rows)
--
-- Safe to re-run: uses IF NOT EXISTS / IF EXISTS guards.
-- =============================================================================

BEGIN;

-- ── 1. asset_inventory: replace UNIQUE constraint ─────────────────────────────
-- Drop old constraint (name from di_001 schema)
ALTER TABLE asset_inventory
    DROP CONSTRAINT IF EXISTS ak_asset_uid_scan_tenant;

-- Add new constraint: one row per (resource_uid, discovery_id, scan+tenant+provider)
ALTER TABLE asset_inventory
    ADD CONSTRAINT ak_asset_uid_did_scan_tenant
    UNIQUE (resource_uid, discovery_id, scan_run_id, tenant_id, provider);

-- ── 2. resource_inventory_identifier: add new columns ────────────────────────
ALTER TABLE resource_inventory_identifier
    ADD COLUMN IF NOT EXISTS uid_template   VARCHAR(1024),
    ADD COLUMN IF NOT EXISTS uid_source     VARCHAR(50)   DEFAULT 'heuristic',
    ADD COLUMN IF NOT EXISTS discovery_id   VARCHAR(255);

-- Index for fast lookup by discovery_id (DIReader uses this for for_each resolution)
CREATE INDEX IF NOT EXISTS idx_rii_discovery_id
    ON resource_inventory_identifier (discovery_id)
    WHERE discovery_id IS NOT NULL;

-- ── 3. Clear stale auto-generated AWS identifier data ────────────────────────
-- The old rows were generated from full boto3 registry without check-rule
-- alignment. Seeder script (di_seed_aws_identifiers.py) will repopulate.
DELETE FROM resource_inventory_identifier WHERE csp = 'aws';

-- ── 4. Add discovery_id index on asset_inventory for DIReader queries ─────────
-- DIReader queries: WHERE discovery_id = $1 AND tenant_id = $2 AND scan_run_id = $3
CREATE INDEX IF NOT EXISTS idx_ai_discovery_tenant_scan
    ON asset_inventory (discovery_id, tenant_id, scan_run_id)
    WHERE discovery_id IS NOT NULL;

DO $$
BEGIN
    RAISE NOTICE 'DI-003 applied: asset_inventory unique key updated, resource_inventory_identifier extended, AWS identifier data cleared.';
END $$;

COMMIT;
