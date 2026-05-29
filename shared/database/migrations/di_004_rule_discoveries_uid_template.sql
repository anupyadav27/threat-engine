-- =============================================================================
-- DI-004: Add uid_template to rule_discoveries
-- =============================================================================
-- Database: threat_engine_check
--
-- Adds uid_template to rule_discoveries so the DI engine can build canonical
-- UIDs directly from rule_discoveries without a separate identifier table.
--
-- uid_template syntax (same as resource_inventory_identifier):
--   {item.FieldName}      — field from emitted item
--   {context.region}      — scan context value
--   {context.account_id}  — cloud account ID
--   {context.partition}   — aws | aws-cn | azure | gcp | etc.
--   {parent.FieldName}    — field from parent resource (chained ops)
--
-- uid_source values:
--   'template'  — use uid_template string (set when uid_template is not null)
--   'heuristic' — scan well-known CSP identifier fields (ARN, OCID, ARM, etc.)
--
-- Populated by:
--   catalog/discovery_generator_data/{csp}/{service}/*.yaml
--   via the YAML upload / re-seed script.
--
-- Safe to re-run: uses IF NOT EXISTS / IF EXISTS guards.
-- =============================================================================

BEGIN;

ALTER TABLE rule_discoveries
    ADD COLUMN IF NOT EXISTS uid_template  VARCHAR(1024),
    ADD COLUMN IF NOT EXISTS uid_source    VARCHAR(50) DEFAULT 'heuristic';

-- Index: DI engine filters rule_discoveries by (provider, is_active, service)
-- This index already exists for is_active; add a compound one for DI queries.
CREATE INDEX IF NOT EXISTS idx_rd_provider_active_service
    ON rule_discoveries (provider, is_active, service)
    WHERE is_active = TRUE;

DO $$
BEGIN
    RAISE NOTICE 'DI-004 applied: uid_template + uid_source added to rule_discoveries.';
END $$;

COMMIT;
