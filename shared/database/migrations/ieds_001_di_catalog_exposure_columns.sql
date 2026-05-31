-- =============================================================================
-- IEDS-M01: Internet & External Exposure Detection System
-- Database: threat_engine_di
-- Table:    di_resource_catalog
-- =============================================================================
-- Adds two columns to di_resource_catalog to support the three-tier exposure
-- detection model:
--   network_exposure_tier: 1=always-public (catalog flag), 2=field-check,
--                           3=graph-traversal. NULL = not an exposure origin.
--   origin_types: JSONB array of possible attack origin types for this resource
--                 class: [internet, vpn, connected_network, direct_connect,
--                         external_iam, supply_chain]
-- Populated by: scripts/load_exposure_rules.py (Tier 1) and YAML rules (Tier 2/3)
-- Read by:      network engine IEDS evaluator + attack-path engine BFS
-- =============================================================================

BEGIN;

ALTER TABLE di_resource_catalog
    ADD COLUMN IF NOT EXISTS network_exposure_tier SMALLINT     DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS origin_types           JSONB        DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_di_catalog_exposure_tier
    ON di_resource_catalog(network_exposure_tier)
    WHERE network_exposure_tier IS NOT NULL;

COMMENT ON COLUMN di_resource_catalog.network_exposure_tier IS
    '1=always-public (catalog flag only), 2=field-check (YAML condition), 3=graph-traversal (multi-hop chain). NULL=not an exposure origin.';

COMMENT ON COLUMN di_resource_catalog.origin_types IS
    'JSONB array: possible origin types for this resource type. e.g. ["internet","external_iam"]';

COMMIT;
