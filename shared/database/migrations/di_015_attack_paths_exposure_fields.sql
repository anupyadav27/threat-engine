-- di_015_attack_paths_exposure_fields.sql
-- Adds exposure-key fields to attack_paths table for AP-DEDUP-01.
-- effective_access_principal: last privilege node before the crown jewel (node_uids[-2])
-- access_capability: final edge type reaching the target (can_read, can_decrypt, etc.)
-- These two fields + crown_jewel_uid form the Exposure Key used by the deduplicator.

BEGIN;

ALTER TABLE attack_paths
    ADD COLUMN IF NOT EXISTS effective_access_principal VARCHAR(512),
    ADD COLUMN IF NOT EXISTS access_capability          VARCHAR(64);

-- Index for BFF queries: "show me all paths where AppRole can reach any crown jewel"
CREATE INDEX IF NOT EXISTS idx_ap_effective_principal
    ON attack_paths (tenant_id, effective_access_principal)
    WHERE effective_access_principal IS NOT NULL;

-- Index for BFF queries: "show me all CAN_READ exposures"
CREATE INDEX IF NOT EXISTS idx_ap_access_capability
    ON attack_paths (tenant_id, access_capability)
    WHERE access_capability IS NOT NULL;

COMMIT;

-- Verify
SELECT
    column_name, data_type
FROM information_schema.columns
WHERE table_name = 'attack_paths'
  AND column_name IN ('effective_access_principal', 'access_capability')
ORDER BY column_name;
