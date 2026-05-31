-- di_019_attack_paths_objective_type.sql
-- Adds objective_type column to attack_paths table and
-- objective_satisfied boolean for BFS capability validation result.
--
-- objective_type: formal attack objective (DATA_THEFT, DECRYPTION, etc.)
-- objective_satisfied: TRUE when final edge capability matches required_capability
--   from attack_objective_catalog. FALSE = topology-only path (network reach
--   without confirmed credential access). NULL = not yet evaluated.

ALTER TABLE attack_paths
    ADD COLUMN IF NOT EXISTS objective_type      VARCHAR(50),
    ADD COLUMN IF NOT EXISTS objective_satisfied BOOLEAN;

CREATE INDEX IF NOT EXISTS idx_ap_objective_type
    ON attack_paths (tenant_id, objective_type)
    WHERE status = 'active';

DO $$ BEGIN RAISE NOTICE 'di_019: attack_paths.objective_type + objective_satisfied added'; END $$;
