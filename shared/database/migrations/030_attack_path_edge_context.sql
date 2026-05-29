-- Migration 030: Add edge_context JSONB to attack_path_nodes
-- Stores per-edge posture signals explaining why each hop traversal is dangerous.
-- Populated by path_explainer._edge_context_signals() during attack-path scan.
-- NULL for hops where no edge-specific risk signals apply.

\connect threat_engine_attack_path;

ALTER TABLE attack_path_nodes
    ADD COLUMN IF NOT EXISTS edge_context JSONB DEFAULT NULL;

-- Index for filtering paths that have edge-level risk signals
CREATE INDEX IF NOT EXISTS idx_attack_path_nodes_edge_ctx
    ON attack_path_nodes ((edge_context IS NOT NULL))
    WHERE edge_context IS NOT NULL;

DO $$ BEGIN
    RAISE NOTICE 'MIGRATION 030 COMPLETE: edge_context column added to attack_path_nodes';
END $$;
