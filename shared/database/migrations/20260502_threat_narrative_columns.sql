-- Migration: 20260502_threat_narrative_columns
-- Purpose: Add LLM-generated narrative fields to threat_detections table.
-- Safe to run multiple times (all operations use IF NOT EXISTS / column existence checks).
--
-- Apply via:
--   kubectl cp /tmp/20260502_threat_narrative_columns.sql \
--     threat-engine-engines/<threat-pod>:/tmp/migration.sql
--   kubectl exec -n threat-engine-engines <threat-pod> -- \
--     psql -h $THREAT_DB_HOST -U $THREAT_DB_USER -d $THREAT_DB_NAME -f /tmp/migration.sql
--
-- Verify after apply:
--   \d threat_detections
--   (Look for: chain_of_consequence, stakes_narrative, narrative_generated_at, narrative_model)

ALTER TABLE threat_detections
    ADD COLUMN IF NOT EXISTS chain_of_consequence  VARCHAR(500),
    ADD COLUMN IF NOT EXISTS stakes_narrative       TEXT,
    ADD COLUMN IF NOT EXISTS narrative_generated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS narrative_model        VARCHAR(100);

COMMENT ON COLUMN threat_detections.chain_of_consequence  IS 'LLM-generated one-sentence consequence summary (max 60 words). NULL = not yet generated or LLM unavailable.';
COMMENT ON COLUMN threat_detections.stakes_narrative       IS 'LLM-generated 3-4 sentence paragraph for Chapter 3 of the Scenario Detail Panel.';
COMMENT ON COLUMN threat_detections.narrative_generated_at IS 'Timestamp of last successful LLM generation for this detection.';
COMMENT ON COLUMN threat_detections.narrative_model        IS 'LLM model identifier used for last generation (e.g. claude-sonnet-4-6, mistral-large).';
