-- Migration 029: Add resource_uid and not_action_mode to iam_policy_statements
-- DB: threat_engine_iam
-- Purpose:
--   resource_uid   = the attached entity ARN (role/user/group) — enables posture aggregation
--   not_action_mode = true when statement uses NotAction (excluded from attack-path edge building
--                     because NotAction semantics are inverse and unsafe to use for graph traversal)

BEGIN;

ALTER TABLE iam_policy_statements
    ADD COLUMN IF NOT EXISTS resource_uid TEXT,
    ADD COLUMN IF NOT EXISTS not_action_mode BOOLEAN DEFAULT FALSE;

-- Backfill resource_uid from attached_to_arn (same value, different name for posture join)
UPDATE iam_policy_statements
SET resource_uid = attached_to_arn
WHERE resource_uid IS NULL AND attached_to_arn IS NOT NULL;

-- Index for attack-path query: filter by scan + entity + effect
CREATE INDEX IF NOT EXISTS idx_iam_stmt_scan_attached_eff
    ON iam_policy_statements (scan_run_id, attached_to_arn, effect)
    WHERE attached_to_arn IS NOT NULL AND effect = 'Allow';

-- Index for posture_signals.py: aggregate by resource_uid per scan
CREATE INDEX IF NOT EXISTS idx_iam_stmt_scan_resource
    ON iam_policy_statements (scan_run_id, resource_uid)
    WHERE resource_uid IS NOT NULL;

COMMIT;

DO $$ BEGIN RAISE NOTICE 'Migration 029 complete: resource_uid + not_action_mode added to iam_policy_statements'; END $$;
