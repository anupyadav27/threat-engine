-- Migration: ciem_ui_gaps_002
-- Target DB: threat_engine_check
-- Purpose: Add remediation_effort to rule_metadata for Stage 5 Kanban bucketing

BEGIN;

ALTER TABLE rule_metadata
    ADD COLUMN IF NOT EXISTS remediation_effort VARCHAR(20) DEFAULT 'medium'
    CONSTRAINT rule_metadata_effort_check
        CHECK (remediation_effort IN ('low', 'medium', 'high'));

COMMENT ON COLUMN rule_metadata.remediation_effort
    IS 'Analyst effort estimate for remediation. Used to bucket findings in the investigation journey Stage 5 Kanban. Default: medium.';

COMMIT;
