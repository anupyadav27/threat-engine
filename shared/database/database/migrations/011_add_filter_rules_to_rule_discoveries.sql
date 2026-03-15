-- Migration: Add filter_rules column to rule_discoveries table
-- Date: 2026-02-20
-- Purpose: Enable database-driven filtering to replace hardcoded filter logic

-- Add filter_rules JSONB column
ALTER TABLE rule_discoveries
ADD COLUMN IF NOT EXISTS filter_rules JSONB DEFAULT '{}'::jsonb;

-- Add index for efficient filter rule queries
CREATE INDEX IF NOT EXISTS idx_rule_discoveries_filter_rules
ON rule_discoveries USING gin(filter_rules);

-- Add comment for documentation
COMMENT ON COLUMN rule_discoveries.filter_rules IS 'Database-driven filter rules for AWS-managed resource filtering. Contains api_filters (pre-call) and response_filters (post-call) arrays.';

-- Verify column was added
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'rule_discoveries'
        AND column_name = 'filter_rules'
    ) THEN
        RAISE NOTICE 'Successfully added filter_rules column to rule_discoveries table';
    ELSE
        RAISE EXCEPTION 'Failed to add filter_rules column';
    END IF;
END $$;
