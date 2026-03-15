-- Add account_id column to discovery_findings table
-- This migration adds explicit account_id tracking for multi-account discovery analysis

-- Add account_id column
ALTER TABLE discovery_findings
ADD COLUMN IF NOT EXISTS account_id VARCHAR(255);

-- Backfill existing data (copy hierarchy_id to account_id)
UPDATE discovery_findings
SET account_id = hierarchy_id
WHERE account_id IS NULL;

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_df_account_id ON discovery_findings(account_id);
CREATE INDEX IF NOT EXISTS idx_df_account_region ON discovery_findings(account_id, region);

-- Add column comment
COMMENT ON COLUMN discovery_findings.account_id IS
'Cloud account identifier (AWS account ID, Azure subscription ID, GCP project ID, etc.)';

-- Verify migration
SELECT
    COUNT(*) as total_records,
    COUNT(account_id) as with_account_id,
    COUNT(DISTINCT account_id) as unique_accounts,
    ROUND(COUNT(account_id)::numeric / NULLIF(COUNT(*), 0)::numeric * 100, 2) as coverage_pct
FROM discovery_findings;
