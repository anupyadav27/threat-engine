-- SECOPS-01A: Add repo_url to cloud_accounts + partial unique index for code_security deduplication
-- Target DB: onboarding DB (cloud_accounts table)
-- Story: SECOPS-01 — prevents duplicate repo accounts under the same tenant (blocker B-6)
-- Idempotent: ADD COLUMN IF NOT EXISTS, CREATE UNIQUE INDEX IF NOT EXISTS

BEGIN;

-- Add repo_url column if it doesn't already exist (required for the unique index)
ALTER TABLE cloud_accounts
    ADD COLUMN IF NOT EXISTS repo_url VARCHAR(1024);

-- Partial unique index: only applies to code_security account_type rows
-- Does not affect existing cloud_csp accounts (which have no repo_url)
CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_accounts_tenant_repo_code_security
    ON cloud_accounts (tenant_id, repo_url)
    WHERE account_type = 'code_security';

RAISE NOTICE 'MIGRATION COMPLETE';

COMMIT;

-- MIGRATION COMPLETE
