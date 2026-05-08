-- Migration: add account_category to cloud_accounts
-- Supports self-hosted database providers (postgres, mysql, mssql, mongodb, oracle)
-- alongside existing cloud providers (aws, azure, gcp, oci, alicloud, ibm, k8s)

ALTER TABLE cloud_accounts
ADD COLUMN IF NOT EXISTS account_category VARCHAR(50) NOT NULL DEFAULT 'cloud';

ALTER TABLE cloud_accounts
ADD CONSTRAINT chk_account_category
  CHECK (account_category IN ('cloud', 'database'));

-- Backfill: all existing rows are cloud accounts
UPDATE cloud_accounts SET account_category = 'cloud' WHERE account_category = 'cloud';

-- Index for filtering by category
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_category
  ON cloud_accounts (account_category);
