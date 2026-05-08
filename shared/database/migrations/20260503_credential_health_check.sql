-- Migration: add last_credential_check_at to cloud_accounts
-- Stamped by the weekly Celery credential health-check task.

BEGIN;

ALTER TABLE cloud_accounts
    ADD COLUMN IF NOT EXISTS last_credential_check_at TIMESTAMPTZ DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_cred_check
    ON cloud_accounts(last_credential_check_at)
    WHERE last_credential_check_at IS NOT NULL;

COMMIT;
