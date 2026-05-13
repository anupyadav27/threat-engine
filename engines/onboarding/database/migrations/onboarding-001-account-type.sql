-- Migration: onboarding-001-account-type
-- Adds account_type, credential lifecycle columns, and agent_registrations table
-- Idempotent: all DDL guarded by IF NOT EXISTS

-- Step 1: Add new columns to cloud_accounts (additive, safe to re-run)
ALTER TABLE cloud_accounts
  ADD COLUMN IF NOT EXISTS account_type        VARCHAR(50)  NOT NULL DEFAULT 'cloud_csp',
  ADD COLUMN IF NOT EXISTS expires_at          TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_rotated_at     TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS validation_status   VARCHAR(20)  NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS validated_at        TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS rotation_enabled    BOOLEAN      NOT NULL DEFAULT FALSE;

-- Step 2: Backfill expires_at for existing accounts (90-day window from created_at)
UPDATE cloud_accounts
  SET expires_at = created_at + INTERVAL '90 days'
  WHERE expires_at IS NULL AND created_at IS NOT NULL;

-- Step 3: Add region/service scope columns to schedules (if schedules table exists)
ALTER TABLE schedules
  ADD COLUMN IF NOT EXISTS include_regions  TEXT[],
  ADD COLUMN IF NOT EXISTS exclude_regions  TEXT[],
  ADD COLUMN IF NOT EXISTS include_services TEXT[],
  ADD COLUMN IF NOT EXISTS exclude_services TEXT[];

-- Step 4: Create agent_registrations table
-- agent_token_hash stores SHA-256 of raw token — raw token NEVER stored in DB
CREATE TABLE IF NOT EXISTS agent_registrations (
  id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id       UUID         NOT NULL REFERENCES cloud_accounts(account_id) ON DELETE CASCADE,
  tenant_id        VARCHAR(255) NOT NULL,
  agent_token_hash VARCHAR(64)  NOT NULL UNIQUE,
  status           VARCHAR(20)  NOT NULL DEFAULT 'pending',
  last_heartbeat   TIMESTAMPTZ,
  registered_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  connected_at     TIMESTAMPTZ,
  agent_version    VARCHAR(50),
  agent_host       VARCHAR(255),
  created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Step 5: Indexes on agent_registrations
CREATE INDEX IF NOT EXISTS idx_agent_reg_account  ON agent_registrations(account_id);
CREATE INDEX IF NOT EXISTS idx_agent_reg_tenant   ON agent_registrations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_reg_status   ON agent_registrations(status);

SELECT 'MIGRATION onboarding-001 COMPLETE';
