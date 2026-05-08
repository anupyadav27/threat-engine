-- Migration: account_type discriminator + agent_registrations table
-- Adds the account_type column to cloud_accounts so the onboarding wizard
-- can branch by type (cloud_csp / vulnerability / secops / database / middleware).
-- Also creates the agent_registrations table for agent-based account types
-- (vulnerability, database, middleware) that phone-home to register themselves.
--
-- Apply with:
--   kubectl cp .../20260503_account_type_and_agent_registrations.sql \
--       threat-engine-engines/<onboarding-pod>:/tmp/migrate.sql
--   kubectl exec -n threat-engine-engines <onboarding-pod> -- \
--       psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f /tmp/migrate.sql

BEGIN;

-- ── 1. Add account_type to cloud_accounts ─────────────────────────────────────

ALTER TABLE cloud_accounts
    ADD COLUMN IF NOT EXISTS account_type VARCHAR(50);

-- Back-fill from existing data:
--   DB providers  → database
--   k8s           → cloud_csp (treated as a CSP for scan purposes)
--   everything else → cloud_csp
UPDATE cloud_accounts
SET account_type = CASE
    WHEN provider IN ('postgres','mysql','mssql','mongodb','oracle') THEN 'database'
    ELSE 'cloud_csp'
END
WHERE account_type IS NULL;

-- Make non-nullable with default for future rows
ALTER TABLE cloud_accounts
    ALTER COLUMN account_type SET DEFAULT 'cloud_csp',
    ALTER COLUMN account_type SET NOT NULL;

-- Add auth_config JSONB for flexible per-type credential metadata (optional extras)
ALTER TABLE cloud_accounts
    ADD COLUMN IF NOT EXISTS auth_config JSONB DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_account_type
    ON cloud_accounts(account_type);

-- ── 2. Create agent_registrations table ───────────────────────────────────────
-- Tracks agents that phone home to register themselves.
-- Lifecycle: issued → active (after bootstrap) → expired / revoked

CREATE TABLE IF NOT EXISTS agent_registrations (
    -- Identity
    registration_id     UUID            NOT NULL DEFAULT gen_random_uuid(),
    account_id          VARCHAR(255)    NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    customer_id         VARCHAR(255)    NOT NULL,

    -- Agent metadata (set by the agent on bootstrap)
    agent_version       VARCHAR(50),
    agent_hostname      VARCHAR(255),
    agent_ip            INET,
    agent_os            VARCHAR(100),

    -- Token lifecycle
    token_hash          VARCHAR(512)    NOT NULL,           -- SHA-256 of the one-time bootstrap token
    status              VARCHAR(30)     NOT NULL DEFAULT 'issued',
                                                            -- issued | active | expired | revoked
    issued_at           TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ     NOT NULL,           -- 15 min for bootstrap token; 30 days after activate
    activated_at        TIMESTAMPTZ,
    last_heartbeat_at   TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    revoke_reason       TEXT,

    -- Timestamps
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT agent_registrations_pkey PRIMARY KEY (registration_id),
    CONSTRAINT agent_registrations_account_fk
        FOREIGN KEY (account_id) REFERENCES cloud_accounts(account_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_agent_reg_account
    ON agent_registrations(account_id);
CREATE INDEX IF NOT EXISTS idx_agent_reg_tenant
    ON agent_registrations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_reg_status
    ON agent_registrations(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_agent_reg_token_hash
    ON agent_registrations(token_hash);

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_agent_registrations_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS agent_registrations_updated_at ON agent_registrations;
CREATE TRIGGER agent_registrations_updated_at
    BEFORE UPDATE ON agent_registrations
    FOR EACH ROW EXECUTE FUNCTION update_agent_registrations_updated_at();

COMMIT;
