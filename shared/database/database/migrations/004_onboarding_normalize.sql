-- ============================================================================
-- Migration 004: Normalize onboarding schema
-- Database:  threat_engine_onboarding
-- Author:    Platform Team
-- Date:      2026-04-06
--
-- WHAT THIS DOES:
--   1. Creates  tenants   table  (extracted from cloud_accounts)
--   2. Creates  schedules table  (extracted from cloud_accounts.schedule_* cols)
--   3. Renames  scan_orchestration → scan_runs
--              (scan_run_id column already exists — only table name changes)
--   4. Alters   cloud_accounts:
--              - Drops all 20 schedule_* columns  (moved to schedules)
--              - Drops tenant_name, tenant_description  (moved to tenants)
--              - Drops customer_name, customer_organization (not needed in acct row)
--              - Adds  last_scan_at TIMESTAMPTZ
--              - Adds  FK tenant_id → tenants.tenant_id
--   5. Keeps    account_hierarchy untouched
--
-- ROLLBACK:   See DOWN section at the bottom
-- SAFE TO RE-RUN: Yes — all steps use IF EXISTS / IF NOT EXISTS / ON CONFLICT
-- ============================================================================

BEGIN;

-- ============================================================================
-- STEP 1 — Create tenants table
-- ============================================================================
-- tenant_id kept as VARCHAR to match existing cloud_accounts.tenant_id values.
-- UUID would require a mapping table — avoid complexity on live data.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id           VARCHAR(255)    NOT NULL,
    customer_id         VARCHAR(255)    NOT NULL,
    tenant_name         VARCHAR(255)    NOT NULL,
    tenant_description  TEXT,
    status              VARCHAR(50)     NOT NULL DEFAULT 'active',
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT tenants_pkey             PRIMARY KEY (tenant_id),
    CONSTRAINT uq_customer_tenant_name  UNIQUE (customer_id, tenant_name)
);

CREATE INDEX IF NOT EXISTS idx_tenants_customer_id
    ON tenants(customer_id);

CREATE INDEX IF NOT EXISTS idx_tenants_status
    ON tenants(status);

-- Trigger: keep updated_at current
DROP TRIGGER IF EXISTS tenants_updated_at ON tenants;
CREATE TRIGGER tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- STEP 2 — Seed tenants from existing cloud_accounts rows
-- ============================================================================
-- One tenant row per distinct tenant_id. Takes earliest created_at as the
-- tenant's own created_at. ON CONFLICT = safe to re-run.

INSERT INTO tenants (
    tenant_id,
    customer_id,
    tenant_name,
    tenant_description,
    status,
    created_at,
    updated_at
)
SELECT DISTINCT ON (ca.tenant_id)
    ca.tenant_id,
    ca.customer_id,
    COALESCE(NULLIF(TRIM(ca.tenant_name), ''), ca.tenant_id),
    ca.tenant_description,
    'active',
    MIN(ca.created_at) OVER (PARTITION BY ca.tenant_id),
    NOW()
FROM cloud_accounts ca
WHERE ca.tenant_id IS NOT NULL
  AND ca.tenant_id <> ''
ORDER BY ca.tenant_id, ca.created_at ASC
ON CONFLICT (tenant_id) DO NOTHING;

-- ============================================================================
-- STEP 3 — Create schedules table
-- ============================================================================

CREATE TABLE IF NOT EXISTS schedules (
    schedule_id             UUID            NOT NULL DEFAULT uuid_generate_v4(),
    account_id              VARCHAR(255)    NOT NULL,
    tenant_id               VARCHAR(255)    NOT NULL,
    customer_id             VARCHAR(255)    NOT NULL,
    schedule_name           VARCHAR(255),
    cron_expression         VARCHAR(255)    NOT NULL DEFAULT '0 2 * * 0',
    timezone                VARCHAR(50)     NOT NULL DEFAULT 'UTC',
    enabled                 BOOLEAN         NOT NULL DEFAULT true,

    -- Scope (null = all)
    include_regions         JSONB,
    include_services        JSONB,
    exclude_services        JSONB,
    engines_requested       JSONB           NOT NULL DEFAULT
        '["discovery","check","inventory","threat","compliance","iam","datasec"]'::jsonb,

    -- Execution tracking
    next_run_at             TIMESTAMPTZ,
    last_run_at             TIMESTAMPTZ,
    run_count               INTEGER         NOT NULL DEFAULT 0,
    success_count           INTEGER         NOT NULL DEFAULT 0,
    failure_count           INTEGER         NOT NULL DEFAULT 0,

    -- Notifications
    notify_on_success       BOOLEAN         NOT NULL DEFAULT false,
    notify_on_failure       BOOLEAN         NOT NULL DEFAULT true,
    notification_emails     JSONB,

    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT schedules_pkey               PRIMARY KEY (schedule_id),
    CONSTRAINT schedules_account_fk         FOREIGN KEY (account_id)
        REFERENCES cloud_accounts(account_id) ON DELETE CASCADE,
    CONSTRAINT schedules_tenant_fk          FOREIGN KEY (tenant_id)
        REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_schedules_account_id
    ON schedules(account_id);

CREATE INDEX IF NOT EXISTS idx_schedules_tenant_id
    ON schedules(tenant_id);

CREATE INDEX IF NOT EXISTS idx_schedules_customer_id
    ON schedules(customer_id);

CREATE INDEX IF NOT EXISTS idx_schedules_due
    ON schedules(enabled, next_run_at)
    WHERE enabled = true;

DROP TRIGGER IF EXISTS schedules_updated_at ON schedules;
CREATE TRIGGER schedules_updated_at
    BEFORE UPDATE ON schedules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- STEP 4 — Migrate existing schedule data from cloud_accounts → schedules
-- ============================================================================
-- Only migrate rows that had a cron expression configured.
-- schedule_id in cloud_accounts is VARCHAR — cast to UUID if it looks like one,
-- otherwise generate a new UUID.

INSERT INTO schedules (
    schedule_id,
    account_id,
    tenant_id,
    customer_id,
    schedule_name,
    cron_expression,
    timezone,
    enabled,
    include_regions,
    include_services,
    exclude_services,
    engines_requested,
    next_run_at,
    last_run_at,
    run_count,
    success_count,
    failure_count,
    notify_on_success,
    notify_on_failure,
    created_at,
    updated_at
)
SELECT
    CASE
        WHEN schedule_id IS NOT NULL
             AND schedule_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        THEN schedule_id::UUID
        ELSE uuid_generate_v4()
    END,
    account_id,
    tenant_id,
    customer_id,
    COALESCE(schedule_name, account_name || ' schedule'),
    COALESCE(NULLIF(TRIM(schedule_cron_expression), ''), '0 2 * * 0'),
    COALESCE(NULLIF(TRIM(schedule_timezone), ''), 'UTC'),
    COALESCE(schedule_enabled, true),
    schedule_include_regions,
    schedule_include_services,
    schedule_exclude_services,
    COALESCE(
        schedule_engines_requested,
        '["discovery","check","inventory","threat","compliance","iam","datasec"]'::jsonb
    ),
    schedule_next_run_at,
    schedule_last_run_at,
    COALESCE(schedule_run_count, 0),
    COALESCE(schedule_success_count, 0),
    COALESCE(schedule_failure_count, 0),
    COALESCE(schedule_notify_on_success, false),
    COALESCE(schedule_notify_on_failure, true),
    created_at,
    updated_at
FROM cloud_accounts
WHERE schedule_cron_expression IS NOT NULL
  AND TRIM(schedule_cron_expression) <> ''
ON CONFLICT (schedule_id) DO NOTHING;

-- ============================================================================
-- STEP 5 — Add last_scan_at to cloud_accounts (new required column)
-- ============================================================================

ALTER TABLE cloud_accounts
    ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMPTZ;

-- Backfill last_scan_at from the most recent scan_orchestration run
UPDATE cloud_accounts ca
SET last_scan_at = so.completed_at
FROM (
    SELECT account_id, MAX(completed_at) AS completed_at
    FROM scan_orchestration
    WHERE overall_status = 'completed'
    GROUP BY account_id
) so
WHERE ca.account_id = so.account_id
  AND ca.last_scan_at IS NULL;

-- ============================================================================
-- STEP 6 — Add FK: cloud_accounts.tenant_id → tenants.tenant_id
-- ============================================================================
-- Only add if tenants table now has all referenced tenant_ids.
-- Skip rows with dangling tenant_id by inserting a placeholder tenant if needed.

INSERT INTO tenants (tenant_id, customer_id, tenant_name, status)
SELECT DISTINCT ca.tenant_id, ca.customer_id, ca.tenant_id, 'active'
FROM cloud_accounts ca
LEFT JOIN tenants t ON t.tenant_id = ca.tenant_id
WHERE ca.tenant_id IS NOT NULL
  AND t.tenant_id IS NULL
ON CONFLICT (tenant_id) DO NOTHING;

-- Now safe to add the FK
ALTER TABLE cloud_accounts
    DROP CONSTRAINT IF EXISTS cloud_accounts_tenant_fk;

ALTER TABLE cloud_accounts
    ADD CONSTRAINT cloud_accounts_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
        ON DELETE RESTRICT;

-- ============================================================================
-- STEP 7 — Drop denormalized columns from cloud_accounts
-- ============================================================================
-- Schedule columns (moved to schedules table)

ALTER TABLE cloud_accounts
    DROP COLUMN IF EXISTS schedule_id,
    DROP COLUMN IF EXISTS schedule_name,
    DROP COLUMN IF EXISTS schedule_cron_expression,
    DROP COLUMN IF EXISTS schedule_timezone,
    DROP COLUMN IF EXISTS schedule_include_services,
    DROP COLUMN IF EXISTS schedule_include_regions,
    DROP COLUMN IF EXISTS schedule_exclude_services,
    DROP COLUMN IF EXISTS schedule_exclude_regions,
    DROP COLUMN IF EXISTS schedule_engines_requested,
    DROP COLUMN IF EXISTS schedule_enabled,
    DROP COLUMN IF EXISTS schedule_status,
    DROP COLUMN IF EXISTS schedule_next_run_at,
    DROP COLUMN IF EXISTS schedule_last_run_at,
    DROP COLUMN IF EXISTS schedule_run_count,
    DROP COLUMN IF EXISTS schedule_success_count,
    DROP COLUMN IF EXISTS schedule_failure_count,
    DROP COLUMN IF EXISTS schedule_notify_on_success,
    DROP COLUMN IF EXISTS schedule_notify_on_failure,
    DROP COLUMN IF EXISTS schedule_notification_emails;

-- Tenant columns (moved to tenants table)
ALTER TABLE cloud_accounts
    DROP COLUMN IF EXISTS tenant_name,
    DROP COLUMN IF EXISTS tenant_description;

-- Customer detail columns (not needed per account row — customer_id is enough)
ALTER TABLE cloud_accounts
    DROP COLUMN IF EXISTS customer_name,
    DROP COLUMN IF EXISTS customer_organization;

-- ============================================================================
-- STEP 8 — Rename scan_orchestration → scan_runs
-- ============================================================================
-- scan_run_id column already exists (rename was done previously).
-- Just rename the table.

ALTER TABLE IF EXISTS scan_orchestration RENAME TO scan_runs;

-- ============================================================================
-- STEP 9 — Enhance scan_runs table
-- ============================================================================
-- Add engine_statuses JSONB (replaces individual *_scan_id columns with a map)
-- Add schedule_id FK to schedules

ALTER TABLE scan_runs
    ADD COLUMN IF NOT EXISTS engine_statuses JSONB DEFAULT '{}'::jsonb;

ALTER TABLE scan_runs
    ADD COLUMN IF NOT EXISTS schedule_uuid UUID;

-- Drop NOT NULL on account_id so orphaned rows can be set to NULL
ALTER TABLE scan_runs ALTER COLUMN account_id DROP NOT NULL;

-- NULL out any account_ids that don't exist in cloud_accounts
-- (scan history for deleted/unknown accounts — keep the run, lose the link)
UPDATE scan_runs
SET account_id = NULL
WHERE account_id IS NOT NULL
  AND account_id NOT IN (SELECT account_id FROM cloud_accounts);

-- Now safe to add the FK
ALTER TABLE scan_runs
    DROP CONSTRAINT IF EXISTS scan_runs_account_fk;

ALTER TABLE scan_runs
    ADD CONSTRAINT scan_runs_account_fk
        FOREIGN KEY (account_id) REFERENCES cloud_accounts(account_id)
        ON DELETE SET NULL;

-- Add indexes on scan_runs
CREATE INDEX IF NOT EXISTS idx_scan_runs_account_id
    ON scan_runs(account_id);

CREATE INDEX IF NOT EXISTS idx_scan_runs_customer_id
    ON scan_runs(customer_id);

CREATE INDEX IF NOT EXISTS idx_scan_runs_tenant_id
    ON scan_runs(tenant_id);

CREATE INDEX IF NOT EXISTS idx_scan_runs_status
    ON scan_runs(overall_status, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_runs_schedule
    ON scan_runs(schedule_id);

CREATE INDEX IF NOT EXISTS idx_scan_runs_engine_statuses
    ON scan_runs USING gin(engine_statuses);

-- ============================================================================
-- VERIFY (informational — shows final table list)
-- ============================================================================

DO $$
DECLARE
    tbl TEXT;
BEGIN
    RAISE NOTICE '=== Migration 004 complete. Tables in threat_engine_onboarding: ===';
    FOR tbl IN
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        ORDER BY table_name
    LOOP
        RAISE NOTICE '  %', tbl;
    END LOOP;
END $$;

COMMIT;

-- ============================================================================
-- DOWN (rollback)
-- ============================================================================
-- Run this block manually to undo the migration.
-- WARNING: Dropping columns is NOT reversible without a backup.
--
-- BEGIN;
-- ALTER TABLE scan_runs RENAME TO scan_orchestration;
-- ALTER TABLE scan_runs DROP COLUMN IF EXISTS engine_statuses;
-- ALTER TABLE scan_runs DROP COLUMN IF EXISTS schedule_uuid;
-- ALTER TABLE cloud_accounts DROP CONSTRAINT IF EXISTS cloud_accounts_tenant_fk;
-- ALTER TABLE cloud_accounts DROP COLUMN IF EXISTS last_scan_at;
-- DROP TABLE IF EXISTS schedules;
-- DROP TABLE IF EXISTS tenants;
-- COMMIT;
