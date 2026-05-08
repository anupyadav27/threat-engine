-- ============================================================================
-- Onboarding Engine Database Schema
-- ============================================================================
-- Database: threat_engine_onboarding
-- Updated:  2026-04-06 (migration 004 — normalized design)
--
-- Tables:
--   tenants           — customer workspaces (extracted from cloud_accounts)
--   cloud_accounts    — one row per cloud account (AWS/Azure/GCP etc.)
--   schedules         — scan schedules (separate table, multiple per account)
--   scan_runs         — every scan execution (renamed from scan_orchestration)
--   account_hierarchy — AWS Org tree (written by discovery engine, read-only here)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================================
-- TRIGGER FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

-- ============================================================================
-- TENANTS
-- ============================================================================
-- Customer workspaces. One customer can have multiple tenants.
-- tenant_id is VARCHAR (not UUID) to match legacy data already in cloud_accounts.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id           VARCHAR(255)    NOT NULL,
    customer_id         VARCHAR(255)    NOT NULL,
    tenant_name         VARCHAR(255)    NOT NULL,
    tenant_description  TEXT,
    status              VARCHAR(50)     NOT NULL DEFAULT 'active',   -- active | inactive | deleted
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT tenants_pkey             PRIMARY KEY (tenant_id),
    CONSTRAINT uq_customer_tenant_name  UNIQUE (customer_id, tenant_name)
);

CREATE INDEX IF NOT EXISTS idx_tenants_customer_id  ON tenants(customer_id);
CREATE INDEX IF NOT EXISTS idx_tenants_status       ON tenants(status);

CREATE TRIGGER tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- CLOUD ACCOUNTS
-- ============================================================================
-- One row per cloud account. No schedule data embedded here — see schedules table.
-- Credentials are stored in AWS Secrets Manager; credential_ref is the path.

CREATE TABLE IF NOT EXISTS cloud_accounts (
    -- Identity
    account_id                  VARCHAR(255)    NOT NULL,
    customer_id                 VARCHAR(255)    NOT NULL,
    tenant_id                   VARCHAR(255)    NOT NULL,

    -- Account metadata
    account_name                VARCHAR(255)    NOT NULL,
    account_number              VARCHAR(255),               -- provider-detected ID (AWS acct, Azure sub, GCP proj)
    account_hierarchy_name      VARCHAR(255),               -- display path in org tree
    provider                    VARCHAR(50)     NOT NULL,   -- aws | azure | gcp | oci | alicloud | ibm | k8s

    -- Credentials
    credential_type             VARCHAR(50)     NOT NULL,   -- iam_role | access_key | service_principal | service_account | api_key | kubeconfig
    credential_ref              VARCHAR(500)    NOT NULL,   -- Secrets Manager path OR IAM role ARN

    -- Lifecycle
    account_status              VARCHAR(50)     NOT NULL DEFAULT 'pending',      -- pending | active | inactive | deleted
    account_onboarding_status   VARCHAR(50)     NOT NULL DEFAULT 'pending',      -- pending | deployed | validated
    account_onboarding_id       VARCHAR(255),                                    -- CloudFormation stack ID etc.
    account_last_validated_at   TIMESTAMPTZ,

    -- Credential validation
    credential_validation_status    VARCHAR(50)     DEFAULT 'pending',           -- pending | valid | invalid | expired
    credential_validation_message   TEXT,
    credential_validated_at         TIMESTAMPTZ,
    credential_validation_errors    JSONB           DEFAULT '[]'::jsonb,

    -- CIEM log source config
    log_sources                 JSONB           DEFAULT '{}'::jsonb,

    -- Scan tracking (updated after each scan_run completes)
    last_scan_at                TIMESTAMPTZ,

    -- Timestamps
    created_at                  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT cloud_accounts_pkey          PRIMARY KEY (account_id),
    CONSTRAINT cloud_accounts_tenant_fk     FOREIGN KEY (tenant_id)
        REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    CONSTRAINT unique_customer_tenant_account
        UNIQUE (customer_id, tenant_id, account_name)
);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_customer        ON cloud_accounts(customer_id);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_tenant          ON cloud_accounts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_customer_tenant ON cloud_accounts(customer_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_provider        ON cloud_accounts(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_status          ON cloud_accounts(account_status, account_onboarding_status);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_credential_val  ON cloud_accounts(credential_validation_status);

CREATE TRIGGER cloud_accounts_updated_at
    BEFORE UPDATE ON cloud_accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- SCHEDULES
-- ============================================================================
-- Scan schedules. Multiple schedules per account allowed.
-- Scheduler polls: WHERE enabled = true AND next_run_at <= NOW()

CREATE TABLE IF NOT EXISTS schedules (
    schedule_id         UUID            NOT NULL DEFAULT uuid_generate_v4(),
    account_id          VARCHAR(255)    NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    customer_id         VARCHAR(255)    NOT NULL,
    schedule_name       VARCHAR(255),

    -- Timing
    cron_expression     VARCHAR(255)    NOT NULL DEFAULT '0 2 * * 0',   -- e.g. "0 2 * * 0" = Sunday 02:00
    timezone            VARCHAR(50)     NOT NULL DEFAULT 'UTC',
    enabled             BOOLEAN         NOT NULL DEFAULT true,

    -- Scan scope (null = all)
    include_regions     JSONB,                              -- ["us-east-1","ap-south-1"] or null
    include_services    JSONB,                              -- ["ec2","s3","iam"] or null
    exclude_services    JSONB,                              -- ["cloudwatch"] or null
    engines_requested   JSONB           NOT NULL DEFAULT
        '["discovery","check","inventory","threat","compliance","iam","datasec"]'::jsonb,

    -- Execution counters
    next_run_at         TIMESTAMPTZ,
    last_run_at         TIMESTAMPTZ,
    run_count           INTEGER         NOT NULL DEFAULT 0,
    success_count       INTEGER         NOT NULL DEFAULT 0,
    failure_count       INTEGER         NOT NULL DEFAULT 0,

    -- Notifications
    notify_on_success   BOOLEAN         NOT NULL DEFAULT false,
    notify_on_failure   BOOLEAN         NOT NULL DEFAULT true,
    notification_emails JSONB,

    -- Timestamps
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT schedules_pkey       PRIMARY KEY (schedule_id),
    CONSTRAINT schedules_account_fk FOREIGN KEY (account_id)
        REFERENCES cloud_accounts(account_id) ON DELETE CASCADE,
    CONSTRAINT schedules_tenant_fk  FOREIGN KEY (tenant_id)
        REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_schedules_account_id ON schedules(account_id);
CREATE INDEX IF NOT EXISTS idx_schedules_tenant_id  ON schedules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_schedules_customer_id ON schedules(customer_id);
CREATE INDEX IF NOT EXISTS idx_schedules_due        ON schedules(enabled, next_run_at)
    WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_schedules_engines    ON schedules USING gin(engines_requested);

CREATE TRIGGER schedules_updated_at
    BEFORE UPDATE ON schedules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- SCAN RUNS
-- ============================================================================
-- Every scan execution — scheduled or manual.
-- Renamed from: scan_orchestration
-- scan_run_id is the single identifier passed to ALL engines.
--
-- engine_statuses tracks per-engine progress:
-- {
--   "discovery":  {"status": "completed", "findings": 120, "duration_seconds": 45},
--   "check":      {"status": "running"},
--   "inventory":  {"status": "pending"},
--   ...
-- }

CREATE TABLE IF NOT EXISTS scan_runs (
    scan_run_id         UUID            NOT NULL DEFAULT uuid_generate_v4(),

    -- Ownership
    customer_id         VARCHAR(255)    NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    account_id          VARCHAR(255),                       -- FK; SET NULL if account deleted

    -- Schedule link (null = manual / API trigger)
    schedule_id         VARCHAR(255),                       -- legacy VARCHAR reference
    schedule_uuid       UUID,                               -- FK to schedules.schedule_id

    -- Cloud provider context (copied from cloud_accounts at scan time)
    provider            VARCHAR(50)     NOT NULL,
    credential_type     VARCHAR(50)     NOT NULL,
    credential_ref      VARCHAR(500)    NOT NULL,

    -- Scan metadata
    scan_name           VARCHAR(255),
    scan_type           VARCHAR(50)     NOT NULL DEFAULT 'full',         -- full | partial
    trigger_type        VARCHAR(50)     NOT NULL DEFAULT 'scheduled',    -- scheduled | manual | api

    -- Scan scope
    include_regions     JSONB,
    include_services    JSONB,
    exclude_services    JSONB,

    -- Engine tracking
    engines_requested   JSONB           NOT NULL,
    engines_completed   JSONB           DEFAULT '[]'::jsonb,
    engine_statuses     JSONB           DEFAULT '{}'::jsonb,             -- per-engine status map

    -- Overall status
    overall_status      VARCHAR(50)     NOT NULL DEFAULT 'pending',      -- pending | running | completed | failed | cancelled

    -- Timestamps
    started_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    -- Results
    results_summary     JSONB           DEFAULT '{}'::jsonb,
    error_details       JSONB           DEFAULT '{}'::jsonb,

    CONSTRAINT scan_runs_pkey           PRIMARY KEY (scan_run_id),
    CONSTRAINT scan_runs_account_fk     FOREIGN KEY (account_id)
        REFERENCES cloud_accounts(account_id) ON DELETE SET NULL,
    CONSTRAINT scan_runs_schedule_fk    FOREIGN KEY (schedule_uuid)
        REFERENCES schedules(schedule_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_account_id     ON scan_runs(account_id);
CREATE INDEX IF NOT EXISTS idx_scan_runs_customer_id    ON scan_runs(customer_id);
CREATE INDEX IF NOT EXISTS idx_scan_runs_tenant_id      ON scan_runs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scan_runs_status         ON scan_runs(overall_status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_runs_schedule       ON scan_runs(schedule_id);
CREATE INDEX IF NOT EXISTS idx_scan_runs_schedule_uuid  ON scan_runs(schedule_uuid);
CREATE INDEX IF NOT EXISTS idx_scan_runs_engine_statuses ON scan_runs USING gin(engine_statuses);
CREATE INDEX IF NOT EXISTS idx_scan_runs_engines_req    ON scan_runs USING gin(engines_requested);

-- ============================================================================
-- ACCOUNT HIERARCHY  (written by discovery engine — read-only from onboarding)
-- ============================================================================

CREATE TABLE IF NOT EXISTS account_hierarchy (
    id              BIGSERIAL       PRIMARY KEY,
    tenant_id       VARCHAR(255),
    customer_id     VARCHAR(255),
    node_id         VARCHAR(255),
    node_name       VARCHAR(255),
    node_type       VARCHAR(255),   -- ROOT | OU | ACCOUNT
    parent_node_id  VARCHAR(255),
    hierarchy_path  TEXT,
    depth           SMALLINT,
    provider        VARCHAR(255),
    provider_org_id VARCHAR(255),
    status          VARCHAR(255),
    metadata        JSONB,
    discovered_at   TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_account_hierarchy_tenant   ON account_hierarchy(tenant_id);
CREATE INDEX IF NOT EXISTS idx_account_hierarchy_customer ON account_hierarchy(customer_id);
CREATE INDEX IF NOT EXISTS idx_account_hierarchy_node     ON account_hierarchy(node_id);
CREATE INDEX IF NOT EXISTS idx_account_hierarchy_parent   ON account_hierarchy(parent_node_id);
