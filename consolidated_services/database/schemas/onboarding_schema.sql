-- ============================================================================
-- Onboarding Engine Database Schema
-- ============================================================================
-- Database: threat_engine_onboarding
-- Purpose: Single-table account management (customer → tenant → account → schedule)
--          and cross-engine scan orchestration state
-- Used by: engine_onboarding
--
-- RDS actual tables (as of 2026-02-20):
--   cloud_accounts     - Flat denormalized table replacing tenants/providers/accounts/schedules
--   scan_orchestration - Cross-engine orchestration (single source of truth)
--
-- NOTE: Previous multi-table design (tenants/providers/accounts/schedules/executions/
--       scan_results) was replaced by the flat cloud_accounts design.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================================
-- TRIGGER FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

-- ============================================================================
-- CLOUD ACCOUNTS TABLE
-- ============================================================================
-- Single table for all cloud account management.
-- Denormalizes: customer → tenant → account → schedule hierarchy into one row.
-- One row per cloud account (e.g. one AWS account ID).

CREATE TABLE IF NOT EXISTS cloud_accounts (
    -- Primary key: cloud account identifier (AWS account ID, Azure subscription ID, etc.)
    account_id          VARCHAR(255)    NOT NULL,

    -- Customer (UI user identity from Auth0/Cognito)
    customer_id         VARCHAR(255)    NOT NULL,
    customer_email      VARCHAR(255)    NOT NULL,
    customer_name       VARCHAR(255),
    customer_organization VARCHAR(255),

    -- Tenant (workspace/organization identifier)
    tenant_id           VARCHAR(255)    NOT NULL,
    tenant_name         VARCHAR(255)    NOT NULL,
    tenant_description  TEXT,

    -- Account
    account_name        VARCHAR(255)    NOT NULL,
    account_number      VARCHAR(255),
    account_hierarchy_name VARCHAR(255),
    provider            VARCHAR(50)     NOT NULL,  -- aws, azure, gcp, oci, alicloud, ibm, k8s

    -- Credentials
    credential_type     VARCHAR(50)     NOT NULL,  -- iam_role or access_key
    credential_ref      VARCHAR(255)    NOT NULL,  -- IAM role ARN OR Secrets Manager path

    -- Account status
    account_status              VARCHAR(50)     NOT NULL DEFAULT 'pending',
    account_onboarding_status   VARCHAR(50)     NOT NULL DEFAULT 'pending',
    account_onboarding_id       VARCHAR(255),
    account_last_validated_at   TIMESTAMP WITH TIME ZONE,

    -- Schedule (embedded, auto-generated when account is validated)
    schedule_id                     VARCHAR(255),
    schedule_name                   VARCHAR(255),
    schedule_cron_expression        VARCHAR(255),   -- e.g. "0 2 * * *"
    schedule_timezone               VARCHAR(50)     DEFAULT 'UTC',
    schedule_include_services       JSONB,          -- null = all services
    schedule_include_regions        JSONB,          -- null = all regions
    schedule_exclude_services       JSONB,
    schedule_exclude_regions        JSONB,
    schedule_engines_requested      JSONB           DEFAULT '["discovery", "check", "inventory", "threat", "compliance", "iam", "datasec"]'::jsonb,
    schedule_enabled                BOOLEAN         DEFAULT true,
    schedule_status                 VARCHAR(50)     DEFAULT 'active',
    schedule_next_run_at            TIMESTAMP WITH TIME ZONE,
    schedule_last_run_at            TIMESTAMP WITH TIME ZONE,
    schedule_run_count              INTEGER         DEFAULT 0,
    schedule_success_count          INTEGER         DEFAULT 0,
    schedule_failure_count          INTEGER         DEFAULT 0,
    schedule_notify_on_success      BOOLEAN         DEFAULT false,
    schedule_notify_on_failure      BOOLEAN         DEFAULT true,
    schedule_notification_emails    JSONB,

    -- Credential validation
    credential_validation_status    VARCHAR(50)     DEFAULT 'pending',
    credential_validation_message   TEXT,
    credential_validated_at         TIMESTAMP WITH TIME ZONE,
    credential_validation_errors    JSONB           DEFAULT '[]'::jsonb,

    -- Timestamps
    created_at  TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    updated_at  TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),

    CONSTRAINT cloud_accounts_pkey PRIMARY KEY (account_id),
    CONSTRAINT unique_customer_tenant_account UNIQUE (customer_id, tenant_id, account_name)
);

COMMENT ON TABLE cloud_accounts IS 'Single table for all cloud account management: customer → tenant → account → schedule hierarchy';
COMMENT ON COLUMN cloud_accounts.account_id IS 'Primary key: Cloud account identifier (AWS account ID, Azure subscription ID, etc.)';
COMMENT ON COLUMN cloud_accounts.customer_id IS 'UI user identity from Auth0/Cognito';
COMMENT ON COLUMN cloud_accounts.tenant_id IS 'Workspace/organization identifier';
COMMENT ON COLUMN cloud_accounts.credential_type IS 'Authentication method: iam_role or access_key';
COMMENT ON COLUMN cloud_accounts.credential_ref IS 'IAM role ARN (if iam_role) or Secrets Manager path (if access_key)';
COMMENT ON COLUMN cloud_accounts.schedule_id IS 'Auto-generated when account is validated';
COMMENT ON COLUMN cloud_accounts.schedule_cron_expression IS 'Cron expression for scan schedule (default: 0 2 * * *)';
COMMENT ON COLUMN cloud_accounts.schedule_include_services IS 'JSONB array of services to scan (null = all)';
COMMENT ON COLUMN cloud_accounts.schedule_include_regions IS 'JSONB array of regions to scan (null = all)';
COMMENT ON COLUMN cloud_accounts.schedule_engines_requested IS 'JSONB array of engines to run (default: all engines)';

-- ============================================================================
-- INDEXES - cloud_accounts
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_customer
    ON cloud_accounts(customer_id);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_tenant
    ON cloud_accounts(tenant_id);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_customer_tenant
    ON cloud_accounts(customer_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_customer_email
    ON cloud_accounts(customer_email);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_tenant_name
    ON cloud_accounts(tenant_name);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_account_name
    ON cloud_accounts(account_name);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_provider
    ON cloud_accounts(provider);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_status
    ON cloud_accounts(account_status, account_onboarding_status);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_credential_type
    ON cloud_accounts(credential_type);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_credential_validation
    ON cloud_accounts(credential_validation_status);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_schedule_id
    ON cloud_accounts(schedule_id) WHERE schedule_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_schedule_status
    ON cloud_accounts(schedule_status);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_schedule_enabled
    ON cloud_accounts(schedule_enabled, schedule_next_run_at) WHERE schedule_enabled = true;

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_services_gin
    ON cloud_accounts USING gin(schedule_include_services);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_regions_gin
    ON cloud_accounts USING gin(schedule_include_regions);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_engines_gin
    ON cloud_accounts USING gin(schedule_engines_requested);

-- ============================================================================
-- CROSS-ENGINE ORCHESTRATION
-- ============================================================================
-- Single source of truth for all engine scan IDs and orchestration state.
-- Each engine reads this table using orchestration_id to know what to do.
-- Engines write back their own scan ID when they start.

CREATE TABLE IF NOT EXISTS scan_orchestration (
    -- Primary identifier
    orchestration_id    UUID            NOT NULL DEFAULT uuid_generate_v4(),

    -- Tenant & Customer
    tenant_id           VARCHAR(255)    NOT NULL,
    customer_id         VARCHAR(255),

    -- Scan metadata
    scan_name           VARCHAR(255),
    scan_type           VARCHAR(50)     NOT NULL DEFAULT 'full',        -- full, partial, test
    trigger_type        VARCHAR(50)     NOT NULL DEFAULT 'scheduled',   -- scheduled, manual, api

    -- Engine tracking
    engines_requested   JSONB           NOT NULL DEFAULT '["discovery", "check", "inventory", "threat", "compliance", "iam", "datasec"]'::jsonb,
    engines_completed   JSONB           DEFAULT '[]'::jsonb,
    overall_status      VARCHAR(50)     NOT NULL DEFAULT 'pending',     -- pending, running, completed, failed

    -- Timestamps
    started_at          TIMESTAMP WITH TIME ZONE    NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMP WITH TIME ZONE,
    created_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),

    -- Scan configuration
    provider            VARCHAR(50)     NOT NULL,           -- aws, azure, gcp, oci, alicloud, ibm, k8s
    hierarchy_id        VARCHAR(255)    NOT NULL,           -- Account/Subscription/Project ID
    account_id          VARCHAR(255)    NOT NULL,           -- Cloud account identifier

    -- Scan scope (JSONB arrays; null = all)
    include_services    JSONB,                              -- ["s3", "ec2", "iam"] or null = all
    include_regions     JSONB,                              -- ["us-east-1", "ap-south-1"] or null = all
    exclude_services    JSONB,                              -- ["cloudwatch"] or null = none
    exclude_regions     JSONB,                              -- ["ap-northeast-1"] or null = none

    -- ENGINE SCAN IDs (each engine writes its own when it starts)
    discovery_scan_id   VARCHAR(255),
    check_scan_id       VARCHAR(255),
    inventory_scan_id   VARCHAR(255),
    threat_scan_id      VARCHAR(255),
    compliance_scan_id  VARCHAR(255),
    iam_scan_id         VARCHAR(255),
    datasec_scan_id     VARCHAR(255),

    -- Credentials (copied from cloud_accounts at scan time)
    credential_type     VARCHAR(50)     NOT NULL,   -- iam_role or access_key
    credential_ref      VARCHAR(255)    NOT NULL,   -- IAM role ARN OR Secrets Manager path

    -- Linking to schedule
    execution_id        UUID,           -- links to execution tracking (if applicable)
    schedule_id         VARCHAR(255),   -- links to cloud_accounts.schedule_id

    -- Results
    results_summary     JSONB           DEFAULT '{}'::jsonb,
    error_details       JSONB           DEFAULT '{}'::jsonb,

    CONSTRAINT scan_orchestration_pkey PRIMARY KEY (orchestration_id)
);

COMMENT ON TABLE scan_orchestration IS 'Cross-engine orchestration: single source of truth for all engine scan IDs and state';

-- ============================================================================
-- INDEXES - scan_orchestration
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_orchestration_tenant
    ON scan_orchestration(tenant_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_status
    ON scan_orchestration(overall_status, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_orchestration_execution
    ON scan_orchestration(execution_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_schedule
    ON scan_orchestration(schedule_id);

-- Engine scan ID lookups
CREATE INDEX IF NOT EXISTS idx_orchestration_discovery
    ON scan_orchestration(discovery_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_check
    ON scan_orchestration(check_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_inventory
    ON scan_orchestration(inventory_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_threat
    ON scan_orchestration(threat_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_compliance
    ON scan_orchestration(compliance_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_iam
    ON scan_orchestration(iam_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_datasec
    ON scan_orchestration(datasec_scan_id);

-- JSONB indexes
CREATE INDEX IF NOT EXISTS idx_orchestration_engines_gin
    ON scan_orchestration USING gin(engines_requested);

CREATE INDEX IF NOT EXISTS idx_orchestration_results_gin
    ON scan_orchestration USING gin(results_summary);
