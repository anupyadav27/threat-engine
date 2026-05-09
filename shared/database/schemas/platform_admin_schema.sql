-- =============================================================================
-- Platform Admin Engine Schema — canonical DDL reference
-- Database: threat_engine_billing  (shared with billing engine)
-- Engine:   platform-admin (Port 8041)
-- Purpose:  Per-org billable resource snapshots for the admin billing overview
-- =============================================================================
-- Tables owned by this engine:
--   billing_resource_snapshots  — daily per-org/account/provider resource counts
--
-- Tables read (owned by billing engine):
--   org_subscriptions           — subscription status and plan for each org
--   subscription_plans          — plan metadata (plan_name, tier, limits)
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- 1. billing_resource_snapshots
-- Daily snapshot of billable resource count per org / cloud account / provider.
-- Written by the billing engine's daily snapshot job.
-- Read by the platform-admin billing overview to compute 30-day averages.
-- =============================================================================
CREATE TABLE IF NOT EXISTS billing_resource_snapshots (
    snapshot_id     UUID          NOT NULL DEFAULT uuid_generate_v4(),
    org_id          VARCHAR(255)  NOT NULL,
    account_id      VARCHAR(255)  NOT NULL,
    provider        VARCHAR(50)   NOT NULL,   -- aws | azure | gcp | oci | alicloud | k8s
    billable_count  INTEGER       NOT NULL DEFAULT 0,
    snapshot_date   DATE          NOT NULL DEFAULT CURRENT_DATE,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT billing_resource_snapshots_pkey PRIMARY KEY (snapshot_id),
    CONSTRAINT uq_snapshot_per_day
        UNIQUE (org_id, account_id, provider, snapshot_date)
);

CREATE INDEX IF NOT EXISTS idx_brs_org_date
    ON billing_resource_snapshots (org_id, snapshot_date DESC);

CREATE INDEX IF NOT EXISTS idx_brs_date
    ON billing_resource_snapshots (snapshot_date DESC);

-- =============================================================================
-- 2. org_subscriptions  (owned by billing engine — read-only for platform-admin)
-- Joined to get plan_name and subscription status for each org.
-- Full DDL: shared/database/schemas/billing_schema.sql
-- =============================================================================
-- Relevant columns used by platform-admin queries:
--   org_id      VARCHAR(255)
--   plan_id     UUID  → FK to subscription_plans.plan_id
--   status      VARCHAR(50)   (trialing | active | past_due | cancelled)

-- =============================================================================
-- 3. subscription_plans  (owned by billing engine — read-only for platform-admin)
-- Full DDL: shared/database/schemas/billing_schema.sql
-- =============================================================================
-- Relevant columns used by platform-admin queries:
--   plan_id     UUID
--   plan_name   VARCHAR(50)   (free | starter | pro | enterprise)
