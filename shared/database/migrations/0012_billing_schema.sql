-- =============================================================================
-- Migration 0012: Billing database — tables, roles, and seed data
-- Database:  threat_engine_billing  (must be created before applying)
-- Idempotent: safe to re-run (CREATE IF NOT EXISTS, DO $$ role guards)
-- =============================================================================
-- Apply:
--   kubectl cp .../0012_billing_schema.sql threat-engine-engines/<pod>:/tmp/0012_billing_schema.sql
--   kubectl exec -n threat-engine-engines <pod> -- \
--     psql -h $DISCOVERIES_DB_HOST -U $DISCOVERIES_DB_USER -d threat_engine_billing \
--     -f /tmp/0012_billing_schema.sql
-- Note: CREATE DATABASE cannot run inside a transaction; create the DB first:
--   psql -h $DISCOVERIES_DB_HOST -U $DISCOVERIES_DB_USER -d postgres \
--     -c "CREATE DATABASE threat_engine_billing;"
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- =============================================================================
-- Table: subscription_plans
-- Defines the 4 commercial tiers (free / starter / pro / enterprise).
-- =============================================================================
CREATE TABLE IF NOT EXISTS subscription_plans (
    plan_id                UUID          NOT NULL DEFAULT uuid_generate_v4(),
    plan_name              VARCHAR(50)   NOT NULL,
    display_name           VARCHAR(100)  NOT NULL,
    price_monthly          NUMERIC(10,2) NOT NULL DEFAULT 0.00,
    price_annual           NUMERIC(10,2),
    stripe_price_id        VARCHAR(255),
    stripe_price_id_annual VARCHAR(255),
    max_accounts           INTEGER       NOT NULL DEFAULT 1,
    max_users              INTEGER       NOT NULL DEFAULT 3,
    scan_freq_per_day      INTEGER       NOT NULL DEFAULT 0,
    data_retention_days    INTEGER       NOT NULL DEFAULT 7,
    engine_allowlist       JSONB         NOT NULL DEFAULT '["discoveries","check","threat","inventory","compliance","iam","ciem","network-security","risk"]'::jsonb,
    is_active              BOOLEAN       NOT NULL DEFAULT true,
    is_public              BOOLEAN       NOT NULL DEFAULT true,
    sort_order             SMALLINT      NOT NULL DEFAULT 0,
    metadata               JSONB         NOT NULL DEFAULT '{}'::jsonb,
    created_at             TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT subscription_plans_pkey PRIMARY KEY (plan_id),
    CONSTRAINT uq_plan_name UNIQUE (plan_name)
);

CREATE INDEX IF NOT EXISTS idx_sp_active ON subscription_plans(is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_sp_sort   ON subscription_plans(sort_order);

-- =============================================================================
-- Table: org_subscriptions
-- One row per org — which plan they are on, Stripe IDs, usage counters.
-- =============================================================================
CREATE TABLE IF NOT EXISTS org_subscriptions (
    subscription_id        UUID         NOT NULL DEFAULT uuid_generate_v4(),
    org_id                 VARCHAR(255) NOT NULL,
    plan_id                UUID         NOT NULL,
    stripe_customer_id     VARCHAR(255),
    stripe_subscription_id VARCHAR(255),
    status                 VARCHAR(50)  NOT NULL DEFAULT 'trialing',
    trial_start_at         TIMESTAMPTZ,
    trial_end_at           TIMESTAMPTZ,
    current_period_start   TIMESTAMPTZ,
    current_period_end     TIMESTAMPTZ,
    cancel_at_period_end   BOOLEAN      NOT NULL DEFAULT false,
    cancelled_at           TIMESTAMPTZ,
    payment_failed_at      TIMESTAMPTZ,
    payment_retry_count    SMALLINT     NOT NULL DEFAULT 0,
    grace_period_end_at    TIMESTAMPTZ,
    is_overridden          BOOLEAN      NOT NULL DEFAULT false,
    override_reason        TEXT,
    override_by_user_id    VARCHAR(255),
    grandfathered_until    TIMESTAMPTZ,
    org_email_domain       VARCHAR(255),
    accounts_connected     INTEGER      NOT NULL DEFAULT 0,
    users_count            INTEGER      NOT NULL DEFAULT 0,
    scans_last_30_days     INTEGER      NOT NULL DEFAULT 0,
    usage_cache_updated_at TIMESTAMPTZ,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT org_subscriptions_pkey PRIMARY KEY (subscription_id),
    CONSTRAINT uq_org_subscription    UNIQUE (org_id),
    CONSTRAINT fk_os_plan             FOREIGN KEY (plan_id) REFERENCES subscription_plans(plan_id)
);

CREATE INDEX IF NOT EXISTS idx_os_org            ON org_subscriptions(org_id);
CREATE INDEX IF NOT EXISTS idx_os_status         ON org_subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_os_stripe_customer ON org_subscriptions(stripe_customer_id)     WHERE stripe_customer_id     IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_os_stripe_sub      ON org_subscriptions(stripe_subscription_id) WHERE stripe_subscription_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_os_trial_end       ON org_subscriptions(trial_end_at)            WHERE status = 'trialing';
CREATE INDEX IF NOT EXISTS idx_os_grace_period    ON org_subscriptions(grace_period_end_at)     WHERE grace_period_end_at    IS NOT NULL;

-- =============================================================================
-- Table: billing_events
-- Immutable event log for every billing state change.
-- =============================================================================
CREATE TABLE IF NOT EXISTS billing_events (
    event_id        UUID         NOT NULL DEFAULT uuid_generate_v4(),
    org_id          VARCHAR(255) NOT NULL,
    event_type      VARCHAR(100) NOT NULL,
    actor_type      VARCHAR(50)  NOT NULL DEFAULT 'system',
    actor_id        VARCHAR(255),
    source_ip       INET,
    previous_state  JSONB,
    new_state       JSONB,
    stripe_event_id VARCHAR(255),
    metadata        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT billing_events_pkey PRIMARY KEY (event_id)
);

CREATE INDEX IF NOT EXISTS idx_be_org          ON billing_events(org_id);
CREATE INDEX IF NOT EXISTS idx_be_event_type   ON billing_events(event_type);
CREATE INDEX IF NOT EXISTS idx_be_created_at   ON billing_events(created_at);
CREATE INDEX IF NOT EXISTS idx_be_stripe_event ON billing_events(stripe_event_id) WHERE stripe_event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_be_org_created  ON billing_events(org_id, created_at DESC);

-- =============================================================================
-- Table: stripe_webhook_log
-- Deduplication and processing-status tracking for inbound Stripe webhooks.
-- =============================================================================
CREATE TABLE IF NOT EXISTS stripe_webhook_log (
    id                BIGSERIAL    NOT NULL,
    stripe_event_id   VARCHAR(255) NOT NULL,
    event_type        VARCHAR(100) NOT NULL,
    received_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    processing_status VARCHAR(20)  NOT NULL DEFAULT 'received',
    processed_at      TIMESTAMPTZ,
    error_message     TEXT,
    payload_hash      VARCHAR(64)  NOT NULL,
    retry_count       SMALLINT     NOT NULL DEFAULT 0,
    CONSTRAINT stripe_webhook_log_pkey PRIMARY KEY (id),
    CONSTRAINT uq_stripe_event_id      UNIQUE (stripe_event_id)
);

CREATE INDEX IF NOT EXISTS idx_swl_event_id   ON stripe_webhook_log(stripe_event_id);
CREATE INDEX IF NOT EXISTS idx_swl_status     ON stripe_webhook_log(processing_status);
CREATE INDEX IF NOT EXISTS idx_swl_received_at ON stripe_webhook_log(received_at);

-- =============================================================================
-- Table: billing_audit_log  (append-only — SOC 2 compliant)
-- All billing plan changes with full before/after state capture.
-- Role billing_app has INSERT+SELECT only; UPDATE and DELETE are NOT granted.
-- =============================================================================
CREATE TABLE IF NOT EXISTS billing_audit_log (
    log_id         UUID         NOT NULL DEFAULT uuid_generate_v4(),
    org_id         VARCHAR(255) NOT NULL,
    event_type     VARCHAR(100) NOT NULL,
    actor_id       VARCHAR(255),
    actor_email    VARCHAR(255),
    actor_role     VARCHAR(50),
    source_ip      INET,
    user_agent     TEXT,
    previous_state JSONB,
    new_state      JSONB,
    change_summary TEXT,
    corr_id        VARCHAR(36),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT billing_audit_log_pkey PRIMARY KEY (log_id)
);

CREATE INDEX IF NOT EXISTS idx_bal_org              ON billing_audit_log(org_id);
CREATE INDEX IF NOT EXISTS idx_bal_event_type       ON billing_audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_bal_created_at       ON billing_audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_bal_actor            ON billing_audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_bal_org_event_created ON billing_audit_log(org_id, event_type, created_at DESC);

-- =============================================================================
-- Table: scan_frequency_tokens
-- Rate-limit window counters — one row per (org, date, window_type).
-- =============================================================================
CREATE TABLE IF NOT EXISTS scan_frequency_tokens (
    token_id     UUID         NOT NULL DEFAULT uuid_generate_v4(),
    org_id       VARCHAR(255) NOT NULL,
    window_date  DATE         NOT NULL,
    tokens_used  INTEGER      NOT NULL DEFAULT 0,
    tokens_limit INTEGER      NOT NULL DEFAULT 1,
    window_type  VARCHAR(10)  NOT NULL DEFAULT 'day',
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT sft_pkey           PRIMARY KEY (token_id),
    CONSTRAINT uq_sft_org_window  UNIQUE (org_id, window_date, window_type)
);

CREATE INDEX IF NOT EXISTS idx_sft_org    ON scan_frequency_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_sft_window ON scan_frequency_tokens(window_date);

-- =============================================================================
-- Table: platform_admin_audit  (append-only — SOC 2 compliant)
-- Tracks every superuser / platform-admin action that affects an org.
-- Role billing_app has INSERT+SELECT only; UPDATE and DELETE are NOT granted.
-- =============================================================================
CREATE TABLE IF NOT EXISTS platform_admin_audit (
    audit_id      UUID         NOT NULL DEFAULT uuid_generate_v4(),
    admin_user_id VARCHAR(255) NOT NULL,
    admin_email   VARCHAR(255),
    action        VARCHAR(100) NOT NULL,
    target_org_id VARCHAR(255),
    target_entity VARCHAR(50),
    payload       JSONB        NOT NULL DEFAULT '{}'::jsonb,
    source_ip     INET,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT platform_admin_audit_pkey PRIMARY KEY (audit_id)
);

CREATE INDEX IF NOT EXISTS idx_paa_admin   ON platform_admin_audit(admin_user_id);
CREATE INDEX IF NOT EXISTS idx_paa_org     ON platform_admin_audit(target_org_id);
CREATE INDEX IF NOT EXISTS idx_paa_action  ON platform_admin_audit(action);
CREATE INDEX IF NOT EXISTS idx_paa_created ON platform_admin_audit(created_at);

-- =============================================================================
-- Postgres Roles (idempotent via DO block)
-- =============================================================================
DO $$
BEGIN
    -- billing_app: application service account (INSERT/SELECT/UPDATE on most tables;
    --              INSERT/SELECT only on audit tables — no UPDATE/DELETE, SOC 2)
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'billing_app') THEN
        CREATE ROLE billing_app WITH LOGIN;
    END IF;

    -- billing_readonly: dashboards, support tooling, read-only queries
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'billing_readonly') THEN
        CREATE ROLE billing_readonly WITH LOGIN;
    END IF;

    -- billing_audit_writer: INSERT-only service account for audit sinks
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'billing_audit_writer') THEN
        CREATE ROLE billing_audit_writer WITH LOGIN;
    END IF;
END
$$;

-- billing_app: full read-write on operational tables
GRANT INSERT, SELECT, UPDATE ON subscription_plans      TO billing_app;
GRANT INSERT, SELECT, UPDATE ON org_subscriptions       TO billing_app;
GRANT INSERT, SELECT, UPDATE ON billing_events          TO billing_app;
GRANT INSERT, SELECT, UPDATE ON stripe_webhook_log      TO billing_app;
GRANT INSERT, SELECT, UPDATE ON scan_frequency_tokens   TO billing_app;
-- Audit tables: INSERT + SELECT only (NO UPDATE, NO DELETE — SOC 2 enforcement)
GRANT INSERT, SELECT          ON billing_audit_log      TO billing_app;
GRANT INSERT, SELECT          ON platform_admin_audit   TO billing_app;

-- billing_readonly: SELECT-only on every table in the schema
GRANT SELECT ON ALL TABLES IN SCHEMA public TO billing_readonly;

-- billing_audit_writer: INSERT-only on the two append-only audit tables
GRANT INSERT ON billing_audit_log    TO billing_audit_writer;
GRANT INSERT ON platform_admin_audit TO billing_audit_writer;

-- =============================================================================
-- Seed Data: 4 Subscription Plans
-- ON CONFLICT DO NOTHING makes this block idempotent on re-runs.
-- =============================================================================
INSERT INTO subscription_plans
    (plan_name, display_name, price_monthly, max_accounts, max_users,
     scan_freq_per_day, data_retention_days, engine_allowlist, sort_order)
VALUES
  ('free',
   'Free',
   0.00,
   1, 3, 0, 7,
   '["discoveries","check","threat","inventory","compliance","iam","ciem","network-security","risk"]'::jsonb,
   1),
  ('starter',
   'Starter',
   49.00,
   3, 10, 1, 30,
   '["discoveries","check","threat","inventory","compliance","iam","ciem","network-security","risk"]'::jsonb,
   2),
  ('pro',
   'Pro',
   99.00,
   10, 25, 4, 90,
   '["discoveries","check","threat","inventory","compliance","iam","ciem","network-security","risk","datasec","secops","vulnerability"]'::jsonb,
   3),
  ('enterprise',
   'Enterprise',
   299.00,
   -1, -1, -1, 365,
   '["discoveries","check","threat","inventory","compliance","iam","ciem","network-security","risk","datasec","secops","vulnerability","ai-security","encryption","dbsec","container-security","fix"]'::jsonb,
   4)
ON CONFLICT (plan_name) DO NOTHING;

-- =============================================================================
-- End of 0012_billing_schema.sql
-- =============================================================================
