-- ============================================================================
-- Migration: check_rule_suppressions_001
-- Database:  threat_engine_check
-- Purpose:   Create rule_suppressions table for per-tenant, per-account rule
--            suppression at rule / service / technology / provider scope.
--
-- Two-level hierarchy:
--   account_id IS NULL  → tenant-wide suppression (all accounts inherit)
--   account_id NOT NULL → account-level suppression (only that account)
--
-- Apply via:
--   kubectl cp /tmp/check_rule_suppressions_001.sql \
--       threat-engine-engines/<check-pod>:/tmp/check_rule_suppressions_001.sql
--   kubectl exec -n threat-engine-engines <check-pod> -- psql \
--       -h $CHECK_DB_HOST -U $CHECK_DB_USER -d $CHECK_DB_NAME \
--       -f /tmp/check_rule_suppressions_001.sql
-- ============================================================================

\set ON_ERROR_STOP on

BEGIN;

CREATE TABLE IF NOT EXISTS rule_suppressions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Scope anchor
    tenant_id       VARCHAR(255) NOT NULL,
    account_id      VARCHAR(255),            -- NULL = tenant-wide

    -- What is suppressed
    scope_type      VARCHAR(50)  NOT NULL
                    CHECK (scope_type IN ('rule', 'service', 'technology', 'provider')),
    scope_value     VARCHAR(255) NOT NULL,   -- rule_id | service | tech_category | provider

    provider        VARCHAR(50),             -- NULL = all providers (rule/tech scope)

    -- Metadata
    reason          TEXT,
    suppressed_by   VARCHAR(255) NOT NULL,
    suppressed_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ             -- NULL = permanent
);

-- Unique index: COALESCE handles NULL account_id and provider so two
-- NULL rows are treated as equal (PostgreSQL UNIQUE ignores NULLs otherwise).
CREATE UNIQUE INDEX IF NOT EXISTS rule_suppressions_unique_idx
    ON rule_suppressions (
        tenant_id,
        COALESCE(account_id, ''),
        scope_type,
        scope_value,
        COALESCE(provider, '')
    );

-- Lookup indexes
CREATE INDEX IF NOT EXISTS idx_rule_suppressions_tenant
    ON rule_suppressions (tenant_id);

CREATE INDEX IF NOT EXISTS idx_rule_suppressions_tenant_account
    ON rule_suppressions (tenant_id, account_id);

CREATE INDEX IF NOT EXISTS idx_rule_suppressions_scope
    ON rule_suppressions (scope_type, scope_value);

CREATE INDEX IF NOT EXISTS idx_rule_suppressions_expires
    ON rule_suppressions (expires_at)
    WHERE expires_at IS NOT NULL;

COMMIT;

\echo 'MIGRATION COMPLETE: check_rule_suppressions_001'
