-- ============================================================================
-- Migration: check_finding_suppressions_002
-- Database:  threat_engine_check
-- Purpose:   Create finding_suppressions table for resource-level (per-finding)
--            suppression. Complements rule_suppressions (coarse-grain) with
--            fine-grain: suppress a specific resource+rule combination.
--
-- Who can use this:
--   analyst+     → POST /api/v1/findings/suppress  (rules:read permission)
--   tenant_admin+ → same, plus can lift any suppression (rules:write)
--
-- Apply via:
--   kubectl cp /tmp/check_finding_suppressions_002.sql \
--       threat-engine-engines/<check-pod>:/tmp/check_finding_suppressions_002.sql
--   kubectl exec -n threat-engine-engines <check-pod> -- psql \
--       -h $CHECK_DB_HOST -U $CHECK_DB_USER -d $CHECK_DB_NAME \
--       -f /tmp/check_finding_suppressions_002.sql
-- ============================================================================

\set ON_ERROR_STOP on

BEGIN;

CREATE TABLE IF NOT EXISTS finding_suppressions (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Multi-tenant scope (account_id is required — finding suppression is always account-scoped)
    tenant_id       VARCHAR(255) NOT NULL,
    account_id      VARCHAR(255) NOT NULL,

    -- What is suppressed (at least rule_id required; resource_uid makes it resource-specific)
    rule_id         VARCHAR(255) NOT NULL,
    resource_uid    VARCHAR(512),            -- NULL = suppress this rule across all resources in account
    finding_id      VARCHAR(255),            -- sha256-derived finding_id from check_findings (most precise)

    -- Metadata
    reason          TEXT,
    suppressed_by   VARCHAR(255) NOT NULL,
    suppressed_by_role VARCHAR(50),         -- role of the user who created the suppression (audit)
    suppressed_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ              -- NULL = permanent
);

-- Unique: one active suppression per tenant + account + rule + resource combo
CREATE UNIQUE INDEX IF NOT EXISTS finding_suppressions_unique_idx
    ON finding_suppressions (
        tenant_id,
        account_id,
        rule_id,
        COALESCE(resource_uid, ''),
        COALESCE(finding_id, '')
    );

CREATE INDEX IF NOT EXISTS idx_finding_suppressions_tenant
    ON finding_suppressions (tenant_id);

CREATE INDEX IF NOT EXISTS idx_finding_suppressions_tenant_account
    ON finding_suppressions (tenant_id, account_id);

CREATE INDEX IF NOT EXISTS idx_finding_suppressions_rule
    ON finding_suppressions (rule_id);

CREATE INDEX IF NOT EXISTS idx_finding_suppressions_resource
    ON finding_suppressions (resource_uid) WHERE resource_uid IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_finding_suppressions_finding
    ON finding_suppressions (finding_id) WHERE finding_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_finding_suppressions_expires
    ON finding_suppressions (expires_at) WHERE expires_at IS NOT NULL;

COMMIT;

\echo 'MIGRATION COMPLETE: check_finding_suppressions_002'
