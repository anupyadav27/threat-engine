-- =============================================================================
-- Migration 0014: Add admin_email_domain column to org_subscriptions.
-- Database:  threat_engine_billing
-- Idempotent: ADD COLUMN IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.
-- =============================================================================
-- Apply:
--   kubectl cp .../0014_billing_add_admin_email_domain.sql \
--     threat-engine-engines/<pod>:/tmp/0014.sql
--   kubectl exec -n threat-engine-engines <pod> -- \
--     psql -h $BILLING_DB_HOST -U billing_app -d threat_engine_billing \
--     -f /tmp/0014.sql
-- =============================================================================

BEGIN;

-- Add admin_email_domain column (derived from the org admin's email address at
-- trial-provision time — used for cross-org trial-abuse detection in addition to
-- the existing org_email_domain field which captures the org's domain slug).
ALTER TABLE org_subscriptions
    ADD COLUMN IF NOT EXISTS admin_email_domain VARCHAR(255);

-- Index for fast domain-deduplication queries in the trial provisioning path.
CREATE INDEX IF NOT EXISTS idx_org_subscriptions_admin_email_domain
    ON org_subscriptions(admin_email_domain)
    WHERE admin_email_domain IS NOT NULL;

COMMIT;

-- =============================================================================
-- Verification
-- =============================================================================
-- SELECT column_name, data_type
-- FROM information_schema.columns
-- WHERE table_name = 'org_subscriptions'
--   AND column_name = 'admin_email_domain';
-- Expected: one row with data_type = 'character varying'
-- =============================================================================
