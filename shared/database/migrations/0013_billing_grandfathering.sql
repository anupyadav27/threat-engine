-- =============================================================================
-- Migration 0013: Grandfather all existing orgs onto the Pro plan for 90 days.
-- Database:  threat_engine_billing
-- Idempotent: safe to re-run (ON CONFLICT guards + WHERE clauses prevent
--             double-grandfathering and duplicate audit rows).
-- =============================================================================
-- Apply:
--   kubectl cp .../0013_billing_grandfathering.sql threat-engine-engines/<pod>:/tmp/0013.sql
--   kubectl exec -n threat-engine-engines <pod> -- \
--     psql -h $BILLING_DB_HOST -U billing_app -d threat_engine_billing -f /tmp/0013.sql
-- Then run the Python companion script to handle orgs with no subscription row yet:
--   python3 shared/database/migrations/0013_billing_grandfathering.py
-- =============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- Step 1: For orgs that ALREADY have a subscription row but have NOT been
--         grandfathered yet, upgrade them to the Pro plan + set overridden flags.
-- ---------------------------------------------------------------------------
UPDATE org_subscriptions os
SET
    plan_id              = (
        SELECT plan_id
        FROM subscription_plans
        WHERE plan_name = 'pro'
        LIMIT 1
    ),
    is_overridden        = true,
    override_reason      = 'Grandfathered — existing user, 90-day Pro equivalent',
    override_by_user_id  = 'system_migration_0013',
    grandfathered_until  = now() + INTERVAL '90 days',
    updated_at           = now()
WHERE os.grandfathered_until IS NULL
  AND os.is_overridden = false;

-- ---------------------------------------------------------------------------
-- Step 2: Log a billing_audit_log row for every org that was just grandfathered
--         (or was grandfathered in a prior run by this same migration).
--         The NOT EXISTS guard makes this block idempotent.
-- ---------------------------------------------------------------------------
INSERT INTO billing_audit_log
    (org_id, event_type, actor_id, actor_role, change_summary, new_state)
SELECT
    os.org_id,
    'grandfathering.applied',
    'system_migration_0013',
    'system',
    'Existing org grandfathered to Pro plan for 90 days from billing launch',
    json_build_object(
        'plan',              'pro',
        'grandfathered_until', (os.grandfathered_until)::text,
        'is_overridden',     true
    )
FROM org_subscriptions os
WHERE os.is_overridden = true
  AND os.override_by_user_id = 'system_migration_0013'
  AND NOT EXISTS (
      SELECT 1
      FROM billing_audit_log bal
      WHERE bal.org_id      = os.org_id
        AND bal.event_type  = 'grandfathering.applied'
  );

-- ---------------------------------------------------------------------------
-- Verification — prints row counts to stdout for the operator to confirm.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    grandfathered_count INTEGER;
    audit_count         INTEGER;
BEGIN
    SELECT COUNT(*) INTO grandfathered_count
    FROM org_subscriptions
    WHERE is_overridden = true
      AND override_by_user_id = 'system_migration_0013';

    SELECT COUNT(*) INTO audit_count
    FROM billing_audit_log
    WHERE event_type = 'grandfathering.applied';

    RAISE NOTICE '0013 grandfathering: org_subscriptions rows grandfathered = %', grandfathered_count;
    RAISE NOTICE '0013 grandfathering: billing_audit_log rows written       = %', audit_count;
END
$$;

COMMIT;

-- =============================================================================
-- NOTE: Orgs that exist in the Django platform DB but have NO row in
--       org_subscriptions at the time this SQL runs are handled by the companion
--       Python script: shared/database/migrations/0013_billing_grandfathering.py
--       Run it AFTER applying this SQL file.
-- =============================================================================
