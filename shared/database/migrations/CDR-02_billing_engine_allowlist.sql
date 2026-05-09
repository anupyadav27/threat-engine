-- Migration: CDR-02_billing_engine_allowlist
-- Target DB: threat_engine_billing
-- Purpose: Replace "ciem" with "cdr" in subscription_plans.engine_allowlist JSONB arrays.

BEGIN;

UPDATE subscription_plans
SET engine_allowlist = (
    SELECT jsonb_agg(CASE WHEN elem::text = '"ciem"' THEN '"cdr"'::jsonb ELSE elem END)
    FROM jsonb_array_elements(engine_allowlist) AS elem
)
WHERE engine_allowlist @> '["ciem"]'::jsonb;

COMMIT;
