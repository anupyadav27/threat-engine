-- Migration: add exclude_regions JSONB column to schedules table
-- Also ensures include_regions, include_services, exclude_services columns exist
-- (they were added in an earlier migration but listed here for idempotency).
--
-- Apply via:
--   kubectl cp 20260503_schedule_region_scope.sql \
--       threat-engine-engines/<onboarding-pod>:/tmp/migrate.sql
--   kubectl exec -n threat-engine-engines <onboarding-pod> -- \
--       psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f /tmp/migrate.sql

BEGIN;

ALTER TABLE schedules
    ADD COLUMN IF NOT EXISTS exclude_regions JSONB DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_schedules_tenant_enabled
    ON schedules(tenant_id, enabled);

COMMIT;
