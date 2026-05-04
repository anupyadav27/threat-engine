-- DI-14: risk_scenarios — add blast_radius and resource_count if missing
-- Apply via:
--   kubectl cp DI-14-risk-columns.sql threat-engine-engines/<risk-pod>:/tmp/
--   kubectl exec -n threat-engine-engines deployment/engine-risk -- \
--       psql -h $RISK_DB_HOST -U $RISK_DB_USER -d $RISK_DB_NAME \
--       -f /tmp/DI-14-risk-columns.sql

BEGIN;

ALTER TABLE risk_scenarios
    ADD COLUMN IF NOT EXISTS blast_radius    INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS resource_count  INTEGER DEFAULT 0;

-- Backfill blast_radius from blast_radius_score if the column was renamed
UPDATE risk_scenarios
SET blast_radius = blast_radius_score::INTEGER
WHERE blast_radius = 0
  AND blast_radius_score IS NOT NULL
  AND blast_radius_score > 0;

COMMIT;
