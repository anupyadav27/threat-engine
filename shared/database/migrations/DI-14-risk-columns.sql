-- DI-14: risk_scenarios — add risk_score, severity, blast_radius aliases
-- Gap report (DI-13) found: risk_score and severity missing; engine uses fair_risk_score/risk_tier.
-- Apply via:
--   kubectl cp DI-14-risk-columns.sql threat-engine-engines/<risk-pod>:/tmp/
--   kubectl exec -n threat-engine-engines deployment/engine-risk -- \
--       psql -h $RISK_DB_HOST -U $RISK_DB_USER -d $RISK_DB_NAME \
--       -f /tmp/DI-14-risk-columns.sql

BEGIN;

-- Add standard risk_score alias (BFF expects it; engine uses fair_risk_score)
ALTER TABLE risk_scenarios
    ADD COLUMN IF NOT EXISTS risk_score      NUMERIC(10,2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS severity        VARCHAR(20),
    ADD COLUMN IF NOT EXISTS blast_radius    INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS resource_count  INTEGER DEFAULT 0;

-- Backfill risk_score from fair_risk_score
UPDATE risk_scenarios
SET risk_score = fair_risk_score
WHERE risk_score = 0
  AND fair_risk_score IS NOT NULL
  AND fair_risk_score > 0;

-- Backfill severity from risk_tier (critical/high/medium/low mapping)
UPDATE risk_scenarios
SET severity = CASE risk_tier
    WHEN 'critical' THEN 'critical'
    WHEN 'high'     THEN 'high'
    WHEN 'medium'   THEN 'medium'
    WHEN 'low'      THEN 'low'
    ELSE CASE
        WHEN fair_risk_score >= 75 THEN 'critical'
        WHEN fair_risk_score >= 50 THEN 'high'
        WHEN fair_risk_score >= 25 THEN 'medium'
        ELSE 'low'
    END
END
WHERE severity IS NULL;

-- Backfill blast_radius from blast_radius_score
UPDATE risk_scenarios
SET blast_radius = blast_radius_score::INTEGER
WHERE blast_radius = 0
  AND blast_radius_score IS NOT NULL
  AND blast_radius_score > 0;

COMMIT;
