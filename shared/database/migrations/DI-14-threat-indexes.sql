-- DI-14: threat_detections — columns + performance indexes for BFF query patterns
-- Gap report (DI-13) found: scan_run_id, finding_id, risk_score missing from threat_detections.
-- The engine uses scan_id internally; scan_run_id is added for cross-engine correlation.
-- Apply via:
--   kubectl cp DI-14-threat-indexes.sql threat-engine-engines/<threat-pod>:/tmp/
--   kubectl exec -n threat-engine-engines deployment/engine-threat -- \
--       psql -h $THREAT_DB_HOST -U $THREAT_DB_USER -d $THREAT_DB_NAME -f /tmp/DI-14-threat-indexes.sql

BEGIN;

-- Add scan_run_id as alias for scan_id (cross-engine correlation column)
ALTER TABLE threat_detections
    ADD COLUMN IF NOT EXISTS scan_run_id UUID;

-- Backfill scan_run_id from scan_id for existing rows
UPDATE threat_detections
SET scan_run_id = scan_id::UUID
WHERE scan_run_id IS NULL AND scan_id IS NOT NULL;

-- Add finding_id (standard column expected across all engine finding tables)
ALTER TABLE threat_detections
    ADD COLUMN IF NOT EXISTS finding_id VARCHAR(32);

-- Backfill finding_id using detection_id
UPDATE threat_detections
SET finding_id = LEFT(detection_id::TEXT, 32)
WHERE finding_id IS NULL AND detection_id IS NOT NULL;

-- Add risk_score (BFF expects it; threat engine uses severity-based scoring)
ALTER TABLE threat_detections
    ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;

-- Backfill risk_score from severity (critical=95, high=75, medium=50, low=25)
UPDATE threat_detections
SET risk_score = CASE severity
    WHEN 'critical' THEN 95
    WHEN 'high'     THEN 75
    WHEN 'medium'   THEN 50
    WHEN 'low'      THEN 25
    ELSE 0
END
WHERE risk_score = 0 AND severity IS NOT NULL;

-- Composite index for the primary BFF query pattern: tenant + scan
CREATE INDEX IF NOT EXISTS idx_threat_detections_tenant_scan
    ON threat_detections(tenant_id, scan_id);

-- Index on scan_run_id for cross-engine lookups
CREATE INDEX IF NOT EXISTS idx_threat_detections_scan_run_id
    ON threat_detections(scan_run_id);

-- GIN index for MITRE tactic array queries (MITRE ATT&CK Coverage page)
CREATE INDEX IF NOT EXISTS idx_threat_detections_mitre_tactics
    ON threat_detections USING GIN(mitre_tactics);

-- GIN index for technique queries
CREATE INDEX IF NOT EXISTS idx_threat_detections_mitre_techniques
    ON threat_detections USING GIN(mitre_techniques);

COMMIT;
