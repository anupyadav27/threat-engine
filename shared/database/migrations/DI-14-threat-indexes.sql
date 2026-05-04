-- DI-14: threat_detections — performance indexes for BFF query patterns
-- Apply via:
--   kubectl cp DI-14-threat-indexes.sql threat-engine-engines/<threat-pod>:/tmp/
--   kubectl exec -n threat-engine-engines deployment/engine-threat -- \
--       psql -h $THREAT_DB_HOST -U $THREAT_DB_USER -d $THREAT_DB_NAME -f /tmp/DI-14-threat-indexes.sql

BEGIN;

-- Composite index for the primary BFF query pattern: tenant + scan
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_detections_tenant_scan
    ON threat_detections(tenant_id, scan_id);

-- GIN index for MITRE tactic array queries (MITRE ATT&CK Coverage page)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_detections_mitre_tactics
    ON threat_detections USING GIN(mitre_tactics);

-- GIN index for technique queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_detections_mitre_techniques
    ON threat_detections USING GIN(mitre_techniques);

COMMIT;
