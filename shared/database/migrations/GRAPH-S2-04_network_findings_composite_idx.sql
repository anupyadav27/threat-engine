-- GRAPH-S2-04: Composite index on network_findings for ExposureLoader query
-- Speeds up: WHERE tenant_id = $1 AND scan_run_id = $2 AND status = 'FAIL'
-- and the tenant-only variant:  WHERE tenant_id = $1 AND status = 'FAIL'
-- Applied to: threat_engine_network database, network_findings table
--
-- CONCURRENTLY means no table lock is held during index creation.
-- Safe to run on a live RDS instance.
--
-- Apply via:
--   kubectl cp /tmp/GRAPH-S2-04_network_findings_composite_idx.sql \
--       threat-engine-engines/<pod>:/tmp/idx.sql
--   kubectl exec -n threat-engine-engines <pod> -- \
--       psql -h $NETWORK_DB_HOST -U $NETWORK_DB_USER \
--            -d threat_engine_network -f /tmp/idx.sql

\connect threat_engine_network

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_findings_tenant_scan_status
    ON network_findings (tenant_id, scan_run_id, status);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_findings_tenant_status
    ON network_findings (tenant_id, status);

-- Emit a clear completion marker for the migration job health check.
DO $$
BEGIN
    RAISE NOTICE 'GRAPH-S2-04 MIGRATION COMPLETE — indexes created on network_findings';
END
$$;
