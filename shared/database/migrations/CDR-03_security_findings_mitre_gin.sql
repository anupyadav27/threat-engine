-- CDR-03: GIN index for multi-technique querying on CDR security_findings
-- Enables: detail->'all_mitre_techniques' @> '["T1078"]'
-- Run against threat_engine_inventory DB (where security_findings lives).
-- Uses CONCURRENTLY to avoid table lock in production.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_sf_all_mitre_techniques'
    ) THEN
        EXECUTE 'CREATE INDEX CONCURRENTLY idx_sf_all_mitre_techniques
                 ON security_findings USING GIN ((detail -> ''all_mitre_techniques''))
                 WHERE source_engine = ''cdr''';
        RAISE NOTICE 'Created idx_sf_all_mitre_techniques';
    ELSE
        RAISE NOTICE 'idx_sf_all_mitre_techniques already exists — skipping';
    END IF;
END $$;
