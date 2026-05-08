-- DI-14: compliance tables — add missing columns found by gap report (DI-13)
-- Gap: compliance_frameworks.csp missing; compliance_report needs overall_score + index.
-- Apply via:
--   kubectl cp DI-14-compliance-columns.sql threat-engine-engines/<compliance-pod>:/tmp/
--   kubectl exec -n threat-engine-engines deployment/engine-compliance -- \
--       psql -h $COMPLIANCE_DB_HOST -U $COMPLIANCE_DB_USER -d $COMPLIANCE_DB_NAME \
--       -f /tmp/DI-14-compliance-columns.sql

BEGIN;

-- compliance_frameworks: add csp column (BFF filters frameworks by CSP)
ALTER TABLE compliance_frameworks
    ADD COLUMN IF NOT EXISTS csp VARCHAR(20);

-- Backfill csp from framework_name heuristics (CIS AWS → aws, CIS Azure → azure, etc.)
UPDATE compliance_frameworks
SET csp = CASE
    WHEN LOWER(framework_name) LIKE '%aws%'   THEN 'aws'
    WHEN LOWER(framework_name) LIKE '%azure%' THEN 'azure'
    WHEN LOWER(framework_name) LIKE '%gcp%'   THEN 'gcp'
    WHEN LOWER(framework_name) LIKE '%oci%'   THEN 'oci'
    ELSE 'multi'
END
WHERE csp IS NULL;

-- compliance_report: add framework_id link + overall_score and index
ALTER TABLE compliance_report
    ADD COLUMN IF NOT EXISTS framework_id    UUID,
    ADD COLUMN IF NOT EXISTS overall_score   NUMERIC(5,2) DEFAULT 0.0;

-- Backfill overall_score as pass rate where we have data
UPDATE compliance_report
SET overall_score = ROUND(
    CASE WHEN total_controls > 0
         THEN (controls_passed::NUMERIC / total_controls) * 100
         ELSE 0
    END, 2
)
WHERE overall_score = 0 AND total_controls > 0;

-- Index for BFF compliance dashboard query
CREATE INDEX IF NOT EXISTS idx_compliance_report_tenant_framework
    ON compliance_report(tenant_id, scan_run_id);

COMMIT;
