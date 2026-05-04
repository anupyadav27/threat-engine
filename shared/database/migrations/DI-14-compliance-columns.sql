-- DI-14: compliance_report — add overall_score if missing
-- compliance_report already has: total_controls, controls_passed, controls_failed, total_findings
-- Apply via:
--   kubectl cp DI-14-compliance-columns.sql threat-engine-engines/<compliance-pod>:/tmp/
--   kubectl exec -n threat-engine-engines deployment/engine-compliance -- \
--       psql -h $COMPLIANCE_DB_HOST -U $COMPLIANCE_DB_USER -d $COMPLIANCE_DB_NAME \
--       -f /tmp/DI-14-compliance-columns.sql

BEGIN;

ALTER TABLE compliance_report
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
