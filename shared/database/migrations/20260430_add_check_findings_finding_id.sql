-- UP Migration: Add finding_id generated column to check_findings
-- Aligns check_findings with the standardized finding_id column used by all other engine tables.
-- finding_id = first 16 hex chars of sha256(rule_id|resource_uid|scan_run_id)
BEGIN;

ALTER TABLE check_findings
  ADD COLUMN IF NOT EXISTS finding_id TEXT GENERATED ALWAYS AS (
    substring(
      encode(
        sha256((rule_id || '|' || COALESCE(resource_uid, '') || '|' || scan_run_id)::bytea),
        'hex'
      ),
      1, 16
    )
  ) STORED;

CREATE INDEX IF NOT EXISTS idx_cf_finding_id ON check_findings(finding_id);

COMMIT;

-- DOWN Migration
-- BEGIN;
-- DROP INDEX IF EXISTS idx_cf_finding_id;
-- ALTER TABLE check_findings DROP COLUMN IF EXISTS finding_id;
-- COMMIT;
