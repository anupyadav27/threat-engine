-- Migration 030: add pipeline_scan_run_id to scan_vulnerabilities
-- Allows linking each vulnerability finding back to the Argo pipeline run
-- that triggered the scan, joining to scan_orchestration on pipeline scan_run_id.
-- DB: vulnerability_db

BEGIN;

ALTER TABLE scan_vulnerabilities
    ADD COLUMN IF NOT EXISTS pipeline_scan_run_id VARCHAR(36);

CREATE INDEX IF NOT EXISTS idx_scan_vulns_pipeline_run
    ON scan_vulnerabilities (pipeline_scan_run_id)
    WHERE pipeline_scan_run_id IS NOT NULL;

COMMENT ON COLUMN scan_vulnerabilities.pipeline_scan_run_id IS
    'Argo pipeline scan_run_id from scan_orchestration; populated when the vul engine is triggered via the main pipeline';

COMMIT;
