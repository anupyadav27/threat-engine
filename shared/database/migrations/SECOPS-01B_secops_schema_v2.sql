-- SECOPS-01B: Extend secops_report + secops_findings, backfill customer_id, create secops_latest_scan
-- Target DB: secops DB
-- Story: SECOPS-01 — adds account_id/scan_run_id for code-repo account flow; creates deterministic
--         latest-scan table replacing Python-side _latest_per_repo() deduplication
-- Idempotent: ADD COLUMN IF NOT EXISTS, CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS

BEGIN;

-- 1. Extend secops_report: account_id + scan_run_id (both nullable, no default)
ALTER TABLE secops_report
    ADD COLUMN IF NOT EXISTS account_id  VARCHAR(255),
    ADD COLUMN IF NOT EXISTS scan_run_id VARCHAR(255);

-- 2. Extend secops_findings: account_id (nullable, no default)
ALTER TABLE secops_findings
    ADD COLUMN IF NOT EXISTS account_id VARCHAR(255);

-- 3. Backfill customer_id = tenant_id where NULL/empty
--    WHERE guard ensures rows with a correctly-set customer_id are not overwritten
UPDATE secops_report
SET    customer_id = tenant_id
WHERE  tenant_id IS NOT NULL
  AND  (customer_id IS NULL OR customer_id = '');

-- 4. Create secops_latest_scan: one row per (tenant_id, account_id, scan_type)
--    Upserted by the engine on scan completion; replaces Python-side deduplication in BFF
CREATE TABLE IF NOT EXISTS secops_latest_scan (
    tenant_id           VARCHAR(255)    NOT NULL,
    account_id          VARCHAR(255)    NOT NULL,
    scan_type           VARCHAR(50)     NOT NULL,   -- 'sast' | 'dast'
    customer_id         VARCHAR(255),
    repo_url            TEXT,
    project_name        VARCHAR(512),
    default_branch      VARCHAR(255),
    secops_scan_id      VARCHAR(255),
    scan_run_id         VARCHAR(255),
    scan_timestamp      TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    status              VARCHAR(50),
    total_findings      INTEGER         DEFAULT 0,
    critical_count      INTEGER         DEFAULT 0,
    high_count          INTEGER         DEFAULT 0,
    medium_count        INTEGER         DEFAULT 0,
    low_count           INTEGER         DEFAULT 0,
    files_scanned       INTEGER         DEFAULT 0,
    languages_detected  JSONB           DEFAULT '[]'::jsonb,
    first_seen_at       TIMESTAMPTZ     DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ     DEFAULT NOW(),
    PRIMARY KEY (tenant_id, account_id, scan_type)
);

-- Tenant-scoped lookup index (all queries will include tenant_id via PK; secondary idx for range scans)
CREATE INDEX IF NOT EXISTS idx_secops_latest_scan_tenant
    ON secops_latest_scan (tenant_id);

RAISE NOTICE 'MIGRATION COMPLETE';

COMMIT;

-- MIGRATION COMPLETE
