-- threat_v1 Sprint 0 Story S0-04b: Add tenant/account/resource/scan segregation columns
-- to scan_vulnerabilities.
--
-- Target DB: threat_engine_vulnerability (vuln engine DB)
-- Applied via: kubectl exec on engine-vulnerability pod
-- Depends on: threat_v1_s0_04_vuln_ddl_fix.sql (must run first — fixes cve_attack_mappings)
--
-- Why these columns are needed:
--   scan_vulnerabilities today has only `scan_id` (short agent scan ID, VARCHAR(20)).
--   Without tenant_id / account_id / resource_uid / scan_run_id the table cannot:
--     - Segregate findings per tenant (multi-tenant violation)
--     - Segregate findings per pipeline run (scan_run_id is the platform UUID)
--     - Join to inventory_findings by resource_uid (blocks GraphBuilder VulnLoader)
--     - Filter by cloud account (blocks account-level blast radius)
--
-- MITRE mapping stays in cve_attack_mappings:
--   scan_vulnerabilities.cve_id → cve_attack_mappings.technique_id
--   This is the authoritative source — no new table needed.

BEGIN;

-- ── Step 1: Add segregation columns ──────────────────────────────────────────

ALTER TABLE scan_vulnerabilities
    ADD COLUMN IF NOT EXISTS tenant_id    VARCHAR(255),
    ADD COLUMN IF NOT EXISTS account_id   VARCHAR(512),
    ADD COLUMN IF NOT EXISTS resource_uid TEXT,
    ADD COLUMN IF NOT EXISTS scan_run_id  VARCHAR(255);

COMMENT ON COLUMN scan_vulnerabilities.tenant_id IS
    'Platform tenant identifier. Required for multi-tenant query isolation.';

COMMENT ON COLUMN scan_vulnerabilities.account_id IS
    'Cloud account ID (AWS account, Azure subscription, GCP project).';

COMMENT ON COLUMN scan_vulnerabilities.resource_uid IS
    'Canonical resource identifier. Joins to inventory_findings.resource_uid '
    'and enables GraphBuilder VulnLoader to create Asset→CVE edges in Neo4j.';

COMMENT ON COLUMN scan_vulnerabilities.scan_run_id IS
    'Pipeline UUID from scan_orchestration.scan_run_id. Distinct from the '
    'legacy scan_id (short agent scan ID). Used for per-run segregation.';

-- ── Step 2: Indexes for the new columns ──────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_scan_vuln_tenant
    ON scan_vulnerabilities(tenant_id);

CREATE INDEX IF NOT EXISTS idx_scan_vuln_account
    ON scan_vulnerabilities(account_id);

CREATE INDEX IF NOT EXISTS idx_scan_vuln_resource
    ON scan_vulnerabilities(resource_uid);

CREATE INDEX IF NOT EXISTS idx_scan_vuln_scan_run
    ON scan_vulnerabilities(scan_run_id);

-- Composite index for the most common query pattern (tenant + scan run)
CREATE INDEX IF NOT EXISTS idx_scan_vuln_tenant_scan
    ON scan_vulnerabilities(tenant_id, scan_run_id);

COMMIT;

-- ── Verify ────────────────────────────────────────────────────────────────────
-- Run after COMMIT to confirm all 4 columns exist:

SELECT
    column_name,
    data_type,
    is_nullable
FROM information_schema.columns
WHERE table_name = 'scan_vulnerabilities'
  AND column_name IN ('tenant_id', 'account_id', 'resource_uid', 'scan_run_id')
ORDER BY column_name;

-- Expected: 4 rows — account_id | character varying | YES
--                     resource_uid | text             | YES
--                     scan_run_id  | character varying | YES
--                     tenant_id    | character varying | YES

-- Verify indexes created:
SELECT indexname
FROM pg_indexes
WHERE tablename = 'scan_vulnerabilities'
  AND indexname LIKE 'idx_scan_vuln%'
ORDER BY indexname;

-- Expected 5 rows:
--   idx_scan_vuln_account
--   idx_scan_vuln_resource
--   idx_scan_vuln_scan_run
--   idx_scan_vuln_tenant
--   idx_scan_vuln_tenant_scan

DO $$ BEGIN RAISE NOTICE 'MIGRATION COMPLETE: threat_v1_s0_04b_vuln_segregation'; END $$;
