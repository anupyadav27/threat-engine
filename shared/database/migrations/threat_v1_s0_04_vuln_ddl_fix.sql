-- threat_v1 Sprint 0 Story S0-04: Fix cve_attack_mappings DDL + add mitre_techniques to scan_vulnerabilities
-- Target DB: threat_engine_vulnerability (vuln engine DB)
-- Applied via: kubectl exec on engine-vulnerability pod
-- Date: 2026-05-10
--
-- Bug: The original cve_attack_mappings DDL had an extra comma in the UNIQUE constraint
-- (UNIQUE(cve_id,,) and a duplicate UNIQUE constraint with malformed syntax.
-- This migration drops the broken table and recreates it with correct DDL.
-- It also adds the mitre_techniques JSONB column to scan_vulnerabilities, required
-- by the threat_v1 VulnLoader (S1-05) to populate VulnFinding nodes in Neo4j.

BEGIN;

-- Step 1: Drop the broken cve_attack_mappings table if it exists
-- The table has a broken UNIQUE constraint and is unpopulated — safe to drop and recreate.
-- No FK children reference this table (it is the leaf in the cve→technique FK chain).
DROP TABLE IF EXISTS cve_attack_mappings;

-- Step 2: Recreate cve_attack_mappings with correct DDL
CREATE TABLE IF NOT EXISTS cve_attack_mappings (
    id               SERIAL PRIMARY KEY,
    cve_id           VARCHAR(20)  REFERENCES cves(cve_id) ON DELETE CASCADE,
    technique_id     VARCHAR(10)  REFERENCES mitre_techniques(technique_id),
    confidence_level VARCHAR(10)  DEFAULT 'medium' CHECK (confidence_level IN ('low', 'medium', 'high')),
    mapping_source   VARCHAR(100),
    created_at       TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT cve_attack_mappings_cve_technique_uq UNIQUE (cve_id, technique_id)
);

COMMENT ON TABLE cve_attack_mappings IS
    'CVE to MITRE ATT&CK technique mappings. Populated by NVD parser heuristic. '
    'Fixed in Sprint 0 S0-04 — original DDL had a broken UNIQUE constraint with extra comma.';

-- Step 3: Add mitre_techniques JSONB column to scan_vulnerabilities
-- Column does not exist yet. ADD COLUMN IF NOT EXISTS is safe for existing rows (NULL default).
-- NULL (not empty array []) is used when no techniques apply — simplifies IS NOT NULL queries.
ALTER TABLE scan_vulnerabilities
    ADD COLUMN IF NOT EXISTS mitre_techniques JSONB;

COMMENT ON COLUMN scan_vulnerabilities.mitre_techniques IS
    'MITRE ATT&CK technique IDs inferred from CVE CVSS vector. '
    'Populated by NVD parser heuristic: CVSS >= 9.0 AND attackVector=NETWORK → T1190; '
    'additionally T1595.002 when cisaExploitAdd is set. NULL when no techniques apply. '
    'Added in Sprint 0 S0-04. Read by threat_v1 VulnLoader (S1-05).';

-- Step 4: GIN index for pattern matching queries (threat_v1 VulnLoader joins on this column)
CREATE INDEX IF NOT EXISTS idx_scan_vulnerabilities_mitre
    ON scan_vulnerabilities USING GIN (mitre_techniques);

COMMIT;

-- Verify the migration applied correctly
-- Run these SELECT statements after COMMIT to confirm:

SELECT
    'cve_attack_mappings' AS check_name,
    to_regclass('public.cve_attack_mappings')::text AS result
UNION ALL
SELECT
    'scan_vulnerabilities.mitre_techniques',
    (SELECT data_type
     FROM information_schema.columns
     WHERE table_name  = 'scan_vulnerabilities'
       AND column_name = 'mitre_techniques')
UNION ALL
SELECT
    'idx_scan_vulnerabilities_mitre',
    (SELECT indexname::text
     FROM pg_indexes
     WHERE tablename = 'scan_vulnerabilities'
       AND indexname  = 'idx_scan_vulnerabilities_mitre')
UNION ALL
SELECT
    'cve_attack_mappings unique constraint count',
    COUNT(*)::text
FROM information_schema.table_constraints
WHERE table_name      = 'cve_attack_mappings'
  AND constraint_type = 'UNIQUE';

-- Expected output:
-- cve_attack_mappings                      | cve_attack_mappings
-- scan_vulnerabilities.mitre_techniques    | jsonb
-- idx_scan_vulnerabilities_mitre           | idx_scan_vulnerabilities_mitre
-- cve_attack_mappings unique constraint count | 1

-- Print completion marker (required by CLAUDE.md migration protocol)
DO $$ BEGIN RAISE NOTICE 'MIGRATION COMPLETE: threat_v1_s0_04_vuln_ddl_fix'; END $$;
