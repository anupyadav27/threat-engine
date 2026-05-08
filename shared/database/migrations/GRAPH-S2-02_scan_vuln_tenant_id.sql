-- GRAPH-S2-02: Add tenant_id to scan_vulnerabilities
-- Applied: 2026-05-07 via kubectl exec on engine-threat pod
-- Purpose: E2 CVE loader queries sbom_vulnerabilities WHERE tenant_id = %s
--          (actual table is scan_vulnerabilities in vulnerability_db)
-- Status: Already applied to production

ALTER TABLE scan_vulnerabilities
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

CREATE INDEX IF NOT EXISTS idx_scan_vuln_tenant_id
    ON scan_vulnerabilities(tenant_id);

-- MIGRATION COMPLETE
