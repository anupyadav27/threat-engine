-- security_findings_schema.sql
-- Schema reference for the security_findings table in threat_engine_inventory DB.
-- This is the cross-engine unified findings layer: one row per individual violation
-- (misconfig, CVE, IAM violation, CDR event, data risk, network exposure).
-- Complements resource_security_posture (1 aggregate row per resource).
--
-- Applied via: shared/database/migrations/025_security_findings.sql
-- DB: threat_engine_inventory

CREATE TABLE IF NOT EXISTS security_findings (
    -- Primary key
    finding_id      UUID DEFAULT gen_random_uuid() PRIMARY KEY,

    -- Source identity (4 cols)
    source_engine   VARCHAR(30) NOT NULL,          -- 'check' | 'iam' | 'network' | 'datasec' | 'vuln' | 'cdr'
    source_finding_id VARCHAR(128) NOT NULL,        -- engine's own finding_id (sha256 hash or UUID)

    -- Standard columns (6 cols)
    resource_uid    VARCHAR(512) NOT NULL,
    scan_run_id     UUID NOT NULL,
    tenant_id       VARCHAR(255) NOT NULL,
    account_id      VARCHAR(512),
    provider        VARCHAR(30),
    resource_type   VARCHAR(128),

    -- Classification (7 cols)
    finding_type    VARCHAR(30) NOT NULL,           -- 'misconfig' | 'cve' | 'iam_violation' | 'cdr_event' | 'data_risk' | 'network_exposure'
    severity        VARCHAR(20) NOT NULL,           -- 'critical' | 'high' | 'medium' | 'low'
    rule_id         VARCHAR(128),
    title           VARCHAR(512),
    description     TEXT,
    epss_score      NUMERIC(5,4),                  -- 0.0000–1.0000; NULL for non-CVE findings
    cvss_score      NUMERIC(4,1),                  -- 0.0–10.0; NULL for non-CVE findings
    in_kev          BOOLEAN NOT NULL DEFAULT FALSE, -- TRUE if CVE is in CISA KEV

    -- Normalized evidence (5 cols)
    mitre_technique_id VARCHAR(20),                -- e.g. 'T1078'
    mitre_tactic    VARCHAR(50),                   -- e.g. 'Initial Access'
    detail          JSONB,                         -- engine-specific evidence blob

    -- Lifecycle (4 cols)
    status          VARCHAR(20) NOT NULL DEFAULT 'open',  -- 'open' | 'resolved' | 'suppressed'
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (source_engine, source_finding_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_sf_tenant_scan     ON security_findings (tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_sf_resource         ON security_findings (tenant_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_sf_severity         ON security_findings (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_sf_type             ON security_findings (tenant_id, finding_type);
CREATE INDEX IF NOT EXISTS idx_sf_engine           ON security_findings (tenant_id, source_engine);
CREATE INDEX IF NOT EXISTS idx_sf_open             ON security_findings (tenant_id, resource_uid) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_sf_epss             ON security_findings (tenant_id, epss_score DESC NULLS LAST) WHERE epss_score IS NOT NULL;

-- Auto-update trigger for updated_at
CREATE OR REPLACE FUNCTION sf_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sf_updated_at ON security_findings;
CREATE TRIGGER trg_sf_updated_at
    BEFORE UPDATE ON security_findings
    FOR EACH ROW EXECUTE FUNCTION sf_set_updated_at();
