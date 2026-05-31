-- =============================================================================
-- API Security Engine — Initial Schema
-- Target DB: threat_engine_api_security
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id  VARCHAR(255) PRIMARY KEY,
    created_at TIMESTAMPTZ  DEFAULT NOW() NOT NULL
);

CREATE TABLE IF NOT EXISTS api_security_findings (
    finding_id              UUID         DEFAULT gen_random_uuid() PRIMARY KEY,
    scan_run_id             UUID         NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL REFERENCES tenants(tenant_id),
    account_id              VARCHAR(512),
    credential_ref          VARCHAR(512),
    credential_type         VARCHAR(50),
    provider                VARCHAR(50)  NOT NULL,
    region                  VARCHAR(100),
    resource_uid            VARCHAR(1024) NOT NULL,
    resource_type           VARCHAR(255) NOT NULL,
    severity                VARCHAR(20)  NOT NULL,
    status                  VARCHAR(20)  NOT NULL DEFAULT 'open',
    first_seen_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    rule_id                 VARCHAR(128) NOT NULL,
    finding_source          VARCHAR(30)  NOT NULL,
    owasp_api_category      VARCHAR(10),
    owasp_api_label         VARCHAR(100),
    api_gateway_id          VARCHAR(512),
    api_name                VARCHAR(512),
    api_stage               VARCHAR(128),
    api_version             VARCHAR(50),
    api_protocol            VARCHAR(20),
    auth_type               VARCHAR(50),
    has_waf                 BOOLEAN      NOT NULL DEFAULT FALSE,
    has_rate_limit          BOOLEAN      NOT NULL DEFAULT FALSE,
    is_publicly_accessible  BOOLEAN      NOT NULL DEFAULT FALSE,
    is_deprecated_version   BOOLEAN      NOT NULL DEFAULT FALSE,
    backend_url             TEXT,
    backend_is_internal_ip  BOOLEAN      NOT NULL DEFAULT FALSE,
    cdr_actor_hash          VARCHAR(64),
    cdr_event_count         INTEGER      NOT NULL DEFAULT 0,
    cdr_first_event_at      TIMESTAMPTZ,
    cdr_last_event_at       TIMESTAMPTZ,
    mitre_technique_id      VARCHAR(20),
    mitre_tactic            VARCHAR(50),
    check_finding_id        VARCHAR(128),
    title                   VARCHAR(512) NOT NULL,
    description             TEXT,
    remediation             TEXT,
    evidence                JSONB,
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (rule_id, resource_uid, scan_run_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS api_security_report (
    report_id          UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    scan_run_id        UUID        NOT NULL UNIQUE,
    tenant_id          VARCHAR(255) NOT NULL REFERENCES tenants(tenant_id),
    provider           VARCHAR(50)  NOT NULL,
    account_id         VARCHAR(512),
    status             VARCHAR(20)  NOT NULL DEFAULT 'running',
    critical_count     INTEGER      NOT NULL DEFAULT 0,
    high_count         INTEGER      NOT NULL DEFAULT 0,
    medium_count       INTEGER      NOT NULL DEFAULT 0,
    low_count          INTEGER      NOT NULL DEFAULT 0,
    total_findings     INTEGER      NOT NULL DEFAULT 0,
    owasp_api1_count   INTEGER      NOT NULL DEFAULT 0,
    owasp_api2_count   INTEGER      NOT NULL DEFAULT 0,
    owasp_api4_count   INTEGER      NOT NULL DEFAULT 0,
    owasp_api7_count   INTEGER      NOT NULL DEFAULT 0,
    owasp_api8_count   INTEGER      NOT NULL DEFAULT 0,
    owasp_api9_count   INTEGER      NOT NULL DEFAULT 0,
    cdr_enriched_count INTEGER      NOT NULL DEFAULT 0,
    started_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at       TIMESTAMPTZ,
    report_data        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    generated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asf_tenant_scan ON api_security_findings(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_asf_resource    ON api_security_findings(tenant_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_asf_severity    ON api_security_findings(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_asf_owasp       ON api_security_findings(tenant_id, owasp_api_category);
CREATE INDEX IF NOT EXISTS idx_asf_public_nowaf
    ON api_security_findings(tenant_id, scan_run_id)
    WHERE is_publicly_accessible = TRUE AND has_waf = FALSE;
CREATE INDEX IF NOT EXISTS idx_asr_tenant_scan ON api_security_report(tenant_id, scan_run_id);

CREATE OR REPLACE FUNCTION asf_set_updated_at() RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END; $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_asf_updated_at ON api_security_findings;
CREATE TRIGGER trg_asf_updated_at
    BEFORE UPDATE ON api_security_findings
    FOR EACH ROW EXECUTE FUNCTION asf_set_updated_at();

DO $$ BEGIN RAISE NOTICE 'MIGRATION COMPLETE: apisec_001_initial_schema'; END; $$;
