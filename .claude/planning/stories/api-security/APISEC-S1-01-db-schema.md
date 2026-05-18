# Story APISEC-S1-01: DB Schema — api_security_findings + posture columns

## Status: done

## Metadata
- **Sprint**: APISEC Sprint 1
- **Points**: 3
- **Priority**: P0 — blocks all other stories
- **Blocks**: APISEC-S1-02 through S1-14
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer (schema touches multi-tenant inventory DB)

## Migration Files

### File 1: `shared/database/migrations/apisec_001_initial_schema.sql`
**Target DB**: `threat_engine_api_security` (new — must be created first)

```sql
-- tenant anchor (required by all engine DBs)
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
    finding_source          VARCHAR(30)  NOT NULL,  -- 'config' | 'behavioral' | 'correlated'
    owasp_api_category      VARCHAR(10),            -- 'API1'..'API10'
    owasp_api_label         VARCHAR(100),
    api_gateway_id          VARCHAR(512),
    api_name                VARCHAR(512),
    api_stage               VARCHAR(128),
    api_version             VARCHAR(50),
    api_protocol            VARCHAR(20),            -- REST | HTTP | WebSocket | GraphQL | gRPC
    auth_type               VARCHAR(50),            -- none | apikey | jwt | oauth2 | mtls | iam
    has_waf                 BOOLEAN      NOT NULL DEFAULT FALSE,
    has_rate_limit          BOOLEAN      NOT NULL DEFAULT FALSE,
    is_publicly_accessible  BOOLEAN      NOT NULL DEFAULT FALSE,
    is_deprecated_version   BOOLEAN      NOT NULL DEFAULT FALSE,
    backend_url             TEXT,
    backend_is_internal_ip  BOOLEAN      NOT NULL DEFAULT FALSE,
    cdr_actor_hash          VARCHAR(64),            -- SHA256(actor_principal) — PII-safe
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
    report_id       UUID         DEFAULT gen_random_uuid() PRIMARY KEY,
    scan_run_id     UUID         NOT NULL UNIQUE,
    tenant_id       VARCHAR(255) NOT NULL REFERENCES tenants(tenant_id),
    provider        VARCHAR(50)  NOT NULL,
    account_id      VARCHAR(512),
    status          VARCHAR(20)  NOT NULL DEFAULT 'running',
    critical_count  INTEGER      NOT NULL DEFAULT 0,
    high_count      INTEGER      NOT NULL DEFAULT 0,
    medium_count    INTEGER      NOT NULL DEFAULT 0,
    low_count       INTEGER      NOT NULL DEFAULT 0,
    total_findings  INTEGER      NOT NULL DEFAULT 0,
    owasp_api1_count  INTEGER    NOT NULL DEFAULT 0,
    owasp_api2_count  INTEGER    NOT NULL DEFAULT 0,
    owasp_api4_count  INTEGER    NOT NULL DEFAULT 0,
    owasp_api7_count  INTEGER    NOT NULL DEFAULT 0,
    owasp_api8_count  INTEGER    NOT NULL DEFAULT 0,
    owasp_api9_count  INTEGER    NOT NULL DEFAULT 0,
    cdr_enriched_count INTEGER   NOT NULL DEFAULT 0,
    started_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    report_data     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    generated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
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
CREATE TRIGGER trg_asf_updated_at
    BEFORE UPDATE ON api_security_findings
    FOR EACH ROW EXECUTE FUNCTION asf_set_updated_at();

DO $$ BEGIN RAISE NOTICE 'MIGRATION COMPLETE: apisec_001_initial_schema'; END; $$;
```

### File 2: `shared/database/migrations/apisec_002_posture_columns.sql`
**Target DB**: `threat_engine_inventory`

```sql
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS api_auth_type                VARCHAR(50),
    ADD COLUMN IF NOT EXISTS api_has_waf                  BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS api_has_rate_limit           BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS api_publicly_accessible      BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS api_deprecated_version_active BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS api_security_score           SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS api_detail                   JSONB;

CREATE INDEX IF NOT EXISTS idx_rsp_api_public_nowaf
    ON resource_security_posture(tenant_id, scan_run_id)
    WHERE api_publicly_accessible = TRUE AND api_has_waf = FALSE;

CREATE INDEX IF NOT EXISTS idx_rsp_api_score
    ON resource_security_posture(tenant_id, api_security_score)
    WHERE api_security_score IS NOT NULL;

DO $$ BEGIN RAISE NOTICE 'MIGRATION COMPLETE: apisec_002_posture_columns'; END; $$;
```

## Acceptance Criteria

- [ ] AC-1: `threat_engine_api_security` DB created; `apisec_001` applies cleanly — kubectl logs end with "MIGRATION COMPLETE: apisec_001_initial_schema"
- [ ] AC-2: `api_security_findings` table has UNIQUE constraint on `(rule_id, resource_uid, scan_run_id, tenant_id)`
- [ ] AC-3: `apisec_002` applies to `threat_engine_inventory` — 7 new columns visible in `\d resource_security_posture`
- [ ] AC-4: `api_auth_type` allows NULL (not API resources have no auth type); `api_has_waf` defaults FALSE
- [ ] AC-5: Both migrations are idempotent (run twice = no error)
- [ ] AC-6: No existing `resource_security_posture` rows affected — all new columns get defaults

## Definition of Done
- [ ] Both migration files committed
- [ ] apisec_001 applied to `threat_engine_api_security` DB via kubectl exec
- [ ] apisec_002 applied to `threat_engine_inventory` DB via kubectl exec
- [ ] Both kubectl log tails confirm MIGRATION COMPLETE
