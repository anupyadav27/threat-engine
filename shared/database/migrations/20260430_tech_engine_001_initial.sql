-- ============================================================
-- Migration: tech_engine_001_initial
-- Database:  threat_engine_tech  (TECH_DB_NAME)
-- Creates all tables for the technology engine pipeline
-- ============================================================

BEGIN;

-- ── Credentials registry ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS tech_credentials (
    credential_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(255) NOT NULL,
    account_id      VARCHAR(255) NOT NULL UNIQUE,
    tech_type       VARCHAR(50)  NOT NULL,
    tech_category   VARCHAR(50)  NOT NULL,
    host            VARCHAR(500) NOT NULL,
    port            INTEGER,
    display_name    VARCHAR(255),
    credential_type VARCHAR(50)  NOT NULL,
    credential_ref  VARCHAR(500) NOT NULL,
    status          VARCHAR(50)  NOT NULL DEFAULT 'active',
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (tenant_id, tech_type, host)
);

-- ── Rule catalog ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tech_rule_discoveries (
    id            SERIAL PRIMARY KEY,
    rule_id       VARCHAR(255),
    tech_type     VARCHAR(50)  NOT NULL,
    tech_category VARCHAR(50)  NOT NULL,
    discovery_id  VARCHAR(255) NOT NULL UNIQUE,
    display_name  VARCHAR(500),
    action_type   VARCHAR(50),
    yaml_path     VARCHAR(500),
    is_active     BOOLEAN      NOT NULL DEFAULT true,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ── Check rule metadata ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS tech_rule_metadata (
    id              SERIAL PRIMARY KEY,
    rule_id         VARCHAR(255) NOT NULL UNIQUE,
    tech_type       VARCHAR(50)  NOT NULL,
    tech_category   VARCHAR(50)  NOT NULL,
    title           VARCHAR(500) NOT NULL,
    severity        VARCHAR(20)  NOT NULL DEFAULT 'medium',
    cis_benchmark   VARCHAR(255),
    cis_section     VARCHAR(50),
    nist_controls   JSONB        DEFAULT '[]',
    soc2_criteria   JSONB        DEFAULT '[]',
    remediation     TEXT,
    rule_metadata   JSONB        DEFAULT '{}',
    is_active       BOOLEAN      NOT NULL DEFAULT true,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ── Control mappings ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tech_rule_control_mapping (
    id           SERIAL PRIMARY KEY,
    rule_id      VARCHAR(255) NOT NULL REFERENCES tech_rule_metadata(rule_id) ON DELETE CASCADE,
    framework    VARCHAR(100) NOT NULL,
    control_id   VARCHAR(100) NOT NULL,
    control_name VARCHAR(500),
    created_at   TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (rule_id, framework, control_id)
);

-- ── Scan orchestration ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tech_scan_orchestration (
    id                  BIGSERIAL PRIMARY KEY,
    scan_run_id         UUID         NOT NULL UNIQUE,
    tenant_id           VARCHAR(255) NOT NULL,
    account_id          VARCHAR(255),
    tech_type           VARCHAR(50),
    status              VARCHAR(50)  NOT NULL DEFAULT 'running',
    completed_engines   JSONB        DEFAULT '[]',
    error_engines       JSONB        DEFAULT '{}',
    finding_counts      JSONB        DEFAULT '{}',
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ── Discovery findings ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tech_discovery_findings (
    id              BIGSERIAL PRIMARY KEY,
    finding_id      VARCHAR(64)  NOT NULL,
    scan_run_id     UUID         NOT NULL,
    tenant_id       VARCHAR(255) NOT NULL,
    account_id      VARCHAR(255) NOT NULL,
    credential_ref  VARCHAR(500),
    credential_type VARCHAR(50),
    provider        VARCHAR(50)  NOT NULL,
    tech_category   VARCHAR(50)  NOT NULL,
    region          VARCHAR(255),
    resource_uid    VARCHAR(500) NOT NULL,
    resource_type   VARCHAR(255),
    discovery_id    VARCHAR(255),
    raw_data        JSONB        NOT NULL DEFAULT '{}',
    error_message   TEXT,
    severity        VARCHAR(20),
    status          VARCHAR(50)  NOT NULL DEFAULT 'active',
    first_seen_at   TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (finding_id, scan_run_id)
);

-- ── Inventory assets ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tech_inventory_assets (
    id                 BIGSERIAL PRIMARY KEY,
    asset_id           VARCHAR(64)  NOT NULL UNIQUE,
    scan_run_id        UUID         NOT NULL,
    tenant_id          VARCHAR(255) NOT NULL,
    account_id         VARCHAR(255) NOT NULL,
    credential_ref     VARCHAR(500),
    credential_type    VARCHAR(50),
    provider           VARCHAR(50)  NOT NULL,
    tech_category      VARCHAR(50)  NOT NULL,
    region             VARCHAR(255),
    resource_uid       VARCHAR(500) NOT NULL,
    resource_type      VARCHAR(255),
    asset_name         VARCHAR(500),
    version            VARCHAR(100),
    os_version         VARCHAR(100),
    metadata           JSONB        DEFAULT '{}',
    cloud_resource_uid VARCHAR(500),
    severity           VARCHAR(20),
    status             VARCHAR(50)  NOT NULL DEFAULT 'active',
    first_seen_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ── Check findings ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tech_check_findings (
    id                 BIGSERIAL PRIMARY KEY,
    finding_id         VARCHAR(64)  NOT NULL,
    scan_run_id        UUID         NOT NULL,
    tenant_id          VARCHAR(255) NOT NULL,
    account_id         VARCHAR(255) NOT NULL,
    credential_ref     VARCHAR(500),
    credential_type    VARCHAR(50),
    provider           VARCHAR(50)  NOT NULL,
    tech_category      VARCHAR(50)  NOT NULL,
    region             VARCHAR(255),
    resource_uid       VARCHAR(500) NOT NULL,
    resource_type      VARCHAR(255),
    rule_id            VARCHAR(255) NOT NULL,
    rule_title         VARCHAR(500),
    cis_benchmark      VARCHAR(255),
    severity           VARCHAR(20)  NOT NULL DEFAULT 'medium',
    status             VARCHAR(20)  NOT NULL DEFAULT 'FAIL',
    evidence           JSONB        DEFAULT '{}',
    framework_mappings JSONB        DEFAULT '{}',
    remediation        TEXT,
    first_seen_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (finding_id, scan_run_id)
);

-- ── CIEM findings ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tech_ciem_findings (
    id               BIGSERIAL PRIMARY KEY,
    finding_id       VARCHAR(64)  NOT NULL UNIQUE,
    scan_run_id      UUID         NOT NULL,
    tenant_id        VARCHAR(255) NOT NULL,
    account_id       VARCHAR(255) NOT NULL,
    credential_ref   VARCHAR(500),
    credential_type  VARCHAR(50),
    provider         VARCHAR(50)  NOT NULL,
    tech_category    VARCHAR(50)  NOT NULL,
    region           VARCHAR(255),
    resource_uid     VARCHAR(500) NOT NULL,
    resource_type    VARCHAR(255),
    rule_id          VARCHAR(255) NOT NULL,
    mitre_technique  VARCHAR(20),
    mitre_tactic     VARCHAR(100),
    actor            VARCHAR(255),
    source_ip        INET,
    event_time       TIMESTAMP WITH TIME ZONE,
    severity         VARCHAR(20)  NOT NULL DEFAULT 'high',
    status           VARCHAR(50)  NOT NULL DEFAULT 'open',
    evidence         JSONB        DEFAULT '{}',
    first_seen_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at     TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ── Indexes ───────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_tech_orch_scan       ON tech_scan_orchestration (scan_run_id);
CREATE INDEX IF NOT EXISTS idx_tech_disc_scan       ON tech_discovery_findings  (scan_run_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_tech_disc_provider   ON tech_discovery_findings  (provider, tech_category);
CREATE INDEX IF NOT EXISTS idx_tech_inv_tenant      ON tech_inventory_assets    (tenant_id, provider);
CREATE INDEX IF NOT EXISTS idx_tech_inv_resource    ON tech_inventory_assets    (resource_uid);
CREATE INDEX IF NOT EXISTS idx_tech_check_scan      ON tech_check_findings      (scan_run_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_tech_check_rule      ON tech_check_findings      (rule_id, status);
CREATE INDEX IF NOT EXISTS idx_tech_ciem_scan       ON tech_ciem_findings       (scan_run_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_tech_ciem_mitre      ON tech_ciem_findings       (mitre_technique);
CREATE INDEX IF NOT EXISTS idx_tech_ciem_actor      ON tech_ciem_findings       (actor, provider);

COMMIT;
