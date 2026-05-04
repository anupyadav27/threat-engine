-- ============================================================
-- Technology Engine Database Schema
-- Database: threat_engine_tech
-- Aligned with cloud engine standard columns
-- ============================================================

-- ── Credentials registry (ARN only — no plaintext secrets) ──
CREATE TABLE IF NOT EXISTS tech_credentials (
    credential_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(255) NOT NULL,
    account_id      VARCHAR(255) NOT NULL,
    tech_type       VARCHAR(50)  NOT NULL,  -- postgres|ubuntu|cisco_ios|docker|...
    tech_category   VARCHAR(50)  NOT NULL,  -- db|linux|network|web_server|...
    host            VARCHAR(500) NOT NULL,
    port            INTEGER,
    display_name    VARCHAR(255),
    credential_type  VARCHAR(50)  NOT NULL,  -- username_password|ssh_key|ssh_password|api_token|oauth|...
    credential_ref   VARCHAR(500) NOT NULL,  -- Secrets Manager ARN
    sudo_required    BOOLEAN      DEFAULT false,
    ssh_private_key  TEXT         DEFAULT NULL,  -- RESERVED: key lives in Secrets Manager; ARN in credential_ref
    status           VARCHAR(50)  NOT NULL DEFAULT 'active',
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (tenant_id, tech_type, host)
);

-- ── Rule catalog (mirrors rule_discoveries in check DB) ─────
CREATE TABLE IF NOT EXISTS tech_rule_discoveries (
    id            SERIAL PRIMARY KEY,
    tech_type     VARCHAR(50)  NOT NULL,
    tech_category VARCHAR(50)  NOT NULL,
    discovery_id  VARCHAR(255) NOT NULL UNIQUE,
    display_name  VARCHAR(500),
    action_type   VARCHAR(50),  -- query_setting|ssh_command|api_call|cli_command|...
    yaml_path     VARCHAR(500),
    is_active     BOOLEAN      NOT NULL DEFAULT true,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ── Check rule metadata (mirrors rule_metadata) ──────────────
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

-- ── Compliance framework mappings (mirrors rule_control_mapping) ─
CREATE TABLE IF NOT EXISTS tech_rule_control_mapping (
    id           SERIAL PRIMARY KEY,
    rule_id      VARCHAR(255) NOT NULL REFERENCES tech_rule_metadata(rule_id),
    framework    VARCHAR(100) NOT NULL,  -- cis_postgres_15|nist_800_53|soc2|pci_dss_v4|...
    control_id   VARCHAR(100) NOT NULL,
    control_name VARCHAR(500),
    created_at   TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (rule_id, framework, control_id)
);

-- ── Discovery findings (raw JSONB output per query) ──────────
CREATE TABLE IF NOT EXISTS tech_discovery_findings (
    id              BIGSERIAL PRIMARY KEY,
    finding_id      VARCHAR(64)  NOT NULL,
    scan_run_id     UUID         NOT NULL,
    tenant_id       VARCHAR(255) NOT NULL,
    account_id      VARCHAR(255) NOT NULL,
    credential_ref  VARCHAR(500),
    credential_type VARCHAR(50),
    provider        VARCHAR(50)  NOT NULL,  -- = tech_type (postgres, ubuntu, etc.)
    tech_category   VARCHAR(50)  NOT NULL,
    region          VARCHAR(255),           -- maps to 'host' for on-prem
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

-- ── Inventory assets (normalized) ───────────────────────────
CREATE TABLE IF NOT EXISTS tech_inventory_assets (
    id              BIGSERIAL PRIMARY KEY,
    asset_id        VARCHAR(64)  NOT NULL UNIQUE,
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
    asset_name      VARCHAR(500),
    version         VARCHAR(100),
    os_version      VARCHAR(100),
    metadata        JSONB        DEFAULT '{}',
    cloud_resource_uid VARCHAR(500),  -- link to cloud inventory if co-located
    severity        VARCHAR(20),
    status          VARCHAR(50)  NOT NULL DEFAULT 'active',
    first_seen_at   TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ── Check findings (PASS/FAIL per rule) ─────────────────────
CREATE TABLE IF NOT EXISTS tech_check_findings (
    id                  BIGSERIAL PRIMARY KEY,
    finding_id          VARCHAR(64)  NOT NULL,  -- sha256(rule_id|resource_uid|scan_run_id)[:16]
    scan_run_id         UUID         NOT NULL,
    tenant_id           VARCHAR(255) NOT NULL,
    account_id          VARCHAR(255) NOT NULL,
    credential_ref      VARCHAR(500),
    credential_type     VARCHAR(50),
    provider            VARCHAR(50)  NOT NULL,
    tech_category       VARCHAR(50)  NOT NULL,
    region              VARCHAR(255),
    resource_uid        VARCHAR(500) NOT NULL,
    resource_type       VARCHAR(255),
    rule_id             VARCHAR(255) NOT NULL,
    rule_title          VARCHAR(500),
    cis_benchmark       VARCHAR(255),
    severity            VARCHAR(20)  NOT NULL DEFAULT 'medium',
    status              VARCHAR(20)  NOT NULL DEFAULT 'FAIL',  -- PASS|FAIL|ERROR|SKIP
    evidence            JSONB        DEFAULT '{}',
    framework_mappings  JSONB        DEFAULT '{}',  -- {nist:[AC-6], soc2:[CC6.1], ...}
    remediation         TEXT,
    first_seen_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (finding_id, scan_run_id)
);

-- ── CIEM findings (auth/access event anomalies) ──────────────
CREATE TABLE IF NOT EXISTS tech_ciem_findings (
    id               BIGSERIAL PRIMARY KEY,
    finding_id       VARCHAR(64)  NOT NULL,
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
    mitre_technique  VARCHAR(20),   -- T1110, T1078, T1068, ...
    mitre_tactic     VARCHAR(100),
    actor            VARCHAR(255),  -- username or IP
    source_ip        INET,
    event_time       TIMESTAMP WITH TIME ZONE,
    severity         VARCHAR(20)  NOT NULL DEFAULT 'high',
    status           VARCHAR(50)  NOT NULL DEFAULT 'open',
    evidence         JSONB        DEFAULT '{}',
    first_seen_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at     TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (finding_id)
);

-- ── Indexes ──────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_tech_disc_scan      ON tech_discovery_findings (scan_run_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_tech_disc_provider  ON tech_discovery_findings (provider, tech_category);
CREATE INDEX IF NOT EXISTS idx_tech_inv_tenant     ON tech_inventory_assets   (tenant_id, provider);
CREATE INDEX IF NOT EXISTS idx_tech_check_scan     ON tech_check_findings     (scan_run_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_tech_check_rule     ON tech_check_findings     (rule_id, status);
CREATE INDEX IF NOT EXISTS idx_tech_ciem_scan      ON tech_ciem_findings      (scan_run_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_tech_ciem_mitre     ON tech_ciem_findings      (mitre_technique);
CREATE INDEX IF NOT EXISTS idx_tech_ciem_actor     ON tech_ciem_findings      (actor, provider);
