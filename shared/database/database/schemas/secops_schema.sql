-- SecOps Engine Schema
-- Database: threat_engine_secops
-- Tables: secops_rule_metadata, secops_report, secops_findings, secops_latest_scan
-- Supports: SAST, DAST, SCA scan types
-- Last updated: SECOPS-01B migration (account_id, scan_run_id, secops_latest_scan)

-- Rule metadata (seeded from scanner docs, ~2,899 rules across 14 languages)
CREATE TABLE IF NOT EXISTS secops_rule_metadata (
    rule_id          VARCHAR(512) NOT NULL,
    scanner          VARCHAR(64)  NOT NULL,   -- python, terraform, java, docker, kubernetes, ansible, javascript, csharp, azure, cloudformation, go, cpp, c, ruby
    PRIMARY KEY (rule_id, scanner),
    title            TEXT,
    description      TEXT,
    default_severity VARCHAR(64),             -- Raw from docs: Critical, Major, Minor, Info, Blocker
    severity         VARCHAR(32)  NOT NULL,   -- Normalized: critical, high, medium, low, info
    status           VARCHAR(32)  DEFAULT 'ready',  -- ready, active, deprecated, disabled
    category         VARCHAR(128),            -- VULNERABILITY, CODE_SMELL, SECURITY_HOTSPOT, BUG, Security, etc
    rule_type        VARCHAR(64),             -- Normalized type
    impact           TEXT,
    recommendation   TEXT,
    remediation      TEXT,
    "references"     JSONB,
    tags             JSONB,
    examples         JSONB,
    security_mappings JSONB,                  -- CWE, OWASP, PCI DSS mappings
    logic            JSONB,                   -- Full rule logic definition
    raw_metadata     JSONB        NOT NULL,   -- Complete original JSON (source of truth)
    metadata_source  VARCHAR(32)  DEFAULT 'seed',  -- seed, manual, generated
    created_at       TIMESTAMPTZ  DEFAULT now(),
    updated_at       TIMESTAMPTZ  DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_srm_scanner    ON secops_rule_metadata(scanner);
CREATE INDEX IF NOT EXISTS idx_srm_severity   ON secops_rule_metadata(severity);
CREATE INDEX IF NOT EXISTS idx_srm_category   ON secops_rule_metadata(category);
CREATE INDEX IF NOT EXISTS idx_srm_status     ON secops_rule_metadata(status);


-- Scan report (one row per scan run)
-- account_id + scan_run_id added by SECOPS-01B migration
CREATE TABLE IF NOT EXISTS secops_report (
    secops_scan_id    UUID         PRIMARY KEY,
    orchestration_id  UUID,
    tenant_id         VARCHAR(255) NOT NULL,
    customer_id       VARCHAR(255),
    account_id        VARCHAR(255),            -- code-repo cloud account ID (SECOPS-01B)
    scan_run_id       VARCHAR(255),            -- pipeline scan_run_id (SECOPS-01B)
    project_name      VARCHAR(512) NOT NULL,   -- Repo name (hierarchy_id equivalent)
    repo_url          VARCHAR(1024) NOT NULL,
    branch            VARCHAR(255) DEFAULT 'main',
    provider          VARCHAR(64)  DEFAULT 'git',
    scan_type         VARCHAR(20)  DEFAULT 'sast',  -- sast, dast, sca
    status            VARCHAR(32)  NOT NULL,   -- queued, running, completed, failed
    scan_timestamp    TIMESTAMPTZ,
    completed_at      TIMESTAMPTZ,
    files_scanned     INTEGER      DEFAULT 0,
    total_findings    INTEGER      DEFAULT 0,
    total_errors      INTEGER      DEFAULT 0,
    languages_detected JSONB,                  -- ["python", "terraform", ...]
    summary           JSONB,
    metadata          JSONB,
    created_at        TIMESTAMPTZ  DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sr_tenant      ON secops_report(tenant_id, scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sr_project     ON secops_report(project_name);
CREATE INDEX IF NOT EXISTS idx_sr_orch        ON secops_report(orchestration_id) WHERE orchestration_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sr_status      ON secops_report(status);
CREATE INDEX IF NOT EXISTS idx_sr_scan_type   ON secops_report(scan_type);


-- Scan findings (one row per finding)
-- account_id added by SECOPS-01B migration
CREATE TABLE IF NOT EXISTS secops_findings (
    id               BIGSERIAL    PRIMARY KEY,
    secops_scan_id   UUID         NOT NULL REFERENCES secops_report(secops_scan_id),
    tenant_id        VARCHAR(255) NOT NULL,
    customer_id      VARCHAR(255),
    account_id       VARCHAR(255),            -- code-repo cloud account ID (SECOPS-01B)
    file_path        VARCHAR(1024),            -- Relative to repo root
    language         VARCHAR(64),
    rule_id          VARCHAR(512),             -- References secops_rule_metadata.rule_id
    severity         VARCHAR(32)  NOT NULL,   -- Normalized: critical, high, medium, low, info
    message          TEXT,
    line_number      INTEGER,
    status           VARCHAR(32),             -- violation, not_applicable
    resource         VARCHAR(512),            -- Terraform resource name
    scan_type        VARCHAR(20)  DEFAULT 'sast',  -- sast, dast, sca
    metadata         JSONB,                   -- property_path, value, extras
    created_at       TIMESTAMPTZ  DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sf_scan_id     ON secops_findings(secops_scan_id);
CREATE INDEX IF NOT EXISTS idx_sf_tenant      ON secops_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sf_severity    ON secops_findings(severity);
CREATE INDEX IF NOT EXISTS idx_sf_language    ON secops_findings(language);
CREATE INDEX IF NOT EXISTS idx_sf_rule_id     ON secops_findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_sf_scan_type   ON secops_findings(scan_type);


-- Latest scan summary per (tenant_id, account_id, scan_type)
-- Upserted on scan completion; replaces Python-side _latest_per_repo() BFF deduplication (SECOPS-01B)
-- PK enforces: one row per logical repo-scan-type pair; tenant_id NOT NULL via PK
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

CREATE INDEX IF NOT EXISTS idx_secops_latest_scan_tenant
    ON secops_latest_scan (tenant_id);
