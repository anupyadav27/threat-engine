-- =============================================================================
-- DEPRECATED — API Security Engine removed. Schema retained for historical data.
-- See engines/api/DEPRECATED.md
-- =============================================================================
-- API Security Engine Schema — Task 4.1
-- Database: threat_engine_api
-- Engine:   engine_api (Port 8021)
-- Purpose:  OWASP API Top 10 evaluation, API inventory, auth/rate-limit posture
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. api_rules — DB-driven rule definitions (OWASP API Top 10)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_rules (
    rule_id             VARCHAR(100)  PRIMARY KEY,
    title               VARCHAR(255)  NOT NULL,
    description         TEXT,
    owasp_category      VARCHAR(10),          -- API1 | API2 | ... | API10
    severity            VARCHAR(20)   NOT NULL DEFAULT 'medium',
    condition_type      VARCHAR(30)   NOT NULL,  -- field_check | threshold | set_membership | composite
    condition           JSONB         NOT NULL,
    frameworks          TEXT[]        DEFAULT '{}',
    remediation         TEXT,
    csp                 TEXT[]        DEFAULT '{aws}',
    is_active           BOOLEAN       DEFAULT true,
    created_at          TIMESTAMP     DEFAULT NOW(),
    updated_at          TIMESTAMP     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_rules_active ON api_rules (is_active) WHERE is_active = true;

-- -----------------------------------------------------------------------------
-- 2. api_input_transformed — Stage 1 ETL output (one row per API endpoint)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_input_transformed (
    id                      BIGSERIAL     PRIMARY KEY,
    api_scan_id             UUID          NOT NULL,
    tenant_id               VARCHAR(100)  NOT NULL,
    orchestration_id        UUID          NOT NULL,
    -- API-level fields
    resource_id             VARCHAR(255),
    resource_arn            VARCHAR(500),
    api_name                VARCHAR(255),
    api_type                VARCHAR(30),          -- rest | http | websocket | graphql | alb
    gateway_type            VARCHAR(30),          -- api-gateway | alb | appsync | app-runner
    base_url                VARCHAR(500),
    stage_name              VARCHAR(50),
    -- Endpoint-level fields
    path                    VARCHAR(500),
    method                  VARCHAR(10),          -- GET | POST | PUT | DELETE | PATCH | ANY
    -- Security posture fields
    auth_required           BOOLEAN       DEFAULT false,
    auth_type               VARCHAR(50),          -- COGNITO_USER_POOLS | AWS_IAM | API_KEY | NONE | CUSTOM
    auth_types              TEXT[]        DEFAULT '{}',
    has_waf                 BOOLEAN       DEFAULT false,
    has_rate_limiting       BOOLEAN       DEFAULT false,
    rate_limit_burst        INTEGER,
    rate_limit_rate         DOUBLE PRECISION,
    tls_minimum             VARCHAR(30),          -- TLS_1_0 | TLS_1_2 | TLS_1_3
    logging_enabled         BOOLEAN       DEFAULT false,
    access_log_arn          VARCHAR(500),
    xray_tracing_enabled    BOOLEAN       DEFAULT false,
    request_validator       BOOLEAN       DEFAULT false,
    has_model_schema        BOOLEAN       DEFAULT false,
    cors_policy             JSONB,                -- {allow_origins: ['*']}
    is_public               BOOLEAN,
    is_deprecated           BOOLEAN       DEFAULT false,
    has_newer_version       BOOLEAN       DEFAULT false,
    -- WAF details
    waf_acl_arn             VARCHAR(500),
    waf_rule_count          INTEGER       DEFAULT 0,
    -- AppSync specific
    log_config              JSONB,                -- {fieldLogLevel, cloudWatchLogsRoleArn}
    -- Runtime stats (from event_aggregations / Tier 2)
    error_rate_pct          DOUBLE PRECISION,
    request_volume_24h      INTEGER,
    p99_latency_ms          DOUBLE PRECISION,
    top_error_paths         JSONB,
    -- Metadata
    is_internal_package     BOOLEAN       DEFAULT false,  -- for dep confusion cross-check
    public_registry_exists  BOOLEAN       DEFAULT false,
    account_id              VARCHAR(20),
    region                  VARCHAR(50),
    csp                     VARCHAR(20)   DEFAULT 'aws',
    scanned_at              TIMESTAMP     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_transformed_scan
    ON api_input_transformed (api_scan_id);
CREATE INDEX IF NOT EXISTS idx_api_transformed_tenant
    ON api_input_transformed (tenant_id, api_scan_id);

-- -----------------------------------------------------------------------------
-- 3. api_findings — Stage 2 rule evaluation output
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_findings (
    finding_id          UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    api_scan_id         UUID          NOT NULL,
    tenant_id           VARCHAR(100)  NOT NULL,
    orchestration_id    UUID,
    api_id              UUID,
    endpoint_id         UUID,
    resource_arn        VARCHAR(500),
    source_type         VARCHAR(30),          -- rest_api | http_api | alb | graphql
    source_id           VARCHAR(255),
    rule_id             VARCHAR(100)  NOT NULL,
    owasp_category      VARCHAR(10),
    finding_type        VARCHAR(50),          -- auth_missing | rate_limit_missing | tls_weak | waf_missing | config_issue | runtime_anomaly
    result              VARCHAR(10)   NOT NULL DEFAULT 'SKIP',  -- PASS | FAIL | SKIP | ERROR
    severity            VARCHAR(20),
    title               TEXT,
    description         TEXT,
    evidence            JSONB,
    remediation         TEXT,
    frameworks          TEXT[]        DEFAULT '{}',
    path                VARCHAR(500),
    method              VARCHAR(10),
    account_id          VARCHAR(20),
    region              VARCHAR(50),
    csp                 VARCHAR(20)   DEFAULT 'aws',
    created_at          TIMESTAMP     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_findings_scan
    ON api_findings (api_scan_id);
CREATE INDEX IF NOT EXISTS idx_api_findings_rule
    ON api_findings (rule_id, result);
CREATE INDEX IF NOT EXISTS idx_api_findings_severity
    ON api_findings (severity) WHERE result = 'FAIL';

-- -----------------------------------------------------------------------------
-- 4. api_inventory — Denormalized API service list (Stage 3 output)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_inventory (
    api_id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    api_scan_id         UUID          NOT NULL,
    tenant_id           VARCHAR(100)  NOT NULL,
    orchestration_id    UUID          NOT NULL,
    resource_id         VARCHAR(255),
    resource_arn        VARCHAR(500),
    api_name            VARCHAR(255),
    api_type            VARCHAR(30),
    gateway_type        VARCHAR(30),
    base_url            VARCHAR(500),
    total_endpoints     INTEGER       DEFAULT 0,
    auth_types          TEXT[]        DEFAULT '{}',
    has_waf             BOOLEAN       DEFAULT false,
    has_rate_limiting   BOOLEAN       DEFAULT false,
    tls_minimum         VARCHAR(30),
    logging_enabled     BOOLEAN       DEFAULT false,
    cors_policy         JSONB,
    is_public           BOOLEAN,
    stage_name          VARCHAR(50),
    -- Compliance summary
    auth_coverage_pct   DOUBLE PRECISION DEFAULT 0,
    owasp_pass_count    INTEGER       DEFAULT 0,
    owasp_fail_count    INTEGER       DEFAULT 0,
    risk_score          INTEGER       DEFAULT 0,
    -- Metadata
    csp                 VARCHAR(20)   DEFAULT 'aws',
    account_id          VARCHAR(20),
    region              VARCHAR(50),
    scanned_at          TIMESTAMP     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_inventory_scan
    ON api_inventory (api_scan_id);

-- -----------------------------------------------------------------------------
-- 5. api_endpoints — Per-endpoint detail (Stage 3 output)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_endpoints (
    endpoint_id         UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id              UUID          REFERENCES api_inventory(api_id),
    api_scan_id         UUID          NOT NULL,
    tenant_id           VARCHAR(100)  NOT NULL,
    path                VARCHAR(500),
    method              VARCHAR(10),
    auth_required       BOOLEAN,
    auth_type           VARCHAR(50),
    rate_limited        BOOLEAN,
    request_validator   BOOLEAN,
    has_model_schema    BOOLEAN,
    is_deprecated       BOOLEAN       DEFAULT false,
    openapi_operation   JSONB,
    created_at          TIMESTAMP     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_endpoints_api
    ON api_endpoints (api_id);
CREATE INDEX IF NOT EXISTS idx_api_endpoints_scan
    ON api_endpoints (api_scan_id);

-- -----------------------------------------------------------------------------
-- 6. api_access_summary — Runtime stats snapshot (Stage 3 / trending)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_access_summary (
    summary_id          UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    api_scan_id         UUID          NOT NULL,
    tenant_id           VARCHAR(100)  NOT NULL,
    resource_arn        VARCHAR(500),
    api_name            VARCHAR(255),
    stage_name          VARCHAR(50),
    time_window_start   TIMESTAMP,
    time_window_end     TIMESTAMP,
    total_requests      BIGINT        DEFAULT 0,
    error_count         BIGINT        DEFAULT 0,
    error_rate_pct      DOUBLE PRECISION DEFAULT 0,
    p50_latency_ms      DOUBLE PRECISION,
    p99_latency_ms      DOUBLE PRECISION,
    top_paths           JSONB,            -- [{path, count, error_rate}]
    top_error_paths     JSONB,            -- [{path, status_code, count}]
    unusual_methods     JSONB,            -- [{method, count}]
    created_at          TIMESTAMP     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_access_scan
    ON api_access_summary (api_scan_id);

-- -----------------------------------------------------------------------------
-- 7. api_report — Scan-level summary (Stage 3 output)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_report (
    api_scan_id         UUID          PRIMARY KEY,
    orchestration_id    UUID          NOT NULL,
    tenant_id           VARCHAR(100)  NOT NULL,
    account_id          VARCHAR(20),
    provider            VARCHAR(20)   DEFAULT 'aws',
    -- API counts
    total_apis          INTEGER       DEFAULT 0,
    total_endpoints     INTEGER       DEFAULT 0,
    -- Coverage metrics
    auth_coverage_pct   DOUBLE PRECISION DEFAULT 0,
    waf_coverage_pct    DOUBLE PRECISION DEFAULT 0,
    logging_coverage_pct DOUBLE PRECISION DEFAULT 0,
    rate_limit_coverage_pct DOUBLE PRECISION DEFAULT 0,
    -- Finding counts
    total_findings      INTEGER       DEFAULT 0,
    total_failures      INTEGER       DEFAULT 0,
    critical_count      INTEGER       DEFAULT 0,
    high_count          INTEGER       DEFAULT 0,
    medium_count        INTEGER       DEFAULT 0,
    low_count           INTEGER       DEFAULT 0,
    info_count          INTEGER       DEFAULT 0,
    -- OWASP compliance
    owasp_compliance_pct DOUBLE PRECISION DEFAULT 0,
    owasp_category_summary JSONB,         -- {API1: {pass: 5, fail: 2}, ...}
    -- Aggregations
    top_failing_rules   JSONB,
    api_type_summary    JSONB,            -- {rest: 5, http: 3, graphql: 1}
    risk_score          INTEGER       DEFAULT 0,
    -- Timing
    started_at          TIMESTAMP,
    completed_at        TIMESTAMP,
    scan_duration_ms    INTEGER,
    status              VARCHAR(20)   DEFAULT 'pending',
    error_message       TEXT,
    created_at          TIMESTAMP     DEFAULT NOW()
);

-- =============================================================================
-- End of API Engine Schema
-- =============================================================================
