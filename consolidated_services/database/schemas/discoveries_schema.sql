-- ============================================================================
-- Discoveries Engine Database Schema
-- ============================================================================
-- Purpose: Store discovered cloud resources from discovery scans
-- Used by: engine_discoveries_aws
-- Tables: customers, tenants, discovery_report, discovery_findings, discovery_history
-- NOTE: Discovery YAML definitions are stored in rule_discoveries (threat_engine_check DB)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS customers (
    customer_id VARCHAR(255) PRIMARY KEY,
    customer_name VARCHAR(255),
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    customer_id VARCHAR(255),           -- nullable in RDS
    provider VARCHAR(50),               -- nullable in RDS
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
    -- NOTE: No FK to customers enforced in RDS
);

CREATE TABLE IF NOT EXISTS discovery_report (
    discovery_scan_id   VARCHAR(255)                    PRIMARY KEY,
    customer_id         VARCHAR(255),                   -- nullable in RDS
    tenant_id           VARCHAR(255),                   -- nullable in RDS
    provider            VARCHAR(50),                    -- nullable in RDS
    hierarchy_id        VARCHAR(255),
    hierarchy_type      VARCHAR(50),
    region              VARCHAR(100),
    service             VARCHAR(100),
    scan_type           VARCHAR(50)     DEFAULT 'discovery',
    status              VARCHAR(50)     DEFAULT 'running',
    metadata            JSONB           DEFAULT '{}'::jsonb,
    scan_timestamp      TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at          TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
    -- NOTE: No FK constraints enforced in RDS
    -- NOTE: orchestration_id is NOT in RDS (removed PLANNED column from local schema)
);

-- Legacy discovery report table (exists in RDS, kept for backward compatibility)
CREATE TABLE IF NOT EXISTS discovery_report_legacy (
    discovery_scan_id   VARCHAR(255)    PRIMARY KEY,
    customer_id         VARCHAR(255)    NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    provider            VARCHAR(50)     NOT NULL,
    hierarchy_id        VARCHAR(255),
    hierarchy_type      VARCHAR(50),
    region              VARCHAR(50),
    service             VARCHAR(100),
    scan_timestamp      TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    scan_type           VARCHAR(50)     DEFAULT 'discovery',
    status              VARCHAR(50),
    metadata            JSONB,
    execution_id        VARCHAR(255)
);

COMMENT ON TABLE discovery_report_legacy IS 'Discovery scan metadata (one row per run) - legacy table';

-- ============================================================================
-- DISCOVERY TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS discovery_findings (
    id SERIAL PRIMARY KEY,
    discovery_scan_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    account_id VARCHAR(255),
    discovery_id VARCHAR(255) NOT NULL,
    resource_uid TEXT,
    resource_arn TEXT,
    resource_id VARCHAR(255),
    resource_type VARCHAR(100),
    service VARCHAR(100),
    region VARCHAR(50),
    emitted_fields JSONB,
    raw_response JSONB,
    config_hash VARCHAR(64),
    version INTEGER DEFAULT 1,
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    FOREIGN KEY (discovery_scan_id) REFERENCES discovery_report(discovery_scan_id) ON DELETE CASCADE
    -- NOTE: No FK to customers/tenants enforced in RDS
);

-- Indexes for account_id
CREATE INDEX IF NOT EXISTS idx_df_account_id ON discovery_findings(account_id);
CREATE INDEX IF NOT EXISTS idx_df_account_region ON discovery_findings(account_id, region);

-- Column comment
COMMENT ON COLUMN discovery_findings.account_id IS
'Cloud account identifier (AWS account ID, Azure subscription ID, GCP project ID, etc.)';

CREATE TABLE IF NOT EXISTS discovery_history (
    id SERIAL PRIMARY KEY,
    customer_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    discovery_id VARCHAR(255) NOT NULL,
    resource_uid TEXT,
    resource_arn TEXT,
    discovery_scan_id VARCHAR(255) NOT NULL,
    config_hash VARCHAR(64) NOT NULL,
    raw_response JSONB,
    emitted_fields JSONB,
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    version INTEGER NOT NULL,
    change_type VARCHAR(50),
    previous_hash VARCHAR(64),
    diff_summary JSONB
    -- NOTE: No FK to customers/tenants enforced in RDS
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- discovery_report indexes (basic; no FK/orchestration_id in RDS)
CREATE INDEX IF NOT EXISTS idx_dr_customer_tenant ON discovery_report(customer_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_dr_timestamp ON discovery_report(scan_timestamp DESC);

-- discovery_report_legacy indexes
CREATE INDEX IF NOT EXISTS idx_discoveries_report_customer_tenant ON discovery_report_legacy(customer_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_discoveries_report_timestamp ON discovery_report_legacy(scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_discoveries_execution_id ON discovery_report_legacy(execution_id);

CREATE INDEX IF NOT EXISTS idx_df_scan ON discovery_findings(discovery_scan_id, discovery_id);
CREATE INDEX IF NOT EXISTS idx_df_tenant ON discovery_findings(tenant_id, hierarchy_id);
CREATE INDEX IF NOT EXISTS idx_df_resource_uid ON discovery_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_df_resource_arn ON discovery_findings(resource_arn);
CREATE INDEX IF NOT EXISTS idx_df_hash ON discovery_findings(config_hash);
CREATE INDEX IF NOT EXISTS idx_df_service ON discovery_findings(service, region);
CREATE INDEX IF NOT EXISTS idx_df_lookup ON discovery_findings(discovery_id, tenant_id, hierarchy_id);
CREATE INDEX IF NOT EXISTS idx_df_latest ON discovery_findings(resource_uid, discovery_id, tenant_id, hierarchy_id, scan_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_history_tenant ON discovery_history(tenant_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON discovery_history(scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_history_hash ON discovery_history(config_hash, previous_hash);

CREATE INDEX IF NOT EXISTS idx_df_emitted_fields_gin ON discovery_findings USING gin(emitted_fields);
CREATE INDEX IF NOT EXISTS idx_discoveries_raw_response_gin ON discovery_findings USING gin(raw_response);
CREATE INDEX IF NOT EXISTS idx_history_diff_summary_gin ON discovery_history USING gin(diff_summary);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE discovery_findings IS 'Discovered cloud resources from discovery scans';
COMMENT ON TABLE discovery_history IS 'Version history and drift detection';
COMMENT ON TABLE discovery_report IS 'Discovery scan metadata';
