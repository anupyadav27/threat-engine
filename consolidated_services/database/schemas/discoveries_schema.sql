-- ============================================================================
-- Discoveries Engine Database Schema
-- ============================================================================
-- Purpose: Store discovered AWS resources, rule YAMLs for loading discovery definitions
-- Used by: engine_discoveries_aws
-- Tables: customers, tenants, discovery_report, discovery_findings, discovery_history, rule_definitions

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
    discovery_scan_id VARCHAR(255) PRIMARY KEY,
    orchestration_id VARCHAR(255),  -- PLANNED: not yet deployed to RDS
    customer_id VARCHAR(255),       -- nullable in RDS
    tenant_id VARCHAR(255),         -- nullable in RDS
    provider VARCHAR(50),           -- nullable in RDS
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    region VARCHAR(100),
    service VARCHAR(100),
    scan_timestamp TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    scan_type VARCHAR(50) DEFAULT 'discovery',
    status VARCHAR(50) DEFAULT 'running',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
    -- NOTE: No FK constraints enforced in RDS
);

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
-- RULE DEFINITIONS (YAML files for loading discovery rules)
-- ============================================================================

CREATE TABLE IF NOT EXISTS rule_definitions (
    id SERIAL PRIMARY KEY,
    csp VARCHAR(50) NOT NULL DEFAULT 'aws',
    service VARCHAR(100) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    content_yaml TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(csp, service, file_path)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- PLANNED: not yet deployed to RDS
CREATE INDEX IF NOT EXISTS idx_dr_customer_tenant ON discovery_report(customer_id, tenant_id);
-- PLANNED: not yet deployed to RDS
CREATE INDEX IF NOT EXISTS idx_dr_timestamp ON discovery_report(scan_timestamp DESC);
-- PLANNED: not yet deployed to RDS
CREATE INDEX IF NOT EXISTS idx_dr_orchestration ON discovery_report(orchestration_id);

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

CREATE INDEX IF NOT EXISTS idx_rule_definitions_csp_service ON rule_definitions(csp, service);
CREATE INDEX IF NOT EXISTS idx_rule_definitions_csp ON rule_definitions(csp);

CREATE INDEX IF NOT EXISTS idx_df_emitted_fields_gin ON discovery_findings USING gin(emitted_fields);
CREATE INDEX IF NOT EXISTS idx_discoveries_raw_response_gin ON discovery_findings USING gin(raw_response);
CREATE INDEX IF NOT EXISTS idx_history_diff_summary_gin ON discovery_history USING gin(diff_summary);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE discovery_findings IS 'Discovered AWS resources from discovery scans';
COMMENT ON TABLE discovery_history IS 'Version history and drift detection';
COMMENT ON TABLE rule_definitions IS 'Full YAML rules for discoveries engine to load';
COMMENT ON TABLE discovery_report IS 'Discovery scan metadata';
