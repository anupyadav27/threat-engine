-- ============================================================================
-- Discoveries Engine Database Schema
-- ============================================================================
-- Purpose: Store discovered AWS resources, rule YAMLs for loading discovery definitions
-- Used by: engine_discoveries_aws
-- Tables: customers, tenants, scans, discoveries, discovery_history, rule_definitions

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS customers (
    customer_id VARCHAR(255) PRIMARY KEY,
    customer_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    customer_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id VARCHAR(255) PRIMARY KEY,
    customer_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    region VARCHAR(50),
    service VARCHAR(100),
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    scan_type VARCHAR(50) DEFAULT 'discovery',
    status VARCHAR(50),
    metadata JSONB,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- ============================================================================
-- DISCOVERY TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS discoveries (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL,
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
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
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
    scan_id VARCHAR(255) NOT NULL,
    config_hash VARCHAR(64) NOT NULL,
    raw_response JSONB,
    emitted_fields JSONB,
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    version INTEGER NOT NULL,
    change_type VARCHAR(50),
    previous_hash VARCHAR(64),
    diff_summary JSONB,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
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

CREATE INDEX IF NOT EXISTS idx_scans_customer_tenant ON scans(customer_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(scan_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_discoveries_scan ON discoveries(scan_id, discovery_id);
CREATE INDEX IF NOT EXISTS idx_discoveries_tenant ON discoveries(tenant_id, hierarchy_id);
CREATE INDEX IF NOT EXISTS idx_discoveries_resource_uid ON discoveries(resource_uid);
CREATE INDEX IF NOT EXISTS idx_discoveries_resource_arn ON discoveries(resource_arn);
CREATE INDEX IF NOT EXISTS idx_discoveries_hash ON discoveries(config_hash);
CREATE INDEX IF NOT EXISTS idx_discoveries_service ON discoveries(service, region);

CREATE INDEX IF NOT EXISTS idx_history_tenant ON discovery_history(tenant_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON discovery_history(scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_history_hash ON discovery_history(config_hash, previous_hash);

CREATE INDEX IF NOT EXISTS idx_rule_definitions_csp_service ON rule_definitions(csp, service);
CREATE INDEX IF NOT EXISTS idx_rule_definitions_csp ON rule_definitions(csp);

CREATE INDEX IF NOT EXISTS idx_discoveries_raw_response_gin ON discoveries USING gin(raw_response);
CREATE INDEX IF NOT EXISTS idx_discoveries_emitted_fields_gin ON discoveries USING gin(emitted_fields);
CREATE INDEX IF NOT EXISTS idx_history_diff_summary_gin ON discovery_history USING gin(diff_summary);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE discoveries IS 'Discovered AWS resources from discovery scans';
COMMENT ON TABLE discovery_history IS 'Version history and drift detection';
COMMENT ON TABLE rule_definitions IS 'Full YAML rules for discoveries engine to load';
COMMENT ON TABLE scans IS 'Discovery scan metadata';
