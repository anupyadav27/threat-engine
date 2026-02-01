-- ============================================================================
-- Check Engine Database Schema
-- ============================================================================
-- Purpose: Store security check results and parsed rule metadata
-- Used by: engine_check_aws
-- Tables: customers, tenants, scans, check_results, checks, rule_metadata

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
    scan_type VARCHAR(50) DEFAULT 'check',
    status VARCHAR(50),
    metadata JSONB,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- ============================================================================
-- CHECK TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS check_results (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    rule_id VARCHAR(255) NOT NULL,
    resource_uid TEXT,
    resource_arn TEXT,
    resource_id VARCHAR(255),
    resource_type VARCHAR(100),
    status VARCHAR(50) NOT NULL,
    checked_fields JSONB,
    finding_data JSONB NOT NULL,
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata_source VARCHAR(50) DEFAULT 'default',
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS checks (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL,
    service VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    check_type VARCHAR(50) DEFAULT 'default',
    customer_id VARCHAR(255),
    tenant_id VARCHAR(255),
    check_config JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    UNIQUE(rule_id, customer_id, tenant_id)
);

-- ============================================================================
-- RULE METADATA (parsed metadata for enriching check findings)
-- ============================================================================

CREATE TABLE IF NOT EXISTS rule_metadata (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL UNIQUE,
    service VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL DEFAULT 'aws',
    resource VARCHAR(100),
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    rationale TEXT,
    domain VARCHAR(100),
    subcategory VARCHAR(100),
    requirement VARCHAR(255),
    assertion_id VARCHAR(255),
    compliance_frameworks JSONB,
    data_security JSONB,
    "references" JSONB,
    metadata_source VARCHAR(50) NOT NULL DEFAULT 'default',
    source VARCHAR(50) NOT NULL DEFAULT 'default',
    generated_by VARCHAR(50) DEFAULT 'default',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    threat_category VARCHAR(50),
    threat_tags JSONB DEFAULT '[]',
    risk_score INTEGER DEFAULT 50,
    risk_indicators JSONB DEFAULT '{}'
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_scans_customer_tenant ON scans(customer_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(scan_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_check_results_scan ON check_results(scan_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_check_results_tenant ON check_results(tenant_id, hierarchy_id);
CREATE INDEX IF NOT EXISTS idx_check_results_status ON check_results(status, scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_check_results_rule_id ON check_results(rule_id, status);
CREATE INDEX IF NOT EXISTS idx_check_results_resource_uid ON check_results(resource_uid);
CREATE INDEX IF NOT EXISTS idx_check_results_resource_arn ON check_results(resource_arn);
CREATE INDEX IF NOT EXISTS idx_check_results_tenant_uid ON check_results(tenant_id, resource_uid);

CREATE INDEX IF NOT EXISTS idx_checks_service ON checks(service, provider, check_type);
CREATE INDEX IF NOT EXISTS idx_checks_customer ON checks(customer_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_rule_metadata_rule_id ON rule_metadata(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_service ON rule_metadata(service);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_severity ON rule_metadata(severity);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_source ON rule_metadata(metadata_source);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_provider ON rule_metadata(provider);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_threat_category ON rule_metadata(threat_category);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_risk_score ON rule_metadata(risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_check_results_finding_data_gin ON check_results USING gin(finding_data);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE check_results IS 'Security check findings from check scans';
COMMENT ON TABLE rule_metadata IS 'Parsed rule metadata for enriching check findings';
COMMENT ON TABLE scans IS 'Check scan metadata';

-- NO discoveries, discovery_history, or rule_definitions here!
