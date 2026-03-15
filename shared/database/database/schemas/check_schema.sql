-- ============================================================================
-- Check Engine Database Schema
-- ============================================================================
-- Purpose: Store security check results and parsed rule metadata
-- Used by: engine_check_aws
-- Tables: check_report, check_findings, rule_checks, rule_metadata, rule_discoveries
-- NOTE: customers/tenants tables do NOT exist in check DB on RDS

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================================
-- REPORT TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS check_report (
    check_scan_id   VARCHAR(255)    PRIMARY KEY,
    customer_id     VARCHAR(255)    NOT NULL,
    tenant_id       VARCHAR(255)    NOT NULL,
    provider        VARCHAR(50)     NOT NULL,
    hierarchy_id    VARCHAR(255),
    hierarchy_type  VARCHAR(50),
    region          VARCHAR(50),
    service         VARCHAR(100),
    scan_timestamp  TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    scan_type       VARCHAR(50)     DEFAULT 'check',
    status          VARCHAR(50),
    metadata        JSONB,
    execution_id    VARCHAR(255),
    discovery_scan_id VARCHAR(255)
    -- NOTE: No FK constraints — customers/tenants tables don't exist in check DB
    -- NOTE: orchestration_id not in RDS (removed from local schema to match)
);

-- ============================================================================
-- CHECK TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS check_findings (
    id SERIAL PRIMARY KEY,
    check_scan_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    rule_id VARCHAR(255) NOT NULL,
    service VARCHAR(100),
    discovery_id VARCHAR(255),
    resource_uid TEXT,                -- Canonical identifier (ARN for AWS, ARM ID for Azure, etc.)
    resource_id VARCHAR(255),
    resource_type VARCHAR(100),
    resource_service VARCHAR(100),
    region VARCHAR(50),
    status VARCHAR(50) NOT NULL,
    checked_fields JSONB,
    actual_values JSONB,
    finding_data JSONB NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
    -- NOTE: No FK constraints — no FK to check_report or customers/tenants in RDS
);

CREATE TABLE IF NOT EXISTS rule_checks (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL,
    service VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL DEFAULT 'aws',
    check_type VARCHAR(50) DEFAULT 'default',
    customer_id VARCHAR(255),
    tenant_id VARCHAR(255),
    check_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    version VARCHAR(50) DEFAULT '1.0',
    source VARCHAR(50) NOT NULL DEFAULT 'default',
    generated_by VARCHAR(50) DEFAULT 'default',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    UNIQUE(rule_id, customer_id, tenant_id)
    -- NOTE: No FK to customers/tenants
);

-- ============================================================================
-- RULE METADATA (parsed metadata for enriching check findings)
-- ============================================================================

CREATE TABLE IF NOT EXISTS rule_metadata (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL,
    service VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL DEFAULT 'aws',
    resource VARCHAR(100),
    resource_service VARCHAR(100),
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
    iam_security JSONB DEFAULT '{}'::jsonb,
    "references" JSONB,
    metadata_source VARCHAR(50) NOT NULL DEFAULT 'default',
    source VARCHAR(50) NOT NULL DEFAULT 'default',
    generated_by VARCHAR(50) DEFAULT 'default',
    customer_id VARCHAR(255),
    tenant_id VARCHAR(255),
    version VARCHAR(50) DEFAULT '1.0',
    mitre_tactics JSONB DEFAULT '[]'::jsonb,
    mitre_techniques JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    threat_category VARCHAR(50),
    threat_tags JSONB DEFAULT '[]',
    risk_score INTEGER DEFAULT 50,
    risk_indicators JSONB DEFAULT '{}',
    UNIQUE(rule_id, customer_id, tenant_id)
);

-- ============================================================================
-- RULE DISCOVERIES (discovery definitions loaded from YAML per service)
-- ============================================================================

CREATE TABLE IF NOT EXISTS rule_discoveries (
    id                                  SERIAL          PRIMARY KEY,
    service                             VARCHAR(100)    NOT NULL,
    provider                            VARCHAR(50)     NOT NULL DEFAULT 'aws',
    version                             VARCHAR(20),
    discoveries_data                    JSONB           NOT NULL DEFAULT '[]'::jsonb,
    customer_id                         VARCHAR(255),
    tenant_id                           VARCHAR(255),
    created_at                          TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    updated_at                          TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    source                              VARCHAR(50)     NOT NULL DEFAULT 'default',
    generated_by                        VARCHAR(50)     DEFAULT 'default',
    is_active                           BOOLEAN         DEFAULT true,
    -- Boto3 integration fields (used by discovery engine)
    boto3_client_name                   VARCHAR(100),
    arn_identifier                      VARCHAR(255),
    arn_identifier_independent_methods  TEXT[],
    arn_identifier_dependent_methods    TEXT[],
    -- Filter rules (merged from filter_rules table — no separate table needed)
    -- Format: {"api_filters": [...], "response_filters": [...]}
    -- api_filters:      pre-call param overrides (e.g. OwnerIds=["self"])
    -- response_filters: post-call exclusion patterns (e.g. exclude ^alias/aws/)
    -- Read by: engine_discoveries/utils/config_loader.py → get_filter_rules()
    --          engine_discoveries/utils/filter_engine.py
    filter_rules                        JSONB           DEFAULT '{}'::jsonb,
    UNIQUE(service, provider, customer_id, tenant_id)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_cr_customer_tenant ON check_report(customer_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_cr_timestamp ON check_report(scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_cr_discovery_scan ON check_report(discovery_scan_id);
-- idx_cr_orchestration removed: orchestration_id column not in RDS

CREATE INDEX IF NOT EXISTS idx_cf_scan ON check_findings(check_scan_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_cf_tenant ON check_findings(tenant_id, hierarchy_id);
CREATE INDEX IF NOT EXISTS idx_cf_status ON check_findings(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cf_rule_id ON check_findings(rule_id, status);
CREATE INDEX IF NOT EXISTS idx_cf_resource_uid ON check_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_cf_tenant_uid ON check_findings(tenant_id, resource_uid);

CREATE INDEX IF NOT EXISTS idx_rc_service ON rule_checks(service, provider, check_type);
CREATE INDEX IF NOT EXISTS idx_rc_customer ON rule_checks(customer_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_rule_metadata_rule_id ON rule_metadata(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_service ON rule_metadata(service);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_severity ON rule_metadata(severity);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_source ON rule_metadata(metadata_source);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_provider ON rule_metadata(provider);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_threat_category ON rule_metadata(threat_category);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_risk_score ON rule_metadata(risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_cf_finding_data_gin ON check_findings USING gin(finding_data);
CREATE INDEX IF NOT EXISTS idx_cf_resource_service ON check_findings(resource_service);
CREATE INDEX IF NOT EXISTS idx_rm_resource_service ON rule_metadata(resource_service);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE check_report IS 'Check scan metadata with link to discovery_scan_id';
COMMENT ON TABLE check_findings IS 'Security check findings from check scans';
COMMENT ON TABLE rule_metadata IS 'Parsed rule metadata for enriching check findings';
COMMENT ON TABLE rule_checks IS 'Check rule configurations loaded from YAML or custom';
COMMENT ON TABLE rule_discoveries IS 'Discovery definitions loaded from YAML per service';
