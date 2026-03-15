-- ============================================================================
-- Check Engine Database Schema (production-aligned)
-- ============================================================================
-- Authoritative source: consolidated_services/database/schemas/check_schema.sql
-- This file mirrors the production schema for local dev setup via setup_database.sh
-- Tables: check_report, check_findings, rule_checks, rule_metadata, rule_discoveries
-- NOTE: customers/tenants tables do NOT exist in check DB — managed by onboarding engine

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
);

-- ============================================================================
-- CHECK FINDINGS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS check_findings (
    id              SERIAL          PRIMARY KEY,
    check_scan_id   VARCHAR(255)    NOT NULL,
    customer_id     VARCHAR(255)    NOT NULL,
    tenant_id       VARCHAR(255)    NOT NULL,
    provider        VARCHAR(50)     NOT NULL,
    hierarchy_id    VARCHAR(255),
    hierarchy_type  VARCHAR(50),
    rule_id         VARCHAR(255)    NOT NULL,
    resource_uid    TEXT,
    resource_arn    TEXT,
    resource_id     VARCHAR(255),
    resource_type   VARCHAR(100),
    status          VARCHAR(50)     NOT NULL,
    checked_fields  JSONB,
    finding_data    JSONB           NOT NULL,
    created_at      TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- RULE CHECKS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS rule_checks (
    id              SERIAL          PRIMARY KEY,
    rule_id         VARCHAR(255)    NOT NULL,
    service         VARCHAR(100)    NOT NULL,
    provider        VARCHAR(50)     NOT NULL DEFAULT 'aws',
    check_type      VARCHAR(50)     DEFAULT 'default',
    customer_id     VARCHAR(255),
    tenant_id       VARCHAR(255),
    check_config    JSONB           NOT NULL DEFAULT '{}'::jsonb,
    version         VARCHAR(50)     DEFAULT '1.0',
    source          VARCHAR(50)     NOT NULL DEFAULT 'default',
    generated_by    VARCHAR(50)     DEFAULT 'default',
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active       BOOLEAN         DEFAULT TRUE,
    UNIQUE(rule_id, customer_id, tenant_id)
);

-- ============================================================================
-- RULE METADATA TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS rule_metadata (
    id                      SERIAL          PRIMARY KEY,
    rule_id                 VARCHAR(255)    NOT NULL,
    service                 VARCHAR(100)    NOT NULL,
    provider                VARCHAR(50)     NOT NULL DEFAULT 'aws',
    resource                VARCHAR(100),
    severity                VARCHAR(20)     NOT NULL DEFAULT 'medium',
    title                   TEXT            NOT NULL,
    description             TEXT,
    remediation             TEXT,
    rationale               TEXT,
    domain                  VARCHAR(100),
    subcategory             VARCHAR(100),
    requirement             VARCHAR(255),
    assertion_id            VARCHAR(255),
    compliance_frameworks   JSONB,
    data_security           JSONB,
    iam_security            JSONB           DEFAULT '{}'::jsonb,
    "references"            JSONB,
    metadata_source         VARCHAR(50)     NOT NULL DEFAULT 'default',
    source                  VARCHAR(50)     NOT NULL DEFAULT 'default',
    generated_by            VARCHAR(50)     DEFAULT 'default',
    customer_id             VARCHAR(255),
    tenant_id               VARCHAR(255),
    version                 VARCHAR(50)     DEFAULT '1.0',
    mitre_tactics           JSONB           DEFAULT '[]'::jsonb,
    mitre_techniques        JSONB           DEFAULT '[]'::jsonb,
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    threat_category         VARCHAR(50),
    threat_tags             JSONB           DEFAULT '[]',
    risk_score              INTEGER         DEFAULT 50,
    risk_indicators         JSONB           DEFAULT '{}',
    UNIQUE(rule_id, customer_id, tenant_id)
);

-- ============================================================================
-- RULE DISCOVERIES TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS rule_discoveries (
    id                                  SERIAL          PRIMARY KEY,
    service                             VARCHAR(100)    NOT NULL,
    provider                            VARCHAR(50)     NOT NULL DEFAULT 'aws',
    version                             VARCHAR(20),
    discoveries_data                    JSONB           NOT NULL DEFAULT '[]'::jsonb,
    customer_id                         VARCHAR(255),
    tenant_id                           VARCHAR(255),
    created_at                          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at                          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    source                              VARCHAR(50)     NOT NULL DEFAULT 'default',
    generated_by                        VARCHAR(50)     DEFAULT 'default',
    is_active                           BOOLEAN         DEFAULT true,
    boto3_client_name                   VARCHAR(100),
    arn_identifier                      VARCHAR(255),
    arn_identifier_independent_methods  TEXT[],
    arn_identifier_dependent_methods    TEXT[],
    filter_rules                        JSONB           DEFAULT '{}'::jsonb,
    UNIQUE(service, provider, customer_id, tenant_id)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_cr_customer_tenant  ON check_report(customer_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_cr_timestamp        ON check_report(scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_cr_discovery_scan   ON check_report(discovery_scan_id);

CREATE INDEX IF NOT EXISTS idx_cf_scan             ON check_findings(check_scan_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_cf_tenant           ON check_findings(tenant_id, hierarchy_id);
CREATE INDEX IF NOT EXISTS idx_cf_status           ON check_findings(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cf_rule_id          ON check_findings(rule_id, status);
CREATE INDEX IF NOT EXISTS idx_cf_resource_uid     ON check_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_cf_resource_arn     ON check_findings(resource_arn);
CREATE INDEX IF NOT EXISTS idx_cf_tenant_uid       ON check_findings(tenant_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_cf_finding_data_gin ON check_findings USING gin(finding_data);

CREATE INDEX IF NOT EXISTS idx_rc_service          ON rule_checks(service, provider, check_type);
CREATE INDEX IF NOT EXISTS idx_rc_customer         ON rule_checks(customer_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_rm_rule_id          ON rule_metadata(rule_id);
CREATE INDEX IF NOT EXISTS idx_rm_service          ON rule_metadata(service);
CREATE INDEX IF NOT EXISTS idx_rm_severity         ON rule_metadata(severity);
CREATE INDEX IF NOT EXISTS idx_rm_source           ON rule_metadata(metadata_source);
CREATE INDEX IF NOT EXISTS idx_rm_provider         ON rule_metadata(provider);
CREATE INDEX IF NOT EXISTS idx_rm_threat_category  ON rule_metadata(threat_category);
CREATE INDEX IF NOT EXISTS idx_rm_risk_score       ON rule_metadata(risk_score DESC);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE check_report    IS 'Check scan metadata with link to discovery_scan_id';
COMMENT ON TABLE check_findings  IS 'Security check findings (PASS/FAIL/ERROR) per resource per rule';
COMMENT ON TABLE rule_metadata   IS 'Parsed rule metadata for enriching check findings';
COMMENT ON TABLE rule_checks     IS 'Check rule configurations loaded from YAML or custom';
COMMENT ON TABLE rule_discoveries IS 'Discovery definitions loaded from YAML per service';
