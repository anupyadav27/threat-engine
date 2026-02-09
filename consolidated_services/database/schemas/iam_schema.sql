-- ============================================================================
-- IAM Security Engine Database Schema
-- ============================================================================
-- Database: threat_engine_iam
-- Purpose: Store IAM security scan results and findings
-- Used by: engine_iam
-- Tables: tenants, iam_report, iam_findings

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- IAM Report (scan-level metadata)
CREATE TABLE IF NOT EXISTS iam_report (
    iam_scan_id VARCHAR(255) PRIMARY KEY,
    orchestration_id VARCHAR(255),  -- links to scan_orchestration in shared DB
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255),
    cloud VARCHAR(50),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    total_findings INTEGER DEFAULT 0,
    iam_relevant_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    findings_by_module JSONB,
    findings_by_status JSONB,
    report_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    discovery_scan_id VARCHAR(255),
    customer_id VARCHAR(255),
    check_scan_id VARCHAR(255),
    threat_scan_id VARCHAR(255),
    status VARCHAR(50),
    execution_id VARCHAR(255),
    provider VARCHAR(50),

    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- IAM Findings (individual IAM security findings)
CREATE TABLE IF NOT EXISTS iam_findings (
    finding_id VARCHAR(255) PRIMARY KEY,
    iam_scan_id VARCHAR(255),
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255),
    rule_id VARCHAR(255) NOT NULL,
    iam_modules TEXT[],
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    resource_arn TEXT,
    account_id VARCHAR(50),
    region VARCHAR(50),
    finding_data JSONB,
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    customer_id VARCHAR(255),
    resource_uid TEXT,

    CONSTRAINT fk_tenant_finding FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_iam_report_tenant ON iam_report(tenant_id);
CREATE INDEX IF NOT EXISTS idx_iam_report_scan_run ON iam_report(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_iam_report_check_scan ON iam_report(check_scan_id);
CREATE INDEX IF NOT EXISTS idx_iam_report_threat_scan ON iam_report(threat_scan_id);
CREATE INDEX IF NOT EXISTS idx_iam_report_generated ON iam_report(generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_iam_findings_iam_scan ON iam_findings(iam_scan_id);
CREATE INDEX IF NOT EXISTS idx_iam_findings_tenant ON iam_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_iam_findings_rule ON iam_findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_iam_findings_severity ON iam_findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_iam_findings_resource ON iam_findings(resource_arn);
CREATE INDEX IF NOT EXISTS idx_iam_findings_resource_uid ON iam_findings(resource_uid);

-- JSONB indexes
CREATE INDEX IF NOT EXISTS idx_iam_report_data_gin ON iam_report USING gin(report_data);
CREATE INDEX IF NOT EXISTS idx_iam_finding_data_gin ON iam_findings USING gin(finding_data);
CREATE INDEX IF NOT EXISTS idx_iam_report_modules_gin ON iam_report USING gin(findings_by_module);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE iam_report IS 'IAM security scan metadata with links to check/threat scans';
COMMENT ON TABLE iam_findings IS 'Individual IAM security findings (least privilege, MFA, etc.)';
