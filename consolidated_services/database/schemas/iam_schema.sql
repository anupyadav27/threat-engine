-- PostgreSQL Schema for IAM Security Reports
-- Database: threat_engine_iam

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenants table (minimal, for FK)
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- IAM Reports Table (main report storage)
CREATE TABLE IF NOT EXISTS iam_reports (
    report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,  -- Links to check scan
    cloud VARCHAR(50) NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Summary stats
    total_findings INTEGER DEFAULT 0,
    iam_relevant_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    
    -- Module breakdown
    findings_by_module JSONB,  -- {"least_privilege": 10, "mfa": 5, ...}
    findings_by_status JSONB,  -- {"PASS": 50, "FAIL": 30, ...}
    
    -- Full report JSON
    report_data JSONB NOT NULL,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- IAM Findings Table (individual IAM findings)
CREATE TABLE IF NOT EXISTS iam_findings (
    finding_id VARCHAR(255) PRIMARY KEY,
    report_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
    
    rule_id VARCHAR(255) NOT NULL,
    iam_modules TEXT[],  -- Array of IAM modules (least_privilege, mfa, etc.)
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,  -- PASS, FAIL, WARN
    
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    resource_arn TEXT,
    account_id VARCHAR(50),
    region VARCHAR(50),
    
    finding_data JSONB NOT NULL,  -- Full finding details + IAM context
    
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_report FOREIGN KEY (report_id) REFERENCES iam_reports(report_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_finding FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_iam_reports_tenant ON iam_reports(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_iam_reports_generated ON iam_reports(generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_iam_findings_report ON iam_findings(report_id);
CREATE INDEX IF NOT EXISTS idx_iam_findings_tenant ON iam_findings(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_iam_findings_rule ON iam_findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_iam_findings_severity ON iam_findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_iam_findings_resource ON iam_findings(resource_arn);

-- JSONB indexes
CREATE INDEX IF NOT EXISTS idx_iam_report_data_gin ON iam_reports USING gin(report_data);
CREATE INDEX IF NOT EXISTS idx_iam_finding_data_gin ON iam_findings USING gin(finding_data);
