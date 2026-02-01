-- PostgreSQL Schema for Data Security Reports
-- Database: threat_engine_datasec

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenants table (minimal, for FK)
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- DataSec Reports Table (main report storage)
CREATE TABLE IF NOT EXISTS datasec_reports (
    report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,  -- Links to check scan
    cloud VARCHAR(50) NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Summary stats
    total_findings INTEGER DEFAULT 0,
    datasec_relevant_findings INTEGER DEFAULT 0,
    classified_resources INTEGER DEFAULT 0,
    total_data_stores INTEGER DEFAULT 0,
    
    -- Module breakdown
    findings_by_module JSONB,  -- {"data_protection": 10, "data_classification": 5, ...}
    classification_summary JSONB,  -- {"PII": 5, "PCI": 3, "PHI": 2}
    residency_summary JSONB,  -- {"compliant": 10, "non_compliant": 5}
    
    -- Full report JSON
    report_data JSONB NOT NULL,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- DataSec Findings Table (individual data security findings)
CREATE TABLE IF NOT EXISTS datasec_findings (
    finding_id VARCHAR(255) PRIMARY KEY,
    report_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
    
    rule_id VARCHAR(255) NOT NULL,
    datasec_modules TEXT[],  -- Array of modules (data_protection, data_classification, etc.)
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,  -- PASS, FAIL, WARN
    
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    resource_arn TEXT,
    account_id VARCHAR(50),
    region VARCHAR(50),
    
    -- Data classification
    data_classification TEXT[],  -- Array of classifications (PII, PCI, PHI, etc.)
    sensitivity_score DECIMAL(3,1),  -- 0.0 to 10.0
    
    finding_data JSONB NOT NULL,  -- Full finding details + data security context
    
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_report FOREIGN KEY (report_id) REFERENCES datasec_reports(report_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_finding FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_datasec_reports_tenant ON datasec_reports(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_datasec_reports_generated ON datasec_reports(generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_datasec_findings_report ON datasec_findings(report_id);
CREATE INDEX IF NOT EXISTS idx_datasec_findings_tenant ON datasec_findings(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_datasec_findings_rule ON datasec_findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_datasec_findings_severity ON datasec_findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_datasec_findings_resource ON datasec_findings(resource_arn);
CREATE INDEX IF NOT EXISTS idx_datasec_findings_classification ON datasec_findings USING gin(data_classification);

-- JSONB indexes
CREATE INDEX IF NOT EXISTS idx_datasec_report_data_gin ON datasec_reports USING gin(report_data);
CREATE INDEX IF NOT EXISTS idx_datasec_finding_data_gin ON datasec_findings USING gin(finding_data);
