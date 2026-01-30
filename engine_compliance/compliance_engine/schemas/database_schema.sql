-- PostgreSQL Schema for Enterprise Compliance Reports
-- Supports querying by tenant, scan_run_id, severity, status, rule_id, resource_type

-- Tenants Table
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Report Index Table
CREATE TABLE IF NOT EXISTS report_index (
    report_id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
    cloud VARCHAR(50) NOT NULL,
    trigger_type VARCHAR(50) NOT NULL,
    collection_mode VARCHAR(50) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    total_controls INTEGER NOT NULL DEFAULT 0,
    controls_passed INTEGER NOT NULL DEFAULT 0,
    controls_failed INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    report_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Finding Index Table
CREATE TABLE IF NOT EXISTS finding_index (
    finding_id VARCHAR(255) PRIMARY KEY,
    report_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
    rule_id VARCHAR(255) NOT NULL,
    rule_version VARCHAR(50),
    category VARCHAR(100),
    severity VARCHAR(20) NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    resource_arn TEXT,
    region VARCHAR(50),
    finding_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_report FOREIGN KEY (report_id) REFERENCES report_index(report_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_finding FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Indexes for Common Queries
CREATE INDEX IF NOT EXISTS idx_report_tenant_scan ON report_index(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_report_completed_at ON report_index(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_cloud ON report_index(cloud);

CREATE INDEX IF NOT EXISTS idx_finding_tenant_scan ON finding_index(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_finding_severity ON finding_index(severity);
CREATE INDEX IF NOT EXISTS idx_finding_status ON finding_index(status);
CREATE INDEX IF NOT EXISTS idx_finding_rule_id ON finding_index(rule_id);
CREATE INDEX IF NOT EXISTS idx_finding_resource_type ON finding_index(resource_type);
CREATE INDEX IF NOT EXISTS idx_finding_last_seen ON finding_index(last_seen_at DESC);

-- JSONB Indexes for Flexible Queries
CREATE INDEX IF NOT EXISTS idx_report_data_gin ON report_index USING gin(report_data);
CREATE INDEX IF NOT EXISTS idx_finding_data_gin ON finding_index USING gin(finding_data);

-- Composite Indexes for Common Query Patterns
CREATE INDEX IF NOT EXISTS idx_finding_severity_status ON finding_index(severity, status);
CREATE INDEX IF NOT EXISTS idx_finding_rule_status ON finding_index(rule_id, status);
CREATE INDEX IF NOT EXISTS idx_finding_tenant_severity ON finding_index(tenant_id, severity, last_seen_at DESC);

-- Full-text search index for resource_arn (requires pg_trgm extension)
-- CREATE EXTENSION IF NOT EXISTS pg_trgm;
-- CREATE INDEX IF NOT EXISTS idx_finding_resource_arn ON finding_index USING gin(resource_arn gin_trgm_ops);

-- Query Examples:
-- 1. List recent reports for tenant
-- SELECT * FROM report_index WHERE tenant_id = 'tenant-123' ORDER BY completed_at DESC LIMIT 10;

-- 2. Show all open findings by severity
-- SELECT * FROM finding_index WHERE tenant_id = 'tenant-123' AND status = 'open' ORDER BY severity DESC, last_seen_at DESC;

-- 3. Drill down findings for a specific rule_id
-- SELECT * FROM finding_index WHERE tenant_id = 'tenant-123' AND rule_id = 'aws.s3.bucket.public_access_blocked' ORDER BY last_seen_at DESC;

-- 4. Drill down findings for a specific resource arn
-- SELECT * FROM finding_index WHERE tenant_id = 'tenant-123' AND resource_arn LIKE '%my-bucket%' ORDER BY severity DESC;

