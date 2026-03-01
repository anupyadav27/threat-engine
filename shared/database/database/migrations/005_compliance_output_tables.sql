-- Migration: Compliance Engine Output Tables
-- Purpose: Store compliance framework scores and control mappings

-- Create compliance database schema if using split DBs
-- For single DB, these go in engine_compliance schema

-- Ensure tenants table exists
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    customer_id VARCHAR(255),
    provider VARCHAR(50),
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- 1. COMPLIANCE SCANS (Scan-level summary)
-- ============================================================================
CREATE TABLE IF NOT EXISTS compliance_scans (
    compliance_scan_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    check_scan_id VARCHAR(255) NOT NULL,  -- Links to check scan
    cloud VARCHAR(50) NOT NULL,
    scan_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Overall stats
    total_checks INT NOT NULL DEFAULT 0,
    total_passed INT DEFAULT 0,
    total_failed INT DEFAULT 0,
    total_controls_evaluated INT DEFAULT 0,
    total_controls_passed INT DEFAULT 0,
    total_controls_failed INT DEFAULT 0,
    
    -- Frameworks covered
    frameworks_evaluated JSONB,  -- ["CIS", "PCI-DSS", "ISO27001"]
    
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE INDEX idx_compliance_scans_tenant ON compliance_scans(tenant_id);
CREATE INDEX idx_compliance_scans_check ON compliance_scans(check_scan_id);
CREATE INDEX idx_compliance_scans_timestamp ON compliance_scans(scan_timestamp DESC);

-- ============================================================================
-- 2. FRAMEWORK SCORES (One row per framework per scan)
-- ============================================================================
CREATE TABLE IF NOT EXISTS framework_scores (
    id SERIAL PRIMARY KEY,
    compliance_scan_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    
    -- Framework identification
    framework_name VARCHAR(100) NOT NULL,  -- CIS, PCI-DSS, ISO27001, SOC2, NIST-CSF
    framework_version VARCHAR(50),
    
    -- Compliance scores
    total_controls INT NOT NULL DEFAULT 0,
    controls_passed INT DEFAULT 0,
    controls_failed INT DEFAULT 0,
    controls_not_applicable INT DEFAULT 0,
    compliance_score DECIMAL(5,2),  -- Percentage 0-100
    
    -- Rule-level stats
    total_rules_mapped INT DEFAULT 0,
    rules_passed INT DEFAULT 0,
    rules_failed INT DEFAULT 0,
    
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (compliance_scan_id) REFERENCES compliance_scans(compliance_scan_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    
    UNIQUE(compliance_scan_id, framework_name, framework_version)
);

CREATE INDEX idx_framework_scores_scan ON framework_scores(compliance_scan_id);
CREATE INDEX idx_framework_scores_framework ON framework_scores(framework_name);
CREATE INDEX idx_framework_scores_score ON framework_scores(compliance_score DESC);

-- ============================================================================
-- 3. CONTROL RESULTS (Detailed control-level results)
-- ============================================================================
CREATE TABLE IF NOT EXISTS control_results (
    id SERIAL PRIMARY KEY,
    compliance_scan_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    
    -- Framework & Control
    framework_name VARCHAR(100) NOT NULL,
    framework_version VARCHAR(50),
    control_id VARCHAR(255) NOT NULL,
    control_title TEXT,
    control_category VARCHAR(255),
    
    -- Control status
    status VARCHAR(20) NOT NULL,  -- PASS, FAIL, NOT_APPLICABLE, PARTIAL
    
    -- Mapped rules
    mapped_rule_ids JSONB,  -- Array of rule_ids that map to this control
    passed_rules JSONB,     -- Rules that passed
    failed_rules JSONB,     -- Rules that failed
    
    -- Affected resources
    total_resources INT DEFAULT 0,
    failed_resources JSONB,  -- Array of resource UIDs that failed
    
    -- Scoring
    control_score DECIMAL(5,2),  -- Percentage for this control
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (compliance_scan_id) REFERENCES compliance_scans(compliance_scan_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    
    UNIQUE(compliance_scan_id, framework_name, control_id)
);

CREATE INDEX idx_control_results_scan ON control_results(compliance_scan_id);
CREATE INDEX idx_control_results_framework ON control_results(framework_name, control_id);
CREATE INDEX idx_control_results_status ON control_results(status);

-- ============================================================================
-- HELPER VIEWS
-- ============================================================================

-- Framework compliance summary
CREATE OR REPLACE VIEW framework_compliance_summary AS
SELECT 
    fs.compliance_scan_id,
    fs.tenant_id,
    fs.framework_name,
    fs.compliance_score,
    fs.total_controls,
    fs.controls_passed,
    fs.controls_failed,
    cs.scan_timestamp
FROM framework_scores fs
JOIN compliance_scans cs ON fs.compliance_scan_id = cs.compliance_scan_id
ORDER BY fs.compliance_score DESC;

-- Control failure summary (top failing controls across frameworks)
CREATE OR REPLACE VIEW failing_controls_summary AS
SELECT 
    framework_name,
    control_id,
    control_title,
    COUNT(*) as failure_count,
    AVG(control_score) as avg_score
FROM control_results
WHERE status IN ('FAIL', 'PARTIAL')
GROUP BY framework_name, control_id, control_title
ORDER BY failure_count DESC;

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================
