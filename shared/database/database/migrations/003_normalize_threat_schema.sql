-- Migration: Normalize Threat Database Schema
-- Purpose: Replace single JSONB blob with queryable normalized tables
-- Enables efficient filtering by severity, category, resource, and proper drift tracking

-- Create tenants table if not exists (for FK constraint)
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    customer_id VARCHAR(255),
    provider VARCHAR(50),
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Backup old threat_reports to archive table (just in case)
CREATE TABLE IF NOT EXISTS threat_reports_archive AS 
SELECT * FROM threat_reports WHERE false;

INSERT INTO threat_reports_archive SELECT * FROM threat_reports;

-- Drop old threat_reports table
DROP TABLE IF EXISTS threat_reports CASCADE;

-- ============================================================================
-- 1. THREAT SCANS (Summary per scan)
-- ============================================================================
CREATE TABLE threat_scans (
    scan_run_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    check_scan_id VARCHAR(255) NOT NULL,
    discovery_scan_id VARCHAR(255),
    cloud VARCHAR(50) NOT NULL,
    trigger_type VARCHAR(50),
    
    -- Threat counts
    total_threats INT NOT NULL DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    info_count INT DEFAULT 0,
    
    -- Category breakdown
    identity_count INT DEFAULT 0,
    exposure_count INT DEFAULT 0,
    data_breach_count INT DEFAULT 0,
    data_exfiltration_count INT DEFAULT 0,
    misconfiguration_count INT DEFAULT 0,
    drift_count INT DEFAULT 0,
    
    -- Status breakdown
    open_count INT DEFAULT 0,
    resolved_count INT DEFAULT 0,
    suppressed_count INT DEFAULT 0,
    
    -- Metadata
    generated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE INDEX idx_threat_scans_tenant ON threat_scans(tenant_id);
CREATE INDEX idx_threat_scans_check ON threat_scans(check_scan_id);
CREATE INDEX idx_threat_scans_generated ON threat_scans(generated_at DESC);

-- ============================================================================
-- 2. THREATS (One row per threat - queryable)
-- ============================================================================
CREATE TABLE threats (
    threat_id VARCHAR(255) PRIMARY KEY,
    scan_run_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    
    -- Link to rule metadata (primary rule that triggered this threat)
    primary_rule_id VARCHAR(255),
    
    -- Threat classification
    threat_type VARCHAR(50) NOT NULL,  -- identity, exposure, drift, misconfiguration, data_breach, data_exfiltration
    category VARCHAR(50),
    severity VARCHAR(20) NOT NULL,     -- critical, high, medium, low, info
    confidence VARCHAR(20),            -- high, medium, low
    status VARCHAR(20) DEFAULT 'open', -- open, resolved, suppressed, false_positive
    
    -- Descriptive fields (from rule_metadata or generated)
    title TEXT NOT NULL,
    description TEXT,
    remediation_summary TEXT,
    remediation_steps JSONB,  -- Array of step strings
    
    -- Tracking
    first_seen_at TIMESTAMP WITH TIME ZONE,
    last_seen_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Counts
    misconfig_count INT DEFAULT 0,           -- How many check failures in this threat
    affected_resource_count INT DEFAULT 0,   -- How many resources affected
    
    -- References to findings (for correlation)
    misconfig_finding_refs JSONB,  -- Array of finding_ids
    
    FOREIGN KEY (scan_run_id) REFERENCES threat_scans(scan_run_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Note: FK to rule_metadata would be cross-database (check DB), so we keep it as reference only
CREATE INDEX idx_threats_scan ON threats(scan_run_id);
CREATE INDEX idx_threats_tenant ON threats(tenant_id);
CREATE INDEX idx_threats_severity ON threats(severity, status);
CREATE INDEX idx_threats_category ON threats(category, severity);
CREATE INDEX idx_threats_type ON threats(threat_type);
CREATE INDEX idx_threats_status ON threats(status);
CREATE INDEX idx_threats_rule ON threats(primary_rule_id);
CREATE INDEX idx_threats_resource_count ON threats(affected_resource_count DESC);

-- ============================================================================
-- 3. THREAT RESOURCES (Which resources affected by which threats)
-- ============================================================================
CREATE TABLE threat_resources (
    id SERIAL PRIMARY KEY,
    threat_id VARCHAR(255) NOT NULL,
    resource_uid TEXT NOT NULL,
    resource_arn TEXT,
    resource_type VARCHAR(100),
    account_id VARCHAR(255),
    region VARCHAR(100),
    
    -- Which specific rule(s) failed for this resource in this threat
    failed_rule_ids JSONB,  -- ["rule1", "rule2", ...]
    
    -- Resource metadata snapshot
    tags JSONB,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (threat_id) REFERENCES threats(threat_id) ON DELETE CASCADE,
    
    UNIQUE(threat_id, resource_uid)
);

CREATE INDEX idx_threat_resources_threat ON threat_resources(threat_id);
CREATE INDEX idx_threat_resources_uid ON threat_resources(resource_uid);
CREATE INDEX idx_threat_resources_type ON threat_resources(resource_type);
CREATE INDEX idx_threat_resources_account ON threat_resources(account_id);
CREATE INDEX idx_threat_resources_arn ON threat_resources(resource_arn);

-- ============================================================================
-- 4. DRIFT RECORDS (Configuration and Check Status Drift)
-- ============================================================================
CREATE TABLE drift_records (
    drift_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    resource_uid TEXT NOT NULL,
    resource_arn TEXT,
    resource_type VARCHAR(100),
    account_id VARCHAR(255),
    region VARCHAR(100),
    
    -- Scan context
    current_scan_id VARCHAR(255) NOT NULL,
    previous_scan_id VARCHAR(255),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Configuration drift (from inventory/discoveries)
    config_drift_detected BOOLEAN DEFAULT FALSE,
    change_type VARCHAR(50),  -- added, removed, modified, unchanged
    config_diff JSONB,         -- Detailed diff of what changed
    
    -- Check status drift (PASS<->FAIL changes)
    status_drift_detected BOOLEAN DEFAULT FALSE,
    previous_check_status VARCHAR(20),  -- Overall: pass, fail, warn
    current_check_status VARCHAR(20),
    
    -- Rule-level drift (granular)
    newly_failed_rules JSONB,   -- ["rule1", "rule2"] - rules that newly failed
    newly_passed_rules JSONB,   -- ["rule3", "rule4"] - rules that got fixed
    still_failing_rules JSONB,  -- Rules that continue to fail
    
    -- Link to generated threat (if drift created a threat)
    threat_id VARCHAR(255),
    
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (threat_id) REFERENCES threats(threat_id) ON DELETE SET NULL
);

CREATE INDEX idx_drift_tenant ON drift_records(tenant_id);
CREATE INDEX idx_drift_resource ON drift_records(resource_uid);
CREATE INDEX idx_drift_current_scan ON drift_records(current_scan_id);
CREATE INDEX idx_drift_type ON drift_records(change_type);
CREATE INDEX idx_drift_status ON drift_records(status_drift_detected, config_drift_detected);
CREATE INDEX idx_drift_threat ON drift_records(threat_id);

-- ============================================================================
-- 5. RESOURCE POSTURE VIEW (Live aggregation from check_results)
-- ============================================================================
-- This view groups check results by resource and shows:
-- - Total checks per resource
-- - Pass/Fail/Warn counts
-- - Failed rule_ids array
-- - Severity breakdown
-- Note: This queries check_results from threat_engine_check DB (cross-DB view)

-- For same-database deployment, create view directly:
-- CREATE OR REPLACE VIEW resource_posture_view AS ...

-- For split-database (current), document the view for threat_engine_check:
COMMENT ON TABLE threat_scans IS 'Threat scan summaries. For resource posture, query resource_posture_view in check DB or create cross-DB foreign data wrapper.';

-- ============================================================================
-- HELPER VIEWS
-- ============================================================================

-- Threats by severity (quick summary)
CREATE OR REPLACE VIEW threats_by_severity AS
SELECT 
    scan_run_id,
    tenant_id,
    severity,
    COUNT(*) as count,
    COUNT(*) FILTER (WHERE status = 'open') as open_count
FROM threats
GROUP BY scan_run_id, tenant_id, severity;

-- Threats by category
CREATE OR REPLACE VIEW threats_by_category AS
SELECT 
    scan_run_id,
    tenant_id,
    category,
    COUNT(*) as count,
    COUNT(*) FILTER (WHERE severity = 'high') as high_count,
    COUNT(*) FILTER (WHERE severity = 'medium') as medium_count
FROM threats
GROUP BY scan_run_id, tenant_id, category;

-- Resources with most threats
CREATE OR REPLACE VIEW high_risk_resources AS
SELECT 
    tr.resource_uid,
    tr.resource_type,
    tr.account_id,
    COUNT(DISTINCT tr.threat_id) as threat_count,
    COUNT(DISTINCT tr.threat_id) FILTER (WHERE t.severity = 'high') as high_severity_count,
    MAX(t.last_seen_at) as last_threat_detected
FROM threat_resources tr
JOIN threats t ON tr.threat_id = t.threat_id
GROUP BY tr.resource_uid, tr.resource_type, tr.account_id
ORDER BY threat_count DESC;

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================
