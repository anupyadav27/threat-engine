-- Migration: Compliance Control Mappings Table
-- Purpose: Store framework control → rule mappings from CSV in database
-- This replaces CSV file dependency with database-driven compliance mapping

-- ============================================================================
-- COMPLIANCE CONTROL MAPPINGS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS compliance_control_mappings (
    id SERIAL PRIMARY KEY,
    
    -- Unique identifier from CSV
    unique_compliance_id VARCHAR(255) UNIQUE NOT NULL,
    
    -- Framework information
    technology VARCHAR(50),                    -- MULTI_CLOUD, AWS, AZURE, etc.
    compliance_framework VARCHAR(100) NOT NULL, -- CANADA_PBMM, CIS, PCI-DSS, ISO27001, SOC2, NIST
    framework_id VARCHAR(100),                 -- canada_pbmm_moderate, cis_aws_3.0, etc.
    framework_version VARCHAR(50),             -- Moderate, 3.0, v4.0, etc.
    
    -- Control/Requirement details
    requirement_id VARCHAR(255) NOT NULL,      -- CCCS AC-2, 1.14, 10.2.1.3, etc.
    requirement_name TEXT,                     -- Control title
    requirement_description TEXT,              -- Control description
    section VARCHAR(255),                      -- Section/category
    
    -- Service mapping
    service VARCHAR(100),                      -- IAM, S3, EC2, Multiple
    total_checks INT DEFAULT 0,
    
    -- Automation
    automation_type VARCHAR(50),               -- automated, manual, semi-automated
    confidence_score VARCHAR(50),
    "references" TEXT,
    source_file VARCHAR(255),
    
    -- Rule mappings (semicolon-separated in CSV, converted to array)
    aws_checks TEXT,                           -- Original check names (legacy)
    final_aws_check TEXT,                      -- Final rule IDs (semicolon-separated)
    rule_ids TEXT[],                           -- Parsed array of rule_ids
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for efficient queries
CREATE INDEX idx_ccm_framework ON compliance_control_mappings(compliance_framework);
CREATE INDEX idx_ccm_framework_req ON compliance_control_mappings(compliance_framework, requirement_id);
CREATE INDEX idx_ccm_service ON compliance_control_mappings(service);
CREATE INDEX idx_ccm_rule_ids ON compliance_control_mappings USING GIN(rule_ids);

-- ============================================================================
-- HELPER VIEWS FOR COMPLIANCE ANALYSIS
-- ============================================================================

-- View 1: Compliance by Framework & Service
-- Shows which services have most compliance requirements
CREATE OR REPLACE VIEW compliance_by_service AS
SELECT 
    compliance_framework,
    service,
    COUNT(*) as total_controls,
    SUM(total_checks) as total_checks_required,
    COUNT(DISTINCT requirement_id) as unique_requirements
FROM compliance_control_mappings
WHERE service IS NOT NULL AND service != ''
GROUP BY compliance_framework, service
ORDER BY compliance_framework, total_checks_required DESC;

-- View 2: Framework Coverage Summary
-- Shows how many controls per framework
CREATE OR REPLACE VIEW framework_coverage AS
SELECT 
    compliance_framework,
    framework_version,
    COUNT(*) as total_controls,
    COUNT(DISTINCT service) as services_covered,
    SUM(total_checks) as total_check_mappings,
    COUNT(*) FILTER (WHERE automation_type = 'automated') as automated_controls
FROM compliance_control_mappings
GROUP BY compliance_framework, framework_version
ORDER BY total_controls DESC;

-- View 3: Multi-Framework Controls
-- Shows controls that appear in multiple frameworks (common requirements)
CREATE OR REPLACE VIEW multi_framework_controls AS
SELECT 
    requirement_name,
    string_agg(DISTINCT compliance_framework, ', ') as frameworks,
    COUNT(DISTINCT compliance_framework) as framework_count,
    service,
    final_aws_check
FROM compliance_control_mappings
GROUP BY requirement_name, service, final_aws_check
HAVING COUNT(DISTINCT compliance_framework) > 1
ORDER BY framework_count DESC;

-- ============================================================================
-- COMPLIANCE RESOURCE VIEWS (Using Check DB data)
-- ============================================================================

-- Note: These views require cross-database access to threat_engine_check
-- For single-database deployment, these work directly
-- For split databases, document for reference or use dblink/foreign data wrapper

COMMENT ON TABLE compliance_control_mappings IS 
'Control-to-rule mappings for compliance frameworks. 
Join with check_results to get actual compliance status per control.

Example query:
SELECT ccm.requirement_id, ccm.requirement_name, 
       COUNT(cr.*) as total_checks,
       COUNT(cr.*) FILTER (WHERE cr.status = ''PASS'') as passed
FROM compliance_control_mappings ccm
CROSS JOIN LATERAL unnest(ccm.rule_ids) AS rule_id
LEFT JOIN check_results cr ON cr.rule_id = rule_id AND cr.scan_id = ''scan_123''
GROUP BY ccm.requirement_id, ccm.requirement_name;';

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================
