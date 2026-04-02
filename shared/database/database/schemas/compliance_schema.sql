-- ============================================================================
-- Compliance Engine Database Schema
-- ============================================================================
-- Database: threat_engine_compliance
-- Purpose: Store compliance scan results, framework mappings, and assessments
-- Used by: engine_compliance
-- Tables: tenants, compliance_report, compliance_findings, compliance_frameworks,
--         compliance_controls, compliance_assessments, control_assessment_results,
--         rule_control_mapping, remediation_tracking

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Compliance Report (scan-level metadata)
CREATE TABLE IF NOT EXISTS compliance_report (
    scan_run_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    cloud VARCHAR(50) DEFAULT 'aws',
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
    customer_id VARCHAR(255),
    provider VARCHAR(50) DEFAULT 'aws',
    status VARCHAR(50) DEFAULT 'completed',
    execution_id VARCHAR(255),

    CONSTRAINT fk_tenant_report FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Compliance Findings (individual compliance check results)
CREATE TABLE IF NOT EXISTS compliance_findings (
    finding_id VARCHAR(255) PRIMARY KEY,
    scan_run_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
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
    resource_uid TEXT,                -- Canonical identifier (ARN for AWS, ARM ID for Azure, etc.)
    region VARCHAR(50),
    finding_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    customer_id VARCHAR(255),
    compliance_framework VARCHAR(255),
    control_id VARCHAR(255),
    control_name VARCHAR(500),
    account_id VARCHAR(255),

    CONSTRAINT fk_tenant_finding FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- ============================================================================
-- FRAMEWORK & CONTROL TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS compliance_frameworks (
    framework_id VARCHAR(100) PRIMARY KEY,
    framework_name VARCHAR(255) NOT NULL,
    version VARCHAR(50),
    description TEXT,
    authority VARCHAR(255),
    category VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    framework_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_controls (
    control_id VARCHAR(255) PRIMARY KEY,
    framework_id VARCHAR(100) NOT NULL,
    control_number VARCHAR(100),
    control_name VARCHAR(500) NOT NULL,
    control_description TEXT,
    control_type VARCHAR(50),
    severity VARCHAR(20),
    control_family VARCHAR(100),
    implementation_guidance TEXT,
    testing_procedures TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    control_data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_framework FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(framework_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rule_control_mapping (
    mapping_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id TEXT NOT NULL,
    control_id VARCHAR(255) NOT NULL,
    framework_id VARCHAR(100) NOT NULL,
    mapping_type VARCHAR(50) DEFAULT 'direct',
    coverage_percentage INTEGER DEFAULT 100,
    mapping_notes TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_control_mapping FOREIGN KEY (control_id) REFERENCES compliance_controls(control_id) ON DELETE CASCADE,
    CONSTRAINT fk_framework_mapping FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(framework_id) ON DELETE CASCADE,
    UNIQUE(rule_id, control_id)
);

-- ============================================================================
-- ASSESSMENT TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS compliance_assessments (
    assessment_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    framework_id VARCHAR(100) NOT NULL,
    assessment_name VARCHAR(255) NOT NULL,
    assessment_type VARCHAR(50) NOT NULL,
    scope_description TEXT,
    assessor VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'draft',
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    target_completion_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    total_controls INTEGER DEFAULT 0,
    controls_implemented INTEGER DEFAULT 0,
    controls_not_applicable INTEGER DEFAULT 0,
    controls_deficient INTEGER DEFAULT 0,
    overall_score DECIMAL(5,2),
    assessment_data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_tenant_assessment FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_framework_assessment FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(framework_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS control_assessment_results (
    result_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID NOT NULL,
    control_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    implementation_status VARCHAR(50) NOT NULL,
    effectiveness VARCHAR(50),
    test_method VARCHAR(100),
    test_results TEXT,
    deficiencies TEXT,
    recommendations TEXT,
    evidence_references JSONB DEFAULT '[]',
    residual_risk VARCHAR(20),
    compensating_controls TEXT,
    target_remediation_date DATE,
    actual_remediation_date DATE,
    assessed_by VARCHAR(255),
    assessed_at TIMESTAMP WITH TIME ZONE,
    reviewed_by VARCHAR(255),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    result_data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_assessment_result FOREIGN KEY (assessment_id) REFERENCES compliance_assessments(assessment_id) ON DELETE CASCADE,
    CONSTRAINT fk_control_result FOREIGN KEY (control_id) REFERENCES compliance_controls(control_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_result FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS remediation_tracking (
    remediation_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    finding_id VARCHAR(255),
    control_id VARCHAR(255),
    issue_type VARCHAR(50) NOT NULL,
    priority VARCHAR(20) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    title VARCHAR(255) NOT NULL,
    description TEXT,
    remediation_plan TEXT,
    assigned_to VARCHAR(255),
    target_date DATE,
    actual_completion_date DATE,
    effort_estimate_hours INTEGER,
    actual_effort_hours INTEGER,
    cost_estimate DECIMAL(12,2),
    actual_cost DECIMAL(12,2),
    business_justification TEXT,
    technical_details JSONB DEFAULT '{}',
    progress_notes JSONB DEFAULT '[]',
    verification_method VARCHAR(100),
    verification_status VARCHAR(50),
    verified_by VARCHAR(255),
    verified_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_tenant_remediation FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_control_remediation FOREIGN KEY (control_id) REFERENCES compliance_controls(control_id) ON DELETE SET NULL
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Report indexes
CREATE INDEX IF NOT EXISTS idx_cr_tenant ON compliance_report(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cr_scan_run ON compliance_report(scan_run_id);
-- Removed: idx_cr_check_scan and idx_cr_discovery_scan (columns removed)
CREATE INDEX IF NOT EXISTS idx_cr_completed_at ON compliance_report(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_cr_cloud ON compliance_report(cloud);

-- Finding indexes
CREATE INDEX IF NOT EXISTS idx_cf_tenant ON compliance_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cf_scan_run ON compliance_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_cf_severity ON compliance_findings(severity);
CREATE INDEX IF NOT EXISTS idx_cf_status ON compliance_findings(status);
CREATE INDEX IF NOT EXISTS idx_cf_rule_id ON compliance_findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_cf_resource_type ON compliance_findings(resource_type);
CREATE INDEX IF NOT EXISTS idx_cf_last_seen ON compliance_findings(last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_cf_framework ON compliance_findings(compliance_framework);
CREATE INDEX IF NOT EXISTS idx_cf_control ON compliance_findings(control_id);

-- Framework & control indexes
CREATE INDEX IF NOT EXISTS idx_controls_framework ON compliance_controls(framework_id, is_active);
CREATE INDEX IF NOT EXISTS idx_controls_severity ON compliance_controls(severity);
CREATE INDEX IF NOT EXISTS idx_controls_family ON compliance_controls(control_family);
CREATE INDEX IF NOT EXISTS idx_mapping_rule ON rule_control_mapping(rule_id, is_active);
CREATE INDEX IF NOT EXISTS idx_mapping_control ON rule_control_mapping(control_id, framework_id);

-- Assessment indexes
CREATE INDEX IF NOT EXISTS idx_assessment_tenant ON compliance_assessments(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_assessment_framework ON compliance_assessments(framework_id, status);
CREATE INDEX IF NOT EXISTS idx_assessment_completion ON compliance_assessments(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_control_results_assessment ON control_assessment_results(assessment_id);
CREATE INDEX IF NOT EXISTS idx_control_results_status ON control_assessment_results(implementation_status);
CREATE INDEX IF NOT EXISTS idx_control_results_risk ON control_assessment_results(residual_risk);

-- Remediation indexes
CREATE INDEX IF NOT EXISTS idx_remediation_tenant ON remediation_tracking(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_remediation_priority ON remediation_tracking(priority, target_date);
CREATE INDEX IF NOT EXISTS idx_remediation_assigned ON remediation_tracking(assigned_to, status);
CREATE INDEX IF NOT EXISTS idx_remediation_finding ON remediation_tracking(finding_id);

-- JSONB GIN Indexes
CREATE INDEX IF NOT EXISTS idx_cr_report_data_gin ON compliance_report USING gin(report_data);
CREATE INDEX IF NOT EXISTS idx_cf_finding_data_gin ON compliance_findings USING gin(finding_data);
CREATE INDEX IF NOT EXISTS idx_framework_data_gin ON compliance_frameworks USING gin(framework_data);
CREATE INDEX IF NOT EXISTS idx_control_data_gin ON compliance_controls USING gin(control_data);
CREATE INDEX IF NOT EXISTS idx_assessment_data_gin ON compliance_assessments USING gin(assessment_data);
CREATE INDEX IF NOT EXISTS idx_result_data_gin ON control_assessment_results USING gin(result_data);
CREATE INDEX IF NOT EXISTS idx_remediation_technical_gin ON remediation_tracking USING gin(technical_details);

-- Composite indexes
CREATE INDEX IF NOT EXISTS idx_cf_severity_status ON compliance_findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_cf_rule_status ON compliance_findings(rule_id, status);
CREATE INDEX IF NOT EXISTS idx_cf_tenant_severity ON compliance_findings(tenant_id, severity, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_cf_account_id ON compliance_findings(account_id) WHERE account_id IS NOT NULL;

-- Full-text search indexes
CREATE INDEX IF NOT EXISTS idx_cf_resource_uid_trgm ON compliance_findings USING gin(resource_uid gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_control_name_trgm ON compliance_controls USING gin(control_name gin_trgm_ops);

-- Triggers for updated_at
CREATE OR REPLACE FUNCTION update_compliance_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_compliance_frameworks_updated_at ON compliance_frameworks;
CREATE TRIGGER update_compliance_frameworks_updated_at BEFORE UPDATE ON compliance_frameworks
    FOR EACH ROW EXECUTE FUNCTION update_compliance_updated_at_column();

DROP TRIGGER IF EXISTS update_compliance_controls_updated_at ON compliance_controls;
CREATE TRIGGER update_compliance_controls_updated_at BEFORE UPDATE ON compliance_controls
    FOR EACH ROW EXECUTE FUNCTION update_compliance_updated_at_column();

DROP TRIGGER IF EXISTS update_rule_control_mapping_updated_at ON rule_control_mapping;
CREATE TRIGGER update_rule_control_mapping_updated_at BEFORE UPDATE ON rule_control_mapping
    FOR EACH ROW EXECUTE FUNCTION update_compliance_updated_at_column();

DROP TRIGGER IF EXISTS update_compliance_assessments_updated_at ON compliance_assessments;
CREATE TRIGGER update_compliance_assessments_updated_at BEFORE UPDATE ON compliance_assessments
    FOR EACH ROW EXECUTE FUNCTION update_compliance_updated_at_column();

DROP TRIGGER IF EXISTS update_control_assessment_results_updated_at ON control_assessment_results;
CREATE TRIGGER update_control_assessment_results_updated_at BEFORE UPDATE ON control_assessment_results
    FOR EACH ROW EXECUTE FUNCTION update_compliance_updated_at_column();

DROP TRIGGER IF EXISTS update_remediation_tracking_updated_at ON remediation_tracking;
CREATE TRIGGER update_remediation_tracking_updated_at BEFORE UPDATE ON remediation_tracking
    FOR EACH ROW EXECUTE FUNCTION update_compliance_updated_at_column();

-- Insert default compliance frameworks
INSERT INTO compliance_frameworks (framework_id, framework_name, version, authority, category, framework_data) VALUES
('nist_csf_1_1', 'NIST Cybersecurity Framework', '1.1', 'NIST', 'security', '{"functions": ["identify", "protect", "detect", "respond", "recover"]}'),
('iso_27001_2013', 'ISO/IEC 27001:2013', '2013', 'ISO', 'security', '{"clauses": 14, "controls": 114}'),
('soc2_type2', 'SOC 2 Type II', '2017', 'AICPA', 'security', '{"principles": ["security", "availability", "confidentiality", "processing_integrity", "privacy"]}'),
('pci_dss_3_2_1', 'PCI DSS', '3.2.1', 'PCI Security Standards Council', 'security', '{"requirements": 12, "sub_requirements": 78}'),
('hipaa_security', 'HIPAA Security Rule', '2003', 'HHS', 'privacy', '{"safeguards": ["administrative", "physical", "technical"]}')
ON CONFLICT (framework_id) DO NOTHING;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE compliance_report IS 'Compliance scan metadata with links to check/discovery scans';
COMMENT ON TABLE compliance_findings IS 'Individual compliance findings mapped to frameworks';
COMMENT ON TABLE compliance_frameworks IS 'Compliance framework definitions';
COMMENT ON TABLE compliance_controls IS 'Individual controls within frameworks';
COMMENT ON TABLE rule_control_mapping IS 'Mapping between check rules and compliance controls';
COMMENT ON TABLE compliance_assessments IS 'Formal compliance assessment tracking';
COMMENT ON TABLE control_assessment_results IS 'Assessment results per control';
COMMENT ON TABLE remediation_tracking IS 'Remediation tracking for compliance gaps';
