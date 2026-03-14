-- ============================================================================
-- Threat Engine Database Schema
-- ============================================================================
-- Database: threat_engine_threat
-- Purpose: Threat detection, analysis, intelligence, and MITRE ATT&CK mapping
-- Used by: engine_threat
-- Tables: tenants, threat_report, threat_findings, threat_detections,
--         threat_analysis, threat_intelligence, threat_hunt_queries,
--         threat_hunt_results, mitre_technique_reference

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Tenants table exists in threat DB on RDS
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Threat Report (scan-level metadata)
CREATE TABLE IF NOT EXISTS threat_report (
    threat_scan_id VARCHAR(255) PRIMARY KEY,
    orchestration_id VARCHAR(255),  -- PLANNED: not yet deployed to RDS
    execution_id VARCHAR(255),
    discovery_scan_id VARCHAR(255),
    check_scan_id VARCHAR(255),
    tenant_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255),
    provider VARCHAR(50) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) DEFAULT 'completed',
    total_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    medium_findings INTEGER DEFAULT 0,
    low_findings INTEGER DEFAULT 0,
    threat_score INTEGER DEFAULT 0,
    report_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Threat Findings (individual threat findings from scans)
CREATE TABLE IF NOT EXISTS threat_findings (
    id SERIAL PRIMARY KEY,
    finding_id VARCHAR(255) NOT NULL UNIQUE,
    threat_scan_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255),
    scan_run_id VARCHAR(255) NOT NULL,
    rule_id VARCHAR(255) NOT NULL,
    threat_category VARCHAR(100),
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    resource_uid TEXT,                -- Canonical identifier (ARN for AWS, ARM ID for Azure, etc.)
    account_id VARCHAR(255),
    region VARCHAR(50),
    mitre_tactics JSONB DEFAULT '[]',
    mitre_techniques JSONB DEFAULT '[]',
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    finding_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- MITRE ATT&CK REFERENCE
-- ============================================================================

CREATE TABLE IF NOT EXISTS mitre_technique_reference (
    id SERIAL PRIMARY KEY,
    technique_id VARCHAR(20) UNIQUE,
    technique_name TEXT NOT NULL,
    tactics JSONB DEFAULT '[]'::jsonb,
    sub_techniques JSONB DEFAULT '[]'::jsonb,
    description TEXT,
    url TEXT,
    platforms JSONB DEFAULT '[]'::jsonb,
    aws_checks JSONB DEFAULT '[]'::jsonb,
    azure_checks JSONB DEFAULT '[]'::jsonb,
    gcp_checks JSONB DEFAULT '[]'::jsonb,
    ibm_keywords JSONB DEFAULT '[]'::jsonb,
    k8s_keywords JSONB DEFAULT '[]'::jsonb,
    ocp_keywords JSONB DEFAULT '[]'::jsonb,
    aws_service_coverage JSONB DEFAULT '{}'::jsonb,
    detection_keywords JSONB DEFAULT '[]'::jsonb,
    -- Detection & Remediation guidance (added for actionable threat intel)
    detection_guidance JSONB DEFAULT '{}',   -- {cloudtrail_events:[], guardduty_types:[], cloudwatch_patterns:[], data_sources:[]}
    remediation_guidance JSONB DEFAULT '{}', -- {immediate:[], preventive:[], detective:[], aws_services:[]}
    severity_base VARCHAR(20),               -- default severity for this technique: critical/high/medium/low
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- DETECTION & ANALYSIS TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS threat_intelligence (
    intel_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    source VARCHAR(100) NOT NULL,
    intel_type VARCHAR(50) NOT NULL,
    category VARCHAR(100),
    severity VARCHAR(20) NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    value_hash VARCHAR(64) NOT NULL,
    threat_data JSONB NOT NULL,
    indicators JSONB DEFAULT '[]',
    ttps JSONB DEFAULT '[]',
    tags JSONB DEFAULT '[]',
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

);

CREATE TABLE IF NOT EXISTS threat_detections (
    detection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    scan_id VARCHAR(255),
    detection_type VARCHAR(50) NOT NULL,
    rule_id VARCHAR(255),
    rule_name VARCHAR(255),
    resource_uid TEXT,                -- Canonical identifier (ARN for AWS, ARM ID for Azure, etc.)
    resource_id VARCHAR(255),
    resource_type VARCHAR(100),
    account_id VARCHAR(255),
    region VARCHAR(50),
    provider VARCHAR(50),
    severity VARCHAR(20) NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    threat_category VARCHAR(100),
    mitre_tactics JSONB DEFAULT '[]',
    mitre_techniques JSONB DEFAULT '[]',
    indicators JSONB DEFAULT '[]',
    evidence JSONB NOT NULL,
    context JSONB DEFAULT '{}',
    detection_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by VARCHAR(255),
    resolution_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

);

CREATE TABLE IF NOT EXISTS threat_analysis (
    analysis_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    detection_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    analysis_type VARCHAR(50) NOT NULL,
    analyzer VARCHAR(100),
    analysis_status VARCHAR(50) NOT NULL DEFAULT 'pending',
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    verdict VARCHAR(50),
    analysis_results JSONB NOT NULL,
    recommendations JSONB DEFAULT '[]',
    related_threats JSONB DEFAULT '[]',
    attack_chain JSONB DEFAULT '[]',
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_detection_analysis FOREIGN KEY (detection_id) REFERENCES threat_detections(detection_id) ON DELETE CASCADE,
    CONSTRAINT uq_detection_analysis_type UNIQUE (detection_id, analysis_type)
);

-- ============================================================================
-- THREAT HUNTING
-- ============================================================================

CREATE TABLE IF NOT EXISTS threat_hunt_queries (
    hunt_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    query_name VARCHAR(255) NOT NULL,
    description TEXT,
    hunt_type VARCHAR(50) NOT NULL,
    query_language VARCHAR(50) NOT NULL,
    query_text TEXT NOT NULL,
    target_data_sources JSONB DEFAULT '[]',
    mitre_tactics JSONB DEFAULT '[]',
    mitre_techniques JSONB DEFAULT '[]',
    tags JSONB DEFAULT '[]',
    schedule_cron VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    last_executed_at TIMESTAMP WITH TIME ZONE,
    execution_count INTEGER DEFAULT 0,
    hit_count INTEGER DEFAULT 0,
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

);

CREATE TABLE IF NOT EXISTS threat_hunt_results (
    result_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hunt_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    execution_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    total_results INTEGER NOT NULL DEFAULT 0,
    new_detections INTEGER NOT NULL DEFAULT 0,
    execution_time_ms INTEGER,
    results_data JSONB NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'completed',
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_hunt_result FOREIGN KEY (hunt_id) REFERENCES threat_hunt_queries(hunt_id) ON DELETE CASCADE
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Threat Report indexes
CREATE INDEX IF NOT EXISTS idx_tr_tenant ON threat_report(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tr_check_scan ON threat_report(check_scan_id);
CREATE INDEX IF NOT EXISTS idx_tr_discovery_scan ON threat_report(discovery_scan_id);
CREATE INDEX IF NOT EXISTS idx_tr_status ON threat_report(status);
CREATE INDEX IF NOT EXISTS idx_tr_completed_at ON threat_report(completed_at DESC);

-- Threat Findings indexes
CREATE INDEX IF NOT EXISTS idx_tf_tenant ON threat_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tf_threat_scan ON threat_findings(threat_scan_id);
CREATE INDEX IF NOT EXISTS idx_tf_severity ON threat_findings(severity);
CREATE INDEX IF NOT EXISTS idx_tf_rule_id ON threat_findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_tf_resource_uid ON threat_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_tf_threat_category ON threat_findings(threat_category);
CREATE INDEX IF NOT EXISTS idx_tf_account_region ON threat_findings(account_id, region);

-- MITRE reference indexes
CREATE INDEX IF NOT EXISTS idx_mitre_technique ON mitre_technique_reference(technique_id);

-- Intelligence indexes
CREATE INDEX IF NOT EXISTS idx_intel_tenant ON threat_intelligence(tenant_id);
CREATE INDEX IF NOT EXISTS idx_intel_type_severity ON threat_intelligence(intel_type, severity);
CREATE INDEX IF NOT EXISTS idx_intel_hash ON threat_intelligence(value_hash);
CREATE INDEX IF NOT EXISTS idx_intel_active ON threat_intelligence(is_active, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_intel_expires ON threat_intelligence(expires_at) WHERE expires_at IS NOT NULL;

-- Detection indexes
CREATE INDEX IF NOT EXISTS idx_detection_tenant ON threat_detections(tenant_id);
CREATE INDEX IF NOT EXISTS idx_detection_status_severity ON threat_detections(status, severity);
CREATE INDEX IF NOT EXISTS idx_detection_resource_uid ON threat_detections(resource_uid);
CREATE INDEX IF NOT EXISTS idx_detection_timestamp ON threat_detections(detection_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_detection_rule ON threat_detections(rule_id, status);
CREATE INDEX IF NOT EXISTS idx_detection_account ON threat_detections(account_id, region, provider);

-- Analysis indexes
CREATE INDEX IF NOT EXISTS idx_analysis_detection ON threat_analysis(detection_id);
CREATE INDEX IF NOT EXISTS idx_analysis_status ON threat_analysis(analysis_status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_verdict ON threat_analysis(verdict, risk_score DESC);

-- Hunt indexes
CREATE INDEX IF NOT EXISTS idx_hunt_tenant_active ON threat_hunt_queries(tenant_id, is_active);
CREATE INDEX IF NOT EXISTS idx_hunt_schedule ON threat_hunt_queries(schedule_cron) WHERE schedule_cron IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hunt_last_executed ON threat_hunt_queries(last_executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_results_hunt ON threat_hunt_results(hunt_id, execution_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_results_tenant ON threat_hunt_results(tenant_id, execution_timestamp DESC);

-- JSONB GIN Indexes
CREATE INDEX IF NOT EXISTS idx_intel_data_gin ON threat_intelligence USING gin(threat_data);
CREATE INDEX IF NOT EXISTS idx_intel_indicators_gin ON threat_intelligence USING gin(indicators);
CREATE INDEX IF NOT EXISTS idx_intel_ttps_gin ON threat_intelligence USING gin(ttps);
CREATE INDEX IF NOT EXISTS idx_detection_evidence_gin ON threat_detections USING gin(evidence);
CREATE INDEX IF NOT EXISTS idx_detection_indicators_gin ON threat_detections USING gin(indicators);
CREATE INDEX IF NOT EXISTS idx_detection_mitre_gin ON threat_detections USING gin(mitre_techniques);
CREATE INDEX IF NOT EXISTS idx_analysis_results_gin ON threat_analysis USING gin(analysis_results);
CREATE INDEX IF NOT EXISTS idx_hunt_results_data_gin ON threat_hunt_results USING gin(results_data);
CREATE INDEX IF NOT EXISTS idx_tf_mitre_tactics_gin ON threat_findings USING gin(mitre_tactics);
CREATE INDEX IF NOT EXISTS idx_tf_mitre_techniques_gin ON threat_findings USING gin(mitre_techniques);
CREATE INDEX IF NOT EXISTS idx_tf_evidence_gin ON threat_findings USING gin(evidence);

-- Full-text search indexes
CREATE INDEX IF NOT EXISTS idx_detection_rule_name_trgm ON threat_detections USING gin(rule_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_hunt_query_name_trgm ON threat_hunt_queries USING gin(query_name gin_trgm_ops);

-- Triggers for updated_at
CREATE OR REPLACE FUNCTION update_threat_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_threat_intelligence_updated_at ON threat_intelligence;
CREATE TRIGGER update_threat_intelligence_updated_at BEFORE UPDATE ON threat_intelligence
    FOR EACH ROW EXECUTE FUNCTION update_threat_updated_at_column();

DROP TRIGGER IF EXISTS update_threat_detections_updated_at ON threat_detections;
CREATE TRIGGER update_threat_detections_updated_at BEFORE UPDATE ON threat_detections
    FOR EACH ROW EXECUTE FUNCTION update_threat_updated_at_column();

DROP TRIGGER IF EXISTS update_threat_hunt_queries_updated_at ON threat_hunt_queries;
CREATE TRIGGER update_threat_hunt_queries_updated_at BEFORE UPDATE ON threat_hunt_queries
    FOR EACH ROW EXECUTE FUNCTION update_threat_updated_at_column();

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE tenants IS 'Tenant master for threat engine DB';
COMMENT ON TABLE threat_report IS 'Threat scan metadata with links to check/discovery scans';
COMMENT ON TABLE threat_findings IS 'Individual threat findings with MITRE mapping';
COMMENT ON TABLE mitre_technique_reference IS 'MITRE ATT&CK technique reference data';
COMMENT ON TABLE threat_intelligence IS 'Threat intelligence feeds and IOCs';
COMMENT ON TABLE threat_detections IS 'Real-time threat detections';
COMMENT ON TABLE threat_analysis IS 'Detailed analysis results for detections';
COMMENT ON TABLE threat_hunt_queries IS 'Proactive threat hunting queries';
COMMENT ON TABLE threat_hunt_results IS 'Results from threat hunt executions';
