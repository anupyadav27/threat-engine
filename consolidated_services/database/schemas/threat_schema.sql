-- PostgreSQL Schema for Threat Engine
-- Threat detection, analysis, and intelligence management

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Minimal tenants table for FK (split-DB: no cross-DB refs)
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Threat Intelligence Table
CREATE TABLE IF NOT EXISTS threat_intelligence (
    intel_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    source VARCHAR(100) NOT NULL,  -- 'internal', 'osint', 'commercial', 'partner'
    intel_type VARCHAR(50) NOT NULL,  -- 'ioc', 'ttp', 'signature', 'behavior'
    category VARCHAR(100),  -- 'malware', 'phishing', 'c2', 'lateral_movement'
    severity VARCHAR(20) NOT NULL,  -- 'low', 'medium', 'high', 'critical'
    confidence VARCHAR(20) NOT NULL,  -- 'low', 'medium', 'high'
    value_hash VARCHAR(64) NOT NULL,  -- SHA256 of the threat value for dedup
    threat_data JSONB NOT NULL,  -- Full threat intelligence data
    indicators JSONB DEFAULT '[]',  -- Array of IOCs/indicators
    ttps JSONB DEFAULT '[]',  -- MITRE ATT&CK TTPs
    tags JSONB DEFAULT '[]',  -- Tags for categorization
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_intel FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Threat Detections Table
CREATE TABLE IF NOT EXISTS threat_detections (
    detection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    scan_id VARCHAR(255),
    detection_type VARCHAR(50) NOT NULL,  -- 'configuration', 'behavioral', 'signature'
    rule_id VARCHAR(255),
    rule_name VARCHAR(255),
    resource_arn TEXT,
    resource_id VARCHAR(255),
    resource_type VARCHAR(100),
    account_id VARCHAR(255),
    region VARCHAR(50),
    provider VARCHAR(50),
    severity VARCHAR(20) NOT NULL,  -- 'low', 'medium', 'high', 'critical'
    confidence VARCHAR(20) NOT NULL,  -- 'low', 'medium', 'high'
    status VARCHAR(50) NOT NULL DEFAULT 'open',  -- 'open', 'investigating', 'resolved', 'false_positive'
    threat_category VARCHAR(100),  -- 'malware', 'data_exfiltration', 'privilege_escalation'
    mitre_tactics JSONB DEFAULT '[]',  -- MITRE ATT&CK tactics
    mitre_techniques JSONB DEFAULT '[]',  -- MITRE ATT&CK techniques
    indicators JSONB DEFAULT '[]',  -- Matching indicators/IOCs
    evidence JSONB NOT NULL,  -- Evidence data that triggered detection
    context JSONB DEFAULT '{}',  -- Additional context (network, process, file info)
    detection_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by VARCHAR(255),
    resolution_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_detection FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Threat Analysis Table (for detailed analysis results)
CREATE TABLE IF NOT EXISTS threat_analysis (
    analysis_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    detection_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    analysis_type VARCHAR(50) NOT NULL,  -- 'automated', 'manual', 'ml'
    analyzer VARCHAR(100),  -- 'yara', 'sigma', 'custom_ml', 'analyst_john'
    analysis_status VARCHAR(50) NOT NULL DEFAULT 'pending',  -- 'pending', 'running', 'completed', 'failed'
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    verdict VARCHAR(50),  -- 'malicious', 'suspicious', 'benign', 'unknown'
    analysis_results JSONB NOT NULL,  -- Detailed analysis results
    recommendations JSONB DEFAULT '[]',  -- Recommended actions
    related_threats JSONB DEFAULT '[]',  -- Related threat IDs
    attack_chain JSONB DEFAULT '[]',  -- Attack progression/kill chain
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_detection_analysis FOREIGN KEY (detection_id) REFERENCES threat_detections(detection_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_analysis FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Threat Hunt Queries Table
CREATE TABLE IF NOT EXISTS threat_hunt_queries (
    hunt_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    query_name VARCHAR(255) NOT NULL,
    description TEXT,
    hunt_type VARCHAR(50) NOT NULL,  -- 'proactive', 'reactive', 'baseline'
    query_language VARCHAR(50) NOT NULL,  -- 'sql', 'kql', 'spl', 'sigma'
    query_text TEXT NOT NULL,
    target_data_sources JSONB DEFAULT '[]',  -- Which data sources to query
    mitre_tactics JSONB DEFAULT '[]',
    mitre_techniques JSONB DEFAULT '[]',
    tags JSONB DEFAULT '[]',
    schedule_cron VARCHAR(100),  -- For automated hunts
    is_active BOOLEAN DEFAULT TRUE,
    last_executed_at TIMESTAMP WITH TIME ZONE,
    execution_count INTEGER DEFAULT 0,
    hit_count INTEGER DEFAULT 0,
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_hunt FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Threat Hunt Results Table
CREATE TABLE IF NOT EXISTS threat_hunt_results (
    result_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hunt_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    execution_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    total_results INTEGER NOT NULL DEFAULT 0,
    new_detections INTEGER NOT NULL DEFAULT 0,
    execution_time_ms INTEGER,
    results_data JSONB NOT NULL,  -- Hunt result data
    status VARCHAR(50) NOT NULL DEFAULT 'completed',  -- 'running', 'completed', 'failed'
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_hunt_result FOREIGN KEY (hunt_id) REFERENCES threat_hunt_queries(hunt_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_hunt_result FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_intel_tenant ON threat_intelligence(tenant_id);
CREATE INDEX IF NOT EXISTS idx_intel_type_severity ON threat_intelligence(intel_type, severity);
CREATE INDEX IF NOT EXISTS idx_intel_hash ON threat_intelligence(value_hash);
CREATE INDEX IF NOT EXISTS idx_intel_active ON threat_intelligence(is_active, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_intel_expires ON threat_intelligence(expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_detection_tenant ON threat_detections(tenant_id);
CREATE INDEX IF NOT EXISTS idx_detection_status_severity ON threat_detections(status, severity);
CREATE INDEX IF NOT EXISTS idx_detection_resource ON threat_detections(resource_arn);
CREATE INDEX IF NOT EXISTS idx_detection_timestamp ON threat_detections(detection_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_detection_rule ON threat_detections(rule_id, status);
CREATE INDEX IF NOT EXISTS idx_detection_account ON threat_detections(account_id, region, provider);

CREATE INDEX IF NOT EXISTS idx_analysis_detection ON threat_analysis(detection_id);
CREATE INDEX IF NOT EXISTS idx_analysis_status ON threat_analysis(analysis_status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_verdict ON threat_analysis(verdict, risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_hunt_tenant_active ON threat_hunt_queries(tenant_id, is_active);
CREATE INDEX IF NOT EXISTS idx_hunt_schedule ON threat_hunt_queries(schedule_cron) WHERE schedule_cron IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hunt_last_executed ON threat_hunt_queries(last_executed_at DESC);

CREATE INDEX IF NOT EXISTS idx_hunt_results_hunt ON threat_hunt_results(hunt_id, execution_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_results_tenant ON threat_hunt_results(tenant_id, execution_timestamp DESC);

-- JSONB GIN Indexes for efficient JSON queries
CREATE INDEX IF NOT EXISTS idx_intel_data_gin ON threat_intelligence USING gin(threat_data);
CREATE INDEX IF NOT EXISTS idx_intel_indicators_gin ON threat_intelligence USING gin(indicators);
CREATE INDEX IF NOT EXISTS idx_intel_ttps_gin ON threat_intelligence USING gin(ttps);

CREATE INDEX IF NOT EXISTS idx_detection_evidence_gin ON threat_detections USING gin(evidence);
CREATE INDEX IF NOT EXISTS idx_detection_indicators_gin ON threat_detections USING gin(indicators);
CREATE INDEX IF NOT EXISTS idx_detection_mitre_gin ON threat_detections USING gin(mitre_techniques);

CREATE INDEX IF NOT EXISTS idx_analysis_results_gin ON threat_analysis USING gin(analysis_results);

CREATE INDEX IF NOT EXISTS idx_hunt_results_data_gin ON threat_hunt_results USING gin(results_data);

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