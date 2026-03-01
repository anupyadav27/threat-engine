-- Migration: Add Rule Metadata Table
-- Purpose: Centralized storage for rule metadata (severity, title, description, remediation, compliance)
-- This allows threat engine to enrich findings without loading YAML files

-- Rule Metadata Table
CREATE TABLE IF NOT EXISTS rule_metadata (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL UNIQUE,
    service VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL DEFAULT 'aws',
    resource VARCHAR(100),
    
    -- Core Metadata
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',  -- 'critical', 'high', 'medium', 'low', 'info'
    title TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    rationale TEXT,
    
    -- Classification
    domain VARCHAR(100),
    subcategory VARCHAR(100),
    requirement VARCHAR(255),
    assertion_id VARCHAR(255),
    
    -- Compliance Frameworks
    compliance_frameworks JSONB,  -- Array of framework IDs
    
    -- Data Security Context
    data_security JSONB,  -- {applicable: bool, modules: [], categories: [], priority: str, impact: {}}
    
    -- References (quoted: reserved word in PostgreSQL)
    "references" JSONB,  -- Array of URLs
    
    -- Source Tracking
    metadata_source VARCHAR(50) NOT NULL DEFAULT 'default',  -- 'default', 'user', 'custom', 'tenant-{id}'
    source VARCHAR(50) NOT NULL DEFAULT 'default',
    generated_by VARCHAR(50) DEFAULT 'default',
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_rule_metadata_rule_id ON rule_metadata(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_service ON rule_metadata(service);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_severity ON rule_metadata(severity);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_source ON rule_metadata(metadata_source);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_provider ON rule_metadata(provider);

-- Add metadata_source to check_results for tracking
ALTER TABLE check_results 
ADD COLUMN IF NOT EXISTS metadata_source VARCHAR(50) DEFAULT 'default';

-- Create index for check_results rule_id (for JOINs with rule_metadata)
CREATE INDEX IF NOT EXISTS idx_check_results_rule_id ON check_results(rule_id);

-- Optional: View for enriched check results
CREATE OR REPLACE VIEW enriched_check_results AS
SELECT 
    cr.*,
    rm.severity,
    rm.title,
    rm.description,
    rm.remediation,
    rm.compliance_frameworks,
    rm.data_security,
    rm.references,
    rm.metadata_source as rule_metadata_source
FROM check_results cr
LEFT JOIN rule_metadata rm ON cr.rule_id = rm.rule_id;

-- Comments
COMMENT ON TABLE rule_metadata IS 'Centralized metadata for security rules/checks';
COMMENT ON COLUMN rule_metadata.severity IS 'Rule severity: critical, high, medium, low, info';
COMMENT ON COLUMN rule_metadata.metadata_source IS 'Source of metadata: default (shipped rules), user (user-created), custom (custom/override), tenant-{id} (tenant-specific). Use for default vs customer-specific rules.';
COMMENT ON COLUMN rule_metadata.compliance_frameworks IS 'Array of compliance framework IDs (e.g., cis_aws_aws_3.4_0046)';
COMMENT ON COLUMN rule_metadata.data_security IS 'Data security context including applicable modules, categories, priority, and impact';
