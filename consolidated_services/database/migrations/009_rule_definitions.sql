-- Migration: Rule Definitions Table (ConfigScan DB)
-- Purpose: Store full rule YAML per service for configscan engines (AWS, Azure, GCP, etc.)
-- Reference: Same pattern as 002_add_rule_metadata.sql (configscan), 006_compliance_control_mappings.sql (compliance)
-- Engines load service rules from DB first, then fallback to file/S3.

-- ============================================================================
-- RULE DEFINITIONS TABLE (configscan database)
-- ============================================================================
CREATE TABLE IF NOT EXISTS rule_definitions (
    id SERIAL PRIMARY KEY,

    -- Scope
    csp VARCHAR(50) NOT NULL DEFAULT 'aws',   -- aws, azure, gcp, alicloud, oci, ibm
    service VARCHAR(100) NOT NULL,            -- s3, ec2, rds, iam, etc.

    -- File identity (matches folder layout: service/rules/service.yaml or service/metadata/...)
    file_path VARCHAR(512) NOT NULL,            -- e.g. rules/s3.yaml, metadata/aws.s3.bucket.encryption.yaml

    -- Content
    content_yaml TEXT NOT NULL,               -- Full YAML body

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(csp, service, file_path)
);

-- Indexes for engine lookups
CREATE INDEX IF NOT EXISTS idx_rule_definitions_csp_service ON rule_definitions(csp, service);
CREATE INDEX IF NOT EXISTS idx_rule_definitions_csp ON rule_definitions(csp);

COMMENT ON TABLE rule_definitions IS 'Full rule YAML per service for configscan. Source: engine_input/.../rule_db/default/services. Load by configscan engines from DB first, then file.';
COMMENT ON COLUMN rule_definitions.file_path IS 'Relative path under service folder, e.g. rules/s3.yaml or metadata/aws.s3.bucket.encryption.yaml';
