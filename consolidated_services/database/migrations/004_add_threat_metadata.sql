-- Migration: Add Threat Categorization to Rule Metadata
-- Purpose: Make threat detection metadata-driven instead of code-based pattern matching

-- Add threat categorization columns to rule_metadata
ALTER TABLE rule_metadata 
ADD COLUMN IF NOT EXISTS threat_category VARCHAR(50),
ADD COLUMN IF NOT EXISTS threat_tags JSONB DEFAULT '[]',
ADD COLUMN IF NOT EXISTS risk_score INT DEFAULT 50,
ADD COLUMN IF NOT EXISTS risk_indicators JSONB DEFAULT '{}';

-- Create indexes for threat queries
CREATE INDEX IF NOT EXISTS idx_rule_metadata_threat_category ON rule_metadata(threat_category);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_risk_score ON rule_metadata(risk_score DESC);

-- Add comments
COMMENT ON COLUMN rule_metadata.threat_category IS 'Primary threat type: identity, exposure, data_breach, data_exfiltration, misconfiguration, drift';
COMMENT ON COLUMN rule_metadata.threat_tags IS 'Additional threat indicators: ["privilege_escalation", "lateral_movement", "public_access"]';
COMMENT ON COLUMN rule_metadata.risk_score IS 'Base risk score 1-100 (combined with severity for threat prioritization)';
COMMENT ON COLUMN rule_metadata.risk_indicators IS 'What makes this a threat: {"public_access": true, "sensitive_data": false, "internet_facing": true}';

-- ============================================================================
-- Populate threat categories based on rule patterns
-- ============================================================================

-- IDENTITY threats (IAM, authentication, authorization)
UPDATE rule_metadata 
SET threat_category = 'identity',
    threat_tags = '["access_control", "privilege_management"]',
    risk_score = 75
WHERE service = 'iam' AND threat_category IS NULL;

-- EXPOSURE threats (public access, internet-facing)
UPDATE rule_metadata
SET threat_category = 'exposure',
    threat_tags = '["public_access", "internet_facing"]',
    risk_score = 85,
    risk_indicators = '{"public_access": true, "internet_facing": true}'
WHERE (rule_id LIKE '%public%' OR rule_id LIKE '%internet%' OR rule_id LIKE '%0.0.0.0%')
  AND threat_category IS NULL;

-- DATA_EXFILTRATION threats (S3 public, logging disabled, encryption off)
UPDATE rule_metadata
SET threat_category = 'data_exfiltration',
    threat_tags = '["data_protection", "logging"]',
    risk_score = 80
WHERE (
    (service = 's3' AND (rule_id LIKE '%public%' OR rule_id LIKE '%logging%' OR rule_id LIKE '%encryption%'))
    OR rule_id LIKE '%data%exfil%'
) AND threat_category IS NULL;

-- DATA_BREACH threats (database public, snapshots public, sensitive data exposed)
UPDATE rule_metadata
SET threat_category = 'data_breach',
    threat_tags = '["sensitive_data", "database_security"]',
    risk_score = 90,
    risk_indicators = '{"sensitive_data": true, "public_access": true}'
WHERE (
    rule_id LIKE '%rds%public%'
    OR rule_id LIKE '%database%public%'
    OR rule_id LIKE '%snapshot%public%'
) AND threat_category IS NULL;

-- MISCONFIGURATION threats (encryption, backup, versioning)
UPDATE rule_metadata
SET threat_category = 'misconfiguration',
    threat_tags = '["encryption", "backup", "resilience"]',
    risk_score = 60
WHERE (
    rule_id LIKE '%encryption%'
    OR rule_id LIKE '%backup%'
    OR rule_id LIKE '%versioning%'
    OR rule_id LIKE '%kms%'
) AND threat_category IS NULL;

-- NETWORK threats (security groups, VPC, networking)
UPDATE rule_metadata
SET threat_category = 'network',
    threat_tags = '["network_security", "segmentation"]',
    risk_score = 70
WHERE (
    service IN ('ec2', 'vpc')
    AND (rule_id LIKE '%security%group%' OR rule_id LIKE '%network%' OR rule_id LIKE '%subnet%')
) AND threat_category IS NULL;

-- DEFAULT for remaining rules
UPDATE rule_metadata
SET threat_category = 'misconfiguration',
    threat_tags = '["security_baseline"]',
    risk_score = 50
WHERE threat_category IS NULL;

-- ============================================================================
-- Specific high-risk rule overrides
-- ============================================================================

-- MFA rules = high risk identity
UPDATE rule_metadata
SET risk_score = 85,
    threat_tags = '["authentication", "mfa", "access_control"]'
WHERE rule_id LIKE '%mfa%';

-- Root account rules = critical risk
UPDATE rule_metadata
SET risk_score = 95,
    threat_tags = '["root_account", "privileged_access"]'
WHERE rule_id LIKE '%root%';

-- Wildcard policies = high risk privilege escalation
UPDATE rule_metadata
SET risk_score = 90,
    threat_tags = '["privilege_escalation", "wildcard_permissions"]',
    risk_indicators = '{"wildcard_actions": true, "admin_access": true}'
WHERE rule_id LIKE '%wildcard%' OR rule_id LIKE '%admin%actions%';

-- ============================================================================
-- Create helper view for threat categorization summary
-- ============================================================================
CREATE OR REPLACE VIEW rule_threat_summary AS
SELECT 
    threat_category,
    COUNT(*) as total_rules,
    COUNT(*) FILTER (WHERE severity = 'critical') as critical_rules,
    COUNT(*) FILTER (WHERE severity = 'high') as high_rules,
    COUNT(*) FILTER (WHERE severity = 'medium') as medium_rules,
    AVG(risk_score) as avg_risk_score
FROM rule_metadata
WHERE threat_category IS NOT NULL
GROUP BY threat_category
ORDER BY avg_risk_score DESC;

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================
