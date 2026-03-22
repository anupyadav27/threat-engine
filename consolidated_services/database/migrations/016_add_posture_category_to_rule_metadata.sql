-- ============================================================================
-- Migration 016: Add posture_category to rule_metadata
-- ============================================================================
-- Purpose: Add a posture_category column that maps domain+subcategory to
--          one of 10 standard security posture labels for the UI.
-- Target DB: threat_engine_check
-- Reversible: DROP COLUMN posture_category
-- ============================================================================

-- Step 1: Add the column
ALTER TABLE rule_metadata
    ADD COLUMN IF NOT EXISTS posture_category VARCHAR(50);

-- Step 2: Create index
CREATE INDEX IF NOT EXISTS idx_rule_metadata_posture
    ON rule_metadata(posture_category);

-- Step 3: Populate posture_category from existing subcategory values
-- Priority: subcategory match first, then domain fallback

UPDATE rule_metadata SET posture_category = CASE
    -- Encryption posture (subcategory match)
    WHEN subcategory IN ('encryption_at_rest', 'encryption_in_transit', 'storage_encryption')
        THEN 'encryption'

    -- Public Access posture (subcategory match)
    WHEN subcategory IN ('network_access_control', 'public_exposure_prevention')
        THEN 'public_access'

    -- Logging & Monitoring posture (subcategory match)
    WHEN subcategory IN ('audit_logging', 'security_monitoring', 'alerting', 'compliance_monitoring')
        THEN 'logging'

    -- Backup & Recovery posture (subcategory match)
    WHEN subcategory IN ('backup_and_recovery', 'disaster_recovery')
        THEN 'backup'

    -- Access Control posture (subcategory match)
    WHEN subcategory IN ('authentication', 'authorization', 'least_privilege', 'identity_federation')
        THEN 'access_control'

    -- Network Security posture (subcategory match)
    WHEN subcategory = 'rate_limiting'
        THEN 'network'

    -- Key & Secret Management posture (subcategory match)
    WHEN subcategory IN ('key_management', 'credential_storage')
        THEN 'key_management'

    -- Configuration posture (subcategory match)
    WHEN subcategory IN ('configuration_baseline', 'configuration_validation', 'change_management', 'policy_enforcement')
        THEN 'configuration'

    -- Data Protection posture (subcategory match)
    WHEN subcategory IN ('data_classification', 'data_lifecycle_management')
        THEN 'data_protection'

    -- Threat Detection posture (subcategory match)
    WHEN subcategory IN ('intrusion_detection', 'malware_protection')
        THEN 'threat_detection'

    -- Model Security
    WHEN subcategory = 'model_security'
        THEN 'configuration'

    -- ── Domain-level fallback (when subcategory is NULL or unrecognised) ──

    WHEN domain = 'data_protection_and_privacy'
        THEN 'data_protection'
    WHEN domain = 'identity_and_access_management'
        THEN 'access_control'
    WHEN domain = 'logging_monitoring_and_alerting'
        THEN 'logging'
    WHEN domain = 'network_security_and_connectivity'
        THEN 'network'
    WHEN domain = 'resilience_and_disaster_recovery'
        THEN 'backup'
    WHEN domain = 'secrets_and_key_management'
        THEN 'key_management'
    WHEN domain = 'storage_and_database_security'
        THEN 'encryption'
    WHEN domain = 'threat_detection_and_incident_response'
        THEN 'threat_detection'
    WHEN domain = 'configuration_and_change_management'
        THEN 'configuration'
    WHEN domain = 'compliance_and_governance'
        THEN 'configuration'
    WHEN domain = 'application_and_api_security'
        THEN 'network'
    WHEN domain = 'ai_ml_and_model_security'
        THEN 'configuration'
    WHEN domain = 'container_and_kubernetes_security'
        THEN 'configuration'
    WHEN domain = 'serverless_and_faas_security'
        THEN 'configuration'

    -- Final fallback
    ELSE 'configuration'
END
WHERE posture_category IS NULL;

-- Verify
-- SELECT posture_category, COUNT(*) FROM rule_metadata GROUP BY posture_category ORDER BY count DESC;
