-- ============================================================================
-- Migration 002: Populate rule_metadata.data_security from domain field
--
-- The domain field is correctly populated for all AWS rules, but data_security
-- JSONB is empty ({}) for every rule. The datasec engine filters rules by
-- `data_security IS NOT NULL AND data_security::text NOT IN ('null','{}')`,
-- so it produces 0 findings.
--
-- Fix: Set data_security based on domain, using the exact module IDs that
-- match the datasec MODULE_REGISTRY in module_orchestrator.py:
--   data_protection_encryption, data_access_governance, data_classification,
--   data_residency, data_lifecycle, data_activity_monitoring, data_lineage
-- ============================================================================

BEGIN;

-- 1. data_protection_and_privacy (417 rules: s3, rds, dynamodb, redshift, macie, etc.)
UPDATE rule_metadata
SET data_security = '{"applicable": true, "modules": ["data_protection_encryption", "data_access_governance", "data_classification"], "categories": ["data_protection", "privacy", "sensitive_data_protection"], "priority": "high"}'::jsonb
WHERE provider = 'aws'
  AND domain = 'data_protection_and_privacy'
  AND (data_security IS NULL OR data_security::text IN ('null', '{}'));

-- 2. storage_and_database_security (55 rules: storage, database)
UPDATE rule_metadata
SET data_security = '{"applicable": true, "modules": ["data_protection_encryption", "data_access_governance"], "categories": ["storage_security", "database_security"], "priority": "high"}'::jsonb
WHERE provider = 'aws'
  AND domain = 'storage_and_database_security'
  AND (data_security IS NULL OR data_security::text IN ('null', '{}'));

-- 3. secrets_and_key_management (101 rules: kms, secretsmanager, acm, etc.)
UPDATE rule_metadata
SET data_security = '{"applicable": true, "modules": ["data_protection_encryption"], "categories": ["encryption", "key_management", "secrets"], "priority": "critical"}'::jsonb
WHERE provider = 'aws'
  AND domain = 'secrets_and_key_management'
  AND (data_security IS NULL OR data_security::text IN ('null', '{}'));

-- 4. cryptography_and_key_management (8 rules)
UPDATE rule_metadata
SET data_security = '{"applicable": true, "modules": ["data_protection_encryption"], "categories": ["encryption", "cryptography"], "priority": "high"}'::jsonb
WHERE provider = 'aws'
  AND domain = 'cryptography_and_key_management'
  AND (data_security IS NULL OR data_security::text IN ('null', '{}'));

-- Verify — should show 0 for with_ds after this migration
SELECT
  domain,
  COUNT(*) AS total,
  COUNT(*) FILTER (WHERE data_security IS NOT NULL AND data_security::text NOT IN ('null','{}') AND (data_security->>'applicable')::boolean = true) AS now_tagged
FROM rule_metadata
WHERE provider = 'aws'
  AND domain IN (
    'data_protection_and_privacy',
    'storage_and_database_security',
    'secrets_and_key_management',
    'cryptography_and_key_management'
  )
GROUP BY domain
ORDER BY total DESC;

COMMIT;
