-- ============================================================================
-- Migration 003: Add per-engine scope JSONB columns to rule_metadata
--
-- Pattern: same as data_security (Migration 002).
-- Each engine queries: WHERE ({engine}_security ->> 'applicable')::boolean = true
-- This migration is the SINGLE source of truth for which services/domains
-- belong to each domain engine. No hard-coded lists in Python code.
--
-- Columns added:
--   encryption_security  — kms, acm, secretsmanager, secrets/crypto domains
--   container_security   — eks, ecs, ecr, fargate, container domain
--   database_security    — rds, dynamodb, redshift, opensearch, db domain
--   ai_security          — sagemaker, bedrock, comprehend, rekognition, etc.
-- ============================================================================

BEGIN;

-- ── Schema ────────────────────────────────────────────────────────────────────
ALTER TABLE rule_metadata ADD COLUMN IF NOT EXISTS encryption_security JSONB DEFAULT '{}'::jsonb;
ALTER TABLE rule_metadata ADD COLUMN IF NOT EXISTS container_security  JSONB DEFAULT '{}'::jsonb;
ALTER TABLE rule_metadata ADD COLUMN IF NOT EXISTS database_security   JSONB DEFAULT '{}'::jsonb;
ALTER TABLE rule_metadata ADD COLUMN IF NOT EXISTS ai_security         JSONB DEFAULT '{}'::jsonb;

-- ── Encryption: kms, acm, secretsmanager services + secrets/crypto domains ───
-- Covers all providers (Azure key vault, GCP KMS, OCI Vault etc.)
UPDATE rule_metadata
SET encryption_security = '{"applicable": true}'::jsonb
WHERE (
    service IN (
        'kms', 'acm', 'acm-pca', 'secretsmanager',
        -- Azure
        'keyvault', 'certificates',
        -- GCP
        'cloudkms',
        -- OCI
        'vault', 'key_management',
        -- AliCloud
        'kms_openapi'
    )
    OR domain IN ('secrets_and_key_management', 'cryptography_and_key_management')
)
AND (encryption_security IS NULL OR encryption_security::text IN ('null', '{}'));

-- ── Container: eks/ecs/ecr/fargate + container domain ────────────────────────
UPDATE rule_metadata
SET container_security = '{"applicable": true}'::jsonb
WHERE (
    service IN (
        'eks', 'ecs', 'ecr', 'fargate', 'lambda', 'container', 'compute',
        -- Azure
        'aks', 'containerregistry', 'containerinstance', 'containerapp',
        -- GCP
        'container', 'artifactregistry', 'run',
        -- OCI
        'containerengine', 'artifacts',
        -- K8s
        'pod', 'deployment', 'namespace', 'networkpolicy', 'serviceaccount',
        'rbac', 'clusterrole', 'clusterrolebinding'
    )
    OR domain = 'container_and_kubernetes_security'
)
AND (container_security IS NULL OR container_security::text IN ('null', '{}'));

-- ── Database: rds/dynamodb/redshift/elasticache + storage_and_database domain ─
UPDATE rule_metadata
SET database_security = '{"applicable": true}'::jsonb
WHERE (
    service IN (
        'rds', 'dynamodb', 'redshift', 'elasticache', 'neptune', 'docdb',
        'documentdb', 'opensearch', 'timestream', 'keyspaces', 'dax',
        -- Azure
        'sql', 'sqlserver', 'cosmosdb', 'redis', 'postgresql', 'mysql',
        'mariadb', 'synapse',
        -- GCP
        'sqladmin', 'spanner', 'bigtable', 'datastore', 'firestore',
        'memorystore', 'alloydb',
        -- OCI
        'database', 'mysql', 'nosql', 'autonomousdatabase',
        -- AliCloud
        'rds', 'polardb', 'mongodb', 'kvstore', 'gpdb'
    )
    OR domain = 'storage_and_database_security'
)
AND (database_security IS NULL OR database_security::text IN ('null', '{}'));

-- ── AI/ML: sagemaker, bedrock, comprehend, etc. (no dedicated domain yet) ────
UPDATE rule_metadata
SET ai_security = '{"applicable": true}'::jsonb
WHERE service IN (
    -- AWS
    'sagemaker', 'sagemaker-runtime', 'sagemaker-edge', 'sagemaker-featurestore-runtime',
    'bedrock', 'bedrock-runtime', 'bedrock-agent', 'bedrock-agent-runtime',
    'comprehend', 'comprehendmedical', 'textract', 'translate', 'transcribe',
    'rekognition', 'polly', 'personalize', 'forecast', 'frauddetector',
    'machinelearning', 'lookoutmetrics', 'lookoutequipment', 'lookoutvision', 'kendra',
    -- Azure
    'cognitiveservices', 'machinelearningservices', 'openai',
    -- GCP
    'aiplatform', 'automl', 'videointelligence', 'vision', 'naturallanguage',
    -- OCI
    'generative_ai', 'ai_language', 'ai_vision'
)
AND (ai_security IS NULL OR ai_security::text IN ('null', '{}'));

-- ── Verify ────────────────────────────────────────────────────────────────────
SELECT
    provider,
    COUNT(*) FILTER (WHERE (encryption_security ->> 'applicable')::boolean = true) AS enc,
    COUNT(*) FILTER (WHERE (container_security  ->> 'applicable')::boolean = true) AS ctr,
    COUNT(*) FILTER (WHERE (database_security   ->> 'applicable')::boolean = true) AS db,
    COUNT(*) FILTER (WHERE (ai_security         ->> 'applicable')::boolean = true) AS ai
FROM rule_metadata
GROUP BY provider
ORDER BY provider;

COMMIT;
