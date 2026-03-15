-- ================================================================
-- Migration 010: Enrich rule_discoveries Table
-- ================================================================
-- Purpose: Add columns to store all service configuration metadata
-- Eliminates: discovery_helper.py, discovery_resource_mapper.py, hardcoded filters/pagination
-- Strategy: Single source of truth in database (no new tables)
-- ================================================================

-- Add new columns to existing rule_discoveries table
ALTER TABLE rule_discoveries
ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE,
ADD COLUMN IF NOT EXISTS boto3_client_name VARCHAR(100),
ADD COLUMN IF NOT EXISTS scope VARCHAR(20) DEFAULT 'regional',  -- 'regional' or 'global'
ADD COLUMN IF NOT EXISTS arn_pattern VARCHAR(512),
ADD COLUMN IF NOT EXISTS arn_identifier VARCHAR(255),
ADD COLUMN IF NOT EXISTS arn_identifier_independent_methods JSONB,
ADD COLUMN IF NOT EXISTS arn_identifier_dependent_methods JSONB,
ADD COLUMN IF NOT EXISTS extraction_patterns JSONB,  -- ARN/ID field patterns from service_list.json
ADD COLUMN IF NOT EXISTS filter_rules JSONB DEFAULT '{}'::jsonb,         -- Filter configuration (api + response filters)
ADD COLUMN IF NOT EXISTS pagination_config JSONB DEFAULT '{}'::jsonb,    -- Pagination configuration
ADD COLUMN IF NOT EXISTS features JSONB DEFAULT '{"discovery": {"enabled": true, "priority": 1}}'::jsonb;  -- Feature enablement flags

-- Add comments for documentation
COMMENT ON COLUMN rule_discoveries.is_active IS 'Enable/disable service without deletion';
COMMENT ON COLUMN rule_discoveries.boto3_client_name IS 'Boto3 client name (e.g., cognito-idp for cognito service)';
COMMENT ON COLUMN rule_discoveries.scope IS 'Service scope: regional (per-region) or global (us-east-1 only)';
COMMENT ON COLUMN rule_discoveries.arn_pattern IS 'ARN template pattern for resource construction';
COMMENT ON COLUMN rule_discoveries.arn_identifier IS 'Primary ARN identifier field name';
COMMENT ON COLUMN rule_discoveries.arn_identifier_independent_methods IS 'ARN extraction for independent discoveries';
COMMENT ON COLUMN rule_discoveries.arn_identifier_dependent_methods IS 'ARN extraction for dependent (enrichment) discoveries';
COMMENT ON COLUMN rule_discoveries.extraction_patterns IS 'Field extraction patterns (ARN/ID/name fields per resource type)';
COMMENT ON COLUMN rule_discoveries.filter_rules IS 'Filter rules JSONB: {api_filters: [...], response_filters: [...]}';
COMMENT ON COLUMN rule_discoveries.pagination_config IS 'Pagination config JSONB: {default_page_size, max_pages, token_field, service_overrides}';
COMMENT ON COLUMN rule_discoveries.features IS 'Feature enablement JSONB: {discovery: {enabled: true, priority: 1}, checks: {...}, deviation: {...}, drift: {...}}';

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_rule_discoveries_provider_service
ON rule_discoveries(provider, service, is_active);

CREATE INDEX IF NOT EXISTS idx_rule_discoveries_active
ON rule_discoveries(is_active) WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_rule_discoveries_scope
ON rule_discoveries(scope);

-- Create GIN indexes for JSONB columns to enable efficient querying
CREATE INDEX IF NOT EXISTS idx_rule_discoveries_features_gin
ON rule_discoveries USING GIN (features);

CREATE INDEX IF NOT EXISTS idx_rule_discoveries_filter_rules_gin
ON rule_discoveries USING GIN (filter_rules);

CREATE INDEX IF NOT EXISTS idx_rule_discoveries_pagination_config_gin
ON rule_discoveries USING GIN (pagination_config);

-- ================================================================
-- Default Pagination Config Template
-- ================================================================
-- This template will be used to populate pagination_config column
-- for AWS services in the population script (03_enrich_rule_discoveries.py)
-- ================================================================

/*
Default AWS Pagination Config Structure:
{
  "default_page_size": 1000,
  "max_pages": 100,
  "timeout_seconds": 600,
  "max_items": 100000,
  "token_field": "NextToken",
  "result_array_field": null,
  "supports_native_pagination": true,
  "circular_token_detection": true,
  "service_overrides": {}
}

Service-Specific Overrides (to be added by population script):
- sagemaker: {"default_page_size": 100}
- cognito-idp: {"default_page_size": 60, "token_field": "PaginationToken"}
- cognito: {"default_page_size": 60}
- kafka: {"default_page_size": 100}
- s3: Service-level overrides for list_buckets (Marker) vs list_objects_v2 (ContinuationToken)
- iam: {"token_field": "Marker"}
- ec2: {"max_pages": 200, "max_items": 200000}
- logs: {"default_page_size": 50}
*/

-- ================================================================
-- Features Column Template
-- ================================================================
-- This template shows the structure for features JSONB column
-- Controls which features are enabled for each service
-- ================================================================

/*
Features Structure:
{
  "discovery": {
    "enabled": true,
    "priority": 1
  },
  "checks": {
    "enabled": true,
    "priority": 1
  },
  "deviation": {
    "enabled": false,
    "priority": 3
  },
  "drift": {
    "enabled": false,
    "priority": 3
  }
}

Priority Levels:
- 1: High priority (always run)
- 2: Medium priority (run if time permits)
- 3: Low priority (run only if specifically requested)

Feature Types:
- discovery: Service resource discovery
- checks: Compliance/security checks
- deviation: Configuration deviation detection
- drift: Configuration drift over time
*/

-- ================================================================
-- Default Filter Rules Template
-- ================================================================
-- This template shows the structure for filter_rules JSONB column
-- Actual data will be populated by 03_enrich_rule_discoveries.py script
-- ================================================================

/*
Filter Rules Structure:
{
  "api_filters": [
    {
      "discovery_id": "aws.ec2.describe_snapshots",
      "parameter": "OwnerIds",
      "value": ["self"],
      "priority": 10,
      "description": "Only return snapshots owned by the account"
    },
    {
      "discovery_id": "aws.rds.describe_db_cluster_snapshots",
      "parameter": "IncludeShared",
      "value": false,
      "priority": 10,
      "description": "Exclude shared cluster snapshots"
    }
  ],
  "response_filters": [
    {
      "discovery_id": "aws.kms.list_aliases",
      "field_path": "AliasName",
      "pattern": "^alias/aws/",
      "pattern_type": "prefix",
      "action": "exclude",
      "priority": 100,
      "description": "Exclude AWS-managed KMS aliases"
    },
    {
      "discovery_id": "aws.secretsmanager.list_secrets",
      "field_path": "Name",
      "pattern": "^(aws/|rds!)",
      "pattern_type": "regex",
      "action": "exclude",
      "priority": 100,
      "description": "Exclude AWS-managed secrets"
    }
  ]
}

Supported Filter Types:
- api_filters: Applied BEFORE API call (modify request params)
- response_filters: Applied AFTER API call (filter response items)

Pattern Types:
- prefix: String starts with pattern
- suffix: String ends with pattern
- contains: Pattern appears anywhere in string
- regex: Full regex matching
*/

-- ================================================================
-- Default Extraction Patterns Template
-- ================================================================
-- This template shows the structure for extraction_patterns JSONB column
-- Actual data will be populated from service_list.json by population script
-- ================================================================

/*
Extraction Patterns Structure (from service_list.json):
{
  "analyzer": {
    "arn_fields": ["analyzer_arn", "analyzerArn", "Arn", "ARN", "arn", "ResourceArn"],
    "id_fields": ["id", "Id", "ID", "ResourceId", "resource_id", "analyzerId"],
    "name_fields": ["name", "Name", "NAME", "ResourceName", "resource_name"]
  },
  "bucket": {
    "arn_fields": ["BucketArn", "Arn"],
    "id_fields": ["Name", "BucketName"],
    "name_fields": ["Name"]
  }
}

Priority Order for Field Extraction:
1. Exact field name match (case-sensitive)
2. Resource-type-specific pattern (e.g., ${resource_type}Id)
3. Generic pattern (ResourceId, resource_id)
4. ARN fallback
*/

-- ================================================================
-- Migration Verification Queries
-- ================================================================

-- Verify columns were added
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_name = 'rule_discoveries'
  AND column_name IN (
    'is_active', 'boto3_client_name', 'scope', 'arn_pattern',
    'extraction_patterns', 'filter_rules', 'pagination_config', 'features'
  )
ORDER BY ordinal_position;

-- Verify indexes were created
SELECT indexname, indexdef
FROM pg_indexes
WHERE tablename = 'rule_discoveries'
  AND indexname LIKE 'idx_rule_discoveries%'
ORDER BY indexname;

-- Count existing services that will need population
SELECT provider, COUNT(*) as service_count
FROM rule_discoveries
GROUP BY provider
ORDER BY provider;

-- ================================================================
-- Rollback Script (if needed)
-- ================================================================

/*
-- To rollback this migration:

DROP INDEX IF EXISTS idx_rule_discoveries_pagination_config_gin;
DROP INDEX IF EXISTS idx_rule_discoveries_filter_rules_gin;
DROP INDEX IF EXISTS idx_rule_discoveries_features_gin;
DROP INDEX IF EXISTS idx_rule_discoveries_provider_service;
DROP INDEX IF EXISTS idx_rule_discoveries_active;
DROP INDEX IF EXISTS idx_rule_discoveries_scope;

ALTER TABLE rule_discoveries
DROP COLUMN IF EXISTS features,
DROP COLUMN IF EXISTS pagination_config,
DROP COLUMN IF EXISTS filter_rules,
DROP COLUMN IF EXISTS extraction_patterns,
DROP COLUMN IF EXISTS arn_identifier_dependent_methods,
DROP COLUMN IF EXISTS arn_identifier_independent_methods,
DROP COLUMN IF EXISTS arn_identifier,
DROP COLUMN IF EXISTS arn_pattern,
DROP COLUMN IF EXISTS scope,
DROP COLUMN IF EXISTS boto3_client_name,
DROP COLUMN IF EXISTS is_active;
*/
