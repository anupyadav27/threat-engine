# Scanner Architecture Refactoring - Phase 1

**Date Started:** 2026-02-18
**Status:** In Progress - Phase 1
**Plan Reference:** `/Users/apple/.claude/plans/async-shimmying-moth.md`

---

## Overview

This refactoring eliminates hardcoded CSP-specific logic and creates a clean, config-driven, multi-CSP scanner architecture.

**Key Problems Solved:**
1. **1,756 lines of code duplication** between `run_global_service()` and `run_regional_service()`
2. **80+ hardcoded filter conditions** in if/elif chains blocking multi-CSP support
3. **Hardcoded pagination parameters** (sagemaker=100, cognito=60) non-generalizable to Azure/GCP
4. **Legacy check execution coupling** in discovery engine (now redundant with CheckEngine)

**Configuration Strategy:** Strictly database-only (no YAML fallback)

---

## Phase 1: Database Schema Enrichment ✅ COMPLETED

### ✅ Completed Steps

1. **Database Schema Migration**
   - Created `consolidated_services/database/migrations/010_enrich_rule_discoveries.sql`
   - Added 10 new columns to `rule_discoveries` table:
     - `is_active` (BOOLEAN) - Enable/disable services
     - `boto3_client_name` (VARCHAR) - Boto3 client name mappings
     - `scope` (VARCHAR) - 'regional' or 'global'
     - `arn_pattern` (VARCHAR) - ARN template patterns
     - `arn_identifier` (VARCHAR) - ARN identifier field
     - `arn_identifier_independent_methods` (JSONB) - Independent ARN methods
     - `arn_identifier_dependent_methods` (JSONB) - Dependent ARN methods
     - `extraction_patterns` (JSONB) - Resource extraction patterns
     - `filter_rules` (JSONB) - Filter configuration (api_filters, response_filters)
     - `pagination_config` (JSONB) - Pagination configuration
   - Created indexes on (provider, service, is_active), (is_active), (scope)
   - Applied migration successfully to database

---

## Phase 2: Data Population ✅ COMPLETED

### ✅ Completed Steps

1. **Data Population Script**
   - Created `scripts/03_enrich_rule_discoveries.py`
   - Extracted boto3 client mappings from `discovery_helper.py` (114 services)
   - Extracted scope from `service_list.json` (23 global, 413 regional)
   - Extracted filter rules from `service_scanner.py` (8 response filters)
   - Extracted pagination config (8 service-specific configs)
   - Successfully populated 5 test services: ec2, s3, iam, sagemaker, kms
   - Verified:
     - Global services: iam, s3
     - Regional services: ec2, kms, sagemaker
     - KMS has 1 response filter (exclude AWS-managed aliases)
     - SageMaker has custom page size of 100

---

## Phase 3: Database-Driven Utilities ✅ COMPLETED

### ✅ Completed Steps

1. **Created config_loader.py** (`engine_discoveries/utils/config_loader.py`)
   - Replaces: `discovery_helper.py`, `discovery_resource_mapper.py`
   - Database-driven configuration loader with caching
   - Key methods:
     - `get_boto3_client_name(service)` - Get boto3 client name
     - `get_scope(service)` - Get 'regional' or 'global'
     - `get_filter_rules(service)` - Get filter configuration
     - `get_pagination_config(service)` - Get pagination settings
     - `get_extraction_patterns(service)` - Get ARN/ID patterns
     - `get_arn_pattern(service)` - Get ARN template
   - Connection pooling with lazy initialization
   - In-memory caching with cache invalidation

2. **Created filter_engine.py** (`engine_discoveries/utils/filter_engine.py`)
   - Replaces: Hardcoded filter logic in `service_scanner.py` (lines 98-276)
   - Database-driven filter application
   - Key methods:
     - `apply_api_filters(discovery_id, params, service)` - Pre-call filtering
     - `apply_response_filters(discovery_id, items, service)` - Post-call filtering
   - Pattern matching types: prefix, suffix, contains, exact, regex
   - Filter actions: exclude, include
   - Field extraction with dot notation support (e.g., 'Tags.Environment')

3. **Created pagination_engine.py** (`engine_discoveries/utils/pagination_engine.py`)
   - Replaces: Hardcoded pagination in `service_scanner.py` (lines 1490-1500)
   - Database-driven pagination configuration
   - Key methods:
     - `get_page_size(service, action)` - Get page size with service overrides
     - `get_token_field(service, action)` - Get token field name
     - `get_pagination_params(service, action)` - Get complete config
     - `build_paginator_config(service, action)` - Build boto3 paginator config
   - Service-specific overrides support (e.g., S3 different tokens for different actions)
   - Default pagination: 1000 page size, 100 max pages, 600s timeout, NextToken

---

## Phase 4: Unified run_service and Integration 🔄 NEXT

### 🔄 Pending Steps

1. **Create Unified run_service()**
   - Create unified `run_service()` in `service_scanner.py`
   - Accept `region` parameter (None for global, value for regional)
   - Query `scope` from database via config_loader
   - Use FilterEngine for all filter operations
   - Use PaginationEngine for all pagination
   - Single code path (eliminate 1,756 lines of duplication)

2. **Update All Boto3 Client Creation**
   ```python
   # OLD (hardcoded):
   client_name = 'cognito-idp' if service == 'cognito' else service

   # NEW (database-driven):
   client_name = config_loader.get_boto3_client_name(service)
   ```

3. **Keep Backward-Compatible Wrappers**
   ```python
   def run_global_service(service, **kwargs):
       return run_service(service, region=None, **kwargs)

   def run_regional_service(service, region, **kwargs):
       return run_service(service, region=region, **kwargs)
   ```

4. **Update discovery_engine.py**
   - Call unified `run_service()` directly

5. **Comprehensive Integration Testing**
   - Compare discovery results before/after refactoring
   - Verify ARN generation for global/regional resources
   - Ensure no resources lost due to filter changes

---

## Phase 5: Cleanup and Remove Legacy Code 📅 FUTURE

### 📅 Pending Steps

1. **Remove Legacy Check Execution**
   - Remove `_run_single_check()` from `service_scanner.py`
   - Remove check execution phases from `run_global_service()` (lines 3370-3421)
   - Remove check execution phases from `run_regional_service()` (lines 4200-4249)

2. **Delete Obsolete Utility Files**
   - Delete `engine_discoveries/utils/discovery_helper.py`
   - Delete `engine_discoveries/utils/action_runner.py`
   - Delete `engine_discoveries/utils/discovery_resource_mapper.py`

3. **Remove Hardcoded Logic from service_scanner.py**
   - Delete `_apply_aws_managed_filters_at_api_level()` (lines 98-182)
   - Delete `_filter_aws_managed_resources()` (lines 185-276)
   - Delete service-specific page size if/elif chain (lines 1490-1500)

---

## Architecture Changes

### Before (Hardcoded)

**Filters:** 80+ if/elif conditions in service_scanner.py
```python
def _apply_aws_managed_filters_at_api_level(discovery_id, params, account_id):
    if discovery_id == 'aws.ec2.describe_snapshots':
        params['OwnerIds'] = ['self']
    elif discovery_id == 'aws.rds.describe_db_cluster_snapshots':
        params['IncludeShared'] = False
        params['IncludePublic'] = False
    # ... 15+ more hardcoded conditions
```

**Pagination:** Hardcoded service-specific page sizes
```python
if service_name == 'sagemaker':
    default_page_size = 100
elif service_name in ['cognito-idp', 'cognito']:
    default_page_size = 60
elif service_name == 'kafka':
    default_page_size = 100
else:
    default_page_size = 1000
```

### After (Config-Driven)

**Filters:** Database-backed with FilterEngine
```python
from engine_common.filters import FilterEngine

filter_engine = FilterEngine(csp='aws')
params = filter_engine.apply_api_filters('aws.ec2.describe_snapshots', params)
# Reads from filter_rules table, no hardcoding
```

**Pagination:** Database-backed with PaginationEngine
```python
from engine_common.pagination import PaginationEngine

pagination_engine = PaginationEngine(csp='aws')
config = pagination_engine.get_config(service_name='sagemaker', action='list_models')
# Returns: {default_page_size: 100, token_field: 'NextToken', ...}
```

---

## Database Schema Details

### filter_rules Table

| Column | Type | Purpose |
|--------|------|---------|
| csp | VARCHAR(50) | 'aws', 'azure', 'gcp', 'oci', etc. |
| discovery_id | VARCHAR(255) | 'aws.ec2.describe_snapshots' |
| filter_type | VARCHAR(50) | 'api_param', 'exclude_pattern', 'include_pattern' |
| api_parameter | VARCHAR(100) | 'OwnerIds', 'IncludeShared' (for api_param) |
| api_value | JSONB | '["self"]', 'false' (for api_param) |
| field_path | VARCHAR(255) | 'AliasName', 'Name' (for pattern filters) |
| pattern | VARCHAR(512) | '^alias/aws/', '^(aws/\|rds!)' |
| pattern_type | VARCHAR(50) | 'regex', 'prefix', 'contains', 'suffix' |
| is_active | BOOLEAN | Enable/disable without deletion |
| priority | INTEGER | Execution order (lower = earlier) |

**Example Records:**
```sql
-- Pre-call filter: Only self-owned EC2 snapshots
INSERT INTO filter_rules VALUES
('aws', 'aws.ec2.describe_snapshots', 'api_param', 'OwnerIds', '["self"]', NULL, NULL, NULL, TRUE, 10);

-- Post-call filter: Exclude AWS-managed KMS aliases
INSERT INTO filter_rules VALUES
('aws', 'aws.kms.list_aliases', 'exclude_pattern', NULL, NULL, 'AliasName', '^alias/aws/', 'prefix', TRUE, 100);
```

### pagination_config Table

| Column | Type | Purpose |
|--------|------|---------|
| csp | VARCHAR(50) | 'aws', 'azure', 'gcp', 'oci', etc. |
| service_name | VARCHAR(100) | 'sagemaker', 'compute', NULL for default |
| action | VARCHAR(100) | 'list_models', NULL for service default |
| default_page_size | INTEGER | Number of items per page |
| max_pages | INTEGER | Maximum pages (safety limit) |
| timeout_seconds | INTEGER | Operation timeout |
| max_items_per_discovery | INTEGER | Total items limit |
| token_field | VARCHAR(100) | 'NextToken', 'nextLink', 'pageToken' |
| result_array_field | VARCHAR(100) | Result array field (NULL = auto-detect) |
| supports_native_pagination | BOOLEAN | CSP SDK has native paginator |
| is_active | BOOLEAN | Enable/disable without deletion |

**Example Records:**
```sql
-- AWS default (fallback for all services)
INSERT INTO pagination_config VALUES
('aws', NULL, NULL, 1000, 100, 600, 100000, 'NextToken', NULL, TRUE, TRUE);

-- AWS SageMaker specific
INSERT INTO pagination_config VALUES
('aws', 'sagemaker', NULL, 100, 100, 600, 100000, 'NextToken', NULL, TRUE, TRUE);

-- Azure default (future - inactive)
INSERT INTO pagination_config VALUES
('azure', NULL, NULL, 100, 100, 600, 100000, 'nextLink', 'value', FALSE, FALSE);
```

**Fallback Logic:**
1. Try: `WHERE csp='aws' AND service_name='sagemaker' AND action='list_models'`
2. Fallback: `WHERE csp='aws' AND service_name='sagemaker' AND action IS NULL`
3. Fallback: `WHERE csp='aws' AND service_name IS NULL AND action IS NULL`
4. Fallback: Hardcoded default in PaginationEngine

---

## File Structure

```
threat-engine/
├── engine_common/                           (Shared CSP utilities)
│   ├── filters/
│   │   ├── __init__.py                     ✅ Created
│   │   ├── filter_engine.py                🔄 Next - Phase 1
│   │   └── filter_rules.py                 🔄 Next - Phase 1
│   ├── pagination/
│   │   ├── __init__.py                     ✅ Created
│   │   ├── pagination_engine.py            🔄 Next - Phase 1
│   │   └── pagination_config.py            🔄 Next - Phase 1
│   └── utils/
│       ├── __init__.py                     ✅ Created
│       ├── template_resolver.py            📅 Future
│       └── response_parser.py              📅 Future
│
├── consolidated_services/database/schemas/
│   ├── filters_schema.sql                  ✅ Created
│   └── pagination_schema.sql               ✅ Created
│
└── engine_discoveries/scanners/
    ├── aws_scanner.py                      🔄 Phase 2 - Use FilterEngine/PaginationEngine
    ├── aws_discovery.py                    🔄 Phase 3 - Unified run_service()
    ├── aws_filters.py                      ⚠️  To be deprecated
    └── aws_pagination.py                   ⚠️  To be deprecated
```

**Legend:**
- ✅ Completed
- 🔄 In Progress / Next
- 📅 Future Phase
- ⚠️  To be deprecated

---

## Migration Notes

### Hardcoded Filters to Migrate

**Source:** `engine_discoveries/engine_discoveries_aws/engine/service_scanner.py`

**Pre-Call Filters (lines 98-182):**
- ✅ `aws.ec2.describe_snapshots` - OwnerIds=['self']
- ✅ `aws.ec2.describe_images` - Owners=['self']
- ✅ `aws.rds.describe_db_cluster_snapshots` - IncludeShared=False, IncludePublic=False
- ✅ `aws.docdb.describe_db_cluster_snapshots` - IncludeShared=False, IncludePublic=False
- ✅ `aws.rds.describe_db_snapshots` - IncludeShared=False, IncludePublic=False

**Post-Call Filters (lines 185-276):**
- ✅ `aws.kms.list_aliases` - Exclude AliasName starting with 'alias/aws/'
- ✅ `aws.secretsmanager.list_secrets` - Exclude Name matching '^(aws/|rds!)'
- ✅ `aws.iam.list_roles` - Exclude Path starting with '/aws-service-role/'
- ✅ `aws.iam.list_policies` - Exclude Arn starting with 'arn:aws:iam::aws:policy/'
- ✅ `aws.lambda.list_functions` - Exclude FunctionArn containing ':function:aws'
- ✅ `aws.cloudformation.describe_stacks` - Exclude StackName matching '^(aws-|AWS-)'
- ✅ `aws.ssm.describe_parameters` - Exclude Name starting with '/aws/'
- ✅ `aws.ecr.describe_repositories` - Exclude repositoryName starting with 'aws/'

**Status:** All filters migrated to filters_schema.sql initial data

### Hardcoded Pagination to Migrate

**Source:** `engine_discoveries/engine_discoveries_aws/engine/service_scanner.py` (lines 1490-1500)

- ✅ Default: 1000 items/page, NextToken
- ✅ SageMaker: 100 items/page, NextToken
- ✅ Cognito (cognito-idp, cognito): 60 items/page, PaginationToken/NextToken
- ✅ Kafka (MSK): 100 items/page, NextToken
- ✅ S3: 1000 items/page, Marker/ContinuationToken
- ✅ IAM: 1000 items/page, Marker
- ✅ EC2: 1000 items/page (200 max pages), NextToken
- ✅ CloudWatch Logs: 50 items/page, nextToken

**Status:** All pagination configs migrated to pagination_schema.sql initial data

---

## Testing Strategy

### Phase 1 Testing

1. **Database Schema Verification**
   ```sql
   -- Verify tables created
   SELECT COUNT(*) FROM filter_rules WHERE csp='aws';
   SELECT COUNT(*) FROM pagination_config WHERE csp='aws';

   -- Test filter lookup
   SELECT * FROM filter_rules WHERE discovery_id='aws.ec2.describe_snapshots';

   -- Test pagination fallback
   SELECT * FROM v_pagination_lookup WHERE csp='aws' AND service_name='sagemaker';
   ```

2. **FilterEngine Unit Tests**
   - Load filters from database
   - Apply API filters (modify params dict)
   - Apply response filters (exclude AWS-managed resources)
   - Cache invalidation

3. **PaginationEngine Unit Tests**
   - Load config with fallback logic
   - Extract token fields from responses
   - Circular token detection
   - Timeout handling

### Integration Testing (Phase 2+)

- Compare discovery results before/after refactoring
- Verify ARN generation for global/regional resources
- Ensure no resources lost due to filter changes
- Performance benchmarking (database query overhead)

---

## Risks and Mitigations

### Risk 1: Database Query Performance
**Impact:** Querying filter_rules for every discovery could slow scans
**Mitigation:**
- In-memory cache with TTL (invalidate on filter_rules update)
- Database indexes on (csp, discovery_id, is_active)
- Benchmark: Target <5ms query time

### Risk 2: Filter Migration Errors
**Impact:** Missing filters could expose AWS-managed resources
**Mitigation:**
- Comprehensive comparison of filtered results before/after
- Keep hardcoded fallback with feature flag during Phase 2
- Automated tests comparing hardcoded vs database filters

### Risk 3: Breaking Changes
**Impact:** Downstream consumers expect specific data formats
**Mitigation:**
- Backward-compatible wrappers during transition
- Version API responses
- Deprecation warnings (not errors)

---

## Next Session

**Priority Actions:**
1. Apply database schemas to PostgreSQL
2. Implement FilterEngine.py
3. Implement PaginationEngine.py
4. Write unit tests
5. Begin Phase 2: Update aws_scanner.py to use new engines

**Questions to Resolve:**
- Database connection details (host, port, credentials)
- Testing database vs production database
- Feature flag strategy for gradual rollout
