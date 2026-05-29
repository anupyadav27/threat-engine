# DI-S1-02 — Identifier Table Refresh (used_by_engines Column + Full Seed)
**Sprint**: DI-S1 | **Points**: 8 | **Status**: Ready for Dev

## Goal
Add `used_by_engines JSONB` column to `resource_inventory_identifier` (in `threat_engine_inventory` DB),
seed the column for all 2,965 `should_inventory=True` rows across 7 CSPs, and add `discovery_id` as
a derived column. This replaces all 17 hardcoded discovery_id lists in downstream engine reader files
with a single parameterized DB query.

## Context
After the 2026-05 cleanup, `resource_inventory_identifier` has 2,965 rows (all `should_inventory=True`).
The table knows which services are needed but not which engine uses each service. Downstream engines
currently maintain independent hardcoded lists (network: 40 IDs, IAM: ~15, datasec: ~16, etc.).
`used_by_engines` centralizes this: `WHERE 'network' = ANY(used_by_engines)` replaces all those lists.

## Files to Create / Modify
- `shared/database/migrations/di_002_identifier_used_by_engines.sql` — ALTER TABLE + seed UPDATEs
- `shared/database/schemas/inventory_identifier_schema.sql` — update schema reference

## Migration DDL

```sql
-- di_002_identifier_used_by_engines.sql

-- Step 1: Add column (idempotent)
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS used_by_engines JSONB DEFAULT '["check"]';

-- Step 2: Add discovery_id derived column (csp.service.operation)
-- discovery_id = csp || '.' || service || '.' || root_ops[0]->'operation'
-- NOTE: root_ops is a JSONB array; the first element's 'operation' key is the canonical discovery_id
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS discovery_id VARCHAR(255)
  GENERATED ALWAYS AS (
    csp || '.' || service || '.' ||
    (root_ops->0->>'operation')
  ) STORED;

-- Step 3: Seed used_by_engines for all CSPs

-- ── AWS: EC2 ──────────────────────────────────────────────────────────────────
-- VPC, subnet, SG, route_table, igw, nat_gateway — needed by check + network + attack-path
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","network","attack-path"]'
WHERE csp='aws' AND service='ec2'
  AND resource_type IN ('vpc','subnet','security_group','route_table',
                        'internet_gateway','nat_gateway','network_interface',
                        'vpc_peering_connection','transit_gateway','transit_gateway_attachment',
                        'vpn_gateway','vpn_connection','egress_only_internet_gateway');

-- EC2 instance — check + attack-path + vulnerability
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","network","attack-path","vulnerability"]'
WHERE csp='aws' AND service='ec2' AND resource_type='instance';

-- EC2 load balancer (elbv2/elb) — check + network + api-sec
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","network","api-sec"]'
WHERE csp='aws' AND service IN ('elbv2','elb')
  AND resource_type IN ('load_balancer','target_group','listener');

-- ── AWS: IAM ──────────────────────────────────────────────────────────────────
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","iam","attack-path"]'
WHERE csp='aws' AND service='iam'
  AND resource_type IN ('role','user','group','policy','access_key',
                        'virtual_mfa_device','account_summary','account_authorization_details');

-- ── AWS: S3 ───────────────────────────────────────────────────────────────────
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","datasec","cdr","encryption","attack-path"]'
WHERE csp='aws' AND service='s3' AND resource_type='bucket';

-- ── AWS: RDS / Aurora ─────────────────────────────────────────────────────────
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","dbsec","network","attack-path"]'
WHERE csp='aws' AND service='rds'
  AND resource_type IN ('db_instance','db_cluster','db_snapshot','db_parameter_group',
                        'db_subnet_group','db_security_group');

-- ── AWS: KMS / ACM / SecretsManager ─────────────────────────────────────────
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","encryption"]'
WHERE csp='aws' AND service IN ('kms','acm','secretsmanager','ssm');

-- ── AWS: CloudTrail / CloudWatch / Config ─────────────────────────────────────
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","cdr","network"]'
WHERE csp='aws' AND service IN ('cloudtrail','config','cloudwatch','logs');

-- ── AWS: API Gateway ─────────────────────────────────────────────────────────
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","api-sec","network"]'
WHERE csp='aws' AND service IN ('apigateway','apigatewayv2');

-- ── AWS: Lambda ──────────────────────────────────────────────────────────────
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","attack-path","vulnerability","api-sec"]'
WHERE csp='aws' AND service='lambda';

-- ── AWS: EKS / ECS / ECR ─────────────────────────────────────────────────────
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","container-security","vulnerability","attack-path"]'
WHERE csp='aws' AND service IN ('eks','ecs','ecr','ecrpublic');

-- ── AWS: SageMaker / Bedrock / Comprehend ─────────────────────────────────────
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","ai-security"]'
WHERE csp='aws' AND service IN ('sagemaker','bedrock','comprehend','rekognition',
                                'textract','translate','polly','transcribe');

-- ── AWS: WAF / Shield ────────────────────────────────────────────────────────
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","network","api-sec"]'
WHERE csp='aws' AND service IN ('wafv2','waf','shield','shieldadvanced');

-- ── AWS: DynamoDB / ElastiCache / Redshift / EMR ────────────────────────────
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","dbsec","datasec"]'
WHERE csp='aws' AND service IN ('dynamodb','elasticache','redshift','emr','dax',
                                'neptune','docdb','memorydb');

-- ── AWS: SNS / SQS / EventBridge / Kinesis ───────────────────────────────────
UPDATE resource_inventory_identifier
SET used_by_engines = '["check","network"]'
WHERE csp='aws' AND service IN ('sns','sqs','events','kinesis','firehose','kafka');

-- ── Azure: all services → used_by_engines reflects check + relevant engine ────
-- (same pattern for Azure, GCP, OCI, IBM, AliCloud, K8s — abbreviated here for space)
-- Full seed script: see companion script scripts/seed_used_by_engines.py

-- Fallback: any row not yet seeded still has default ["check"]
-- Rows without a specific engine assignment stay as check-only

-- Step 4: Create GIN index for array containment queries
CREATE INDEX IF NOT EXISTS idx_rii_used_by_engines
  ON resource_inventory_identifier USING GIN (used_by_engines);
```

## Companion Seed Script
A full Python seed script at `scripts/seed_used_by_engines.py` covers all CSPs. The SQL above
covers AWS. The Python script applies the same categorical logic for:
- Azure: VNet/NSG/VM/SQL/KeyVault/AKS/API Management
- GCP: VPC/GCE/GKE/CloudSQL/KMS/PubSub/BigQuery
- OCI: VCN/Compute/ObjectStorage/ADB/Vault/OKE
- IBM: VPC/VSI/COS/Databases/KeyProtect/OpenShift
- AliCloud: VPC/ECS/OSS/RDS/KMS/ACK
- K8s: Pods/Services/RBAC/NetworkPolicies/Ingress/Workloads

The script is idempotent (UPDATE … WHERE) and can be re-run after adding new CSP services.

## Acceptance Criteria

### Functional
- [ ] `used_by_engines` column exists on `resource_inventory_identifier` after migration
- [ ] `discovery_id` computed column exists and returns `csp.service.operation` format
- [ ] `WHERE 'network' = ANY(used_by_engines)` returns ≥ 40 rows for provider='aws'
- [ ] `WHERE 'iam' = ANY(used_by_engines)` returns ≥ 8 rows for provider='aws'
- [ ] `WHERE 'datasec' = ANY(used_by_engines)` returns ≥ 12 rows for provider='aws'
- [ ] `WHERE 'encryption' = ANY(used_by_engines)` returns ≥ 10 rows for provider='aws'
- [ ] `WHERE 'cdr' = ANY(used_by_engines)` returns ≥ 4 rows for provider='aws' (cloudtrail, flow logs, S3, ALB)
- [ ] GIN index created: `\d resource_inventory_identifier` shows `idx_rii_used_by_engines`
- [ ] No `should_inventory=True` row has NULL `used_by_engines` (all have at least `["check"]`)
- [ ] All 7 CSPs have ≥ 1 row with a non-check engine in `used_by_engines`

### Security
- [ ] No credentials or secrets written in migration SQL
- [ ] `discovery_id` computed column uses IMMUTABLE expression (verified — string concatenation is immutable)
- [ ] Migration applies in a transaction; partial failure rolls back cleanly

### Error Handling
- [ ] Migration is idempotent: `ADD COLUMN IF NOT EXISTS` — second run produces no error
- [ ] `discovery_id` column conflicts with `(root_ops->0->>'operation')` being NULL for edge cases → store NULL (not error)

## Testing Requirements

**SQL validation** (run after migration):
```sql
-- Engine coverage check
SELECT engine, count(*)
FROM resource_inventory_identifier,
     jsonb_array_elements_text(used_by_engines) AS engine
WHERE should_inventory = TRUE
GROUP BY engine
ORDER BY count(*) DESC;
-- Expected: check=2965, network>=40, iam>=8, attack-path>=30, etc.

-- discovery_id format check
SELECT COUNT(*) FROM resource_inventory_identifier
WHERE discovery_id IS NOT NULL
  AND discovery_id NOT LIKE '%.%.%';
-- Expected: 0 (all discovery_ids have 3+ segments)
```

**Unit test** (`tests/database/test_identifier_table.py`):
- `get_discovery_ids_for_engine('network', 'aws')` returns ≥ 40 strings
- `get_discovery_ids_for_engine('iam', 'aws')` returns ≥ 8 strings
- `get_discovery_ids_for_engine('unknown', 'aws')` returns `[]` (no crash)
- All returned strings match pattern `aws.<service>.<operation>` (3+ segments)

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge |
| QA acceptance | cspm-qa | deploy |

## Definition of Done
- [ ] `di_002_identifier_used_by_engines.sql` committed
- [ ] `scripts/seed_used_by_engines.py` committed (full CSP coverage)
- [ ] Migration applied on prod; `idx_rii_used_by_engines` GIN index visible
- [ ] Engine coverage query shows all 11 engines with ≥ 1 discovery_id for AWS
- [ ] Unit tests passing
- [ ] MEMORY.md updated: `resource_inventory_identifier` has `used_by_engines` + `discovery_id` columns

## Dependencies
- DI-S1-01 (must confirm `threat_engine_di` DB exists before starting, though this migration applies to `threat_engine_inventory`)

## Rollback
```sql
ALTER TABLE resource_inventory_identifier DROP COLUMN IF EXISTS used_by_engines;
ALTER TABLE resource_inventory_identifier DROP COLUMN IF EXISTS discovery_id;
DROP INDEX IF EXISTS idx_rii_used_by_engines;
```