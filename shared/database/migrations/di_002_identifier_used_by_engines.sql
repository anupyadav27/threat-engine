-- =============================================================================
-- DI-S1-02: Add used_by_engines + discovery_id to resource_inventory_identifier
-- =============================================================================
-- Database:  threat_engine_inventory
-- Purpose:   Replace 17 hardcoded discovery_id lists scattered across downstream
--            engine adapters with a single queryable JSONB column.
--
-- Apply with:
--   psql -h $RDS_HOST -U postgres -d threat_engine_inventory \
--     -f di_002_identifier_used_by_engines.sql
--
-- Safe to re-run: ADD COLUMN IF NOT EXISTS, UPDATE is idempotent.
-- =============================================================================

-- ── Step 1: used_by_engines JSONB ─────────────────────────────────────────────
-- Contains the list of downstream engine names that read resources of this type.
-- Default: '["check"]' because check engine reads all resource types.
ALTER TABLE resource_inventory_identifier
    ADD COLUMN IF NOT EXISTS used_by_engines JSONB NOT NULL DEFAULT '["check"]';

-- ── Step 2: GIN index for fast containment queries ────────────────────────────
-- Supports: WHERE 'network' = ANY(used_by_engines) via @> operator
CREATE INDEX IF NOT EXISTS idx_rii_used_by_engines
    ON resource_inventory_identifier USING GIN (used_by_engines);

-- ── Step 3: Seed engine assignments per resource category ─────────────────────

-- network engine: VPC, subnet, SG, route tables, load balancers, WAF, IGW, etc.
UPDATE resource_inventory_identifier
SET used_by_engines = (
    SELECT jsonb_agg(DISTINCT e) FROM (
        SELECT jsonb_array_elements_text(used_by_engines) AS e
        UNION SELECT 'network'
    ) sub
)
WHERE csp IN ('aws', 'azure', 'gcp', 'oci', 'alicloud', 'ibm', 'k8s')
  AND (
    service ILIKE '%vpc%'
    OR service ILIKE '%subnet%'
    OR service ILIKE '%security_group%'
    OR service ILIKE '%securitygroup%'
    OR service ILIKE '%route%'
    OR service ILIKE '%network%'
    OR service ILIKE '%loadbalancer%'
    OR service ILIKE '%elb%'
    OR service ILIKE '%elbv2%'
    OR service ILIKE '%waf%'
    OR service ILIKE '%nacl%'
    OR service ILIKE '%gateway%'
    OR service = 'ec2'
    OR service = 'cloudfront'
    OR resource_type ILIKE '%load-balancer%'
    OR resource_type ILIKE '%loadbalancer%'
    OR resource_type ILIKE '%vpc%'
    OR resource_type ILIKE '%subnet%'
    OR resource_type ILIKE '%security-group%'
    OR resource_type ILIKE '%route-table%'
    OR resource_type ILIKE '%internet-gateway%'
    OR resource_type ILIKE '%nat-gateway%'
    OR resource_type ILIKE '%network-interface%'
  );

-- iam engine: IAM users, roles, policies, access keys, MFA devices, groups
UPDATE resource_inventory_identifier
SET used_by_engines = (
    SELECT jsonb_agg(DISTINCT e) FROM (
        SELECT jsonb_array_elements_text(used_by_engines) AS e
        UNION SELECT 'iam'
    ) sub
)
WHERE csp IN ('aws', 'azure', 'gcp', 'oci', 'alicloud', 'ibm')
  AND (
    service = 'iam'
    OR service ILIKE '%identity%'
    OR service ILIKE '%access_management%'
    OR service ILIKE '%azure_ad%'
    OR service ILIKE '%activedirectory%'
    OR service ILIKE '%mfa%'
    OR resource_type ILIKE '%user%'
    OR resource_type ILIKE '%role%'
    OR resource_type ILIKE '%policy%'
    OR resource_type ILIKE '%access-key%'
    OR resource_type ILIKE '%mfa-device%'
    OR resource_type ILIKE '%group%'
    OR resource_type ILIKE '%service-account%'
    OR resource_type ILIKE '%managed-identity%'
  );

-- datasec engine: S3 buckets, storage accounts, BigQuery, data lakes, DynamoDB
UPDATE resource_inventory_identifier
SET used_by_engines = (
    SELECT jsonb_agg(DISTINCT e) FROM (
        SELECT jsonb_array_elements_text(used_by_engines) AS e
        UNION SELECT 'datasec'
    ) sub
)
WHERE csp IN ('aws', 'azure', 'gcp', 'oci')
  AND (
    service = 's3'
    OR service ILIKE '%storage%'
    OR service ILIKE '%bigquery%'
    OR service = 'dynamodb'
    OR service = 'rds'
    OR service = 'glue'
    OR service = 'lakeformation'
    OR resource_type ILIKE '%bucket%'
    OR resource_type ILIKE '%storage-account%'
    OR resource_type ILIKE '%data-lake%'
    OR resource_type ILIKE '%table%'
    OR resource_type ILIKE '%dataset%'
  );

-- encryption engine: KMS, ACM, Secrets Manager, Key Vault, Cloud KMS
UPDATE resource_inventory_identifier
SET used_by_engines = (
    SELECT jsonb_agg(DISTINCT e) FROM (
        SELECT jsonb_array_elements_text(used_by_engines) AS e
        UNION SELECT 'encryption'
    ) sub
)
WHERE (
    service ILIKE '%kms%'
    OR service ILIKE '%acm%'
    OR service = 'secretsmanager'
    OR service ILIKE '%keyvault%'
    OR service ILIKE '%certificate%'
    OR service ILIKE '%vault%'
    OR resource_type ILIKE '%key%'
    OR resource_type ILIKE '%certificate%'
    OR resource_type ILIKE '%secret%'
  );

-- dbsec engine: RDS, Aurora, DynamoDB, Cosmos DB, Cloud SQL, etc.
UPDATE resource_inventory_identifier
SET used_by_engines = (
    SELECT jsonb_agg(DISTINCT e) FROM (
        SELECT jsonb_array_elements_text(used_by_engines) AS e
        UNION SELECT 'dbsec'
    ) sub
)
WHERE (
    service = 'rds'
    OR service = 'docdb'
    OR service = 'neptune'
    OR service = 'elasticache'
    OR service = 'redshift'
    OR service ILIKE '%database%'
    OR service ILIKE '%sql%'
    OR service ILIKE '%mongodb%'
    OR service ILIKE '%cassandra%'
    OR service ILIKE '%postgres%'
    OR resource_type ILIKE '%db-instance%'
    OR resource_type ILIKE '%database%'
    OR resource_type ILIKE '%cluster%'
  );

-- container engine: EKS, ECS, ECR, AKS, GKE, K8s workloads
UPDATE resource_inventory_identifier
SET used_by_engines = (
    SELECT jsonb_agg(DISTINCT e) FROM (
        SELECT jsonb_array_elements_text(used_by_engines) AS e
        UNION SELECT 'container'
    ) sub
)
WHERE (
    service = 'eks'
    OR service = 'ecs'
    OR service = 'ecr'
    OR service ILIKE '%kubernetes%'
    OR service ILIKE '%container%'
    OR service ILIKE '%gke%'
    OR service ILIKE '%aks%'
    OR csp = 'k8s'
    OR resource_type ILIKE '%cluster%'
    OR resource_type ILIKE '%node%'
    OR resource_type ILIKE '%pod%'
    OR resource_type ILIKE '%deployment%'
    OR resource_type ILIKE '%namespace%'
  );

-- ai-security engine: SageMaker, Bedrock, Vertex AI, Cognitive Services
UPDATE resource_inventory_identifier
SET used_by_engines = (
    SELECT jsonb_agg(DISTINCT e) FROM (
        SELECT jsonb_array_elements_text(used_by_engines) AS e
        UNION SELECT 'ai_security'
    ) sub
)
WHERE (
    service = 'sagemaker'
    OR service = 'bedrock'
    OR service ILIKE '%ml%'
    OR service ILIKE '%aiplatform%'
    OR service ILIKE '%cognitive%'
    OR service ILIKE '%openai%'
    OR resource_type ILIKE '%model%'
    OR resource_type ILIKE '%endpoint%'
  );

-- attack-path engine: EC2 instances, SGs, IAM roles, S3, RDS (internet-facing check)
UPDATE resource_inventory_identifier
SET used_by_engines = (
    SELECT jsonb_agg(DISTINCT e) FROM (
        SELECT jsonb_array_elements_text(used_by_engines) AS e
        UNION SELECT 'attack_path'
    ) sub
)
WHERE csp = 'aws'
  AND (
    (service = 'ec2' AND resource_type = 'ec2.instance')
    OR (service = 'elbv2' AND resource_type ILIKE '%load-balancer%')
    OR (service = 'rds' AND resource_type ILIKE '%db-instance%')
    OR (service = 's3' AND resource_type = 's3.bucket')
    OR (service = 'lambda' AND resource_type ILIKE '%function%')
    OR (service = 'iam' AND resource_type ILIKE '%role%')
    OR (service = 'ec2' AND resource_type = 'ec2.security-group')
    OR (service = 'apigateway' OR service = 'apigatewayv2')
  );

-- threat-v1 engine: same scope as attack-path (IAM violations, credentials)
UPDATE resource_inventory_identifier
SET used_by_engines = (
    SELECT jsonb_agg(DISTINCT e) FROM (
        SELECT jsonb_array_elements_text(used_by_engines) AS e
        UNION SELECT 'threat'
    ) sub
)
WHERE csp = 'aws'
  AND service IN ('iam', 'ec2', 's3', 'lambda', 'rds', 'elbv2', 'apigateway', 'apigatewayv2');

-- risk engine: read from security_findings (not asset_inventory directly)
-- No used_by_engines update needed for risk.

-- ── Step 4: Verify ────────────────────────────────────────────────────────────
DO $$
DECLARE
    total_rows INT;
    network_rows INT;
    iam_rows INT;
    datasec_rows INT;
BEGIN
    SELECT COUNT(*) INTO total_rows FROM resource_inventory_identifier;
    SELECT COUNT(*) INTO network_rows FROM resource_inventory_identifier
        WHERE used_by_engines @> '["network"]';
    SELECT COUNT(*) INTO iam_rows FROM resource_inventory_identifier
        WHERE used_by_engines @> '["iam"]';
    SELECT COUNT(*) INTO datasec_rows FROM resource_inventory_identifier
        WHERE used_by_engines @> '["datasec"]';

    RAISE NOTICE 'DI-S1-02 complete: total=% network=% iam=% datasec=%',
        total_rows, network_rows, iam_rows, datasec_rows;
END $$;
