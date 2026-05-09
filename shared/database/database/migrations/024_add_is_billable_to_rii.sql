-- Migration 024: Add is_billable to resource_inventory_identifier
-- Marks which resource types count toward monthly billing across all CSPs.
-- Billing rule: 0-50 billable resources = $1,000 flat; 51+ = $1,000 + (n-50) * $20
-- Only applies to threat_engine_inventory DB.

-- ── Step 1: Add column ───────────────────────────────────────────────────────
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS is_billable BOOLEAN NOT NULL DEFAULT FALSE;

-- ── Step 2: Bulk-enable by category (PRIMARY_RESOURCE only) ─────────────────
UPDATE resource_inventory_identifier
SET is_billable = TRUE
WHERE classification = 'PRIMARY_RESOURCE'
  AND category IN ('compute', 'container', 'database', 'storage');

-- ── Step 3: Explicit AWS billable types not covered by category ──────────────
UPDATE resource_inventory_identifier
SET is_billable = TRUE
WHERE csp = 'aws'
  AND resource_type IN (
    'ec2.instance',
    'ec2.host',
    'ec2.volume',
    'lambda.function',
    'eks.cluster',
    'ecs.cluster',
    'ecs.task-definition',
    'ecs.capacity-provider',
    'emr.cluster',
    'ecr.repository',
    'secretsmanager.secret',
    'apigateway.rest-api',
    'apigatewayv2.api',
    'cloudfront.distribution',
    'elbv2.load-balancer',
    'stepfunctions.state-machine',
    'dynamodb.table',
    'rds.db-instance',
    'rds.instance',
    'rds.cluster',
    'docdb.db-instance',
    'neptune.db-instance',
    'redshift.resource',
    'opensearch.domain',
    'cassandra.resource',
    'memorydb.resource',
    'timestream.resource',
    's3.bucket',
    'efs.file-system',
    'elasticfilesystem.file-system',
    'mwaa.resource',
    'sagemaker.hub',
    'eks.deployment'
  );

-- ── Step 4: Explicit GCP billable types ─────────────────────────────────────
UPDATE resource_inventory_identifier
SET is_billable = TRUE
WHERE csp = 'gcp'
  AND resource_type IN (
    'gcp.compute_instance',
    'gcp.gcs_bucket',
    'gcp.bigquery_dataset',
    'gcp.pubsub_topic',
    'gcp.secret'
  );

-- ── Step 5: Explicit Azure billable types ────────────────────────────────────
UPDATE resource_inventory_identifier
SET is_billable = TRUE
WHERE csp = 'azure'
  AND resource_type IN (
    'compute.VirtualMachine',
    'storage.StorageAccount',
    'disk.ManagedDisk',
    'keyvault.KeyVault'
  );

-- ── Step 6: Explicit OCI billable types ──────────────────────────────────────
UPDATE resource_inventory_identifier
SET is_billable = TRUE
WHERE csp = 'oci'
  AND resource_type IN (
    'compute.oci.core/Instance',
    'object_storage.oci.objectstorage/Bucket',
    'key_management.oci.key_management/Vault'
  );

-- ── Step 7: Explicit K8s billable types ──────────────────────────────────────
UPDATE resource_inventory_identifier
SET is_billable = TRUE
WHERE csp = 'k8s'
  AND resource_type IN (
    'node.k8s.core/Node',
    'deployment.k8s.apps/Deployment',
    'daemonset.k8s.apps/DaemonSet',
    'cronjob.k8s.batch/CronJob',
    'ingress.k8s.networking/Ingress'
  );

-- ── Step 8: Force-exclude noise regardless of category ───────────────────────
-- Snapshots/backups (auto-generated, unpredictable count)
UPDATE resource_inventory_identifier
SET is_billable = FALSE
WHERE resource_type ILIKE '%snapshot%'
   OR resource_type ILIKE '%backup%'
   OR resource_type ILIKE '%offering%'
   OR resource_type ILIKE '%-event%'
   OR resource_type ILIKE '%event-%'
   OR resource_type ILIKE '%.resource'    -- generic catch-all types
   OR resource_type ILIKE '%parameter-group%'
   OR resource_type ILIKE '%parameter_group%'
   OR resource_type ILIKE '%subnet-group%'
   OR resource_type ILIKE '%subnet_group%';

-- AliCloud: nothing billable yet (discovery only covers IAM/audit)
UPDATE resource_inventory_identifier
SET is_billable = FALSE
WHERE csp = 'alicloud';

-- ── Step 9: Verify ───────────────────────────────────────────────────────────
DO $$
DECLARE
  billable_count INT;
BEGIN
  SELECT COUNT(*) INTO billable_count
  FROM resource_inventory_identifier
  WHERE is_billable = TRUE;

  RAISE NOTICE 'Migration 024 complete: % billable resource types defined', billable_count;
END $$;
