-- Migration 028: Attack-path relationship rules for all 7 CSPs
-- Adds missing edges that enable real attack path detection:
--   1. IAM assume edges  (compute → IAM role)
--   2. Encryption edges  (resource → KMS key)
--   3. EKS membership    (nodegroup → cluster)
--   4. Data-flow edges   (CloudTrail/Glue/EMR → S3)
--   5. Service account   (K8s pod → serviceaccount)
--   6. Multi-CSP identity edges (Azure managed identity, GCP SA, OCI instance principal)
-- DB: threat_engine_inventory
-- Table: resource_security_relationship_rules

BEGIN;

-- ══════════════════════════════════════════════════════════════════════════
-- AWS
-- ══════════════════════════════════════════════════════════════════════════

INSERT INTO resource_security_relationship_rules
    (csp, service, from_resource_type, relation_type, to_resource_type,
     source_field, source_field_item, target_uid_pattern,
     is_active, rule_source, attack_path_category)
VALUES

-- ── IAM assume edges ──────────────────────────────────────────────────────

-- Lambda → assumes → IAM execution role
('aws', 'lambda', 'lambda.function', 'assumes', 'iam.role',
 'Role', NULL, '{Role}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- ECS task-definition → assumes → task IAM role
('aws', 'ecs', 'ecs.task-definition', 'assumes', 'iam.role',
 'TaskRoleArn', NULL, '{TaskRoleArn}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- ECS task-definition → assumes → execution IAM role
('aws', 'ecs', 'ecs.task-definition', 'assumes', 'iam.role',
 'ExecutionRoleArn', NULL, '{ExecutionRoleArn}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- CodeBuild project → assumes → service IAM role
('aws', 'codebuild', 'codebuild.project', 'assumes', 'iam.role',
 'ServiceRole', NULL, '{ServiceRole}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- EKS cluster → assumes → cluster IAM role
('aws', 'eks', 'eks.cluster', 'assumes', 'iam.role',
 'roleArn', NULL, '{roleArn}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- EKS nodegroup → assumes → node IAM role (workers use this to call AWS APIs)
('aws', 'eks', 'eks.nodegroup', 'assumes', 'iam.role',
 'nodeRole', NULL, '{nodeRole}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- EKS nodegroup → member_of → EKS cluster
('aws', 'eks', 'eks.nodegroup', 'member_of', 'eks.cluster',
 'clusterName', NULL, 'arn:aws:eks:{region}:{account_id}:cluster/{clusterName}',
 TRUE, 'attack_path_028', 'lateral_movement'),

-- StepFunctions state machine → assumes → IAM role
('aws', 'stepfunctions', 'stepfunctions.state-machine', 'assumes', 'iam.role',
 'roleArn', NULL, '{roleArn}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- EventBridge rule → assumes → IAM role (target invocation)
('aws', 'events', 'events.rule', 'assumes', 'iam.role',
 'RoleArn', NULL, '{RoleArn}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- SageMaker model → assumes → IAM execution role
('aws', 'sagemaker', 'sagemaker.model', 'assumes', 'iam.role',
 'ExecutionRoleArn', NULL, '{ExecutionRoleArn}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- SageMaker hub → assumes → IAM role
('aws', 'sagemaker', 'sagemaker.hub', 'assumes', 'iam.role',
 'RoleArn', NULL, '{RoleArn}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- Glue job → assumes → IAM role
('aws', 'glue', 'glue.job', 'assumes', 'iam.role',
 'Role', NULL, '{Role}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- EMR cluster → assumes → IAM role (job flow role)
('aws', 'emr', 'emr.cluster', 'assumes', 'iam.role',
 'Ec2InstanceAttributes.IamInstanceProfile', NULL, '{Ec2InstanceAttributes.IamInstanceProfile}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- CodePipeline → assumes → IAM role
('aws', 'codepipeline', 'codepipeline.pipeline_role', 'assumes', 'iam.role',
 'roleArn', NULL, '{roleArn}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- ── Encryption edges ──────────────────────────────────────────────────────

-- RDS DB instance → encrypted_by → KMS key
('aws', 'rds', 'rds.db-instance', 'encrypted_by', 'kms.key',
 'KmsKeyId', NULL, '{KmsKeyId}',
 TRUE, 'attack_path_028', 'data_access'),

-- Secrets Manager secret → encrypted_by → KMS key
('aws', 'secretsmanager', 'secretsmanager.secret', 'encrypted_by', 'kms.key',
 'KmsKeyId', NULL, '{KmsKeyId}',
 TRUE, 'attack_path_028', 'data_access'),

-- Lambda function → encrypted_by → KMS key (env var encryption)
('aws', 'lambda', 'lambda.function', 'encrypted_by', 'kms.key',
 'KMSKeyArn', NULL, '{KMSKeyArn}',
 TRUE, 'attack_path_028', 'data_access'),

-- ECR repository → encrypted_by → KMS key
('aws', 'ecr', 'ecr.repository', 'encrypted_by', 'kms.key',
 'encryptionConfiguration.kmsKey', NULL, '{encryptionConfiguration.kmsKey}',
 TRUE, 'attack_path_028', 'data_access'),

-- EFS file system → encrypted_by → KMS key
('aws', 'elasticfilesystem', 'elasticfilesystem.file-system', 'encrypted_by', 'kms.key',
 'KmsKeyId', NULL, '{KmsKeyId}',
 TRUE, 'attack_path_028', 'data_access'),

-- EKS cluster → encrypted_by → KMS key (secrets encryption)
('aws', 'eks', 'eks.cluster', 'encrypted_by', 'kms.key',
 'encryptionConfig.provider.keyArn', NULL, '{encryptionConfig.provider.keyArn}',
 TRUE, 'attack_path_028', 'data_access'),

-- Backup vault → encrypted_by → KMS key
('aws', 'backup', 'backup.backup-vault', 'encrypted_by', 'kms.key',
 'EncryptionKeyArn', NULL, '{EncryptionKeyArn}',
 TRUE, 'attack_path_028', 'data_access'),

-- ── Data-flow / stores_data_in edges ─────────────────────────────────────

-- CloudTrail → stores_data_in → S3 bucket (audit logs destination)
('aws', 'cloudtrail', 'cloudtrail.trail', 'stores_data_in', 's3.bucket',
 'S3BucketName', NULL, 'arn:aws:s3:::{S3BucketName}',
 TRUE, 'attack_path_028', 'data_access'),

-- CloudTrail → logging_enabled_to → CloudWatch log group
('aws', 'cloudtrail', 'cloudtrail.trail', 'logging_enabled_to', 'logs.log-group',
 'CloudWatchLogsLogGroupArn', NULL, '{CloudWatchLogsLogGroupArn}',
 TRUE, 'attack_path_028', 'data_access'),

-- Glue database → stores_data_in → S3 bucket (data lake location)
('aws', 'glue', 'glue.database', 'stores_data_in', 's3.bucket',
 'DatabaseInput.LocationUri', NULL, '{DatabaseInput.LocationUri}',
 TRUE, 'attack_path_028', 'data_access'),

-- Glue table → stores_data_in → S3
('aws', 'glue', 'glue.table', 'stores_data_in', 's3.bucket',
 'StorageDescriptor.Location', NULL, '{StorageDescriptor.Location}',
 TRUE, 'attack_path_028', 'data_access'),

-- Kinesis Firehose → stores_data_in → S3
('aws', 'kinesisfirehose', 'kinesisfirehose.delivery_stream_description_version', 'stores_data_in', 's3.bucket',
 'S3DestinationDescription.BucketARN', NULL, '{S3DestinationDescription.BucketARN}',
 TRUE, 'attack_path_028', 'data_access'),

-- Lambda → subscribes_to → Kinesis stream (trigger)
('aws', 'lambda', 'lambda.function', 'subscribes_to', 'kinesis.stream',
 'EventSourceMappings', 'EventSourceArn', '{EventSourceArn}',
 TRUE, 'attack_path_028', 'data_flow'),

-- ── Containment/membership ─────────────────────────────────────────────────

-- ECS service → member_of → ECS cluster
('aws', 'ecs', 'ecs.service', 'member_of', 'ecs.cluster',
 'clusterArn', NULL, '{clusterArn}',
 TRUE, 'attack_path_028', 'lateral_movement'),

-- RDS subnet group → contained_by → VPC
('aws', 'rds', 'rds.db-subnet-group', 'contained_by', 'ec2.vpc',
 'VpcId', NULL, 'arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}',
 TRUE, 'attack_path_028', 'network'),

-- Cognito User Pool → manages → IAM role (for authenticated/unauthenticated access)
('aws', 'cognito-identity', 'cognito-identity.identitypool', 'assumes', 'iam.role',
 'Roles.authenticated', NULL, '{Roles.authenticated}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- ══════════════════════════════════════════════════════════════════════════
-- AZURE
-- ══════════════════════════════════════════════════════════════════════════

-- Azure VM → uses → Managed Identity (system-assigned principalId)
('azure', 'compute', 'compute.VirtualMachine', 'uses', 'azure.managed-identity',
 'identity.principalId', NULL, '{identity.principalId}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- Azure VM (alt type) → uses → Managed Identity
('azure', 'compute', 'azure.virtual_machine', 'uses', 'azure.managed-identity',
 'identity.principalId', NULL, '{identity.principalId}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- Azure App Service → uses → Managed Identity
('azure', 'web', 'azure.app_service', 'uses', 'azure.managed-identity',
 'identity.principalId', NULL, '{identity.principalId}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- Azure Function App → uses → Managed Identity
('azure', 'web', 'azure.function_app', 'uses', 'azure.managed-identity',
 'identity.principalId', NULL, '{identity.principalId}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- Azure AKS cluster → assumes → Managed Identity (control plane)
('azure', 'containerservice', 'azure.kubernetes_service', 'uses', 'azure.managed-identity',
 'identity.principalId', NULL, '{identity.principalId}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- Azure SQL Server → encrypted_by → Key Vault key
('azure', 'sql', 'azure.sql_server', 'encrypted_by', 'azure.key_vault_key',
 'transparentDataEncryption.serverKeyName', NULL, '{transparentDataEncryption.serverKeyName}',
 TRUE, 'attack_path_028', 'data_access'),

-- Azure Storage Account → encrypted_by → Key Vault key
('azure', 'storage', 'azure.storage_account', 'encrypted_by', 'azure.key_vault_key',
 'encryption.keyVaultProperties.keyVaultUri', NULL, '{encryption.keyVaultProperties.keyVaultUri}',
 TRUE, 'attack_path_028', 'data_access'),

-- Azure SQL Database → contained_by → SQL Server
('azure', 'sql', 'azure.sql_database', 'contained_by', 'azure.sql_server',
 'serverName', NULL, '{serverName}',
 TRUE, 'attack_path_028', 'lateral_movement'),

-- ══════════════════════════════════════════════════════════════════════════
-- GCP
-- ══════════════════════════════════════════════════════════════════════════

-- GCE instance → uses → Service Account (first SA in list)
('gcp', 'compute', 'gcp.compute_instance', 'uses', 'gcp.service_account',
 'serviceAccounts', 'email', 'projects/{account_id}/serviceAccounts/{email}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- GKE cluster → uses → Service Account (node SA)
('gcp', 'container', 'gcp.gke_cluster', 'uses', 'gcp.service_account',
 'nodeConfig.serviceAccount', NULL, 'projects/{account_id}/serviceAccounts/{nodeConfig.serviceAccount}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- Cloud Function → uses → Service Account
('gcp', 'cloudfunctions', 'gcp.cloud_function', 'uses', 'gcp.service_account',
 'serviceAccountEmail', NULL, 'projects/{account_id}/serviceAccounts/{serviceAccountEmail}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- Cloud Run → uses → Service Account
('gcp', 'run', 'gcp.cloud_run', 'uses', 'gcp.service_account',
 'spec.template.spec.serviceAccountName', NULL, 'projects/{account_id}/serviceAccounts/{spec.template.spec.serviceAccountName}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- Cloud SQL → encrypted_by → KMS key
('gcp', 'sql', 'gcp.cloud_sql', 'encrypted_by', 'gcp.kms_key',
 'diskEncryptionConfiguration.kmsKeyName', NULL, '{diskEncryptionConfiguration.kmsKeyName}',
 TRUE, 'attack_path_028', 'data_access'),

-- GCS Bucket → encrypted_by → KMS key (CMEK)
('gcp', 'storage', 'gcp.cloud_storage_bucket', 'encrypted_by', 'gcp.kms_key',
 'defaultKmsKeyName', NULL, '{defaultKmsKeyName}',
 TRUE, 'attack_path_028', 'data_access'),

-- GKE nodepool → member_of → GKE cluster
('gcp', 'container', 'gcp.gke_nodepool', 'member_of', 'gcp.gke_cluster',
 'selfLink', NULL, '{selfLink}',
 TRUE, 'attack_path_028', 'lateral_movement'),

-- BigQuery dataset → encrypted_by → KMS key
('gcp', 'bigquery', 'gcp.bigquery_dataset', 'encrypted_by', 'gcp.kms_key',
 'defaultEncryptionConfiguration.kmsKeyName', NULL, '{defaultEncryptionConfiguration.kmsKeyName}',
 TRUE, 'attack_path_028', 'data_access'),

-- ══════════════════════════════════════════════════════════════════════════
-- OCI
-- ══════════════════════════════════════════════════════════════════════════

-- OCI Compute instance → uses → dynamic group (instance principal for IAM)
('oci', 'compute', 'compute.oci.core/Instance', 'uses', 'oci.dynamic-group',
 'metadata.iam.instancePrincipalGroupId', NULL, '{metadata.iam.instancePrincipalGroupId}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- OCI Function → assumes → resource principal
('oci', 'functions', 'functions.oci.core/Function', 'uses', 'oci.dynamic-group',
 'freeformTags.oci:compute:instance-group', NULL, '{freeformTags.oci:compute:instance-group}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- OCI Object Storage → encrypted_by → KMS key
('oci', 'objectstorage', 'objectstorage.oci.core/Bucket', 'encrypted_by', 'oci.kms_key',
 'kmsKeyId', NULL, '{kmsKeyId}',
 TRUE, 'attack_path_028', 'data_access'),

-- OCI Autonomous Database → encrypted_by → KMS key
('oci', 'database', 'database.oci.core/AutonomousDatabase', 'encrypted_by', 'oci.kms_key',
 'kmsKeyId', NULL, '{kmsKeyId}',
 TRUE, 'attack_path_028', 'data_access'),

-- OCI OKE cluster → member_of → OCI compartment (for IAM scoping)
('oci', 'containerengine', 'containerengine.oci.core/Cluster', 'contained_by', 'oci.compartment',
 'compartmentId', NULL, '{compartmentId}',
 TRUE, 'attack_path_028', 'lateral_movement'),

-- ══════════════════════════════════════════════════════════════════════════
-- AliCloud
-- ══════════════════════════════════════════════════════════════════════════

-- AliCloud ECS → assumes → RAM role (already has rule; add alt field)
('alicloud', 'ecs', 'ecs.instance', 'assumes', 'ram.role',
 'RamRoleName', NULL, 'acs:ram::{account_id}:role/{RamRoleName}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- AliCloud FC (Function Compute) service → uses → RAM role
('alicloud', 'fc', 'fc.service', 'assumes', 'ram.role',
 'role', NULL, '{role}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- AliCloud CS cluster → assumes → RAM role
('alicloud', 'cs', 'cs.cluster', 'assumes', 'ram.role',
 'resource_group_id', NULL, 'acs:ram::{account_id}:role/AliyunCSManagedKubernetesRole',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- AliCloud OSS → encrypted_by → KMS key (already partially exists; add alt)
('alicloud', 'oss', 'oss.bucket', 'encrypted_by', 'kms.key',
 'ServerSideEncryption.KMSMasterKeyID', NULL, '{ServerSideEncryption.KMSMasterKeyID}',
 TRUE, 'attack_path_028', 'data_access'),

-- AliCloud RDS → encrypted_by → KMS key
('alicloud', 'rds', 'rds.dbinstance', 'encrypted_by', 'kms.key',
 'TDEStatus', NULL, 'acs:kms:{region}:{account_id}:key/{DBInstanceId}',
 TRUE, 'attack_path_028', 'data_access'),

-- ══════════════════════════════════════════════════════════════════════════
-- KUBERNETES (K8s)
-- ══════════════════════════════════════════════════════════════════════════

-- Pod → uses → ServiceAccount
('k8s', 'core', 'core.pod', 'uses', 'core.serviceaccount',
 'serviceAccountName', NULL, '{serviceAccountName}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- Pod → uses → ServiceAccount (nested spec)
('k8s', 'core', 'core.pod', 'uses', 'core.serviceaccount',
 'spec.serviceAccountName', NULL, '{spec.serviceAccountName}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- Deployment → manages → Pod (via selector — use template serviceAccount)
('k8s', 'apps', 'apps.deployment', 'uses', 'core.serviceaccount',
 'spec.template.spec.serviceAccountName', NULL, '{spec.template.spec.serviceAccountName}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- StatefulSet → uses → ServiceAccount
('k8s', 'apps', 'apps.statefulset', 'uses', 'core.serviceaccount',
 'spec.template.spec.serviceAccountName', NULL, '{spec.template.spec.serviceAccountName}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- DaemonSet → uses → ServiceAccount
('k8s', 'apps', 'apps.daemonset', 'uses', 'core.serviceaccount',
 'spec.template.spec.serviceAccountName', NULL, '{spec.template.spec.serviceAccountName}',
 TRUE, 'attack_path_028', 'privilege_escalation'),

-- K8s Secret → contained_by → Namespace (already handled by architecture containment)

-- ServiceAccount → uses → Secret (imagePullSecrets / token)
('k8s', 'core', 'core.serviceaccount', 'uses', 'core.secret',
 'secrets', 'name', '{name}',
 TRUE, 'attack_path_028', 'data_access'),

-- Pod → mounts → Secret (volumes)
('k8s', 'core', 'core.pod', 'uses', 'core.secret',
 'spec.volumes', 'secret.secretName', '{secret.secretName}',
 TRUE, 'attack_path_028', 'data_access'),

-- Ingress → exposes → Service
('k8s', 'networking.k8s.io', 'networking.k8s.io.ingress', 'exposes', 'core.service',
 'spec.rules', 'http.paths.backend.service.name', '{http.paths.backend.service.name}',
 TRUE, 'attack_path_028', 'lateral_movement')

ON CONFLICT DO NOTHING;

COMMIT;
