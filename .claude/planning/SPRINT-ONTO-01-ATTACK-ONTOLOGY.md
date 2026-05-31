# ONTO-01 Sprint: Attack Ontology & Relationship Quality

**Goal**: Replace flat boolean posture signals with a structured two-axis ontology
(Attack Entry Points × Attack Targets) that covers all CSPs, all service types,
and is **fully DB-driven** — same pattern as `resource_relationship_catalog`.

**Key renames (this sprint)**:
| Old | New | Reason |
|-----|-----|--------|
| `is_internet_exposed` | `is_attack_entry_point` | Not all entry points are internet-exposed |
| `is_crown_jewel` | `is_attack_target` | "Target" matches the ontology language |
| `crown_jewel_type` | `attack_target_category` | Symmetric with `attack_entry_point_category` |

**Architecture**:
```
catalog/ontology/resource_ontology.yaml
        ↓  (upload_ontology_catalog.py)
resource_ontology_catalog (DB table, threat_engine_di)
        ↓  (read at runtime)
ontology_writer.py (DI engine Phase 3)
        ↓
resource_security_posture  ←  is_attack_entry_point / attack_entry_point_category
                               is_attack_target / attack_target_category
```

---

## Ontology Reference

### Axis A — Attack Entry Points
| Category | Meaning |
|----------|---------|
| `INTERNET_ENTRY` | Internet-reachable surface (API GW, ALB, CloudFront, public EC2) |
| `IDENTITY_ENTRY` | Compromised credential path (IAM User, federated, service account) |
| `THIRD_PARTY_ENTRY` | External trust (OIDC, CI/CD, cross-account role) |
| `WORKLOAD_ENTRY` | Compromised compute lateral start (EC2, Lambda, K8s pod) |
| `MANAGEMENT_ENTRY` | Management plane access (SSM, bastion, RDP, K8s API) |
| `DATA_ENTRY` | Publicly accessible data plane (public S3, public DB endpoint) |

### Axis B — Attack Targets
| Category | Meaning |
|----------|---------|
| `DATA_TARGET` | Sensitive data stores (S3, RDS, DynamoDB, GCS, Blob) |
| `SECRET_TARGET` | Secrets and credentials (Secrets Manager, Key Vault, SSM SecureString) |
| `CRYPTO_TARGET` | Encryption keys (KMS Key, CMK, Cloud KMS) |
| `IDENTITY_TARGET` | Privileged identities (Admin Role, Root, Service Account) |
| `CONTROL_PLANE_TARGET` | Management/control plane (EKS Cluster, AWS Account, AKS) |
| `WORKLOAD_TARGET` | Production workloads (EC2, Lambda, EKS NodeGroup, ECS) |

A resource type can appear in BOTH axes.

---

## Stories

### ONTO-1-A: DB Migration
**File**: `shared/database/migrations/di_010_attack_ontology.sql`

```sql
BEGIN;

-- ── 1. New table: resource_ontology_catalog ────────────────────────────────────
-- DB-driven ontology rules (same pattern as resource_relationship_catalog).
-- condition_* columns make classification logic data-driven (no hardcoded Python).
CREATE TABLE IF NOT EXISTS resource_ontology_catalog (
    id                     BIGSERIAL PRIMARY KEY,
    csp                    VARCHAR(64)  NOT NULL,
    resource_type          VARCHAR(255) NOT NULL,
    entry_point_category   VARCHAR(64),
    attack_target_category VARCHAR(64),
    is_conditional         BOOLEAN      NOT NULL DEFAULT FALSE,
    condition_field        VARCHAR(255),   -- emitted_fields key to check
    condition_value        VARCHAR(255),   -- expected value
    condition_operator     VARCHAR(32)  DEFAULT 'eq',  -- eq | not_null | contains | ne
    description            TEXT,
    is_active              BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at             TIMESTAMPTZ  DEFAULT NOW(),
    updated_at             TIMESTAMPTZ  DEFAULT NOW(),
    UNIQUE (csp, resource_type, COALESCE(entry_point_category,''), COALESCE(attack_target_category,''))
);

CREATE INDEX IF NOT EXISTS idx_roc_csp_type
  ON resource_ontology_catalog (csp, resource_type) WHERE is_active = TRUE;

-- ── 2. asset_relationships: promote JSONB fields to real columns ───────────────
ALTER TABLE asset_relationships
  ADD COLUMN IF NOT EXISTS relationship_category VARCHAR(64),
  ADD COLUMN IF NOT EXISTS attack_path_category  VARCHAR(64),
  ADD COLUMN IF NOT EXISTS evidence_field_path   TEXT,
  ADD COLUMN IF NOT EXISTS evidence_value        TEXT,
  ADD COLUMN IF NOT EXISTS resolution_status     VARCHAR(32) DEFAULT 'unresolved',
  ADD COLUMN IF NOT EXISTS confidence            VARCHAR(20) DEFAULT 'medium';

CREATE INDEX IF NOT EXISTS idx_ar_resolution_status
  ON asset_relationships (tenant_id, resolution_status);
CREATE INDEX IF NOT EXISTS idx_ar_attack_path_category
  ON asset_relationships (tenant_id, attack_path_category);

-- Backfill existing rows from relation_metadata JSONB
UPDATE asset_relationships
SET
  attack_path_category = relation_metadata->>'attack_path_category',
  resolution_status    = 'resolved'
WHERE relation_metadata IS NOT NULL
  AND relation_metadata->>'attack_path_category' IS NOT NULL;

-- ── 3. resource_security_posture: rename columns + add new ────────────────────

-- is_internet_exposed → is_attack_entry_point
ALTER TABLE resource_security_posture
  ADD COLUMN IF NOT EXISTS is_attack_entry_point       BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS attack_entry_point_category VARCHAR(64);

UPDATE resource_security_posture
  SET is_attack_entry_point = TRUE
  WHERE is_internet_exposed = TRUE;

UPDATE resource_security_posture
  SET attack_entry_point_category = 'INTERNET_ENTRY'
  WHERE is_internet_exposed = TRUE;

-- is_crown_jewel → is_attack_target
ALTER TABLE resource_security_posture
  ADD COLUMN IF NOT EXISTS is_attack_target           BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE resource_security_posture
  SET is_attack_target = TRUE
  WHERE is_crown_jewel = TRUE;

-- crown_jewel_type → attack_target_category
ALTER TABLE resource_security_posture
  ADD COLUMN IF NOT EXISTS attack_target_category     VARCHAR(64);

UPDATE resource_security_posture
  SET attack_target_category = crown_jewel_type
  WHERE crown_jewel_type IS NOT NULL;

-- Old columns kept as deprecated read aliases (dropped in ONTO-1-G next sprint)

-- Indexes on new columns
CREATE INDEX IF NOT EXISTS idx_rsp_is_attack_entry_point
  ON resource_security_posture (tenant_id, is_attack_entry_point)
  WHERE is_attack_entry_point = TRUE;
CREATE INDEX IF NOT EXISTS idx_rsp_entry_point_category
  ON resource_security_posture (tenant_id, attack_entry_point_category)
  WHERE attack_entry_point_category IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rsp_is_attack_target
  ON resource_security_posture (tenant_id, is_attack_target)
  WHERE is_attack_target = TRUE;
CREATE INDEX IF NOT EXISTS idx_rsp_attack_target_category
  ON resource_security_posture (tenant_id, attack_target_category)
  WHERE attack_target_category IS NOT NULL;

-- ── 4. resource_relationship_catalog: add resolver columns ────────────────────
ALTER TABLE resource_relationship_catalog
  ADD COLUMN IF NOT EXISTS source_identifier_field VARCHAR(255),
  ADD COLUMN IF NOT EXISTS target_value_transform  VARCHAR(255) DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS resolution_required     BOOLEAN DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS confidence              VARCHAR(20) DEFAULT 'high';

COMMIT;
```

**ACs**:
- [ ] `resource_ontology_catalog` table created with UNIQUE constraint
- [ ] `is_attack_entry_point` backfilled from `is_internet_exposed` for all existing rows
- [ ] `is_attack_target` backfilled from `is_crown_jewel`
- [ ] `attack_target_category` backfilled from `crown_jewel_type`
- [ ] `attack_entry_point_category='INTERNET_ENTRY'` set for all rows where `is_internet_exposed=TRUE`
- [ ] All indexes created
- [ ] No existing query breaks

---

### ONTO-1-B: Ontology YAML Seed + Upload Script

**Files**:
- `catalog/ontology/resource_ontology.yaml` — comprehensive seed data
- `catalog/ontology/upload_ontology_catalog.py` — upserts YAML → DB

The YAML covers **both naming conventions** (underscore from step6 scanner + dot-notation from Resource Explorer) and all 6 CSPs.

**YAML (comprehensive)**:
```yaml
# catalog/ontology/resource_ontology.yaml
# Seed for resource_ontology_catalog DB table.
# condition_operator: eq | not_null | contains | ne
# A resource_type may appear multiple times (once per category axis).

resources:

  # ══════════════════════════════════════════════════════
  # AWS — underscore types (step6 scanner, has emitted_fields)
  # ══════════════════════════════════════════════════════

  # ── Internet Entry Points ─────────────────────────────
  - csp: aws
    resource_type: apigatewayv2_api
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: API Gateway v2 HTTP/WebSocket API

  - csp: aws
    resource_type: apigateway_rest_api
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: API Gateway v1 REST API

  - csp: aws
    resource_type: cloudfront_distribution
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: CloudFront CDN distribution

  - csp: aws
    resource_type: elbv2_load_balancer
    entry_point_category: INTERNET_ENTRY
    is_conditional: true
    condition_field: Scheme
    condition_value: internet-facing
    condition_operator: eq
    description: ALB/NLB with internet-facing scheme

  # ── Workload Entry ────────────────────────────────────
  - csp: aws
    resource_type: ec2_instance
    entry_point_category: WORKLOAD_ENTRY
    is_conditional: true
    condition_field: PublicIpAddress
    condition_operator: not_null
    description: EC2 instance with public IP

  - csp: aws
    resource_type: lambda_function
    entry_point_category: WORKLOAD_ENTRY
    is_conditional: false
    description: Lambda function

  - csp: aws
    resource_type: ecs_cluster
    entry_point_category: WORKLOAD_ENTRY
    is_conditional: false
    description: ECS cluster

  # ── Management Entry ──────────────────────────────────
  - csp: aws
    resource_type: ssm_managed_instance
    entry_point_category: MANAGEMENT_ENTRY
    is_conditional: false
    description: SSM managed instance (management-plane access)

  - csp: aws
    resource_type: eks_cluster
    entry_point_category: MANAGEMENT_ENTRY
    is_conditional: false
    description: EKS cluster control plane

  # ── Identity Entry ────────────────────────────────────
  - csp: aws
    resource_type: iam_user
    entry_point_category: IDENTITY_ENTRY
    is_conditional: false
    description: IAM user (credential compromise path)

  - csp: aws
    resource_type: iam_role
    entry_point_category: IDENTITY_ENTRY
    is_conditional: false
    description: IAM role (assume-role path)

  - csp: aws
    resource_type: iam_open_id_connect_provider
    entry_point_category: THIRD_PARTY_ENTRY
    is_conditional: false
    description: OIDC provider (GitHub Actions, CI/CD federation)

  # ── Data Entry ────────────────────────────────────────
  - csp: aws
    resource_type: s3_bucket
    entry_point_category: DATA_ENTRY
    is_conditional: true
    condition_field: PublicAccessBlockConfiguration.BlockPublicAcls
    condition_value: "False"
    condition_operator: eq
    description: S3 bucket with public access not blocked

  # ── Attack Targets: Data ──────────────────────────────
  - csp: aws
    resource_type: s3_bucket
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: S3 bucket

  - csp: aws
    resource_type: rds_db_instance
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: RDS database instance

  - csp: aws
    resource_type: efs_file_system
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: EFS file system

  - csp: aws
    resource_type: backup_backup_vault
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: AWS Backup vault

  - csp: aws
    resource_type: glacier_vault
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: S3 Glacier vault

  # ── Attack Targets: Secret ────────────────────────────
  - csp: aws
    resource_type: secretsmanager_secret
    attack_target_category: SECRET_TARGET
    is_conditional: false
    description: Secrets Manager secret

  - csp: aws
    resource_type: ssm_document
    attack_target_category: SECRET_TARGET
    is_conditional: false
    description: SSM document (may contain sensitive automation)

  - csp: aws
    resource_type: ssm_patch_baseline
    attack_target_category: SECRET_TARGET
    is_conditional: false
    description: SSM patch baseline

  # ── Attack Targets: Crypto ────────────────────────────
  - csp: aws
    resource_type: kms_key
    attack_target_category: CRYPTO_TARGET
    is_conditional: false
    description: KMS customer managed key

  - csp: aws
    resource_type: kms_alias
    attack_target_category: CRYPTO_TARGET
    is_conditional: false
    description: KMS alias pointing to a key

  - csp: aws
    resource_type: acm_certificate
    attack_target_category: CRYPTO_TARGET
    is_conditional: false
    description: ACM TLS certificate

  # ── Attack Targets: Identity ──────────────────────────
  - csp: aws
    resource_type: iam_role
    attack_target_category: IDENTITY_TARGET
    is_conditional: true
    condition_field: RoleName
    condition_value: Admin
    condition_operator: contains
    description: IAM admin role

  - csp: aws
    resource_type: iam_user
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: IAM user (account takeover target)

  - csp: aws
    resource_type: cognito_user_pool
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: Cognito user pool (identity store)

  - csp: aws
    resource_type: iam_instance_profile
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: IAM instance profile (role escalation via EC2)

  # ── Attack Targets: Control Plane ─────────────────────
  - csp: aws
    resource_type: eks_cluster
    attack_target_category: CONTROL_PLANE_TARGET
    is_conditional: false
    description: EKS cluster control plane

  - csp: aws
    resource_type: ecs_cluster
    attack_target_category: CONTROL_PLANE_TARGET
    is_conditional: false
    description: ECS cluster

  - csp: aws
    resource_type: organizations_account
    attack_target_category: CONTROL_PLANE_TARGET
    is_conditional: false
    description: AWS Organizations account

  # ── Attack Targets: Workload ──────────────────────────
  - csp: aws
    resource_type: ec2_instance
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: EC2 compute instance

  - csp: aws
    resource_type: lambda_function
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: Lambda function

  - csp: aws
    resource_type: eks_nodegroup
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: EKS node group

  # ══════════════════════════════════════════════════════
  # AWS — dot-notation types (Resource Explorer discovery)
  # Same categories, different resource_type string in asset_inventory
  # ══════════════════════════════════════════════════════
  - csp: aws
    resource_type: "ec2.instance"
    entry_point_category: WORKLOAD_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: EC2 instance (Resource Explorer type)

  - csp: aws
    resource_type: "iam.role"
    entry_point_category: IDENTITY_ENTRY
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: IAM role (Resource Explorer type)

  - csp: aws
    resource_type: "iam.user"
    entry_point_category: IDENTITY_ENTRY
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: IAM user (Resource Explorer type)

  - csp: aws
    resource_type: "kms.key"
    attack_target_category: CRYPTO_TARGET
    is_conditional: false
    description: KMS key (Resource Explorer type)

  - csp: aws
    resource_type: "kms.alias"
    attack_target_category: CRYPTO_TARGET
    is_conditional: false
    description: KMS alias (Resource Explorer type)

  - csp: aws
    resource_type: "s3.bucket"
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: S3 bucket (Resource Explorer type)

  - csp: aws
    resource_type: "lambda.function"
    entry_point_category: WORKLOAD_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: Lambda function (Resource Explorer type)

  - csp: aws
    resource_type: "secretsmanager.secret"
    attack_target_category: SECRET_TARGET
    is_conditional: false
    description: Secrets Manager secret (Resource Explorer type)

  - csp: aws
    resource_type: "eks.cluster"
    entry_point_category: MANAGEMENT_ENTRY
    attack_target_category: CONTROL_PLANE_TARGET
    is_conditional: false
    description: EKS cluster (Resource Explorer type)

  - csp: aws
    resource_type: "ecs.cluster"
    attack_target_category: CONTROL_PLANE_TARGET
    is_conditional: false
    description: ECS cluster (Resource Explorer type)

  - csp: aws
    resource_type: "dynamodb.table"
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: DynamoDB table (Resource Explorer type)

  - csp: aws
    resource_type: "rds.db-instance"
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: RDS instance (Resource Explorer type)

  - csp: aws
    resource_type: "elasticfilesystem.file-system"
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: EFS file system (Resource Explorer type)

  - csp: aws
    resource_type: "acm.certificate"
    attack_target_category: CRYPTO_TARGET
    is_conditional: false
    description: ACM certificate (Resource Explorer type)

  - csp: aws
    resource_type: "elbv2.load-balancer"
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: ELBv2 load balancer (Resource Explorer type — no Scheme field, classify all)

  - csp: aws
    resource_type: "apigateway.rest-api"
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: API Gateway REST API (Resource Explorer type)

  - csp: aws
    resource_type: "apigatewayv2.api"
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: API Gateway v2 (Resource Explorer type)

  - csp: aws
    resource_type: "cloudfront.distribution"
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: CloudFront (Resource Explorer type)

  - csp: aws
    resource_type: "cognito-idp.user-pool"
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: Cognito user pool (Resource Explorer type)

  - csp: aws
    resource_type: "backup.backup-vault"
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: Backup vault (Resource Explorer type)

  - csp: aws
    resource_type: "ssm.managed-instance"
    entry_point_category: MANAGEMENT_ENTRY
    is_conditional: false
    description: SSM managed instance (Resource Explorer type)

  # ══════════════════════════════════════════════════════
  # Azure
  # ══════════════════════════════════════════════════════
  - csp: azure
    resource_type: network.load_balancer
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: Azure Load Balancer

  - csp: azure
    resource_type: network.application_gateway
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: Azure Application Gateway

  - csp: azure
    resource_type: cdn.profile
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: Azure CDN / Front Door

  - csp: azure
    resource_type: compute.virtual_machine
    entry_point_category: WORKLOAD_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: Azure VM

  - csp: azure
    resource_type: containerservice.managed_cluster
    entry_point_category: MANAGEMENT_ENTRY
    attack_target_category: CONTROL_PLANE_TARGET
    is_conditional: false
    description: Azure AKS cluster

  - csp: azure
    resource_type: storage.storage_account
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: Azure Storage Account

  - csp: azure
    resource_type: StorageAccount
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: Azure Storage Account (Resource Explorer type)

  - csp: azure
    resource_type: sql.database
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: Azure SQL Database

  - csp: azure
    resource_type: sql.server
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: Azure SQL Server

  - csp: azure
    resource_type: keyvault.vault
    attack_target_category: SECRET_TARGET
    is_conditional: false
    description: Azure Key Vault (secrets + keys)

  - csp: azure
    resource_type: KeyVault
    attack_target_category: SECRET_TARGET
    is_conditional: false
    description: Azure Key Vault (Resource Explorer type)

  - csp: azure
    resource_type: authorization.role_assignment
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: Azure RBAC role assignment

  - csp: azure
    resource_type: web.site
    entry_point_category: INTERNET_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: Azure App Service

  - csp: azure
    resource_type: logic.workflow
    entry_point_category: WORKLOAD_ENTRY
    is_conditional: false
    description: Azure Logic App

  # ══════════════════════════════════════════════════════
  # GCP
  # ══════════════════════════════════════════════════════
  - csp: gcp
    resource_type: compute.url_map
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: GCP HTTP(S) Load Balancer URL map

  - csp: gcp
    resource_type: compute.forwardingRule
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: GCP forwarding rule (internet-facing LB)

  - csp: gcp
    resource_type: compute.instance
    entry_point_category: WORKLOAD_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: GCP Compute instance

  - csp: gcp
    resource_type: run.service
    entry_point_category: INTERNET_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: GCP Cloud Run service

  - csp: gcp
    resource_type: cloudfunctions.function
    entry_point_category: WORKLOAD_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: GCP Cloud Function

  - csp: gcp
    resource_type: container.cluster
    entry_point_category: MANAGEMENT_ENTRY
    attack_target_category: CONTROL_PLANE_TARGET
    is_conditional: false
    description: GCP GKE cluster

  - csp: gcp
    resource_type: storage.bucket
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: GCP Cloud Storage bucket

  - csp: gcp
    resource_type: storage_buckets.list
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: GCP Cloud Storage bucket (list type)

  - csp: gcp
    resource_type: sqladmin.instance
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: GCP Cloud SQL instance

  - csp: gcp
    resource_type: cloudkms.crypto_key
    attack_target_category: CRYPTO_TARGET
    is_conditional: false
    description: GCP Cloud KMS crypto key

  - csp: gcp
    resource_type: "secretmanager.googleapis.com/Secret"
    attack_target_category: SECRET_TARGET
    is_conditional: false
    description: GCP Secret Manager secret

  - csp: gcp
    resource_type: gcp.secret
    attack_target_category: SECRET_TARGET
    is_conditional: false
    description: GCP Secret Manager secret (alternate type)

  - csp: gcp
    resource_type: iam.service_account
    entry_point_category: IDENTITY_ENTRY
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: GCP service account

  - csp: gcp
    resource_type: gcp.iam_service_account
    entry_point_category: IDENTITY_ENTRY
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: GCP service account (alternate type)

  - csp: gcp
    resource_type: "iam.googleapis.com/ServiceAccount"
    entry_point_category: IDENTITY_ENTRY
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: GCP service account (googleapis type)

  - csp: gcp
    resource_type: "pubsub.googleapis.com/Topic"
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: GCP Pub/Sub topic

  # ══════════════════════════════════════════════════════
  # OCI
  # ══════════════════════════════════════════════════════
  - csp: oci
    resource_type: compute.instance
    entry_point_category: WORKLOAD_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: OCI Compute instance

  - csp: oci
    resource_type: "oci.core/Instance"
    entry_point_category: WORKLOAD_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: OCI Compute instance (alternate type)

  - csp: oci
    resource_type: "compute.oci.core/Instance"
    entry_point_category: WORKLOAD_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: OCI Compute instance (alternate type 2)

  - csp: oci
    resource_type: database.autonomous_database
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: OCI Autonomous Database

  - csp: oci
    resource_type: containerengine.cluster
    entry_point_category: MANAGEMENT_ENTRY
    attack_target_category: CONTROL_PLANE_TARGET
    is_conditional: false
    description: OCI OKE cluster

  - csp: oci
    resource_type: key_management.vault
    attack_target_category: CRYPTO_TARGET
    is_conditional: false
    description: OCI Vault (KMS)

  - csp: oci
    resource_type: "oci.key_management/Vault"
    attack_target_category: CRYPTO_TARGET
    is_conditional: false
    description: OCI Vault (alternate type)

  - csp: oci
    resource_type: loadbalancer.load_balancer
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: OCI Load Balancer

  # ══════════════════════════════════════════════════════
  # AliCloud
  # ══════════════════════════════════════════════════════
  - csp: alicloud
    resource_type: ecs.instance
    entry_point_category: WORKLOAD_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: AliCloud ECS instance

  - csp: alicloud
    resource_type: rds.db_instance
    attack_target_category: DATA_TARGET
    is_conditional: false
    description: AliCloud RDS instance

  - csp: alicloud
    resource_type: slb.load_balancer
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: AliCloud SLB

  - csp: alicloud
    resource_type: cs.cluster
    entry_point_category: MANAGEMENT_ENTRY
    attack_target_category: CONTROL_PLANE_TARGET
    is_conditional: false
    description: AliCloud Container Service cluster

  - csp: alicloud
    resource_type: ram_ListRole
    entry_point_category: IDENTITY_ENTRY
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: AliCloud RAM role

  - csp: alicloud
    resource_type: ram_ListUser
    entry_point_category: IDENTITY_ENTRY
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: AliCloud RAM user

  # ══════════════════════════════════════════════════════
  # IBM
  # ══════════════════════════════════════════════════════
  - csp: ibm
    resource_type: is.instance
    entry_point_category: WORKLOAD_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: IBM VPC Virtual Server Instance

  - csp: ibm
    resource_type: is.load_balancer
    entry_point_category: INTERNET_ENTRY
    is_conditional: false
    description: IBM VPC Load Balancer

  - csp: ibm
    resource_type: containers.kubernetes
    entry_point_category: MANAGEMENT_ENTRY
    attack_target_category: CONTROL_PLANE_TARGET
    is_conditional: false
    description: IBM Kubernetes Service cluster

  - csp: ibm
    resource_type: codeengine.app
    entry_point_category: INTERNET_ENTRY
    attack_target_category: WORKLOAD_TARGET
    is_conditional: false
    description: IBM Code Engine app

  - csp: ibm
    resource_type: iam.service_id
    entry_point_category: IDENTITY_ENTRY
    attack_target_category: IDENTITY_TARGET
    is_conditional: false
    description: IBM IAM service ID
```

**Upload script** (`catalog/ontology/upload_ontology_catalog.py`):
```python
"""
Upload resource_ontology.yaml to resource_ontology_catalog table in threat_engine_di.
Usage: kubectl exec -n threat-engine-engines deployment/engine-di -- python3 -c "..."
"""
import os, yaml, psycopg2, psycopg2.extras
from pathlib import Path

YAML_PATH = Path(__file__).parent / "resource_ontology.yaml"

UPSERT_SQL = """
INSERT INTO resource_ontology_catalog
  (csp, resource_type, entry_point_category, attack_target_category,
   is_conditional, condition_field, condition_value, condition_operator,
   description, is_active, updated_at)
VALUES
  (%(csp)s, %(resource_type)s, %(entry_point_category)s, %(attack_target_category)s,
   %(is_conditional)s, %(condition_field)s, %(condition_value)s, %(condition_operator)s,
   %(description)s, TRUE, NOW())
ON CONFLICT (csp, resource_type,
             COALESCE(entry_point_category,''), COALESCE(attack_target_category,''))
DO UPDATE SET
  is_conditional         = EXCLUDED.is_conditional,
  condition_field        = EXCLUDED.condition_field,
  condition_value        = EXCLUDED.condition_value,
  condition_operator     = EXCLUDED.condition_operator,
  description            = EXCLUDED.description,
  is_active              = TRUE,
  updated_at             = NOW()
"""

def _conn():
    return psycopg2.connect(
        host=os.environ['DI_DB_HOST'], dbname=os.environ['DI_DB_NAME'],
        user=os.environ['DI_DB_USER'], password=os.environ['DI_DB_PASSWORD'],
        port=int(os.environ.get('DI_DB_PORT', 5432))
    )

catalog = yaml.safe_load(YAML_PATH.read_text())
rows = []
for r in catalog.get('resources', []):
    rows.append({
        'csp': r['csp'],
        'resource_type': r['resource_type'],
        'entry_point_category': r.get('entry_point_category'),
        'attack_target_category': r.get('attack_target_category'),
        'is_conditional': r.get('is_conditional', False),
        'condition_field': r.get('condition_field'),
        'condition_value': r.get('condition_value'),
        'condition_operator': r.get('condition_operator', 'eq'),
        'description': r.get('description'),
    })

conn = _conn()
with conn.cursor() as cur:
    psycopg2.extras.execute_batch(cur, UPSERT_SQL, rows, page_size=100)
conn.commit()
conn.close()
print(f"Uploaded {len(rows)} ontology rules")
```

**ACs**:
- [ ] YAML validates cleanly
- [ ] Upload script upserts all rows without error
- [ ] `SELECT COUNT(*) FROM resource_ontology_catalog` shows ≥ 80 rows after upload
- [ ] Both naming conventions covered for AWS (underscore + dot-notation)
- [ ] All 6 CSPs present
- [ ] Every row has at least one of `entry_point_category` or `attack_target_category`

---

### ONTO-1-C: DI Engine Phase 3 — Ontology Writer (DB-driven)
**File**: `engines/di/di_engine/phase3/ontology_writer.py`

Reads `resource_ontology_catalog` from DB. Applies condition checks against `asset_inventory.emitted_fields`.
Writes `is_attack_entry_point`, `attack_entry_point_category`, `is_attack_target`, `attack_target_category`
to `resource_security_posture`.

**Logic**:
```python
# 1. Load all active rules for this CSP from DB (one query)
rules_by_type: dict[str, list[Rule]] = load_ontology_rules(conn, csp)

# 2. Page through asset_inventory for this scan
for resource_uid, resource_type, emitted_fields in fetch_assets(conn, ...):
    rules = rules_by_type.get(resource_type, [])
    for rule in rules:
        if not _condition_passes(rule, emitted_fields):
            continue
        if rule.entry_point_category:
            upsert_posture(resource_uid, is_attack_entry_point=True,
                           attack_entry_point_category=rule.entry_point_category)
        if rule.attack_target_category:
            upsert_posture(resource_uid, is_attack_target=True,
                           attack_target_category=rule.attack_target_category)

# 3. _condition_passes(rule, emitted_fields):
#    is_conditional=false → always True
#    operator='not_null'  → emitted_fields.get(field) is not None
#    operator='eq'        → str(emitted_fields.get(field)) == value
#    operator='ne'        → str(emitted_fields.get(field)) != value
#    operator='contains'  → value in str(emitted_fields.get(field, ''))
```

**Upsert**: Uses `ON CONFLICT (tenant_id, scan_run_id, resource_uid) DO UPDATE` — COALESCE so
network engine enrichment in a later phase is not overwritten.

**ACs**:
- [ ] Non-fatal — exception logs and returns (0, 0) tuple (entry_point_count, target_count)
- [ ] Reads from `resource_ontology_catalog` — no YAML file access at runtime
- [ ] `is_conditional=false`: 100% of matching resource_type rows get classified
- [ ] `is_attack_target=true` always set alongside `attack_target_category`
- [ ] `is_attack_entry_point=true` always set alongside `attack_entry_point_category`
- [ ] No writes to `is_crown_jewel`, `crown_jewel_type`, `is_internet_exposed`
- [ ] Called from `engines/di/run_scan.py` after Phase 2
- [ ] Logs: `ontology_writer: N entry_points, M targets for csp=X scan=Y`

---

### ONTO-1-D: catalog_relationship_writer.py — Enrich Edge Columns
**File**: `engines/di/di_engine/phase2/catalog_relationship_writer.py`

Add `_resolution_status()` helper and populate 6 new columns on every edge dict:

```python
def _resolution_status(tgt_uid: str, raw_ident: str) -> str:
    if tgt_uid == raw_ident:          return "target_not_found"
    if tgt_uid.startswith("pseudo:"): return "pseudo_target"
    return "resolved"
```

Edge dict additions:
```python
"relationship_category": rule.get("relationship_category", "infrastructure"),
"attack_path_category":  category,
"evidence_field_path":   field_path,
"evidence_value":        ident,
"resolution_status":     _resolution_status(tgt_uid, ident),
"confidence":            rule.get("confidence") or "high",
```

Also update `upsert_asset_relationships()` in `shared/common/relationship_writer.py`
to include these 6 columns in INSERT and ON CONFLICT DO UPDATE.

**ACs**:
- [ ] All new edges have non-NULL `resolution_status`
- [ ] `evidence_value` = raw extracted identifier before UID resolution
- [ ] `attack_path_category` matches `relation_metadata->>'attack_path_category'`
- [ ] `confidence='high'` for all catalog-driven edges (default)

---

### ONTO-1-E: Relationship Quality Report
**Endpoint**: `GET /api/v1/views/relationship-quality`

SQL:
```sql
SELECT
  COUNT(*)                                                       AS total,
  COUNT(*) FILTER (WHERE resolution_status='resolved')           AS resolved,
  COUNT(*) FILTER (WHERE resolution_status='pseudo_target')      AS pseudo_target,
  COUNT(*) FILTER (WHERE resolution_status='target_not_found')   AS target_not_found,
  COUNT(*) FILTER (WHERE resolution_status='unresolved')         AS unresolved,
  COUNT(*) FILTER (WHERE source_type IS NULL)                    AS blank_source_type,
  COUNT(*) FILTER (WHERE target_type IS NULL)                    AS blank_target_type,
  ROUND(100.0 * COUNT(*) FILTER (WHERE resolution_status='resolved') / NULLIF(COUNT(*),0), 1)
                                                                 AS coverage_pct
FROM asset_relationships
WHERE tenant_id = %s AND scan_run_id = %s
```

Also fix: blank `source_type` / `target_type` for AliCloud BELONGS_TO edges
by back-filling from `asset_inventory.resource_type` via a one-time UPDATE.

---

### ONTO-1-F: Network Engine — Entry Point Category
**File**: `engines/network-security/network_security_engine/phase_l0/exposure_evaluator.py`

When writing posture for an IEDS-detected resource:
```python
posture_fields = {
    "is_attack_entry_point":       True,
    "attack_entry_point_category": "INTERNET_ENTRY",
    "is_internet_exposed":         True,   # deprecated alias — kept for backward compat
}
```

No new writes to `is_crown_jewel`, `crown_jewel_type`.

---

### ONTO-1-G: Drop Deprecated Columns (next sprint — deferred)
```sql
ALTER TABLE resource_security_posture
  DROP COLUMN is_internet_exposed,
  DROP COLUMN is_crown_jewel,
  DROP COLUMN crown_jewel_type;
```
Gate: BFF views + frontend updated to use new column names first.

---

## Deploy Order

1. **ONTO-1-A** — migration (prerequisite)
2. **ONTO-1-B** — create YAML + upload script, run upload against DB
3. **ONTO-1-D** — `engine-di:v-di-rel3` (already built) — push + deploy
4. **ONTO-1-C** — `engine-di:v-di-rel4`
5. **ONTO-1-E** — gateway rebuild
6. **ONTO-1-F** — network-security rebuild

## Definition of Done
- [ ] Migration applied in production; new columns visible in all 3 tables
- [ ] `resource_ontology_catalog` has ≥ 80 rows covering all 6 CSPs
- [ ] After DI scan: `is_attack_entry_point` and `is_attack_target` populated in `resource_security_posture`
- [ ] `is_attack_target=true` aligned with `attack_target_category IS NOT NULL` (0 divergence)
- [ ] `asset_relationships.resolution_status='resolved'` for ≥ 80% of edges
- [ ] Quality report endpoint returns JSON for latest scan
- [ ] Network engine writes `attack_entry_point_category='INTERNET_ENTRY'`
- [ ] Zero new code writes `is_crown_jewel`, `crown_jewel_type`, or `is_internet_exposed`
- [ ] Image tags updated: `engine-di:v-di-rel4`, `engine-network-security` new tag