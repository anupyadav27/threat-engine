# Secrets & Credentials Management

> **CRITICAL:** This file documents secret **locations and structure**, NOT the actual secret values
> **Last Updated:** 2026-02-20
> **Security Level:** Internal Documentation

---

## Overview

All sensitive credentials are stored in **AWS Secrets Manager** with KMS encryption. This document maps where each credential is stored and how to access it.

---

## Database Credentials

### RDS PostgreSQL

**Master Credentials:**
- **Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com`
- **Port:** `5432`
- **Username:** `postgres`
- **Password:** Stored in AWS Secrets Manager
- **SSL Mode:** `require`

**Secret Path in AWS Secrets Manager:**
```
threat-engine/prod/rds/postgres-master-password
```

**Retrieve via AWS CLI:**
```bash
aws secretsmanager get-secret-value \
  --region ap-south-1 \
  --secret-id threat-engine/prod/rds/postgres-master-password \
  --query SecretString \
  --output text
```

**Database List:**
| Database Name | Purpose | Used By |
|---------------|---------|---------|
| `postgres` | Default admin database | DBA operations |
| `threat_engine_discoveries` | Discovery scan results | engine-discoveries |
| `threat_engine_check` | Compliance check findings | engine-check |
| `threat_engine_inventory` | Asset inventory | engine-inventory |
| `threat_engine_threat` | Threat detections | engine-threat |
| `threat_engine_compliance` | Compliance reports | engine-compliance |
| `threat_engine_iam` | IAM security findings | engine-iam |
| `threat_engine_datasec` | Data security findings | engine-datasec |
| `threat_engine_shared` | Onboarding, orchestration | engine-onboarding |
| `threat_engine_pythonsdk` | Legacy SDK data | (deprecated) |

**Local pgAdmin Connection:**
```
Host: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
Port: 5432
Maintenance Database: postgres
Username: postgres
Password: <from Secrets Manager: threat-engine/prod/rds/postgres-master-password>
SSL Mode: Require
```

---

## Graph Database Credentials

### Neo4j

**Connection Details:**
- **Protocol:** Bolt (`neo4j://...`)
- **Host:** (Check deployment - typically internal K8s service or managed instance)
- **Port:** 7687 (Bolt), 7474 (HTTP)
- **Username:** `neo4j`
- **Password:** Stored in AWS Secrets Manager

**Secret Path:**
```
threat-engine/prod/neo4j/password
```

**Retrieve via AWS CLI:**
```bash
aws secretsmanager get-secret-value \
  --region ap-south-1 \
  --secret-id threat-engine/prod/neo4j/password \
  --query SecretString \
  --output text
```

**Usage:**
- Threat engine writes attack graphs
- Query attack paths using Cypher

---

## Cloud Provider Credentials

The threat-engine supports 6 cloud providers. Credentials are stored per provider in Secrets Manager.

### AWS Credentials

**Authentication Methods:**
1. **IAM Role (Recommended for AWS accounts)**
2. **Access Key/Secret Key (for external AWS accounts)**

**Secret Paths:**
```
# Cross-account role ARN (preferred)
threat-engine/prod/aws/cross-account-role-arn

# Access keys (if role not possible)
threat-engine/prod/aws/<account-id>/access-key-id
threat-engine/prod/aws/<account-id>/secret-access-key
```

**Structure:**
```json
{
  "role_arn": "arn:aws:iam::123456789012:role/ThreatEngineScanRole",
  "external_id": "unique-external-id-12345"
}
```

**Local CLI Configuration:**
```bash
# Check current AWS credentials
aws sts get-caller-identity

# Configure profile
aws configure --profile threat-engine
```

### Azure Credentials

**Authentication Method:** Service Principal

**Required Information:**
- Tenant ID
- Client ID (Application ID)
- Client Secret

**Secret Paths:**
```
threat-engine/prod/azure/<subscription-id>/tenant-id
threat-engine/prod/azure/<subscription-id>/client-id
threat-engine/prod/azure/<subscription-id>/client-secret
```

**Structure:**
```json
{
  "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "subscription_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

**Local CLI Configuration:**
```bash
# Check current Azure login
az account show

# Login with service principal
az login --service-principal \
  --username <client-id> \
  --password <client-secret> \
  --tenant <tenant-id>
```

### GCP Credentials

**Authentication Method:** Service Account Key (JSON)

**Required Information:**
- Service Account Email
- Private Key (JSON key file)
- Project ID

**Secret Path:**
```
threat-engine/prod/gcp/<project-id>/service-account-key
```

**Structure (entire JSON key):**
```json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "client_email": "threat-engine@your-project.iam.gserviceaccount.com",
  "client_id": "...",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "..."
}
```

**Local CLI Configuration:**
```bash
# Check current GCP project
gcloud config get-value project

# Authenticate with service account
gcloud auth activate-service-account \
  --key-file=<path-to-key.json>

# Set project
gcloud config set project <project-id>
```

### OCI (Oracle Cloud Infrastructure) Credentials

**Authentication Method:** API Key (PEM file + config)

**Required Information:**
- User OCID
- Tenancy OCID
- Region
- Fingerprint
- Private Key (PEM format)

**Secret Path:**
```
threat-engine/prod/oci/<tenancy-id>/api-key
```

**Structure:**
```json
{
  "user_ocid": "ocid1.user.oc1..",
  "tenancy_ocid": "ocid1.tenancy.oc1..",
  "region": "us-ashburn-1",
  "fingerprint": "xx:xx:xx:...",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
}
```

**Local CLI Configuration:**
```bash
# Check OCI config
cat ~/.oci/config

# Configure OCI CLI
oci setup config
```

### AliCloud Credentials

**Authentication Method:** Access Key/Secret Key

**Required Information:**
- Access Key ID
- Access Key Secret
- Region

**Secret Path:**
```
threat-engine/prod/alicloud/<account-id>/credentials
```

**Structure:**
```json
{
  "access_key_id": "LTAI...",
  "access_key_secret": "...",
  "region_id": "cn-hangzhou"
}
```

**Local CLI Configuration:**
```bash
# Configure Aliyun CLI
aliyun configure

# Verify
aliyun sts GetCallerIdentity
```

### IBM Cloud Credentials

**Authentication Method:** API Key

**Required Information:**
- API Key
- Account ID
- Region

**Secret Path:**
```
threat-engine/prod/ibm/<account-id>/api-key
```

**Structure:**
```json
{
  "api_key": "...",
  "account_id": "...",
  "region": "us-south"
}
```

**Local CLI Configuration:**
```bash
# Login with API key
ibmcloud login --apikey <api-key>

# Set target account
ibmcloud target -c <account-id> -r <region>
```

---

## Kubernetes Secrets

### How Secrets Flow

```
AWS Secrets Manager (source of truth)
  ↓ (External Secrets Operator syncs)
Kubernetes Secret (namespace: threat-engine-engines)
  ↓ (mounted as env vars or files)
Pod containers
```

### Kubernetes Secret: threat-engine-db-passwords

**Namespace:** `threat-engine-engines`

**Keys:**
```
discoveries-db-password
check-db-password
inventory-db-password
threat-db-password
compliance-db-password
iam-db-password
datasec-db-password
shared-db-password
```

**View secret (base64 encoded):**
```bash
kubectl get secret threat-engine-db-passwords \
  -n threat-engine-engines \
  -o yaml
```

**Decode a key:**
```bash
kubectl get secret threat-engine-db-passwords \
  -n threat-engine-engines \
  -o jsonpath='{.data.discoveries-db-password}' | base64 -d
```

### Kubernetes Secret: threat-engine-cloud-credentials

**Namespace:** `threat-engine-engines`

**Keys:**
```
aws-role-arn
azure-client-secret
gcp-service-account-key
oci-private-key
alicloud-access-key-secret
ibm-api-key
```

---

## External Secrets Operator Configuration

### External Secret Resource

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: threat-engine-db-passwords
  namespace: threat-engine-engines
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: threat-engine-db-passwords
    creationPolicy: Owner
  data:
  - secretKey: discoveries-db-password
    remoteRef:
      key: threat-engine/prod/rds/postgres-master-password
  - secretKey: check-db-password
    remoteRef:
      key: threat-engine/prod/rds/postgres-master-password
  # ... (all engines use same RDS password)
```

### SecretStore Resource

```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  namespace: threat-engine-engines
spec:
  provider:
    aws:
      service: SecretsManager
      region: ap-south-1
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa
```

---

## Secret Rotation Policy

### Database Passwords

- **Frequency:** 90 days
- **Method:** AWS Secrets Manager automatic rotation
- **Lambda Function:** `threat-engine-rds-password-rotator`
- **Process:**
  1. Create new password in RDS
  2. Update secret in Secrets Manager
  3. External Secrets Operator syncs to K8s
  4. Pods restart with new credentials (rolling update)

### Cloud Provider Credentials

- **Frequency:** Manually, or per provider policy
- **AWS:** Rotate IAM role credentials via IAM policy
- **Azure:** Service principal secret expiry (1-2 years)
- **GCP:** Rotate service account keys manually
- **OCI/AliCloud/IBM:** Rotate access keys per security policy

### Neo4j Password

- **Frequency:** 180 days (manual rotation)
- **Process:**
  1. Update password in Neo4j
  2. Update Secrets Manager
  3. Restart threat engine pods

---

## Access Control (IAM Policies)

### Who Can Access Secrets?

**EKS Node Role:**
- Can read all `threat-engine/*` secrets
- Required for External Secrets Operator

**Developers:**
- Can read secrets via AWS CLI (with MFA)
- Requires IAM group membership

**CI/CD:**
- Read-only access via dedicated IAM role
- For automated deployments

### IAM Policy Example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:ap-south-1:588989875114:secret:threat-engine/*"
    },
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:ap-south-1:588989875114:key/<kms-key-id>",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "secretsmanager.ap-south-1.amazonaws.com"
        }
      }
    }
  ]
}
```

---

## Retrieving Credentials Securely

### From Local Machine (AWS CLI)

**Prerequisites:**
- AWS CLI installed
- Credentials configured (`aws configure`)
- IAM permissions for Secrets Manager

**Retrieve secret:**
```bash
# Get secret value
aws secretsmanager get-secret-value \
  --region ap-south-1 \
  --secret-id threat-engine/prod/rds/postgres-master-password \
  --query SecretString \
  --output text

# Store in environment variable
export DB_PASSWORD=$(aws secretsmanager get-secret-value \
  --region ap-south-1 \
  --secret-id threat-engine/prod/rds/postgres-master-password \
  --query SecretString \
  --output text)
```

### From Kubernetes Pod

**Method 1: Environment Variable**
```yaml
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: threat-engine-db-passwords
        key: discoveries-db-password
```

**Method 2: Mounted File**
```yaml
volumeMounts:
  - name: secrets
    mountPath: /etc/secrets
    readOnly: true
volumes:
  - name: secrets
    secret:
      secretName: threat-engine-db-passwords
```

---

## Emergency Procedures

### Lost Database Password

1. **Reset via AWS Console:**
   - RDS → Select instance → Modify → Set new password
   - Or use AWS CLI:
     ```bash
     aws rds modify-db-instance \
       --db-instance-identifier postgres-vulnerability-db \
       --master-user-password <new-password> \
       --apply-immediately
     ```

2. **Update Secrets Manager:**
   ```bash
   aws secretsmanager update-secret \
     --secret-id threat-engine/prod/rds/postgres-master-password \
     --secret-string <new-password>
   ```

3. **Restart pods** (External Secrets Operator will sync automatically within 1 hour, or force restart)

### Compromised Cloud Credentials

1. **Immediately revoke** in cloud provider console
2. **Create new credentials**
3. **Update Secrets Manager**
4. **Restart engine-onboarding** pods
5. **Audit access logs** (CloudTrail, Azure Activity Log, etc.)

---

## Auditing & Compliance

### CloudTrail Logging

All Secrets Manager access is logged to CloudTrail:
```bash
# Query recent secret access
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=threat-engine/prod/rds/postgres-master-password \
  --region ap-south-1 \
  --max-items 50
```

### Secret Access Audit

**Who accessed which secrets?**
1. CloudTrail → Event history → Filter by `GetSecretValue`
2. Check `userIdentity` field for IAM principal
3. Review `requestParameters.secretId`

### Compliance Requirements

- **PCI-DSS:** Secrets must be encrypted, rotated every 90 days
- **HIPAA:** Access logging required, MFA for admin access
- **GDPR:** Encryption at rest and in transit, audit trail

---

## Best Practices

1. ✅ **Never commit secrets to Git** (use `.gitignore` for `.env` files)
2. ✅ **Use IAM roles** over access keys when possible
3. ✅ **Enable MFA** for AWS Secrets Manager access
4. ✅ **Rotate secrets** per policy (90 days for databases)
5. ✅ **Audit access logs** monthly
6. ✅ **Use least privilege** IAM policies
7. ✅ **Encrypt at rest** with KMS (enabled by default in Secrets Manager)
8. ✅ **Encrypt in transit** with TLS (all connections use SSL)

---

## Secret Inventory Checklist

| Secret Type | Path | Rotation | Last Rotated | Owner |
|-------------|------|----------|--------------|-------|
| RDS Master Password | `threat-engine/prod/rds/postgres-master-password` | 90 days | 2026-01-15 | DBA Team |
| Neo4j Password | `threat-engine/prod/neo4j/password` | 180 days | 2026-01-01 | Platform Team |
| AWS Cross-Account Role | `threat-engine/prod/aws/cross-account-role-arn` | N/A | N/A | Security Team |
| Azure Service Principal | `threat-engine/prod/azure/<sub-id>/client-secret` | 365 days | 2025-12-01 | Cloud Team |
| GCP Service Account | `threat-engine/prod/gcp/<project-id>/service-account-key` | Manual | 2025-11-15 | Cloud Team |
| OCI API Key | `threat-engine/prod/oci/<tenancy-id>/api-key` | Manual | 2025-10-20 | Cloud Team |
| AliCloud Access Key | `threat-engine/prod/alicloud/<account-id>/credentials` | Manual | 2025-10-10 | Cloud Team |
| IBM API Key | `threat-engine/prod/ibm/<account-id>/api-key` | Manual | 2025-10-05 | Cloud Team |

---

## Contact & Support

**For credential issues:**
- Platform Team: platform@example.com
- Security Team: security@example.com
- On-call: PagerDuty escalation

**Emergency secret rotation:**
1. Contact Security Team immediately
2. Follow emergency procedures above
3. Document incident in ticketing system
