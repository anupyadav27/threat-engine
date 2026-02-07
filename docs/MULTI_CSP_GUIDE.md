# Multi-Cloud Provider Guide

> How to onboard and scan AWS, Azure, GCP, OCI, AliCloud, IBM Cloud, and Kubernetes.

---

## Supported Providers

| Provider | Discovery | Rules | Compliance | Status |
|----------|-----------|-------|-----------|--------|
| **AWS** | 40+ services | 500+ | CIS, NIST, SOC2, PCI, HIPAA | Production |
| **Azure** | 20+ services | 200+ | CIS Azure, NIST | Beta |
| **GCP** | 15+ services | 150+ | CIS GCP | Beta |
| **OCI** | 10+ services | 80+ | CIS OCI | Beta |
| **AliCloud** | 10+ services | 100+ | CIS Alibaba | Beta |
| **IBM Cloud** | 10+ services | 80+ | CIS IBM | Beta |
| **Kubernetes** | 5+ resource types | 50+ | CIS K8s | Beta |

---

## AWS Onboarding

### Authentication Methods

| Method | Use Case | Setup |
|--------|----------|-------|
| **IAM Cross-Account Role** | Production (recommended) | CloudFormation template |
| **Access Keys** | Local development | Manual key creation |
| **IRSA (Web Identity)** | EKS pods | Service account annotation |

### Step 1: Create Cross-Account Role

```bash
# Get CloudFormation template
curl http://localhost:8010/api/v1/onboarding/aws/cloudformation-template
```

Deploy the template in the target AWS account. It creates:
- IAM role with read-only access to all services
- Trust policy allowing your platform account to assume the role

### Step 2: Onboard Account

```bash
curl -X POST http://localhost:8010/api/v1/onboarding/aws/init \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "your-tenant",
    "account_id": "123456789012",
    "auth_method": "cross_account_role",
    "role_arn": "arn:aws:iam::123456789012:role/CSPMReadOnlyRole",
    "regions": ["us-east-1", "ap-south-1"]
  }'
```

### Step 3: Validate

```bash
curl -X POST http://localhost:8010/api/v1/onboarding/aws/validate \
  -H "Content-Type: application/json" \
  -d '{"account_id": "123456789012"}'
```

### AWS Services Scanned

s3, iam, ec2, rds, lambda, dynamodb, sns, sqs, cloudfront, cloudtrail, cloudwatch, config, efs, elasticache, elasticsearch, elb, elbv2, glacier, kms, redshift, route53, secretsmanager, ses, ssm, vpc, waf, backup, codebuild, codepipeline, ecr, ecs, eks, guardduty, inspector, kinesis, macie, organizations, sagemaker, and more.

---

## Azure Onboarding

### Authentication Methods

| Method | Use Case |
|--------|----------|
| **Service Principal** | Production |
| **Managed Identity** | Azure VMs/AKS |

### Onboard

```bash
curl -X POST http://localhost:8010/api/v1/onboarding/azure/init \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "your-tenant",
    "subscription_id": "azure-sub-id",
    "auth_method": "service_principal",
    "client_id": "app-client-id",
    "client_secret": "app-secret",
    "azure_tenant_id": "azure-ad-tenant"
  }'
```

---

## GCP Onboarding

### Authentication Methods

| Method | Use Case |
|--------|----------|
| **Service Account Key** | Production |
| **Workload Identity** | GKE pods |

### Onboard

```bash
curl -X POST http://localhost:8010/api/v1/onboarding/gcp/init \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "your-tenant",
    "project_id": "gcp-project-id",
    "auth_method": "service_account",
    "credentials_json": { "type": "service_account", "..." }
  }'
```

---

## OCI Onboarding

### Onboard

```bash
curl -X POST http://localhost:8010/api/v1/onboarding/oci/init \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "your-tenant",
    "tenancy_ocid": "ocid1.tenancy.oc1...",
    "auth_method": "api_key",
    "user_ocid": "ocid1.user.oc1...",
    "fingerprint": "xx:xx:xx:...",
    "private_key": "..."
  }'
```

---

## Scheduling Scans

### Create a Schedule

```bash
curl -X POST http://localhost:8010/api/v1/schedules \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "your-tenant",
    "account_id": "123456789012",
    "schedule_name": "Daily AWS Scan",
    "cron_expression": "0 2 * * *",
    "pipeline": ["discovery", "check", "inventory", "threat", "compliance"],
    "config": {
      "services": ["s3", "iam", "ec2", "rds"],
      "regions": ["ap-south-1"]
    }
  }'
```

### CRON Examples

| Schedule | CRON Expression |
|----------|----------------|
| Every day at 2 AM | `0 2 * * *` |
| Every 6 hours | `0 */6 * * *` |
| Every Monday at 9 AM | `0 9 * * 1` |
| First of month at midnight | `0 0 1 * *` |

### Manual Trigger

```bash
curl -X POST http://localhost:8010/api/v1/schedules/{schedule_id}/trigger
```
