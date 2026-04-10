# CSP Credentials Context — Laptop + EKS

## Available Now (Laptop CLI)

### AWS
- **Account ID**: 588989875114
- **Region**: ap-south-1
- **Auth method**: IAM user access key (`~/.aws/credentials`)
- **EKS cluster**: `arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster`
- **RDS**: `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`
- **Status**: WORKING — full pipeline running

### Azure
- **Subscription ID**: f6d24b5d-51ed-47b7-9f6a-0ad194156b5e
- **Subscription Name**: Azure subscription 1
- **Auth method**: `az login` (Azure CLI — `yadav.anup@gmail.com`)
- **Tenant ID**: check via `az account show --query tenantId`
- **Status**: CLI authenticated — scanner code not yet wired
- **Next step**: Create service principal for scanner: `az ad sp create-for-rbac --name cspm-scanner --role Reader --scopes /subscriptions/f6d24b5d-51ed-47b7-9f6a-0ad194156b5e`

### GCP
- **Project**: `cloudsecurityapp-437319` (CloudSecurityApp — primary CSPM project)
- **Other projects**: `magnetic-market-215908`, `test-215908`, `test-2277`
- **Auth account**: yadav.anup@gmail.com
- **Current gcloud project set to**: `test-215908` (need to switch to `cloudsecurityapp-437319`)
- **Auth method**: `gcloud auth application-default login` (ADC)
- **Status**: CLI authenticated — switch project before using
- **Switch command**: `gcloud config set project cloudsecurityapp-437319`
- **Next step**: Create service account: `gcloud iam service-accounts create cspm-scanner`

### Kubernetes (EKS — dogfood)
- **Context**: `arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster`
- **Context name in kubeconfig**: same as ARN
- **Current context**: YES (marked with `*` in kubectl config)
- **Namespace**: `threat-engine-engines`
- **Status**: WORKING — production cluster running CSPM
- **Note**: K8s scanner scans THIS cluster — dogfood use case

### Minikube (local dev)
- **Context**: `minikube`
- **Status**: Available but not current context
- **Use for**: Local K8s scanner testing without hitting EKS

## Not Available — Need Credentials

### OCI (Oracle Cloud)
- **Status**: No account — needs provisioning
- **Free tier**: oracle.com/cloud/free (Always Free tier)
- **Required**: Tenancy OCID, User OCID, API signing key, fingerprint, region
- **K8s secret name**: `oci-creds`

### IBM Cloud
- **Status**: No account — needs provisioning
- **Free tier**: ibm.com/cloud (Lite tier)
- **Required**: API key, Account ID, Resource Group
- **K8s secret name**: `ibm-creds`

### AliCloud (Alibaba Cloud)
- **Status**: No account — needs provisioning
- **Free tier**: alibabacloud.com (limited free tier)
- **Required**: AccessKeyId, AccessKeySecret, AccountID
- **Primary regions**: cn-hangzhou, ap-southeast-1 (Singapore)
- **K8s secret name**: `alicloud-creds`

## EKS K8s Secrets for Scanner Credentials

| CSP | K8s Secret | Status |
|-----|-----------|--------|
| AWS | `aws-creds` or `external-secret-db-passwords` | Working |
| Azure | `azure-creds` | Not created yet |
| GCP | `gcp-creds` | Not created yet |
| K8s | kubeconfig in-cluster (serviceaccount) | Working |
| OCI | `oci-creds` | Not created yet |
| IBM | `ibm-creds` | Not created yet |
| AliCloud | `alicloud-creds` | Not created yet |

## Argo Workflow Credential Passing

Current pattern (AWS):
```yaml
env:
  - name: AWS_ACCESS_KEY_ID
    valueFrom:
      secretKeyRef:
        name: aws-creds
        key: access_key_id
```

Per-CSP pattern to implement:
- Azure: `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`
- GCP: `GOOGLE_APPLICATION_CREDENTIALS` (path to service account JSON)
- K8s: `KUBECONFIG` or in-cluster ServiceAccount token
- OCI: `OCI_TENANCY_ID`, `OCI_USER_ID`, `OCI_KEY_FILE`, `OCI_FINGERPRINT`, `OCI_REGION`
- IBM: `IBM_API_KEY`, `IBM_ACCOUNT_ID`, `IBM_RESOURCE_GROUP`
- AliCloud: `ALICLOUD_ACCESS_KEY_ID`, `ALICLOUD_ACCESS_KEY_SECRET`, `ALICLOUD_ACCOUNT_ID`

## Session Notes
- GCP active project needs to be switched to `cloudsecurityapp-437319` before scanning
- Azure SP creation needed before scanner can be deployed
- OCI/IBM/AliCloud accounts need to be provisioned before any scanner work
