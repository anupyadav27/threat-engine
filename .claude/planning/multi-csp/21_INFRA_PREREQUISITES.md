# Infrastructure Prerequisites — Multi-CSP EKS Setup

## Current State (as of 2026-04-07)

### Credentials in AWS Secrets Manager

| CSP | Secret Path | Status | Notes |
|-----|------------|--------|-------|
| AWS | `threat-engine/account/588989875114` | ✓ READY | access_key type, active |
| Azure | `threat-engine/account/f6d24b5d-51ed-47b7-9f6a-0ad194156b5e` | ✓ READY | SP: client_id + client_secret + tenant_id |
| GCP | `threat-engine/account/test-215908` | ⚠ PARTIAL | SA JSON exists but for `test-215908`, not `cloudsecurityapp-437319` |
| K8s | N/A (in-cluster ServiceAccount token) | ✓ READY | Uses IRSA, no external secret needed |
| OCI | ✗ MISSING | No account | Needs provisioning |
| IBM | ✗ MISSING | No account | Needs provisioning |
| AliCloud | ✗ MISSING | No account | Needs provisioning |

### Cloud Accounts in DB (cloud_accounts table)

| CSP | account_id | Status | Credential |
|-----|-----------|--------|-----------|
| AWS | 588989875114 | active/deployed | access_key → SecretsManager |
| Azure | f6d24b5d-51ed-47b7-9f6a-0ad194156b5e | active/validated | azure_service_principal |
| GCP | test-215908 | active/validated | gcp_service_account |
| K8s | ✗ NOT REGISTERED | — | Needs INSERT |
| OCI | ✗ NOT REGISTERED | — | Needs account first |
| IBM | ✗ NOT REGISTERED | — | Needs account first |
| AliCloud | ✗ NOT REGISTERED | — | Needs account first |

### EKS Infrastructure

| Component | Status | Details |
|-----------|--------|---------|
| Cluster | ✓ READY | vulnerability-eks-cluster, ap-south-1, 1.31/1.34 |
| IRSA | ✓ READY | engine-sa → threat-engine-platform-role (IRSA annotated) |
| SecretsManager policy | ✓ READY | ThreatEngineSecretsManager attached to platform role |
| Spot nodegroup | ✓ READY | vulnerability-spot-scanners, min=1 max=20, t3/m5/c5.2xlarge |
| DB access | ✓ READY | threat-engine-db-passwords K8s secret, all 10 DBs |
| K8s ClusterRole for scanner | ✗ MISSING | RBAC for K8s self-scan not created |
| Docker image: azure | ✗ MISSING | engine-discoveries-azure:latest not built |
| Docker image: gcp | ✗ MISSING | engine-discoveries-gcp:latest not built |
| Docker image: k8s | ✗ MISSING | engine-discoveries-k8s:latest not built |

### Scanner Stub Status

| CSP | Scanner file | Lines | Implemented services |
|-----|-------------|-------|---------------------|
| AWS | providers/aws/scanner/service_scanner.py | 2060 | All ~380 active |
| Azure | providers/azure/scanner/service_scanner.py | 343 | compute, storage, sql, resource_groups |
| GCP | providers/gcp/scanner/service_scanner.py | 392 | compute, storage, bigquery, iam |
| K8s | providers/kubernetes/scanner/service_scanner.py | 293 | pods, services (stubs) |
| OCI | providers/oci/scanner/service_scanner.py | ? | stub |
| IBM | providers/ibm/scanner/service_scanner.py | ? | stub |
| AliCloud | ✗ MISSING | 0 | No provider dir |

---

## Action Items (Priority Order)

### IMMEDIATE — Fix GCP project mismatch

GCP secret is for `test-215908` but primary CSPM project is `cloudsecurityapp-437319`.
Two options:

**Option A (Preferred):** Add new cloud account for `cloudsecurityapp-437319`:
```bash
# 1. Create service account in the right project
gcloud config set project cloudsecurityapp-437319
gcloud iam service-accounts create cspm-scanner \
  --display-name="CSPM Scanner" \
  --project=cloudsecurityapp-437319

# 2. Grant read permissions
gcloud projects add-iam-policy-binding cloudsecurityapp-437319 \
  --member="serviceAccount:cspm-scanner@cloudsecurityapp-437319.iam.gserviceaccount.com" \
  --role="roles/viewer"
gcloud projects add-iam-policy-binding cloudsecurityapp-437319 \
  --member="serviceAccount:cspm-scanner@cloudsecurityapp-437319.iam.gserviceaccount.com" \
  --role="roles/iam.securityReviewer"

# 3. Create key
gcloud iam service-accounts keys create /tmp/cspm-sa-key.json \
  --iam-account=cspm-scanner@cloudsecurityapp-437319.iam.gserviceaccount.com

# 4. Store in Secrets Manager
aws secretsmanager create-secret \
  --name "threat-engine/account/cloudsecurityapp-437319" \
  --secret-string "$(cat /tmp/cspm-sa-key.json | python3 -c "
import sys, json
key = json.load(sys.stdin)
print(json.dumps({
  'credential_type': 'gcp_service_account',
  'credentials': key,
  'account_id': 'cloudsecurityapp-437319',
  'created_at': '2026-04-07',
  'expires_at': None
}))
")" --region ap-south-1

# 5. Register in cloud_accounts
# (via onboarding API or direct SQL)
```

**Option B:** Update existing `test-215908` secret to point at `cloudsecurityapp-437319` — simpler but mixes account IDs.

### IMMEDIATE — Register K8s cloud account

```sql
INSERT INTO cloud_accounts (
    account_id, customer_id, customer_email, tenant_id,
    account_name, account_number, provider,
    credential_type, credential_ref,
    account_status, account_onboarding_status
) VALUES (
    'arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster',
    'cspm-admin',
    'admin@cspm.local',
    'default-tenant',
    'vulnerability-eks-cluster',
    '588989875114',
    'k8s',
    'in_cluster',
    'in-cluster',
    'active',
    'deployed'
);
```

### IMMEDIATE — K8s RBAC for Self-Scan

Create ClusterRole + ClusterRoleBinding so `engine-sa` can read all K8s resources:

```yaml
# File: deployment/aws/eks/rbac/cspm-scanner-k8s-rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cspm-scanner-reader
  labels:
    app: cspm-scanner
rules:
- apiGroups: [""]
  resources:
  - pods, services, serviceaccounts, namespaces, nodes
  - configmaps, secrets, persistentvolumes, endpoints
  verbs: ["get", "list", "watch"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources:
  - clusterroles, clusterrolebindings, roles, rolebindings
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: [networkpolicies, ingresses]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: [deployments, daemonsets, statefulsets, replicasets]
  verbs: ["get", "list", "watch"]
- apiGroups: ["policy"]
  resources: [podsecuritypolicies]
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources: [jobs, cronjobs]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cspm-scanner-reader-binding
subjects:
- kind: ServiceAccount
  name: engine-sa
  namespace: threat-engine-engines
roleRef:
  kind: ClusterRole
  name: cspm-scanner-reader
  apiGroup: rbac.authorization.k8s.io
```

Apply:
```bash
kubectl apply -f deployment/aws/eks/rbac/cspm-scanner-k8s-rbac.yaml
```

### WHEN SCANNER CODE READY — Build Docker Images

```bash
# Azure image
docker build -t yadavanup84/engine-discoveries-azure:v1.azure.20260407 \
  -f engines/discoveries/providers/azure/Dockerfile \
  --build-arg PROVIDER=azure .
docker push yadavanup84/engine-discoveries-azure:v1.azure.20260407

# GCP image
docker build -t yadavanup84/engine-discoveries-gcp:v1.gcp.20260407 \
  -f engines/discoveries/providers/gcp/Dockerfile \
  --build-arg PROVIDER=gcp .
docker push yadavanup84/engine-discoveries-gcp:v1.gcp.20260407

# K8s image
docker build -t yadavanup84/engine-discoveries-k8s:v1.k8s.20260407 \
  -f engines/discoveries/providers/kubernetes/Dockerfile \
  --build-arg PROVIDER=k8s .
docker push yadavanup84/engine-discoveries-k8s:v1.k8s.20260407
```

### WHEN IMAGES READY — Create K8s Deployments

Files to create (per 11_DOCKER_SPLIT.md):
```
deployment/aws/eks/engines/engine-discoveries-azure.yaml
deployment/aws/eks/engines/engine-discoveries-gcp.yaml
deployment/aws/eks/engines/engine-discoveries-k8s.yaml
```

Pattern (uses same spec as engine-discoveries-aws.yaml, change image + envFrom):
```yaml
containers:
- name: engine-discoveries-azure
  image: yadavanup84/engine-discoveries-azure:v1.azure.20260407
  env:
  - name: PROVIDER
    value: azure
  # Credentials read from Secrets Manager via IRSA — no envFrom needed
  # engine-sa ServiceAccount → IRSA → ThreatEngineSecretsManager policy
```

### WHEN OCI/IBM/ALICLOUD ACCOUNTS PROVISIONED

Follow same pattern:
1. Create account in respective cloud
2. Create service credentials (API key / SA key / access key)
3. `aws secretsmanager create-secret --name "threat-engine/account/{account_id}" ...`
4. INSERT into cloud_accounts
5. Build Docker image
6. Create K8s Deployment

---

## MCP Server Tools (for Development Workflow)

### Available MCP Servers

| Server | Use for |
|--------|---------|
| `threat-engine-db` | Query all 10 DBs directly, Neo4j graph queries |
| `kubernetes` | kubectl operations — pod status, logs, deployments |
| `docker` | Build and inspect images |
| `github` | PR operations, issue tracking |

### How to use during CSP development

**Check rule_discoveries counts:**
```
MCP: threat-engine-db → pg_query
DB: threat_engine_check
SQL: SELECT provider, is_active, COUNT(*) FROM rule_discoveries GROUP BY provider, is_active ORDER BY provider
```

**Check scan pipeline status:**
```
MCP: threat-engine-db → pg_query
DB: threat_engine_onboarding
SQL: SELECT scan_run_id, provider, overall_status, engine_statuses FROM scan_runs ORDER BY started_at DESC LIMIT 5
```

**Check findings after smoke test:**
```
MCP: threat-engine-db → pg_query
DB: threat_engine_discoveries
SQL: SELECT provider, resource_type, COUNT(*) FROM discovery_findings WHERE scan_run_id='<id>' GROUP BY provider, resource_type
```

**Check K8s pod status:**
```
MCP: kubernetes → get pods -n threat-engine-engines
```

**Check engine logs:**
```
MCP: kubernetes → logs -l app=engine-discoveries -n threat-engine-engines --tail=50
```

---

## Checklist Before First Azure Scan

- [ ] Azure credentials in Secrets Manager ✓ (already done)
- [ ] Azure cloud_account in DB ✓ (already done)
- [ ] Azure scanner expanded (currently 4 services → need 267)
- [ ] Azure Docker image built and pushed
- [ ] Azure K8s Deployment created
- [ ] Azure noise removed from rule_discoveries (billing/monitoring services disabled)
- [ ] Azure relationship rules seeded in resource_security_relationship_rules
- [ ] Azure asset classification seeded in service_classification
- [ ] Azure check rules seeded in rule_metadata (≥50 rules)
- [ ] CIS Azure 1.5 framework seeded in compliance_frameworks
- [ ] IRSA policy includes SecretsManager:GetSecretValue ✓ (already done)

## Checklist Before First GCP Scan

- [ ] GCP credentials for `cloudsecurityapp-437319` in Secrets Manager (fix project mismatch)
- [ ] GCP cloud_account for `cloudsecurityapp-437319` in DB
- [ ] GCP scanner expanded (currently 4 services → need 286)
- [ ] GCP Docker image built and pushed
- [ ] GCP K8s Deployment created
- [ ] GCP noise removed from rule_discoveries
- [ ] GCP relationship rules + classification seeded
- [ ] GCP check rules in rule_metadata (≥50 rules)
- [ ] CIS GCP 1.3 framework seeded

## Checklist Before First K8s Scan

- [ ] K8s cloud_account registered in DB (INSERT above)
- [ ] K8s RBAC ClusterRole + ClusterRoleBinding applied
- [ ] K8s scanner expanded from stub
- [ ] K8s Docker image built and pushed
- [ ] K8s K8s Deployment created (uses in-cluster SA, no external creds)
- [ ] K8s noise removed (events, endpoints, componentstatuses)
- [ ] K8s relationship rules + classification seeded
- [ ] K8s check rules in rule_metadata
- [ ] CIS K8s 1.8 framework seeded
