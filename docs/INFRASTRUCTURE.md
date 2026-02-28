# AWS Infrastructure Documentation

> **Last Updated:** 2026-02-22
> **Environment:** Production
> **Region:** ap-south-1 (Mumbai)
> **AWS Account:** 588989875114

---

## Overview

The Threat Engine CSPM platform is deployed on AWS using managed services for high availability, scalability, and security.

**Core Services:**
- **EKS (Elastic Kubernetes Service)**: Container orchestration
- **RDS PostgreSQL 15**: Primary database
- **Network Load Balancer (NLB)**: Traffic distribution via nginx ingress
- **AWS Secrets Manager**: Secure credential storage
- **S3**: Scan results and output storage
- **KMS**: Encryption key management

---

## EKS Cluster Details

### Cluster Configuration

| Property | Value |
|----------|-------|
| **Cluster Name** | `vulnerability-eks-cluster` |
| **Region** | `ap-south-1` (Mumbai) |
| **AWS Account** | `588989875114` |
| **ARN** | `arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster` |
| **Kubernetes Version** | 1.31.13-eks |
| **Endpoint** | Private + Public |

### kubectl Context

```bash
# Current context
arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster

# Configure kubectl
aws eks update-kubeconfig \
  --region ap-south-1 \
  --name vulnerability-eks-cluster \
  --profile default
```

### Node Groups

| Node Group | Type | Instance Types | Min/Max/Desired | Status |
|------------|------|----------------|-----------------|--------|
| Default (on-demand) | On-demand | t3.medium | 2/2/2 | Active |
| `vulnerability-spot-scanners` | SPOT | t3.xlarge, m5.xlarge, c5.xlarge | 0/6/0 | Active (scales on scan) |

Spot scanner nodes are tainted `spot-scanner=true:NoSchedule` with labels `workload-type=scan`.
Managed by **Cluster Autoscaler** (v1.31.0, IRSA: `ThreatEngineClusterAutoscalerRole`).
Scale-down delay: 5 minutes after scan complete.

**Current nodes:**
- `ip-172-31-35-172.ap-south-1.compute.internal` — on-demand, Ready
- `ip-172-31-6-50.ap-south-1.compute.internal` — on-demand, Ready

### Namespaces

| Namespace | Purpose | Services |
|-----------|---------|----------|
| `threat-engine-engines` | Core scanning engines | 13 deployments |
| `cspm` | Backend API services | Legacy services |
| `cspm-ui` | Frontend UI | User portal |
| `secops-engine` | IaC scanning | SecOps scanner |
| `kube-system` | Kubernetes system | CoreDNS, kube-proxy, Cluster Autoscaler |
| `ingress-nginx` | Ingress controller | nginx ingress |

---

## Load Balancer & Networking

### Network Load Balancer (NLB)

**Single Consolidated NLB** (replaced 6 Classic ELBs)

| Property | Value |
|----------|-------|
| **DNS Name** | `a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com` |
| **Type** | Network Load Balancer (NLB) |
| **Scheme** | Internet-facing |
| **Port** | 80 (HTTP) |
| **Protocol** | TCP |
| **Health Check** | HTTP on target port |

### Ingress Controller

**nginx Ingress Controller** routes traffic to all services via path-based routing.

**Ingress Resources:**

| Namespace | Ingress Name | Backend Service | Age |
|-----------|--------------|-----------------|-----|
| `threat-engine-engines` | `threat-engine-ingress` | All engine services | 15d |
| `cspm` | `cspm-backend-ingress` | Backend API | 11d |
| `cspm-ui` | `cspm-ui-ingress` | Frontend UI | 11d |
| `secops-engine` | `secops-ingress` | SecOps scanner | 11d |

**All ingress resources share the same NLB endpoint.**

### Service Endpoints (Internal ClusterIP)

| Service | Type | Cluster IP | Port | Purpose |
|---------|------|------------|------|---------|
| `api-gateway` | ClusterIP | 10.100.209.181 | 80 | Central API routing |
| `engine-discoveries` | ClusterIP | 10.100.188.200 | 80 | Resource discovery |
| `engine-check` | ClusterIP | 10.100.43.124 | 80 | Compliance checking |
| `engine-inventory` | ClusterIP | 10.100.246.103 | 80 | Asset inventory |
| `engine-threat` | ClusterIP | 10.100.60.108 | 80 | Threat detection |
| `engine-compliance` | ClusterIP | 10.100.48.135 | 80 | Compliance reporting |
| `engine-iam` | ClusterIP | 10.100.170.233 | 80 | IAM security |
| `engine-datasec` | ClusterIP | 10.100.155.216 | 80 | Data security |
| `engine-onboarding` | ClusterIP | 10.100.138.231 | 80 | Account onboarding |
| `engine-rule` | ClusterIP | 10.100.88.168 | 80 | Rule management |
| `engine-secops` | ClusterIP | 10.100.192.50 | 80 | IaC scanning |
| `engine-userportal` | ClusterIP | 10.100.35.144 | 80 | Django backend |
| `engine-userportal-ui` | ClusterIP | 10.100.213.168 | 80 | React frontend |

---

## RDS Database Details

### Database Instance

| Property | Value |
|----------|-------|
| **Endpoint** | `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com` |
| **Port** | `5432` |
| **Engine** | PostgreSQL 15 |
| **Instance Class** | db.t3.medium (or higher) |
| **Storage** | General Purpose SSD (gp3) |
| **Multi-AZ** | Yes (recommended for production) |
| **Backup Retention** | 7 days |
| **Encryption** | AES-256 (enabled) |
| **Username** | `postgres` |

### Database Inventory

All engines use the same RDS instance with separate databases:

| Database Name | Purpose | Engine(s) |
|---------------|---------|-----------|
| `threat_engine_onboarding` | Cloud accounts + scan_orchestration (pipeline hub) | engine-onboarding |
| `threat_engine_discoveries` | Raw cloud resource records | engine-discoveries |
| `threat_engine_check` | Compliance check findings (PASS/FAIL) | engine-check |
| `threat_engine_inventory` | Normalised asset inventory + relationships | engine-inventory |
| `threat_engine_compliance` | Framework compliance reports | engine-compliance |
| `threat_engine_threat` | Threat detections + MITRE mappings | engine-threat |
| `threat_engine_iam` | IAM posture findings | engine-iam |
| `threat_engine_datasec` | Data security findings | engine-datasec |
| `threat_engine_secops` | IaC scan results | engine-secops |
| `vulnerability_db` | CVE/vulnerability database | Vulnerability-main |
| `threat_engine_shared` | Legacy scan_orchestration copy (deprecated) | — |
| `threat_engine_pythonsdk` | Legacy SDK data (deprecated) | — |

### Connection Configuration

Stored in ConfigMap: `threat-engine-db-config` (namespace: `threat-engine-engines`)

**Environment Variables:**
```bash
# Common pattern for all engines
<ENGINE>_DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
<ENGINE>_DB_PORT=5432
<ENGINE>_DB_NAME=threat_engine_<engine>
<ENGINE>_DB_USER=postgres
<ENGINE>_DB_PASSWORD=<from AWS Secrets Manager>
```

**Examples:**
```bash
DISCOVERIES_DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
DISCOVERIES_DB_NAME=threat_engine_discoveries
DISCOVERIES_DB_USER=postgres

THREAT_DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
THREAT_DB_NAME=threat_engine_threat
THREAT_DB_USER=postgres
```

### Database Access

**From Local (via port-forward):**
```bash
# Port forward to RDS (requires bastion or kubectl proxy)
kubectl run -it --rm psql-client \
  --image=postgres:15 \
  --restart=Never \
  --namespace=threat-engine-engines \
  -- psql -h postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
       -U postgres \
       -d threat_engine_discoveries

# Or via kubectl port-forward (if you have a DB proxy pod)
kubectl port-forward svc/<db-proxy> 5432:5432 -n threat-engine-engines
psql -h localhost -U postgres -d threat_engine_discoveries
```

**From Pods:**
Pods connect directly using ConfigMap environment variables and Secrets for passwords.

---

## Deployment Configuration

### Engine Deployments (as of 2026-02-22)

| Deployment | Replicas | Containers | Image | Status |
|------------|----------|------------|-------|--------|
| `api-gateway` | 1 | 1 | `yadavanup84/threat-engine-api-gateway:latest` | ✓ Running |
| `engine-discoveries` | 1 | 1 | `yadavanup84/engine-discoveries:v10-multicloud` | ✓ Running |
| `engine-check` | 1 | 1 | `yadavanup84/engine-check:latest` | ✓ Running |
| `engine-inventory` | 1 | 2 (+ s3-sync) | `yadavanup84/inventory-engine:v6-multi-csp` | ✓ Running |
| `engine-threat` | 1 | 2 (+ s3-sync) | `yadavanup84/threat-engine:latest` | ✓ Running |
| `engine-compliance` | 1 | 2 (+ s3-sync) | `yadavanup84/threat-engine-compliance-engine:v2-db-reports` | ✓ Running |
| `engine-iam` | 1 | 2 (+ s3-sync) | `yadavanup84/engine-iam:v2-fixes` | ✓ Running |
| `engine-datasec` | 1 | 2 (+ s3-sync) | `yadavanup84/engine-datasec:v3-fixes` | ✓ Running |
| `engine-onboarding` | 1 | 1 | `yadavanup84/threat-engine-onboarding-api:latest` | ✓ Running |
| `engine-rule` | 1 | 2 (+ s3-sync) | `yadavanup84/threat-engine-yaml-rule-builder:latest` | ✓ Running |
| `engine-secops` | 1 | 2 (+ s3-sync) | `yadavanup84/secops-scanner:latest` | ✓ Running |
| `engine-userportal` | 1 | 1 | `yadavanup84/cspm-django-backend:latest` | ✓ Running |
| `engine-userportal-ui` | 1 | 1 | `yadavanup84/cspm-ui:latest` | ⚠ CrashLoopBackOff |

**Note:** Deployments with `s3-sync` sidecar container sync scan results to S3 bucket.
`engine-userportal-ui` has 388+ restarts — frontend React app needs separate investigation.

### Resource Allocations

**Typical Pod Resources (example from engine-discoveries):**
```yaml
resources:
  requests:
    cpu: 250m
    memory: 512Mi
  limits:
    cpu: 500m
    memory: 1Gi
```

### Health Checks

All engines implement health endpoints:
```yaml
livenessProbe:
  httpGet:
    path: /api/v1/health/live
    port: 8001
  initialDelaySeconds: 30
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /api/v1/health/ready
    port: 8001
  initialDelaySeconds: 10
  periodSeconds: 10
```

---

## S3 Storage

### Bucket Configuration

| Bucket Name | Purpose | Region |
|-------------|---------|--------|
| `cspm-lgtech` | Scan results, engine outputs | ap-south-1 |

**Directory Structure:**
```
s3://cspm-lgtech/
└── engine_output/
    ├── discoveries/
    ├── check/
    ├── threat/
    ├── compliance/
    ├── iam/
    ├── datasec/
    └── inventory/
```

### S3 Sync Sidecars

Most engines have an AWS CLI sidecar container that syncs results:
```yaml
- name: s3-sync
  image: amazon/aws-cli:latest
  command:
    - /bin/sh
    - -c
    - |
      while true; do
        aws s3 sync /app/output/ s3://cspm-lgtech/engine_output/$(ENGINE_NAME)/
        sleep 300
      done
```

**ConfigMap for S3:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: s3-mount-config
  namespace: threat-engine-engines
data:
  S3_BUCKET: cspm-lgtech
  S3_REGION: ap-south-1
```

---

## AWS Secrets Manager

### Secrets Management Strategy

**All sensitive credentials stored in AWS Secrets Manager:**
- Database passwords
- Cloud provider credentials (AWS, Azure, GCP, OCI)
- API keys
- Service account credentials

### Secret Naming Convention

```
threat-engine/<environment>/<component>/<credential-type>

Examples:
- threat-engine/prod/rds/postgres-password
- threat-engine/prod/aws/role-arn
- threat-engine/prod/azure/client-secret
- threat-engine/prod/gcp/service-account-key
```

### Kubernetes Secret Integration

**External Secrets Operator** syncs AWS Secrets Manager → Kubernetes Secrets

ConfigMap: `external-secret-db-passwords` (namespace: `threat-engine-engines`)

**Pods consume secrets via environment variables:**
```yaml
env:
  - name: DISCOVERIES_DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: threat-engine-db-passwords
        key: discoveries-db-password
```

### Secrets Inventory (Examples)

| Secret Path | Purpose | Used By |
|-------------|---------|---------|
| `threat-engine/prod/rds/postgres-password` | RDS master password | All engines |
| `threat-engine/prod/aws/onboarding-role` | AWS cross-account role ARN | engine-onboarding |
| `threat-engine/prod/azure/tenant-id` | Azure tenant ID | engine-onboarding |
| `threat-engine/prod/gcp/service-account` | GCP service account JSON | engine-onboarding |
| `threat-engine/prod/api/jwt-secret` | API JWT signing key | api-gateway |

### Accessing Secrets (via AWS CLI)

```bash
# Get secret value
aws secretsmanager get-secret-value \
  --region ap-south-1 \
  --secret-id threat-engine/prod/rds/postgres-password \
  --query SecretString \
  --output text

# List all secrets
aws secretsmanager list-secrets \
  --region ap-south-1 \
  --filters Key=name,Values=threat-engine/
```

### KMS Encryption

**All secrets encrypted with AWS KMS:**
- KMS Key Alias: `alias/threat-engine-secrets`
- Automatic rotation: Enabled (90 days)
- Key Policy: Restricted to EKS node IAM roles

---

## Network Topology

### VPC Configuration

| Property | Value |
|----------|-------|
| **VPC ID** | `vpc-xxxxxxxx` (retrieve via AWS Console) |
| **CIDR Block** | `10.0.0.0/16` (typical) |
| **Subnets** | Public (2+), Private (2+) across AZs |
| **NAT Gateway** | Yes (for private subnet internet access) |
| **Internet Gateway** | Yes |

### Subnet Layout (Typical)

| Subnet Type | CIDR | AZ | Usage |
|-------------|------|-----|-------|
| Public Subnet 1 | 10.0.1.0/24 | ap-south-1a | NLB, NAT Gateway |
| Public Subnet 2 | 10.0.2.0/24 | ap-south-1b | NLB, NAT Gateway |
| Private Subnet 1 | 10.0.10.0/24 | ap-south-1a | EKS worker nodes, RDS |
| Private Subnet 2 | 10.0.11.0/24 | ap-south-1b | EKS worker nodes, RDS |

### Security Groups

**EKS Node Security Group:**
- Inbound: Allow from NLB on port 80
- Outbound: Allow all (for cloud API calls)
- Inter-node: Allow all traffic between nodes

**RDS Security Group:**
- Inbound: Port 5432 from EKS node security group only
- Outbound: None required

**NLB Security Group:**
- Inbound: Port 80 from 0.0.0.0/0 (public access)
- Outbound: To EKS nodes on port 80

### DNS & Service Discovery

**Internal DNS:**
- Kubernetes CoreDNS for service discovery
- Format: `<service-name>.<namespace>.svc.cluster.local`

**Example:**
```
engine-discoveries.threat-engine-engines.svc.cluster.local
```

**External DNS:**
- NLB DNS: `a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com`
- Optional: Route53 alias (e.g., `cspm.example.com` → NLB)

---

## IAM Roles & Permissions

### EKS Node Role

**Role Name:** `eks-node-role` (or similar)

**Required Policies:**
- `AmazonEKSWorkerNodePolicy`
- `AmazonEC2ContainerRegistryReadOnly`
- `AmazonEKS_CNI_Policy`
- Custom policy for Secrets Manager access
- Custom policy for S3 access

**Custom Policy (Secrets Manager):**
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
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "arn:aws:kms:ap-south-1:588989875114:key/<key-id>"
    }
  ]
}
```

**Custom Policy (S3):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::cspm-lgtech",
        "arn:aws:s3:::cspm-lgtech/*"
      ]
    }
  ]
}
```

### Service Account Roles (IRSA - IAM Roles for Service Accounts)

**Recommended:** Use IRSA for fine-grained permissions per engine

**Example for engine-discoveries:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: engine-discoveries-sa
  namespace: threat-engine-engines
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::588989875114:role/engine-discoveries-role
```

---

## Monitoring & Logging

### CloudWatch Logs

**EKS Control Plane Logs:**
- Log Group: `/aws/eks/vulnerability-eks-cluster/cluster`
- Streams: api-server, audit, authenticator, controller-manager, scheduler

**Application Logs:**
- Log Group: `/aws/eks/threat-engine/applications`
- Streams: One per pod (via Fluent Bit or CloudWatch agent)

### Metrics & Dashboards

**Container Insights:**
- Enabled on EKS cluster
- Dashboards: Cluster, Namespace, Pod, Node

**Custom Metrics:**
- Engine-specific metrics via `/api/v1/metrics` endpoints
- Scraped by Prometheus (if installed)

### Alerts

**Recommended CloudWatch Alarms:**
- RDS CPU > 80%
- RDS Storage < 20%
- EKS Node CPU > 80%
- Pod restart count > 5 in 15 minutes
- NLB unhealthy target count > 0

---

## Backup & Disaster Recovery

### RDS Backups

- **Automated Backups:** Enabled (7-day retention)
- **Backup Window:** 03:00-04:00 UTC (customize based on traffic)
- **Snapshot Frequency:** Daily
- **Point-in-Time Recovery:** Enabled (last 7 days)

### Manual Snapshots

```bash
# Create manual snapshot
aws rds create-db-snapshot \
  --db-instance-identifier postgres-vulnerability-db \
  --db-snapshot-identifier threat-engine-manual-$(date +%Y%m%d) \
  --region ap-south-1
```

### Kubernetes Backups

**Velero** (recommended for EKS cluster state backup):
- Backup frequency: Daily
- Retention: 30 days
- Includes: ConfigMaps, Secrets, PVCs, Deployments

---

## Cost Optimization

### Resource Costs (Estimates)

| Resource | Monthly Cost (approx.) |
|----------|------------------------|
| EKS Cluster | $75 |
| EC2 Worker Nodes (t3.medium x 3) | $75-100 |
| RDS PostgreSQL (db.t3.medium) | $100-150 |
| NLB | $20-30 |
| S3 Storage (100GB) | $3-5 |
| Secrets Manager (10 secrets) | $4 |
| Data Transfer | $10-50 |
| **Total** | **~$300-450/month** |

### Optimization Tips

1. **Right-size instances:** Monitor CPU/memory usage, downsize if underutilized
2. **Spot instances:** Use for non-critical worker nodes
3. **S3 lifecycle policies:** Move old scan results to Glacier
4. **RDS Reserved Instances:** 1-year commitment saves ~40%
5. **Cleanup unused resources:** Delete old snapshots, unattached volumes

---

## Disaster Recovery Plan

### RTO (Recovery Time Objective)

- **Target:** < 4 hours
- **Procedure:** Restore RDS from snapshot, redeploy EKS from manifests

### RPO (Recovery Point Objective)

- **Target:** < 1 hour
- **Mechanism:** Automated RDS backups (point-in-time recovery)

### DR Procedure

1. **Restore RDS:**
   ```bash
   aws rds restore-db-instance-to-point-in-time \
     --source-db-instance-identifier postgres-vulnerability-db \
     --target-db-instance-identifier postgres-vulnerability-db-restored \
     --restore-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
     --region ap-south-1
   ```

2. **Update ConfigMap with new RDS endpoint**

3. **Redeploy all engines:**
   ```bash
   kubectl apply -f /Users/apple/Desktop/threat-engine/deployment/aws/eks/
   ```

4. **Verify health:**
   ```bash
   kubectl get pods -n threat-engine-engines
   kubectl get ingress -A
   ```

---

## Quick Reference Commands

### EKS Cluster Access
```bash
# Configure kubectl
aws eks update-kubeconfig --region ap-south-1 --name vulnerability-eks-cluster

# Get cluster info
kubectl cluster-info
```

### Check Service Status
```bash
# All deployments
kubectl get deployments -n threat-engine-engines

# All pods
kubectl get pods -n threat-engine-engines -o wide

# Services
kubectl get svc -n threat-engine-engines
```

### Database Connection
```bash
# From pod
kubectl run -it --rm psql-client --image=postgres:15 --restart=Never \
  --namespace=threat-engine-engines \
  -- psql -h postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
       -U postgres -d threat_engine_discoveries
```

### Logs
```bash
# Pod logs
kubectl logs -f <pod-name> -n threat-engine-engines

# Logs with label selector
kubectl logs -f -l app=engine-discoveries -n threat-engine-engines
```

### Secrets
```bash
# Get secret from AWS
aws secretsmanager get-secret-value \
  --region ap-south-1 \
  --secret-id threat-engine/prod/rds/postgres-password
```

---

## Support & Troubleshooting

### Common Issues

**Pod not starting:**
1. Check logs: `kubectl logs <pod-name> -n threat-engine-engines`
2. Describe pod: `kubectl describe pod <pod-name> -n threat-engine-engines`
3. Verify secrets: `kubectl get secret threat-engine-db-passwords -n threat-engine-engines`

**Database connection failed:**
1. Check RDS status in AWS Console
2. Verify security group allows traffic from EKS nodes
3. Test connection from pod: `kubectl exec -it <pod> -- nc -zv <rds-endpoint> 5432`

**Ingress not routing:**
1. Check ingress: `kubectl get ingress -n threat-engine-engines`
2. Check nginx controller: `kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx`
3. Verify NLB target health in AWS Console

### Contact Information

- **AWS Support:** Enterprise plan (24/7)
- **Infrastructure Team:** infrastructure@example.com
- **On-call:** PagerDuty rotation

---

## Next Steps

1. **Set up monitoring:** Configure CloudWatch alarms
2. **Implement DR:** Test disaster recovery procedure
3. **Document runbooks:** Create operational playbooks
4. **Cost optimization:** Review and right-size resources
5. **Security audit:** Regular security group and IAM review
