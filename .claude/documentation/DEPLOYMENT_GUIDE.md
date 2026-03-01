# Deployment Guide

> How to deploy the CSPM platform: Docker Compose (local), Docker Hub, and AWS EKS (production).

---

## Deployment Options

| Method | Use Case | Complexity |
|--------|----------|------------|
| Docker Compose (local) | Development, testing | Low |
| AWS EKS | Production | High |

---

## 1. Docker Compose (Local Development)

### Quick Start

```bash
cd deployment
cp ../config.env.template .env
# Edit .env with your credentials
docker-compose up -d
```

### Verify

```bash
# Check all services
docker-compose ps

# Check gateway health
curl http://localhost:8000/gateway/health

# View logs
docker-compose logs -f threat-engine
```

---

## 2. Docker Hub Images

All images are published under `yadavanup84/` on Docker Hub.

| Image | Engine | Used By |
|-------|--------|---------|
| `yadavanup84/threat-engine-api-gateway` | API Gateway | `api-gateway` deployment |
| `yadavanup84/engine-discoveries-aws` | Discovery Engine | `engine-discoveries` deployment |
| `yadavanup84/engine-check-aws` | Check Engine | `engine-check` deployment |
| `yadavanup84/threat-engine` | Threat Engine | `engine-threat` deployment |
| `yadavanup84/threat-engine-compliance-engine` | Compliance Engine | `engine-compliance` deployment |
| `yadavanup84/threat-engine-iam` | IAM Security Engine | `engine-iam` deployment |
| `yadavanup84/threat-engine-datasec` | DataSec Engine | `engine-datasec` deployment |
| `yadavanup84/inventory-engine` | Inventory Engine | `engine-inventory` deployment |
| `yadavanup84/threat-engine-onboarding-api` | Onboarding Engine | `engine-onboarding` deployment |
| `yadavanup84/threat-engine-yaml-rule-builder` | Rule Builder | `engine-rule` deployment |
| `yadavanup84/secops-scanner` | SecOps Scanner | `engine-secops` deployment |
| `yadavanup84/cspm-ui` | CSPM Frontend | `cspm-ui` deployment |
| `yadavanup84/cspm-django-backend` | CSPM Backend | `django-backend` deployment |

### Build and Push

```bash
# Login to Docker Hub
docker login -u yadavanup84

# Build and push (example: threat engine)
docker build -f engine_threat/Dockerfile -t yadavanup84/threat-engine:latest .
docker push yadavanup84/threat-engine:latest
```

---

## 3. AWS EKS Production Deployment

### Infrastructure

| Component | Details |
|-----------|---------|
| **EKS Cluster** | `vulnerability-eks-cluster` in `ap-south-1` (Mumbai) |
| **Node Group** | `vulnerability-nodegroup` — 2x `t3.medium` |
| **RDS** | PostgreSQL 15, single instance hosting 9 databases |
| **Load Balancer** | Single NLB via nginx ingress controller |
| **Namespaces** | `threat-engine-engines`, `cspm`, `cspm-ui`, `secops-engine`, `ingress-nginx` |

### Networking — Single NLB with Nginx Ingress

All traffic routes through one Network Load Balancer via nginx ingress controller. No Classic ELBs.

```
Internet → NLB (nginx ingress) → Ingress Rules → ClusterIP Services → Pods
```

| Ingress Path | Namespace | Service | Port |
|-------------|-----------|---------|------|
| `/gateway/*` | threat-engine-engines | api-gateway | 80 |
| `/discoveries/*` | threat-engine-engines | discoveries-api | 8001 |
| `/check/*` | threat-engine-engines | check-api | 8002 |
| `/compliance/*` | threat-engine-engines | compliance-api | 8003 |
| `/threat/*` | threat-engine-engines | threat-api | 8004 |
| `/iam/*` | threat-engine-engines | iam-api | 8005 |
| `/datasec/*` | threat-engine-engines | datasec-api | 8006 |
| `/inventory/*` | threat-engine-engines | inventory-api | 8007 |
| `/onboarding/*` | threat-engine-engines | onboarding-api | 8008 |
| `/ui/*` | cspm-ui | cspm-ui | 80 |
| `/cspm/*` | cspm | django-backend | 8000 |
| `/secops/*` | secops-engine | secops-scanner | 8000 |

### Databases (Single RDS Instance)

| Database | Engine | Size |
|----------|--------|------|
| `threat_engine_discoveries` | Discovery | 136 MB |
| `threat_engine_check` | Check | 337 MB |
| `threat_engine_threat` | Threat | 114 MB |
| `threat_engine_compliance` | Compliance | 132 MB |
| `threat_engine_iam` | IAM | 29 MB |
| `threat_engine_datasec` | DataSec | 11 MB |
| `threat_engine_inventory` | Inventory | 14 MB |
| `threat_engine_onboarding` | Onboarding | 8.5 KB |
| `threat_engine_pythonsdk` | PythonSDK (metadata) | 75 MB |
| `threat_engine_shared` | Shared (orchestration) | 8.8 KB |
| `vulnerability_db` | Vulnerability Scanner | 1.8 GB |
| `cspm` | CSPM Django Backend | 9 MB |

### Step 1: Configure EKS Cluster

```bash
# Update kubeconfig
aws eks update-kubeconfig --name vulnerability-eks-cluster --region ap-south-1

# Verify connection
kubectl get nodes
```

### Step 2: Create Namespace

```bash
kubectl create namespace threat-engine-engines
kubectl config set-context --current --namespace=threat-engine-engines
```

### Step 3: Create Secrets

```bash
# Database credentials
kubectl create secret generic database-credentials \
  --from-literal=DB_HOST=<rds-endpoint> \
  --from-literal=DB_PORT=5432 \
  --from-literal=DB_USER=postgres \
  --from-literal=DB_PASSWORD=<password>

# Neo4j credentials
kubectl create secret generic neo4j-credentials \
  --from-literal=NEO4J_URI=neo4j+s://<instance>.databases.neo4j.io \
  --from-literal=NEO4J_USER=neo4j \
  --from-literal=NEO4J_PASSWORD=<password>
```

### Step 4: Install Nginx Ingress Controller

```bash
# Install via Helm
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace \
  --set controller.service.type=LoadBalancer
```

### Step 4b: Deploy PgBouncer (connection pooler)

```bash
kubectl apply -f deployment/aws/eks/pgbouncer/pgbouncer.yaml -n threat-engine-engines
# Verify
kubectl get pods -n threat-engine-engines -l app=pgbouncer
```

All engine ConfigMaps already point to `pgbouncer.threat-engine-engines.svc.cluster.local:5432`.
PgBouncer runs in transaction mode — 500 max app connections → 20 real RDS connections per DB.

### Step 4c: Run Database Migrations (Alembic)

Run before every deploy to ensure schema is current:

```bash
export RDS_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
export DB_PASSWORD=<password>

for DB in check compliance discoveries inventory threat iam datasec secops onboarding; do
  DATABASE_URL="postgresql://postgres:${DB_PASSWORD}@${RDS_HOST}/threat_engine_${DB}" \
    alembic -c shared/database/alembic.ini upgrade head
done
```

Migration files are in `shared/database/alembic/versions/{engine}/`. Alembic tracks applied
migrations in an `alembic_version` table per DB — safe to re-run.

### Step 4d: Deploy OTel Collector (observability)

```bash
# ConfigMap first, then collector
kubectl apply -f deployment/aws/eks/configmaps/otel-config.yaml -n threat-engine-engines
kubectl apply -f deployment/aws/eks/otel/otel-collector.yaml -n threat-engine-engines
# Verify collector is running
kubectl get pods -n threat-engine-engines -l app=otel-collector
```

The OTel Collector receives OTLP gRPC (4317) and HTTP (4318) from all engine pods,
exports Prometheus metrics on port 8889, and forwards traces to the debug exporter
(swap for `otlp/tempo` or `awsxray` in the ConfigMap to route to a real backend).

### Step 5: Deploy All Engines

```bash
# Deploy everything
cd deployment/aws/eks
./deploy.sh

# Or deploy individually:
kubectl apply -f deployment/aws/eks/api-gateway.yaml
kubectl apply -f deployment/aws/eks/engines/engine-threat.yaml
kubectl apply -f deployment/aws/eks/engines/engine-discoveries.yaml
kubectl apply -f deployment/aws/eks/engines/engine-check.yaml
kubectl apply -f deployment/aws/eks/engines/engine-inventory.yaml
kubectl apply -f deployment/aws/eks/engines/engine-onboarding.yaml
kubectl apply -f deployment/aws/eks/engines/engine-compliance.yaml
kubectl apply -f deployment/aws/eks/engines/engine-iam.yaml
kubectl apply -f deployment/aws/eks/engines/engine-datasec.yaml
kubectl apply -f deployment/aws/eks/engines/engine-rule.yaml
```

### Step 6: Verify Deployment

```bash
# Check all pods
kubectl get pods -n threat-engine-engines -o wide

# Check services
kubectl get svc -n threat-engine-engines

# Check ingress
kubectl get ingress --all-namespaces

# Test via NLB
NLB=$(kubectl get svc ingress-nginx-controller -n ingress-nginx -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
curl http://$NLB/gateway/health
curl http://$NLB/ui/
```

---

## Resource Limits

| Service | Memory Request/Limit | CPU Request/Limit |
|---------|---------------------|-------------------|
| `api-gateway` | 256Mi / 512Mi | 100m / 500m |
| `engine-threat` | 256Mi / 1Gi | 100m / 500m |
| `engine-onboarding` | 512Mi / 1Gi | 250m / 1000m |
| `engine-discoveries` | 128Mi / 512Mi | 50m / 250m |
| `engine-check` | 128Mi / 512Mi | 50m / 250m |
| `engine-inventory` | 128Mi / 512Mi | 50m / 250m |
| `engine-compliance` | 128Mi / 512Mi | 50m / 250m |
| `engine-iam` | 128Mi / 512Mi | 50m / 250m |
| `engine-datasec` | 128Mi / 512Mi | 50m / 250m |
| S3 Sync Sidecar | 64Mi / 128Mi | 25m / 100m |

---

## Rolling Updates

```bash
# Update image (example: engine-threat)
kubectl set image deployment/engine-threat \
  engine-threat=yadavanup84/threat-engine:v2.0

# Check rollout status
kubectl rollout status deployment/engine-threat

# Rollback if needed
kubectl rollout undo deployment/engine-threat
```

---

## Monitoring

```bash
# Pod status
kubectl get pods -n threat-engine-engines
kubectl describe pod <pod-name> -n threat-engine-engines
kubectl logs <pod-name> -f -n threat-engine-engines
kubectl top pods -n threat-engine-engines

# Service health via NLB
curl http://<nlb-hostname>/gateway/health
curl http://<nlb-hostname>/ui/
curl http://<nlb-hostname>/secops/
```
