# Deployment Guide

> How to deploy the CSPM platform: Docker Compose (local), Docker Hub, and AWS EKS (production).

---

## Deployment Options

| Method | Use Case | Complexity |
|--------|----------|------------|
| Docker Compose (local) | Development, testing | Low |
| Docker Compose (hybrid) | Multi-CSP development | Medium |
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

### Services Started

| Service | Port | Image |
|---------|------|-------|
| PostgreSQL | 5432 | postgres:15 |
| Redis | 6379 | redis:7-alpine |
| API Gateway | 8000 | threat-engine/api-gateway |
| Core Engine | 8001 | threat-engine/core-engine |
| ConfigScan | 8002 | threat-engine/configscan |
| Platform | 8003 | threat-engine/platform |
| Data SecOps | 8004 | threat-engine/data-secops |

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

## 2. Docker Hub Deployment

### Build and Push Images

```bash
# Login to Docker Hub
docker login -u yadavanup84

# Build all images (from repo root)
docker build -f engine_threat/Dockerfile -t yadavanup84/threat-engine:latest .
docker build -f engine_check/Dockerfile -t yadavanup84/check-engine:latest .
docker build -f engine_inventory/Dockerfile -t yadavanup84/inventory-engine:latest .
docker build -f engine_compliance/Dockerfile -t yadavanup84/compliance-engine:latest .
docker build -f engine_rule/Dockerfile -t yadavanup84/rule-engine:latest .
docker build -f api_gateway/Dockerfile -t yadavanup84/api-gateway:latest .

# Push all
docker push yadavanup84/threat-engine:latest
docker push yadavanup84/check-engine:latest
docker push yadavanup84/inventory-engine:latest
docker push yadavanup84/compliance-engine:latest
docker push yadavanup84/rule-engine:latest
docker push yadavanup84/api-gateway:latest
```

### Using Makefile

```bash
cd deployment
make build-all    # Build all images
make push-all     # Push all images
make deploy        # Deploy to K8s
```

---

## 3. AWS EKS Production Deployment

### Prerequisites

- AWS CLI configured with appropriate permissions
- kubectl configured for EKS cluster
- Docker Hub credentials (or ECR setup)
- RDS PostgreSQL instance running
- Neo4j Aura instance (optional)

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
  --from-literal=DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
  --from-literal=DB_PORT=5432 \
  --from-literal=DB_USER=postgres \
  --from-literal=DB_PASSWORD=your_password

# Neo4j credentials
kubectl create secret generic neo4j-credentials \
  --from-literal=NEO4J_URI=neo4j+s://your-instance.databases.neo4j.io \
  --from-literal=NEO4J_USER=neo4j \
  --from-literal=NEO4J_PASSWORD=your_password

# Or apply from YAML
kubectl apply -f kubernetes/database-credentials.yaml
kubectl apply -f kubernetes/encryption-keys.yaml
```

### Step 4: Apply ConfigMaps

```bash
kubectl apply -f kubernetes/platform-config.yaml
```

### Step 5: Create Service Account (IRSA)

```bash
# Single service account for ALL engines with IRSA
kubectl apply -f deployment/aws/eks/01-service-account.yaml
```

**IRSA Role:** `threat-engine-platform-role` with policies:
- `ThreatEngineSecretsManager` — access to `threat-engine/*` secrets
- `threat-engine-s3-cspm-lgtech-access` — S3 bucket access
- `ThreatEngineAssumeCustomerRoles` — STS AssumeRole for customer scans
- `ThreatEngineDynamoDB` — DynamoDB access (onboarding)

### Step 6: Deploy All Engines (One Command)

```bash
# Deploy everything using the deploy script
cd deployment/aws/eks
./deploy.sh

# Or deploy individually with uniform naming:
kubectl apply -f deployment/aws/eks/api-gateway.yaml
kubectl apply -f deployment/aws/eks/engines/engine-threat.yaml
kubectl apply -f deployment/aws/eks/engines/engine-discoveries.yaml
kubectl apply -f deployment/aws/eks/engines/engine-check.yaml
kubectl apply -f deployment/aws/eks/engines/engine-inventory.yaml
kubectl apply -f deployment/aws/eks/engines/engine-onboarding.yaml

# Scale-to-0 engines (deploy manifests, scale up when ready)
kubectl apply -f deployment/aws/eks/engines/engine-compliance.yaml
kubectl apply -f deployment/aws/eks/engines/engine-iam.yaml
kubectl apply -f deployment/aws/eks/engines/engine-datasec.yaml
kubectl apply -f deployment/aws/eks/engines/engine-rule.yaml
```

### Engine Naming Convention

| Deployment | Service (ClusterIP) | Port | Image |
|------------|-------------------|------|-------|
| `api-gateway` | `api-gateway` + `api-gateway-lb` | 8000 | `yadavanup84/threat-engine-api-gateway:latest` |
| `engine-threat` | `engine-threat` | 8020 | `yadavanup84/threat-engine:latest` |
| `engine-discoveries` | `engine-discoveries` | 8001 | `yadavanup84/engine-discoveries-aws:latest` |
| `engine-check` | `engine-check` | 8002 | `yadavanup84/engine-check-aws:latest` |
| `engine-inventory` | `engine-inventory` | 8022 | `yadavanup84/inventory-engine:latest` |
| `engine-onboarding` | `engine-onboarding` | 8008 | `yadavanup84/threat-engine-onboarding-api:latest` |
| `engine-compliance` | `engine-compliance` | 8010 | `yadavanup84/threat-engine-compliance-engine:latest` |
| `engine-iam` | `engine-iam` | 8003 | `yadavanup84/threat-engine-iam:latest` |
| `engine-datasec` | `engine-datasec` | 8004 | `yadavanup84/threat-engine-datasec:latest` |
| `engine-rule` | `engine-rule` | 8000 | `yadavanup84/threat-engine-yaml-rule-builder:latest` |

### Step 7: Verify Deployment

```bash
# Check all pods are running
kubectl get pods -n threat-engine-engines -o wide

# Check services
kubectl get svc -n threat-engine-engines

# Check deployments
kubectl get deployments -n threat-engine-engines

# Port forward for testing
kubectl port-forward svc/api-gateway 8000:80 -n threat-engine-engines

# Test
curl http://localhost:8000/gateway/health

# Scale up an engine when ready
kubectl scale deployment engine-compliance --replicas=1 -n threat-engine-engines
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

## Scaling

### Horizontal Pod Autoscaler

```bash
# Apply HPA
kubectl apply -f - <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: engine-threat-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: engine-threat
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
EOF
```

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

### Pod Health

```bash
kubectl get pods -n threat-engine-engines
kubectl describe pod <pod-name> -n threat-engine-engines
kubectl logs <pod-name> -f -n threat-engine-engines
kubectl top pods -n threat-engine-engines
```

### Service Health

```bash
# Port forward and check health endpoints
kubectl port-forward svc/engine-threat 8020:80 -n threat-engine-engines
curl http://localhost:8020/health

# Or via API Gateway
kubectl port-forward svc/api-gateway 8000:80 -n threat-engine-engines
curl http://localhost:8000/gateway/health
```
