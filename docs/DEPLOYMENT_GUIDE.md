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
kubectl apply -f kubernetes/aws-engine-sa.yaml
```

### Step 6: Initialize Database

```bash
kubectl apply -f kubernetes/init-db-schema-job.yaml
# Wait for completion
kubectl wait --for=condition=complete job/init-db-schema --timeout=300s
```

### Step 7: Deploy Engines

```bash
# Deploy all engines
kubectl apply -f deployment/aws/eks/api-gateway-deployment.yaml
kubectl apply -f deployment/aws/eks/threat-engine-deployment.yaml
kubectl apply -f deployment/aws/eks/engines/check-engine-deployment.yaml
kubectl apply -f deployment/aws/eks/engines/discoveries-engine-deployment.yaml
kubectl apply -f deployment/aws/eks/engines/compliance-engine-deployment.yaml
kubectl apply -f deployment/aws/eks/engines/yaml-rule-builder-deployment.yaml
kubectl apply -f deployment/aws/eks/engines/datasec-engine-deployment.yaml
kubectl apply -f deployment/aws/eks/engines/iam-engine-deployment.yaml
kubectl apply -f deployment/aws/eks/inventory-engine-deployment.yaml
kubectl apply -f deployment/aws/eks/onboarding/onboarding-deployment.yaml
kubectl apply -f deployment/aws/eks/scheduler/scheduler-deployment.yaml

# Verify
kubectl get pods
kubectl get services
```

### Step 8: Verify Deployment

```bash
# Check all pods are running
kubectl get pods -o wide

# Check services
kubectl get svc

# Port forward for testing
kubectl port-forward svc/api-gateway 8000:8000

# Test
curl http://localhost:8000/gateway/health
```

---

## Resource Limits

| Service | Memory Request/Limit | CPU Request/Limit |
|---------|---------------------|-------------------|
| API Gateway | 256Mi / 512Mi | 250m / 500m |
| Core Engine | 2Gi / 4Gi | 1000m / 2000m |
| Threat Engine | 512Mi / 2Gi | 250m / 1000m |
| Scanner Engine | 512Mi / 2Gi | 250m / 1000m |
| Other Engines | 256Mi / 1Gi | 250m / 500m |

---

## Scaling

### Horizontal Pod Autoscaler

```bash
# Apply HPA
kubectl apply -f - <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: core-engine-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: core-engine
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
# Update image
kubectl set image deployment/threat-engine \
  threat-engine=yadavanup84/threat-engine:v2.0

# Check rollout status
kubectl rollout status deployment/threat-engine

# Rollback if needed
kubectl rollout undo deployment/threat-engine
```

---

## Monitoring

### Pod Health

```bash
kubectl get pods
kubectl describe pod <pod-name>
kubectl logs <pod-name> -f
kubectl top pods
```

### Service Health

```bash
# Port forward and check health endpoints
kubectl port-forward svc/threat-engine 8020:8020
curl http://localhost:8020/health
```
