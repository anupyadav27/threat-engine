# Kubernetes Deployment Guide for Orchestration Engines

## Quick Start

### 1. Deploy All Engines

```bash
cd deployment/local-k8s
./deploy-orchestration.sh deploy
```

This will:
- Build Docker images for all engines
- Deploy to Kubernetes (Docker Desktop)
- Wait for pods to be ready
- Show status and access URLs

### 2. Check Status

```bash
./deploy-orchestration.sh status
```

### 3. Check Health

```bash
./deploy-orchestration.sh health
```

### 4. Run Tests

```bash
# From project root
export AUTO_CONTINUE=true
python3 test_orchestration_k8s.py
```

## Prerequisites

1. **Docker Desktop** with Kubernetes enabled
2. **kubectl** installed and configured
3. **PostgreSQL** running locally (accessible via `host.docker.internal:5432`)
4. **Database schemas** created:
   - `threat_engine_discoveries`
   - `threat_engine_check`
   - `threat_engine_threat`
   - `threat_engine_inventory`

## Services Deployed

| Service | Port | Kubernetes Service | Type |
|---------|------|-------------------|------|
| API Gateway | 8000 | `api-gateway` | NodePort |
| Discovery | 8001 | `discovery-service` | ClusterIP |
| Check | 8002 | `check-service` | ClusterIP |
| Threat | 8020 | `threat-service` | ClusterIP |
| Compliance | 8010 | `compliance-service` | ClusterIP |
| IAM | 8003 | `iam-service` | ClusterIP |
| DataSec | 8004 | `datasec-service` | ClusterIP |
| Inventory | 8022 | `inventory-service` | ClusterIP |

## Accessing Services

### From Local Machine

1. **API Gateway** (NodePort):
   ```bash
   # Get NodePort
   kubectl get service api-gateway -n threat-engine-local -o jsonpath='{.spec.ports[0].nodePort}'
   
   # Access
   curl http://localhost:<NODEPORT>/gateway/health
   ```

2. **Port Forward** (for other services):
   ```bash
   # API Gateway
   kubectl port-forward -n threat-engine-local service/api-gateway 8000:8000
   
   # Discovery
   kubectl port-forward -n threat-engine-local service/discovery-service 8001:8001
   
   # Check
   kubectl port-forward -n threat-engine-local service/check-service 8002:8002
   
   # Threat
   kubectl port-forward -n threat-engine-local service/threat-service 8020:8020
   
   # Compliance
   kubectl port-forward -n threat-engine-local service/compliance-service 8010:8010
   
   # IAM
   kubectl port-forward -n threat-engine-local service/iam-service 8003:8003
   
   # DataSec
   kubectl port-forward -n threat-engine-local service/datasec-service 8004:8004
   
   # Inventory
   kubectl port-forward -n threat-engine-local service/inventory-service 8022:8022
   ```

### From Within Kubernetes Cluster

Use service DNS names:
- `http://api-gateway.threat-engine-local.svc.cluster.local:8000`
- `http://discovery-service.threat-engine-local.svc.cluster.local:8001`
- etc.

## Database Configuration

All engines connect to PostgreSQL using `host.docker.internal` to access the host machine's database.

**Environment Variables:**
- `DISCOVERIES_DB_HOST=host.docker.internal`
- `CHECK_DB_HOST=host.docker.internal`
- `THREAT_DB_HOST=host.docker.internal`
- `INVENTORY_DB_HOST=host.docker.internal`

**Update in `orchestration-deployments.yaml` if your PostgreSQL is:**
- On a different host: Change `host.docker.internal` to the actual host
- In Kubernetes: Use the PostgreSQL service name
- Remote: Use the remote hostname/IP

## Troubleshooting

### Pods Not Starting

```bash
# Check pod status
kubectl get pods -n threat-engine-local

# Check logs
kubectl logs -n threat-engine-local <pod-name>

# Describe pod
kubectl describe pod -n threat-engine-local <pod-name>
```

### Database Connection Issues

```bash
# Test database connectivity from a pod
kubectl run -it --rm debug --image=postgres:15 --restart=Never -- \
  psql -h host.docker.internal -U postgres -d threat_engine_discoveries
```

### Service Not Accessible

```bash
# Check service endpoints
kubectl get endpoints -n threat-engine-local

# Check service
kubectl get service -n threat-engine-local api-gateway

# Test from within cluster
kubectl run -it --rm test --image=curlimages/curl --restart=Never -- \
  curl http://api-gateway.threat-engine-local.svc.cluster.local:8000/gateway/health
```

### Rebuild and Redeploy

```bash
# Cleanup
./deploy-orchestration.sh cleanup

# Rebuild and deploy
./deploy-orchestration.sh deploy
```

## Commands Reference

```bash
# Build images only
./deploy-orchestration.sh build

# Deploy everything
./deploy-orchestration.sh deploy

# Show status
./deploy-orchestration.sh status

# Check health
./deploy-orchestration.sh health

# Cleanup
./deploy-orchestration.sh cleanup
```

## Next Steps

1. Deploy: `./deploy-orchestration.sh deploy`
2. Wait for pods: `kubectl get pods -n threat-engine-local -w`
3. Run tests: `python3 test_orchestration_k8s.py`
4. Monitor logs: `kubectl logs -f -n threat-engine-local -l app=api-gateway`
