# Quick Start: Deploy Orchestration Engines to Kubernetes

## Prerequisites

1. Docker Desktop with Kubernetes enabled
2. PostgreSQL running locally (accessible on host machine)
3. Database schemas created

## Deploy

```bash
cd deployment/local-k8s
./deploy-orchestration.sh deploy
```

## Test

```bash
# From project root
export AUTO_CONTINUE=true
python3 test_orchestration_k8s.py
```

## Access Services

```bash
# Get API Gateway NodePort
kubectl get service api-gateway -n threat-engine-local -o jsonpath='{.spec.ports[0].nodePort}'

# Or port-forward
kubectl port-forward -n threat-engine-local service/api-gateway 8000:8000
```

## Check Status

```bash
./deploy-orchestration.sh status
```

## Cleanup

```bash
./deploy-orchestration.sh cleanup
```
