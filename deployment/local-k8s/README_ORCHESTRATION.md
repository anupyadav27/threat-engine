# Orchestration Engines - Build and Deploy

## Quick Start

### 1. Build All Engines
```bash
cd deployment/local-k8s
./build-all-engines.sh local
```

### 2. Deploy to Kubernetes
```bash
./deploy-orchestration.sh deploy
```

### 3. Test
```bash
cd ../..
export AUTO_CONTINUE=true
python3 test_orchestration_k8s.py
```

## Configuration

Edit `config.yaml` to switch between:
- **Local**: Uses `host.docker.internal` for PostgreSQL
- **AWS EKS**: Uses Kubernetes service names

## Files

- `config.yaml` - Configuration (local/EKS)
- `build-all-engines.sh` - Build script
- `deploy-orchestration.sh` - Deploy script
- `orchestration-deployments.yaml` - K8s manifests
- `test_orchestration_k8s.py` - Test script

## Status

✅ Scripts created
⏳ Need to complete `orchestration-deployments.yaml` with all engines
⏳ Need Docker Desktop running to build
