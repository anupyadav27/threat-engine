# Build and Deploy Summary

## Overview

This directory contains scripts and configurations to build all orchestration engines and deploy them to Kubernetes (local Docker Desktop or AWS EKS).

## Files Created

### 1. Configuration Files
- **`config.yaml`** - Central configuration for local and AWS EKS deployments
  - Database settings (uses `host.docker.internal` for local)
  - Service URLs and ports
  - Resource limits
  - Image registry and tags

### 2. Build Scripts
- **`build-all-engines.sh`** - Builds all Docker images
  ```bash
  ./build-all-engines.sh [tag] [registry]
  # Example: ./build-all-engines.sh local threat-engine
  ```

### 3. Deployment Files
- **`orchestration-deployments.yaml`** - Kubernetes manifests (partial, needs completion)
- **`deploy-orchestration.sh`** - Deployment script
  ```bash
  ./deploy-orchestration.sh [build|deploy|status|health|cleanup]
  ```

### 4. Test Scripts
- **`test_orchestration_k8s.py`** - Test orchestration with Kubernetes services

## Quick Start

### Step 1: Build All Engines

```bash
cd deployment/local-k8s

# Build all engines with 'local' tag
./build-all-engines.sh local

# Or with custom registry
./build-all-engines.sh local your-registry
```

**Engines Built:**
1. API Gateway (`api_gateway/Dockerfile`)
2. Discovery Engine (`engine_discoveries/engine_discoveries_aws/Dockerfile`)
3. Check Engine (`engine_check/engine_check_aws/Dockerfile`)
4. Threat Engine (`engine_threat/Dockerfile`)
5. Compliance Engine (`engine_compliance/Dockerfile`)
6. IAM Engine (`engine_iam/Dockerfile`)
7. DataSec Engine (`engine_datasec/Dockerfile`)
8. Inventory Engine (`engine_inventory/Dockerfile`)

### Step 2: Deploy to Kubernetes

```bash
# Deploy everything (builds + deploys)
./deploy-orchestration.sh deploy

# Or just deploy (if images already built)
./deploy-orchestration.sh deploy
```

### Step 3: Test Orchestration

```bash
# From project root
export AUTO_CONTINUE=true
python3 test_orchestration_k8s.py
```

## Configuration for AWS EKS

To adapt for AWS EKS, update `config.yaml`:

```yaml
environment: aws-eks

database:
  host: postgres-service.database.svc.cluster.local  # K8s service name
  # ... rest of config

images:
  registry: "your-ecr-registry/"  # ECR registry
  tag: latest

services:
  api_gateway:
    type: LoadBalancer  # Instead of NodePort
```

Then regenerate deployment YAML or manually update `orchestration-deployments.yaml`.

## Current Status

✅ **Created:**
- Config file (`config.yaml`)
- Build script (`build-all-engines.sh`)
- Deployment script (`deploy-orchestration.sh`)
- Test script (`test_orchestration_k8s.py`)
- Partial deployment YAML

⏳ **Next Steps:**
1. Complete `orchestration-deployments.yaml` with all engines
2. Start Docker Desktop
3. Run `./build-all-engines.sh local`
4. Run `./deploy-orchestration.sh deploy`
5. Run tests

## Dockerfile Locations

| Engine | Dockerfile Path |
|--------|----------------|
| API Gateway | `api_gateway/Dockerfile` |
| Discovery | `engine_discoveries/engine_discoveries_aws/Dockerfile` |
| Check | `engine_check/engine_check_aws/Dockerfile` |
| Threat | `engine_threat/Dockerfile` |
| Compliance | `engine_compliance/Dockerfile` |
| IAM | `engine_iam/Dockerfile` |
| DataSec | `engine_datasec/Dockerfile` |
| Inventory | `engine_inventory/Dockerfile` |

## Troubleshooting

### Docker Not Running
```bash
# Start Docker Desktop, then retry
./build-all-engines.sh local
```

### Images Not Found
```bash
# Check if images were built
docker images | grep threat-engine
```

### Deployment Fails
```bash
# Check pod status
kubectl get pods -n threat-engine-local

# Check logs
kubectl logs -n threat-engine-local <pod-name>
```

## Next: Complete Deployment YAML

The `orchestration-deployments.yaml` currently only has API Gateway. Need to add:
- Discovery Engine deployment + service
- Check Engine deployment + service
- Threat Engine deployment + service
- Compliance Engine deployment + service
- IAM Engine deployment + service
- DataSec Engine deployment + service
- Inventory Engine deployment + service
