# DockerHub Deployment Guide for Local K8s

This guide explains how to build Docker images, push them to DockerHub, and deploy to local Docker Desktop Kubernetes.

## Overview

**Why consolidated_services must be in container:**
- The code imports Python modules from `consolidated_services` at runtime
- Connection logic and classes are Python code that must be present
- Environment variables provide connection details, but the Python code must exist to read them

## Prerequisites

1. **Docker Desktop** with Kubernetes enabled
2. **DockerHub account** (configured locally via `docker login`)
3. **PostgreSQL** running locally (for databases)

## Quick Start

### 1. Setup Local Database (single-DB)

```bash
./deployment/local-k8s/setup-database.sh
# Or: psql -U postgres -d postgres -f scripts/init-databases.sql
```

### 2. Build and Push Images to DockerHub

```bash
# Build and push all engines
./deployment/local-k8s/build-and-push-dockerhub.sh [DOCKERHUB_USERNAME] [TAG]

# Example:
./deployment/local-k8s/build-and-push-dockerhub.sh myusername v1.0.0
```

This will:
- Build images for: onboarding, configscan-aws, secops, compliance, inventory
- Tag them with your DockerHub username
- Push to DockerHub

### 3. Update K8s Manifests

```bash
# Update manifests to use DockerHub images
./deployment/local-k8s/update-images-for-dockerhub.sh [DOCKERHUB_USERNAME] [TAG]

# Example:
./deployment/local-k8s/update-images-for-dockerhub.sh myusername v1.0.0
```

This updates:
- `onboarding-deployment.yaml`
- `configscan-aws-deployment.yaml`
- Changes `imagePullPolicy` to `Always` (to pull from DockerHub)

### 4. Deploy to Local K8s

```bash
# Apply all manifests
kubectl apply -f deployment/local-k8s/

# Check status
kubectl get pods -n threat-engine-local

# View logs
kubectl logs -f deployment/onboarding-service -n threat-engine-local
```

## Engines Updated

All these engines now include `consolidated_services/` in their Dockerfiles:

1. ✅ **engine_onboarding** - Uses shared database
2. ✅ **engine_configscan_aws** - Uses configscan database
3. ✅ **engine_secops** - Uses shared database
4. ✅ **engine_compliance** - Uses compliance database
5. ✅ **engine_inventory** - Uses inventory database

## Dockerfile Changes

All Dockerfiles now include:
```dockerfile
# Copy consolidated_services for database configuration (REQUIRED)
COPY consolidated_services/ ./consolidated_services/
```

## Database Connection

**How it works:**
1. `consolidated_services/database` contains Python code for database connections
2. Code imports: `from consolidated_services.database.config.database_config import get_database_config`
3. Environment variables (from K8s ConfigMap/Secrets) provide connection details:
   - `SHARED_DB_HOST`, `SHARED_DB_PORT`, `SHARED_DB_NAME`, etc.
4. `get_database_config("shared")` reads env vars and returns connection config
5. Connection is made using the config

**Important:** The Python code MUST be in the container image. Environment variables alone are not enough.

## Troubleshooting

### Image Pull Errors

```bash
# Check if image exists on DockerHub
docker pull [DOCKERHUB_USER]/onboarding-service:latest

# Verify DockerHub login
docker login
```

### Database Connection Errors

```bash
# Verify single-DB setup (engine_* schemas)
./deployment/local-k8s/check-database-readiness.sh

# Check from host
psql -h localhost -U postgres -d postgres -c "SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE 'engine_%';"

# Check from pod
kubectl exec -it deployment/onboarding-service -n threat-engine-local -- \
  python3 -c "from consolidated_services.database.config.database_config import get_database_config; print(get_database_config('shared'))"
```

### Import Errors

If you see `ModuleNotFoundError: No module named 'consolidated_services'`:
- Verify Dockerfile includes `COPY consolidated_services/`
- Rebuild image
- Check image contents: `docker run --rm [IMAGE] ls -la /app/consolidated_services`

## Manual Steps

### Build Individual Engine

```bash
# Build specific engine
docker build -t [DOCKERHUB_USER]/onboarding-service:latest \
  -f engine_onboarding/Dockerfile .

# Push
docker push [DOCKERHUB_USER]/onboarding-service:latest
```

### Update Single Manifest

```bash
# Edit manifest
vim deployment/local-k8s/onboarding-deployment.yaml

# Change:
# image: threat-engine/onboarding-service:local
# To:
# image: [DOCKERHUB_USER]/onboarding-service:latest
# imagePullPolicy: Always
```

## Next Steps

1. ✅ All Dockerfiles updated with `consolidated_services`
2. ✅ Build and push scripts created
3. ✅ Database setup script created
4. ⏭️ Build and push images to DockerHub
5. ⏭️ Update K8s manifests
6. ⏭️ Deploy and test
