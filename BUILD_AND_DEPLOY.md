# Build and Deploy Orchestration Pipeline

## ✅ Completed

### 1. Orchestration API Created
- ✅ `api_gateway/orchestration.py` - Orchestration service
- ✅ `api_gateway/main.py` - Added `/gateway/orchestrate` endpoint
- ✅ Endpoint orchestrates: Discovery → Check → Inventory
- ✅ Each step uploads to respective database

### 2. Engine Split Complete
- ✅ `engine_discoveries` - Discovery engine
- ✅ `engine_check` - Check engine  
- ✅ Cross-engine integration working

## ⏳ Next Steps: Build and Deploy

### Step 1: Build Docker Images

```bash
# Build Discoveries Engine
cd /Users/apple/Desktop/threat-engine
docker build -t your-registry/discoveries-engine:latest \
  -f engine_discoveries/engine_discoveries_aws/Dockerfile \
  --platform linux/amd64 .

# Build Check Engine
docker build -t your-registry/check-engine:latest \
  -f engine_check/engine_check_aws/Dockerfile \
  --platform linux/amd64 .

# Build API Gateway (with orchestration)
docker build -t your-registry/api-gateway:latest \
  -f api_gateway/Dockerfile \
  --platform linux/amd64 .

# Build Inventory Engine (if needed)
docker build -t your-registry/inventory-engine:latest \
  -f engine_inventory/Dockerfile \
  --platform linux/amd64 .
```

### Step 2: Push to Registry

```bash
docker push your-registry/discoveries-engine:latest
docker push your-registry/check-engine:latest
docker push your-registry/api-gateway:latest
docker push your-registry/inventory-engine:latest
```

### Step 3: Create Kubernetes Deployments

Create deployment YAMLs for:
- `discoveries-engine-deployment.yaml`
- `check-engine-deployment.yaml`
- `api-gateway-deployment.yaml` (updated with orchestration)
- `inventory-engine-deployment.yaml`

### Step 4: Update Onboarding Orchestrator

Update `engine_onboarding/orchestrator/engine_orchestrator.py` to call:
```python
POST /gateway/orchestrate
```

Instead of calling engines individually.

## Environment Variables

### Discoveries Engine
```yaml
DISCOVERIES_DB_HOST: localhost
DISCOVERIES_DB_PORT: 5432
DISCOVERIES_DB_NAME: threat_engine_discoveries
DISCOVERIES_DB_USER: discoveries_user
DISCOVERIES_DB_PASSWORD: discoveries_password
OUTPUT_DIR: /output/discoveries
```

### Check Engine
```yaml
CHECK_DB_HOST: localhost
CHECK_DB_PORT: 5432
CHECK_DB_NAME: threat_engine_check
CHECK_DB_USER: check_user
CHECK_DB_PASSWORD: check_password
DISCOVERIES_DB_HOST: localhost  # For reading discoveries
DISCOVERIES_DB_NAME: threat_engine_discoveries
OUTPUT_DIR: /output/checks
```

### API Gateway
```yaml
DISCOVERIES_ENGINE_URL: http://discoveries-engine:8001
CHECK_ENGINE_URL: http://check-engine:8002
INVENTORY_ENGINE_URL: http://inventory-engine:8022
```

## Testing

1. Test orchestration endpoint:
```bash
curl -X POST http://localhost:8000/gateway/orchestrate \
  -H "Content-Type: application/json" \
  -d '{
    "customer_id": "test-customer",
    "tenant_id": "test-tenant",
    "provider": "aws",
    "hierarchy_id": "588989875114",
    "hierarchy_type": "account",
    "use_database": true
  }'
```

2. Verify databases:
- Check `threat_engine_discoveries.discoveries` table
- Check `threat_engine_check.check_results` table
- Check `threat_engine_inventory` tables

## Summary

✅ Orchestration API created and ready
⏳ Docker images need to be built
⏳ Kubernetes deployments need to be created
⏳ Onboarding orchestrator needs update
