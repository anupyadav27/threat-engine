# Orchestration API - Discovery → Check → Inventory

## Overview

The API Gateway now includes an orchestration endpoint that runs the complete pipeline:
1. **Discovery** → Stores in `threat_engine_discoveries` database
2. **Check** → Reads from discoveries DB, stores in `threat_engine_check` database
3. **Inventory** → Reads from discoveries DB, stores in `threat_engine_inventory` database

## Endpoint

**POST** `/gateway/orchestrate`

### Request Body

```json
{
  "customer_id": "test-customer",
  "tenant_id": "test-tenant",
  "provider": "aws",
  "hierarchy_id": "588989875114",
  "hierarchy_type": "account",
  "include_services": ["s3", "iam"],
  "include_regions": null,
  "credentials": {
    "credential_type": "aws_access_key",
    "access_key_id": "...",
    "secret_access_key": "..."
  },
  "use_database": true
}
```

### Response

```json
{
  "orchestration_id": "orch_20260127_124500",
  "customer_id": "test-customer",
  "tenant_id": "test-tenant",
  "provider": "aws",
  "hierarchy_id": "588989875114",
  "started_at": "2026-01-27T12:45:00.000Z",
  "status": "completed",
  "discovery_scan_id": "discovery_20260127_124501",
  "check_scan_id": "check_20260127_124510",
  "inventory_scan_id": "inv_abc123",
  "completed_at": "2026-01-27T12:50:00.000Z",
  "steps": {
    "discovery": {
      "status": "completed",
      "discovery_scan_id": "discovery_20260127_124501",
      "message": "Discovery scan completed"
    },
    "check": {
      "status": "completed",
      "check_scan_id": "check_20260127_124510",
      "message": "Check scan completed"
    },
    "inventory": {
      "status": "completed",
      "scan_run_id": "inv_abc123",
      "message": "Inventory scan completed",
      "total_assets": 169,
      "total_relationships": 45
    }
  }
}
```

## Integration with Onboarding

The onboarding engine can trigger this orchestration based on schedule:

```python
# In engine_onboarding/orchestrator/engine_orchestrator.py
async def trigger_orchestration_pipeline(
    self,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider_type: str,
    credentials: Dict[str, Any]
):
    """Trigger complete orchestration pipeline via API Gateway"""
    api_gateway_url = os.getenv("API_GATEWAY_URL", "http://api-gateway:8000")
    
    request = {
        "customer_id": "default",  # Or from tenant
        "tenant_id": tenant_id,
        "provider": provider_type,
        "hierarchy_id": account_id,
        "hierarchy_type": "account",
        "credentials": credentials,
        "use_database": True
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{api_gateway_url}/gateway/orchestrate",
            json=request
        )
        return response.json()
```

## Database Flow

```
1. Discovery Engine
   └─> Runs discovery scan
   └─> Stores in: threat_engine_discoveries.discoveries

2. Check Engine
   └─> Reads from: threat_engine_discoveries.discoveries
   └─> Runs compliance checks
   └─> Stores in: threat_engine_check.check_results

3. Inventory Engine
   └─> Reads from: threat_engine_discoveries.discoveries
   └─> Normalizes to assets/relationships
   └─> Stores in: threat_engine_inventory (PostgreSQL + Neo4j)
```

## Environment Variables

```bash
# Engine URLs (defaults to localhost for local dev)
DISCOVERIES_ENGINE_URL=http://discoveries-engine:8001
CHECK_ENGINE_URL=http://check-engine:8002
INVENTORY_ENGINE_URL=http://inventory-engine:8022

# API Gateway URL (for onboarding to call)
API_GATEWAY_URL=http://api-gateway:8000
```

## Next Steps

1. ✅ Orchestration endpoint created
2. ⏳ Update onboarding orchestrator to use this endpoint
3. ⏳ Build Docker images
4. ⏳ Deploy to Kubernetes
