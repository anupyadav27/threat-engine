# Orchestration API - Discovery → Check → Threat → (Compliance + IAM + DataSec) → Inventory

## Overview

The orchestration API runs the full CSPM pipeline in order:

1. **Discovery** → Scans cloud resources, stores in `threat_engine_discoveries`
2. **Check** → Reads discoveries, runs compliance checks, stores in `threat_engine_check`
3. **Threat** → Reads check results, runs threat analysis (incl. drift), writes threat report
4. **Compliance, IAM, DataSec** → Run in parallel after Threat:
   - **Compliance** reads from Check DB (via `scan_run_id`)
   - **IAM** and **DataSec** read from Threat/Check DB (via `scan_run_id`)
5. **Inventory** → Reads discoveries, builds assets/relationships, stores in `threat_engine_inventory`

## Endpoint

```
POST /gateway/orchestrate
```

## Request Body

```json
{
  "customer_id": "customer-123",
  "tenant_id": "tenant-456",
  "provider": "aws",
  "account_id": "588989875114",
  "hierarchy_type": "account",
  "include_services": ["s3", "iam"],
  "include_regions": ["us-east-1"],
  "credentials": {
    "credential_type": "aws_access_key",
    "access_key_id": "...",
    "secret_access_key": "..."
  },
  "use_database": true
}
```

## Response

```json
{
  "scan_run_id": "550e8400-e29b-41d4-a716-446655440000",
  "customer_id": "customer-123",
  "tenant_id": "tenant-456",
  "provider": "aws",
  "account_id": "588989875114",
  "started_at": "2026-01-27T12:45:00",
  "completed_at": "2026-01-27T12:50:00",
  "status": "completed",
  "steps": {
    "discovery": { "status": "completed", "scan_run_id": "..." },
    "check": { "status": "completed", "scan_run_id": "..." },
    "threat": { "status": "completed", "report_id": "...", "total_threats": 42 },
    "compliance": { "status": "completed", "report_id": "..." },
    "iam_security": { "status": "completed", "findings_count": 10 },
    "data_security": { "status": "completed", "findings_count": 5 },
    "inventory": { "status": "completed", "scan_run_id": "...", "total_assets": 169, "total_relationships": 45 }
  }
}
```

## Integration with Onboarding

The onboarding engine can trigger orchestration on schedule:

```python
# In engine_onboarding/orchestrator/engine_orchestrator.py
async def trigger_orchestration(self, scan_run_id, tenant_id, account_id, provider_type):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://api-gateway:8000/gateway/orchestrate",
            json={
                "customer_id": customer_id,
                "tenant_id": tenant_id,
                "provider": provider_type,
                "account_id": account_id,
                "hierarchy_type": "account",
                "use_database": True
            }
        )
        return response.json()
```

## Environment Variables

```bash
# Engine URLs (use same hostnames/ports as in Kubernetes or local)
DISCOVERIES_ENGINE_URL=http://discoveries-engine:8001
CHECK_ENGINE_URL=http://check-engine:8002
THREAT_ENGINE_URL=http://threat-engine:8020
COMPLIANCE_ENGINE_URL=http://compliance-engine:8010
IAM_ENGINE_URL=http://iam-engine:8003
DATASEC_ENGINE_URL=http://datasec-engine:8004
INVENTORY_ENGINE_URL=http://inventory-engine:8022
```

## Database Flow

```
1. Discovery Engine
   └─> POST /api/v1/discovery
   └─> Stores in threat_engine_discoveries.discoveries
   └─> Uses scan_run_id

2. Check Engine
   └─> POST /api/v1/check (scan_run_id)
   └─> Reads threat_engine_discoveries, runs checks
   └─> Stores in threat_engine_check.check_results

3. Threat Engine
   └─> POST /api/v1/threat/generate (scan_run_id)
   └─> Reads check DB, writes threat report

4. Compliance / IAM / DataSec (parallel)
   └─> Compliance: POST /api/v1/compliance/generate/from-check-db (scan_run_id)
   └─> IAM:       POST /api/v1/iam-security/scan (scan_run_id)
   └─> DataSec:   POST /api/v1/data-security/scan (scan_run_id)

5. Inventory Engine
   └─> POST /api/v1/inventory/scan/discovery (scan_run_id)
   └─> Reads threat_engine_discoveries
   └─> Stores in threat_engine_inventory
```

## Build and Deploy

### Build Docker image

```bash
cd /Users/apple/Desktop/threat-engine/api_gateway
docker build -t api-gateway:latest .
```

### Deploy to Kubernetes

Set the engine URLs in the API gateway deployment (env or ConfigMap) and deploy. Ensure discoveries, check, threat, compliance, IAM, datasec, and inventory services are running and reachable at the configured URLs.
