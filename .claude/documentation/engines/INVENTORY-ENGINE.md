# Inventory Engine — Architecture & API Reference

> Last updated: 2026-02-22 | Image: `yadavanup84/inventory-engine:v6-multi-csp`

## Overview

The Inventory Engine normalises raw discovery data from the Discoveries DB into a structured
asset graph: **Assets** (inventory_findings) and **Relationships** (inventory_relationships).
It runs after the Discoveries Engine and before the Check/Compliance/IAM/DataSec engines.

**Pipeline position**: `onboarding → discoveries → **inventory** → check → compliance/iam/datasec`

Port: **8022** | Namespace: `threat-engine-engines` | Service: `engine-inventory`

---

## Architecture

### Key Files

| File | Purpose |
|------|---------|
| `engine_inventory/inventory_engine/api/api_server.py` | FastAPI server, all endpoints |
| `engine_inventory/inventory_engine/api/orchestrator.py` | Two-pass scan logic (root → enrich) |
| `engine_inventory/inventory_engine/api/inventory_db_loader.py` | Read assets/rels/summaries from inventory DB |
| `engine_inventory/inventory_engine/connectors/discovery_db_reader.py` | Read discovery_findings from discoveries DB |
| `engine_inventory/inventory_engine/connectors/step5_catalog_loader.py` | Step5 catalog for ARN extraction + op classification |
| `engine_inventory/inventory_engine/index/index_writer.py` | Write assets/rels/reports to inventory DB |
| `engine_inventory/inventory_engine/normalizer/asset_normalizer.py` | Convert discovery record → Asset schema |
| `engine_inventory/inventory_engine/normalizer/relationship_builder.py` | Build edges from DB-loaded relationship rules |

### Databases

| DB | Env Vars | Purpose |
|----|----------|---------|
| `threat_engine_inventory` | `INVENTORY_DB_*` | Write: inventory_findings, inventory_relationships, inventory_report |
| `threat_engine_discoveries` | `DISCOVERIES_DB_*` | Read: discovery_findings |
| `threat_engine_check` | `CHECK_DB_*` | Read (optional): check_findings for posture enrichment |
| `threat_engine_onboarding` | `ONBOARDING_DB_*` | Read/Write: scan_orchestration |

### Two-Pass Scan Algorithm

**Pass 1 — Root records** (`is_root=True` per Step5 catalog):
- Classify each discovery record using `step5_catalog_loader`
- Create primary Asset (e.g., S3 bucket, EC2 instance, IAM role)
- Extract ARN via `step5.arn_entity` dot-path when `resource_arn` is missing

**Pass 2 — Dependent records** (`is_root=False`):
- Merge enrichment data into existing assets' `configuration`
- Match parent asset via `resource_uid` or `param_sources` strategy

---

## API Endpoints

All endpoints use `tenant_id` as a required query param (unless noted).

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness/readiness probe |
| GET | `/` | Service info |

### Scan Triggers

| Method | Path | Body | Notes |
|--------|------|------|-------|
| POST | `/api/v1/scan` | `ScanRequest` | Synchronous scan (blocks until complete, uses thread pool) |
| POST | `/api/v1/inventory/scan/discovery` | `DiscoveryScanRequest` | Recommended endpoint; handles pipeline mode via `orchestration_id` |
| POST | `/api/v1/inventory/scan/discovery/async` | `DiscoveryScanRequest` | Returns `job_id` immediately, runs in background thread |
| GET | `/api/v1/inventory/jobs/{job_id}` | — | Poll async job status |

**DiscoveryScanRequest fields:**
```json
{
  "tenant_id": "...",
  "orchestration_id": "...",        // pipeline mode: reads discovery_scan_id from scan_orchestration
  "discovery_scan_id": "...",       // ad-hoc mode: direct scan id (or omit for orchestration_id)
  "accounts": ["588989875114"],     // optional filter — multi-account supported
  "providers": ["aws"],             // optional filter
  "previous_scan_id": "..."         // optional: for drift detection
}
```

**Pipeline mode** (via `orchestration_id`):
1. Reads `discovery_scan_id`, `account_id`, `provider_type`, `tenant_id` from `scan_orchestration`
2. Runs the inventory scan
3. Writes `inventory_scan_id` back to `scan_orchestration`

### Scan Results / Summaries

| Method | Path | Query Params | Notes |
|--------|------|-------------|-------|
| GET | `/api/v1/inventory/runs/latest/summary` | `tenant_id` | Latest completed scan summary from inventory_report |
| GET | `/api/v1/inventory/runs/{scan_run_id}/summary` | `tenant_id` | Specific scan summary; also handles `scan_run_id=latest` |
| GET | `/api/v1/inventory/scans` | `tenant_id` | List available discovery scans |

**Summary response fields**: `inventory_scan_id`, `tenant_id`, `started_at`, `completed_at`, `status`, `total_assets`, `total_relationships`, `assets_by_provider` (JSONB), `assets_by_resource_type` (JSONB), `assets_by_region` (JSONB), `providers_scanned`, `accounts_scanned`, `regions_scanned`, `errors_count`

### Assets

| Method | Path | Query Params | Notes |
|--------|------|-------------|-------|
| GET | `/api/v1/inventory/assets` | `tenant_id`, `scan_run_id`, `provider`, `region`, `resource_type`, `account_id`, `account_ids`, `limit`, `offset` | Paginated asset list. `account_ids` = comma-separated for multi-account |
| GET | `/api/v1/inventory/assets/{resource_uid}` | `tenant_id`, `scan_run_id` | Single asset by resource_uid |
| GET | `/api/v1/inventory/assets/{resource_uid}/relationships` | `tenant_id`, `scan_run_id`, `depth`, `relation_type`, `direction` | Asset relationships (inbound/outbound/both) |
| GET | `/api/v1/inventory/assets/{resource_uid}/drift` | `tenant_id`, `limit` | Returns empty + hint to use `/drift` endpoint |

**Multi-account example:**
```
GET /api/v1/inventory/assets?tenant_id=T&account_ids=111111111111,222222222222&limit=100
```

**Asset response schema:**
```json
{
  "schema_version": "cspm_asset.v1",
  "tenant_id": "...",
  "scan_run_id": "...",
  "provider": "aws",
  "account_id": "588989875114",
  "region": "ap-south-1",
  "resource_type": "ec2.instance",
  "resource_id": "i-0abc123...",
  "resource_uid": "arn:aws:ec2:...",
  "name": "my-instance",
  "tags": {},
  "metadata": {}
}
```

### Relationships

| Method | Path | Query Params | Notes |
|--------|------|-------------|-------|
| GET | `/api/v1/inventory/relationships` | `tenant_id`, `scan_run_id`, `relation_type`, `provider`, `account_id`, `from_uid`, `to_uid`, `limit`, `offset` | Paginated relationship list |

### Graph

| Method | Path | Query Params | Notes |
|--------|------|-------------|-------|
| GET | `/api/v1/inventory/graph` | `tenant_id`, `scan_run_id`, `resource_uid`, `depth`, `limit` | Returns `nodes` + `edges` for visualization |

### Drift

| Method | Path | Query Params | Notes |
|--------|------|-------------|-------|
| GET | `/api/v1/inventory/drift` | `tenant_id`, `baseline_scan`, `compare_scan`, `provider`, `resource_type`, `account_id` | Compare two scan runs. Supply BOTH `baseline_scan` + `compare_scan` for diff output |
| GET | `/api/v1/inventory/runs/{scan_run_id}/drift` | `tenant_id`, `change_type`, `provider`, `resource_type`, `account_id` | Returns empty + hint |

### Summaries by Dimension

| Method | Path | Query Params | Notes |
|--------|------|-------------|-------|
| GET | `/api/v1/inventory/accounts/{account_id}` | `tenant_id`, `scan_run_id` | Assets grouped by service + region for a specific account |
| GET | `/api/v1/inventory/services/{service}` | `tenant_id`, `scan_run_id` | Assets grouped by account/region/resource_type for a service (prefix match, e.g. `ec2`) |

---

## Multi-Account Support

The inventory engine fully supports multiple cloud accounts in a single scan:

### Per-request multi-account (direct API call)
```json
POST /api/v1/inventory/scan/discovery
{
  "tenant_id": "...",
  "discovery_scan_id": "...",
  "accounts": ["111111111111", "222222222222", "333333333333"]
}
```

### Query assets across multiple accounts
```
GET /api/v1/inventory/assets?tenant_id=T&account_ids=111111111111,222222222222&limit=500
```

### How multi-account works internally
1. `accounts` list is passed to `orchestrator.run_scan_from_discovery()`
2. Orchestrator passes `account_ids=accounts` (or `account_id=accounts[0]` for single) to `DiscoveryDBReader.read_discovery_records()`
3. DB reader uses `WHERE hierarchy_id = ANY(%s::text[])` for multi-account or `WHERE hierarchy_id = %s` for single
4. Assets written to inventory_findings with their respective `account_id`

---

## Multi-CSP Support

The engine is CSP-agnostic at the pipeline level. CSP is determined by:
1. `provider_type` column in `scan_orchestration` (pipeline mode)
2. `providers` field in request body (direct mode)
3. `provider` column in `discovery_findings` (per-record)

**Supported CSPs**: `aws`, `azure`, `gcp`, `oci`, `alicloud`, `ibm`

Step5 catalog files at `data_pythonsdk/{csp}/{service}/step5_resource_catalog_inventory_enrich.json`
drive the root/enrichment classification for each CSP.

---

## Important Implementation Notes

### FastAPI Route Ordering Bug
`GET /api/v1/inventory/runs/{scan_run_id}/summary` matches BEFORE the static
`/api/v1/inventory/runs/latest/summary` route. The `{scan_run_id}` handler therefore
handles `scan_run_id="latest"` by calling `get_latest_scan_id()` first.

### DB Column Names (actual RDS)
- `inventory_findings`: uses `inventory_scan_id` (NOT `scan_run_id`)
- `inventory_relationships`: uses `inventory_scan_id` (NOT `scan_run_id`)
- Always check actual RDS columns before writing DB queries

### Asyncio / Liveness Probes
Long-running scans (~73s for 1,529 assets) run in a `ThreadPoolExecutor` (`_scan_executor`, 4 workers)
via `await loop.run_in_executor(...)`. This keeps the asyncio event loop free so that:
- `GET /health` liveness probes always respond
- Pods are not killed mid-scan by kubelet

### psycopg2 JSONB Auto-Deserialisation
psycopg2 returns JSONB columns as Python dicts directly. Never call `json.loads()` on them.
Use `isinstance(d, dict)` guard: `d if isinstance(d, dict) else json.loads(d)`.

---

## Deployment

### Current Production State
- **Image**: `yadavanup84/inventory-engine:v6-multi-csp`
- **Replicas**: 1
- **Resources**: request 128Mi/50m, limit 512Mi/250m
- **Liveness**: `GET /health` every 15s, failureThreshold 20 (5 min grace for long scans)
- **Manifest**: `deployment/aws/eks/engines/engine-inventory.yaml`

### Build & Deploy
```bash
# Build
docker build -t yadavanup84/inventory-engine:v6-multi-csp \
  -f engine_inventory/Dockerfile .

# Push
docker push yadavanup84/inventory-engine:v6-multi-csp

# Deploy
kubectl apply -f deployment/aws/eks/engines/engine-inventory.yaml
kubectl rollout status deployment/engine-inventory -n threat-engine-engines
```

### Test via Port-Forward
```bash
kubectl port-forward svc/engine-inventory 8022:80 -n threat-engine-engines &

# Health
curl http://localhost:8022/health

# Trigger pipeline scan
curl -X POST http://localhost:8022/api/v1/inventory/scan/discovery \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "...", "orchestration_id": "..."}'

# Latest summary
curl "http://localhost:8022/api/v1/inventory/runs/latest/summary?tenant_id=..."

# Assets for specific account
curl "http://localhost:8022/api/v1/inventory/assets?tenant_id=...&account_ids=588989875114&limit=100"
```

### External ELB Access
- Path prefix: `/inventory`
- Health: `http://<ELB>/inventory/health`
- Assets: `http://<ELB>/inventory/api/v1/inventory/assets?tenant_id=...`

---

## Verified Test Results (2026-02-22)

| Endpoint | Result |
|----------|--------|
| `GET /health` | 200 `{"status":"healthy"}` |
| `GET /api/v1/inventory/runs/latest/summary?tenant_id=T` | 200, total_assets=1529, total_relationships=199 |
| `GET /api/v1/inventory/assets?tenant_id=T&limit=5` | 200, total=1440, 5 assets returned |
| `GET /api/v1/inventory/assets?...&account_ids=588989875114&limit=5` | 200, multi-account filter works |
| `GET /api/v1/inventory/relationships?tenant_id=T&limit=3` | 200, total=199 |
| `GET /api/v1/inventory/graph?tenant_id=T&limit=5` | 200, 5 nodes + edges |
| `GET /api/v1/inventory/accounts/588989875114?tenant_id=T` | 200, by_service: {ec2:1163, iam:238, lambda:18, s3:21} |
| `GET /api/v1/inventory/services/ec2?tenant_id=T` | 200, total_assets=1163 |
| `GET /api/v1/inventory/drift?...&baseline_scan=A&compare_scan=B` | 200, drift records for changed assets |
| Scan via orchestration_id | 1529 assets, 199 rels in ~73s, inventory_scan_id written to scan_orchestration |
