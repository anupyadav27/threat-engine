# engine_inventory — Asset Inventory & Relationships

> Port: **8022** | Image: `yadavanup84/inventory-engine:v6-multi-csp`
> Database: `threat_engine_inventory` (PostgreSQL)
> Last updated: 2026-02-22

---

## External URL (via ELB)

```
http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/inventory
```

## Internal ClusterIP

```
http://engine-inventory.threat-engine-engines.svc.cluster.local:80
# Short form (same namespace):
http://engine-inventory:80
```

---

## Key Architecture Notes

- **Two-pass scan**: Pass 1 = root resources → create assets. Pass 2 = enrichment records → merge into assets.
- **Step5 catalog**: ARN patterns and root/enrichment classification come from `resource_inventory_identifier` DB table (loaded from `data_pythonsdk/{csp}/{service}/step5_resource_catalog_inventory_enrich.json`).
- **Multi-account**: All scan and query endpoints accept `account_ids` (comma-separated list).
- **Multi-CSP**: Supported — `aws`, `azure`, `gcp`, `oci`, `alicloud`, `ibm`. CSP determined by `provider_type` in `scan_orchestration` or per-record `provider` field.
- **Asyncio safe**: Long scans (~73s for 1,529 assets) run in a `ThreadPoolExecutor` so liveness probes always respond.
- **FastAPI route note**: `/api/v1/inventory/runs/{scan_run_id}/summary` handles `scan_run_id="latest"` by calling `get_latest_scan_id()` first — the static `/latest/` route cannot come before the parameterized one in FastAPI.

---

## Folder Structure

```
engine_inventory/inventory_engine/
├── api/
│   ├── api_server.py             # FastAPI server, all endpoints
│   ├── orchestrator.py           # Two-pass scan logic (root → enrich)
│   └── inventory_db_loader.py   # Read assets/rels/summaries from inventory DB
├── connectors/
│   ├── discovery_db_reader.py   # Read discovery_findings from discoveries DB
│   └── step5_catalog_loader.py  # Step5 catalog for ARN extraction + op classification
├── index/
│   └── index_writer.py          # Write assets/rels/reports to inventory DB
├── normalizer/
│   ├── asset_normalizer.py      # Convert discovery record → Asset schema
│   └── relationship_builder.py  # Build edges from DB-loaded relationship rules
└── database/connection/
    └── database_config.py       # DB connection factory
```

---

## Databases Used

| DB | Env Vars | Access |
|----|----------|--------|
| `threat_engine_inventory` | `INVENTORY_DB_*` | WRITE: inventory_findings, inventory_relationships, inventory_report |
| `threat_engine_discoveries` | `DISCOVERIES_DB_*` | READ: discovery_findings |
| `threat_engine_onboarding` | `ONBOARDING_DB_*` | READ: scan_orchestration (get discovery_scan_id, account_id) |
| | | WRITE: scan_orchestration.inventory_scan_id |

---

## Endpoint Reference

All endpoints use `tenant_id` as a required query param.

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness / readiness probe → `{"status":"healthy"}` |
| GET | `/` | Service info |

### Scan Triggers

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/scan` | Synchronous scan (legacy, blocks caller) |
| POST | `/api/v1/inventory/scan/discovery` | **Recommended**: pipeline scan via discovery data |
| POST | `/api/v1/inventory/scan/discovery/async` | Returns `job_id` immediately, runs in background |
| GET | `/api/v1/inventory/jobs/{job_id}` | Poll async job status |

**DiscoveryScanRequest** (body for `/api/v1/inventory/scan/discovery`):
```json
{
  "tenant_id": "...",
  "orchestration_id": "...",          // pipeline mode: looks up discovery_scan_id from scan_orchestration
  "discovery_scan_id": "...",         // ad-hoc mode: direct scan id (omit when using orchestration_id)
  "accounts": ["588989875114", "..."], // optional: multi-account filter
  "providers": ["aws"],               // optional: CSP filter
  "previous_scan_id": "..."           // optional: for drift detection
}
```

**Pipeline mode** (recommended): pass `orchestration_id` only. Engine reads
`discovery_scan_id`, `account_id`, `provider_type` from `scan_orchestration`, runs
the scan, then writes `inventory_scan_id` back to `scan_orchestration`.

### Scan Results / Summaries

| Method | Path | Query Params | Notes |
|--------|------|-------------|-------|
| GET | `/api/v1/inventory/runs/latest/summary` | `tenant_id` | Latest completed scan summary |
| GET | `/api/v1/inventory/runs/{scan_run_id}/summary` | `tenant_id` | Specific scan; also handles `scan_run_id=latest` |
| GET | `/api/v1/inventory/scans` | `tenant_id` | List available discovery scans |

**Summary response fields**: `inventory_scan_id`, `tenant_id`, `started_at`,
`completed_at`, `status`, `total_assets`, `total_relationships`,
`assets_by_provider` (JSONB), `assets_by_resource_type` (JSONB),
`assets_by_region` (JSONB), `providers_scanned`, `accounts_scanned`,
`regions_scanned`, `errors_count`

### Assets

| Method | Path | Query Params | Notes |
|--------|------|-------------|-------|
| GET | `/api/v1/inventory/assets` | `tenant_id`, `scan_run_id`, `provider`, `region`, `resource_type`, `account_id`, `account_ids`, `limit` (default 100), `offset` | Paginated asset list. `account_ids` = comma-separated |
| GET | `/api/v1/inventory/assets/{resource_uid}` | `tenant_id`, `scan_run_id` | Single asset by resource_uid |
| GET | `/api/v1/inventory/assets/{resource_uid}/relationships` | `tenant_id`, `scan_run_id`, `depth`, `relation_type`, `direction` | Asset relationships (inbound/outbound/both) |
| GET | `/api/v1/inventory/assets/{resource_uid}/drift` | `tenant_id`, `limit` | Hint to use `/drift` endpoint |

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
  "resource_uid": "arn:aws:ec2:ap-south-1:588989875114:instance/i-0abc123",
  "name": "my-instance",
  "tags": {},
  "metadata": {}
}
```

### Relationships

| Method | Path | Query Params | Notes |
|--------|------|-------------|-------|
| GET | `/api/v1/inventory/relationships` | `tenant_id`, `scan_run_id`, `relation_type`, `provider`, `account_id`, `from_uid`, `to_uid`, `limit`, `offset` | Paginated list |

### Graph

| Method | Path | Query Params | Notes |
|--------|------|-------------|-------|
| GET | `/api/v1/inventory/graph` | `tenant_id`, `scan_run_id`, `resource_uid`, `depth`, `limit` | Returns `nodes` + `edges` for graph visualisation |

### Drift

| Method | Path | Query Params | Notes |
|--------|------|-------------|-------|
| GET | `/api/v1/inventory/drift` | `tenant_id`, `baseline_scan`, `compare_scan`, `provider`, `resource_type`, `account_id` | Compare two scan runs. Requires both `baseline_scan` + `compare_scan` |
| GET | `/api/v1/inventory/runs/{scan_run_id}/drift` | `tenant_id`, `change_type`, `provider`, `resource_type`, `account_id` | Returns hint to use `/drift` |

### Summaries by Dimension

| Method | Path | Query Params | Notes |
|--------|------|-------------|-------|
| GET | `/api/v1/inventory/accounts/{account_id}` | `tenant_id`, `scan_run_id` | Assets grouped by service + region for an account |
| GET | `/api/v1/inventory/services/{service}` | `tenant_id`, `scan_run_id` | Assets for a service prefix (e.g. `ec2` matches `ec2.instance`, `ec2.security-group`, …) |

---

## Database Tables

| Table | Description |
|-------|-------------|
| `inventory_findings` | Normalised asset records. Key cols: `inventory_scan_id`, `tenant_id`, `resource_uid`, `provider`, `account_id`, `region`, `resource_type`, `resource_id`, `name`, `tags` |
| `inventory_relationships` | Asset edges. Key cols: `inventory_scan_id`, `tenant_id`, `from_uid`, `to_uid`, `relation_type`, `provider`, `account_id` |
| `inventory_report` | Per-scan summary. Key cols: `inventory_scan_id`, `total_assets`, `total_relationships`, `assets_by_provider`, `assets_by_resource_type`, `assets_by_region`, `status` |
| `resource_inventory_identifier` | Static step5 catalog (seeded once). Cols: `service`, `resource_type`, `arn_entity`, `root_ops`, `enrich_ops`, `identifier_pattern`, `parent_resource_type` |

**Important**: Column name is `inventory_scan_id` in all inventory tables, NOT `scan_run_id`.

---

## UI Page Mapping

| UI Page | API Endpoint | Notes |
|---------|-------------|-------|
| Asset Inventory list | `GET /api/v1/inventory/assets` | Use `account_ids` for multi-account |
| Asset Detail | `GET /api/v1/inventory/assets/{uid}` | |
| Asset Relationships | `GET /api/v1/inventory/assets/{uid}/relationships` | |
| Asset Graph | `GET /api/v1/inventory/graph` | Returns nodes + edges |
| Drift / Changes | `GET /api/v1/inventory/drift` | Pass both `baseline_scan` and `compare_scan` |
| Scan Summary | `GET /api/v1/inventory/runs/latest/summary` | |
| Account Dashboard | `GET /api/v1/inventory/accounts/{account_id}` | |
| Service Breakdown | `GET /api/v1/inventory/services/{service}` | |

---

## Sample Calls (via ELB)

```bash
ELB=a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com

# Health check
curl http://$ELB/inventory/health

# Trigger scan (pipeline mode)
curl -X POST http://$ELB/inventory/api/v1/inventory/scan/discovery \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"T","orchestration_id":"<uuid>"}'

# Latest scan summary
curl "http://$ELB/inventory/api/v1/inventory/runs/latest/summary?tenant_id=T"

# List assets (first 100)
curl "http://$ELB/inventory/api/v1/inventory/assets?tenant_id=T&limit=100"

# Multi-account assets
curl "http://$ELB/inventory/api/v1/inventory/assets?tenant_id=T&account_ids=111111111111,222222222222&limit=100"

# Graph (5 nodes)
curl "http://$ELB/inventory/api/v1/inventory/graph?tenant_id=T&limit=5"

# Relationships
curl "http://$ELB/inventory/api/v1/inventory/relationships?tenant_id=T&limit=50"

# Account summary
curl "http://$ELB/inventory/api/v1/inventory/accounts/588989875114?tenant_id=T"

# Service breakdown
curl "http://$ELB/inventory/api/v1/inventory/services/ec2?tenant_id=T"

# Drift between two scans
curl "http://$ELB/inventory/api/v1/inventory/drift?tenant_id=T&baseline_scan=<id1>&compare_scan=<id2>"
```

---

## Verified Test Results (2026-02-22)

| Endpoint | Result |
|----------|--------|
| `GET /health` | 200 `{"status":"healthy"}` |
| `GET /api/v1/inventory/runs/latest/summary?tenant_id=T` | 200 — total_assets=1529, total_relationships=199 |
| `GET /api/v1/inventory/assets?tenant_id=T&limit=5` | 200 — total=1440, 5 assets returned |
| `GET /api/v1/inventory/assets?...&account_ids=588989875114&limit=5` | 200 — multi-account filter works |
| `GET /api/v1/inventory/relationships?tenant_id=T&limit=3` | 200 — total=199 |
| `GET /api/v1/inventory/graph?tenant_id=T&limit=5` | 200 — 5 nodes + edges |
| `GET /api/v1/inventory/accounts/588989875114?tenant_id=T` | 200 — by_service: {ec2:1163, iam:238, lambda:18, s3:21} |
| `GET /api/v1/inventory/services/ec2?tenant_id=T` | 200 — total_assets=1163 |
| `GET /api/v1/inventory/drift?...&baseline_scan=A&compare_scan=B` | 200 — drift records for changed assets |
| Scan via orchestration_id | 1529 assets, 199 rels in ~73s; `inventory_scan_id` written to scan_orchestration |
