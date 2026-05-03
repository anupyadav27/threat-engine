---
name: inventory-engine
description: Full-context agent for the Inventory engine — asset normalization, relationships, drift detection. Covers DB schema, all API endpoints, BFF views, UI pages, K8s service, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

You are the Inventory Engine specialist. You know every detail of this engine's DB, API, BFF, and pipeline role.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** Stage 2 — runs after discovery, before check.
**Reads:** `discovery_findings` from `threat_engine_discoveries` DB
**Writes:** `inventory_findings`, `inventory_relationships`, `inventory_drift` in `threat_engine_inventory`
**Feeds downstream:** threat engine (Neo4j graph), check engine (resource context), BFF inventory view
**Credentials:** NONE — reads from DB only, no cloud API calls
**Execution:** Spawns a K8s Job (not run in API pod)
**Timeout:** 14400s (4 hours)

---

## 2. Database

**DB name:** `threat_engine_inventory`
**Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

### Tables

**`inventory_findings`** — normalized cloud assets (latest state per resource_uid)
```
asset_id            UUID PK
tenant_id           UUID FK
resource_uid        TEXT UNIQUE        -- canonical ID across all engines
provider            VARCHAR
account_id          VARCHAR
region              VARCHAR
resource_type       VARCHAR
resource_id         VARCHAR
name, display_name, description VARCHAR
tags                JSONB              -- ALREADY A DICT
labels              JSONB              -- ALREADY A DICT
properties          JSONB              -- ALREADY A DICT
configuration       JSONB              -- ALREADY A DICT
compliance_status   VARCHAR
risk_score          INTEGER (0-100)
criticality, environment, cost_center, owner, business_unit VARCHAR
latest_scan_run_id  UUID
scan_run_id         UUID
first_seen_at, last_seen_at TIMESTAMP
```

**`inventory_relationships`** — resource connections
```
relationship_id     UUID PK
tenant_id, scan_run_id, provider, account_id, region
relation_type       VARCHAR    -- attached_to|member_of|depends_on|contains|exposes|...
from_uid            TEXT       -- source resource_uid
to_uid              TEXT       -- target resource_uid
from_resource_type, to_resource_type VARCHAR
relationship_strength FLOAT
bidirectional       BOOLEAN
properties, metadata JSONB
first_discovered_at, last_confirmed_at TIMESTAMP
```

**`inventory_drift`** — config changes between scans
```
drift_id            UUID
scan_run_id, previous_scan_id UUID
asset_id            UUID FK
resource_uid        TEXT
change_type         VARCHAR    -- added|removed|modified
previous_state, current_state, changes_summary JSONB
severity            VARCHAR
detected_at         TIMESTAMP
```

**`inventory_asset_history`** — per-asset change log
```
history_id          UUID PK
asset_id            UUID FK
scan_run_id         UUID
change_type         VARCHAR
previous_state, current_state, changes_summary JSONB
detected_at         TIMESTAMP
```

**`resource_inventory_identifier`** — static step5 catalog (authoritative for what CAN be inventoried)
```
csp, service, resource_type     UNIQUE KEY
classification, has_arn, arn_entity, identifier_type
primary_param, identifier_pattern, canonical_type
asset_category, can_inventory_from_roots, should_inventory
parent_service, parent_resource_type
root_ops, enrich_ops, raw_catalog JSONB
```
Never hardcode resource types — query this table.

**`resource_relationship_rules`** — 369 DB-driven relationship extraction rules
```
rule_id             BIGSERIAL PK
csp, service, from_resource_type, relation_type, to_resource_type
source_field, source_field_item, target_uid_pattern
attack_path_category VARCHAR
is_active           BOOLEAN
rule_metadata       JSONB
UNIQUE(csp, from_resource_type, relation_type, to_resource_type, source_field)
```
Loaded at job startup from DB. Changes take effect on next scan — no code deploy needed.

**`inventory_asset_collections`**, **`inventory_asset_collection_membership`** — business groupings
**`inventory_asset_tags_index`** — fast tag-based queries
**`inventory_asset_metrics`** — performance metrics (cpu, memory, cost)

### Common Queries

```sql
-- Asset count for a scan
SELECT COUNT(*) FROM inventory_findings
WHERE scan_run_id = $1 AND tenant_id = $2;

-- Assets by service
SELECT resource_type, provider, COUNT(*) c
FROM inventory_findings
WHERE tenant_id = $1 AND latest_scan_run_id = $2
GROUP BY resource_type, provider ORDER BY c DESC;

-- Relationships for a resource
SELECT from_uid, relation_type, to_uid, to_resource_type
FROM inventory_relationships
WHERE tenant_id = $1 AND scan_run_id = $2
  AND (from_uid = $3 OR to_uid = $3);

-- Drift this scan vs last
SELECT resource_uid, change_type, changes_summary
FROM inventory_drift
WHERE scan_run_id = $1 AND tenant_id = $2
ORDER BY severity DESC;
```

---

## 3. API Endpoints

**SERVICE URL:** `http://engine-inventory` (port 80 in cluster)
**CRITICAL PORT NOTE:** BFF calls use `http://engine-inventory:8022` (explicit port). Do not change without updating BFF.

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| POST | `/api/v1/scan` | `scan_run_id`, `tenant_id`, `providers`, `accounts` | Trigger scan job |
| GET | `/api/v1/inventory/scan/{scan_run_id}/status` | path | Poll job status |
| GET | `/api/v1/inventory/runs/{scan_run_id}/summary` | path | Totals (assets, relationships, errors) |
| GET | `/api/v1/inventory/runs/latest/summary` | — | Latest scan summary |
| GET | `/api/v1/inventory/assets` | `tenant_id`, `?scan_run_id=latest`, `?provider`, `?region`, `?resource_type`, `?account_id`, `?limit=100`, `?offset=0` | Paginated asset list |
| GET | `/api/v1/inventory/assets/{resource_uid}` | path, `?tenant_id` | Asset detail + drift_info |
| GET | `/api/v1/inventory/assets/{resource_uid}/drift` | path, `?tenant_id` | Full drift history |
| GET | `/api/v1/inventory/assets/{resource_uid}/relationships` | path, `?tenant_id` | All relationships for asset |
| GET | `/api/v1/inventory/assets/{resource_uid}/blast-radius` | path, `?tenant_id`, `?max_depth=3` | BFS blast radius |
| GET | `/api/v1/inventory/graph` | `tenant_id`, `?scan_run_id=latest`, `?relation_type`, `?depth=2` | Full asset graph |
| GET | `/api/v1/inventory/relationships` | `tenant_id`, `?scan_run_id=latest`, `?from_resource_type`, `?to_resource_type` | Edge list |
| GET | `/api/v1/inventory/taxonomy` | `tenant_id` | Resource taxonomy hierarchy |
| GET | `/api/v1/inventory/architecture` | `tenant_id`, `?scan_run_id=latest` | Architecture view |
| GET | `/api/v1/inventory/drift` | `tenant_id`, `?scan_run_id`, `?severity` | Drift list |
| GET | `/api/v1/inventory/ui-data` | `tenant_id`, `?scan_run_id=latest`, `?limit=2000` | Pre-joined assets+threat counts for BFF |
| GET | `/api/v1/admin/rules` | — | List relationship rules |
| POST | `/api/v1/admin/rules` | rule JSON | Upsert relationship rule |
| POST | `/api/v1/admin/rules/reload` | — | Reload rule cache |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |

---

## 4. BFF Views I Feed

**`shared/api_gateway/bff/inventory.py`** — `GET /gateway/api/v1/views/inventory`

Parallel calls:
1. `http://engine-inventory:8022/api/v1/inventory/ui-data` — assets with pre-joined threat severity counts
2. `http://engine-threat:8020/api/v1/threat/ui-data` — threat detections per resource
3. `http://engine-onboarding/api/v1/cloud-accounts` — provider enrichment

Response: assets list with `{resource_uid, resource_type, service, region, provider, account_id, risk_score, critical/high/medium/low finding counts}`.

BFF timeout for inventory: 10.0s.

---

## 5. UI Pages I Power

- **`/inventory`** — main asset inventory table (full list, filters, drill-down)
- **`/inventory/{resource_uid}`** — asset detail: properties, relationships, drift history, findings
- **`/dashboard`** — total assets KPI card, asset-by-provider chart

---

## 6. K8s Service

```yaml
name: engine-inventory
namespace: threat-engine-engines
image: yadavanup84/inventory-engine:v-inventory-auth
containerPort: 8022
service: ClusterIP port 80 → targetPort 8022    ← BFF must use :8022 explicitly
replicas: 1
resources:
  requests: 100m CPU, 256Mi memory
  limits: 500m CPU, 1Gi memory
liveness:  GET /api/v1/health/live  port 8022  initialDelay=30  period=15  failThreshold=20
readiness: GET /api/v1/health/ready port 8022  initialDelay=10  period=10  failThreshold=3
env: PORT=8022, ENGINE_NAME=inventory, USE_DATABASE=true
```

Scanner Job (spot node): `SCANNER_CPU_REQUEST=250m`, `SCANNER_MEM_REQUEST=1Gi`

---

## 7. Engine-Specific Gotchas

**BFF uses explicit :8022** — `http://engine-inventory:8022/api/v1/inventory/ui-data`. Do not change without updating BFF.

**No cloud credentials needed** — reads from `discovery_findings` DB only.

**resource_uid is universal** — same value across discovery_findings, inventory_findings, check_findings, threat_findings. Always join on resource_uid.

**Relationship rules in DB** — 369 rules live in `resource_relationship_rules` table. `resource_inventory_identifier` is the authoritative catalog for what resource types are inventoried. Never hardcode resource types.

**scan_run_id (not inventory_scan_id)** — the `inventory_report` table uses `scan_run_id` as PK. An old agent file said `inventory_scan_id` — that is wrong.

**Blast radius uses BFS** — `/blast-radius` does BFS graph traversal on `inventory_relationships`. This is inventory-level reachability, distinct from `blast_radius_score` in the risk engine.

---

## 8. Common Workflows

### Debug zero inventory assets
1. Confirm discovery ran: `SELECT COUNT(*) FROM discovery_findings WHERE scan_run_id = $1` in discoveries DB
2. Check inventory_report status: `SELECT status FROM inventory_report WHERE scan_run_id = $1`
3. Check logs: `kubectl logs -l app=engine-inventory -n threat-engine-engines --tail=200`
4. Check relationship rules: `GET /api/v1/admin/rules/stats`

### Add a new relationship rule
```sql
INSERT INTO resource_relationship_rules
  (csp, service, from_resource_type, relation_type, to_resource_type,
   source_field, target_uid_pattern, is_active)
VALUES ('aws', 'ec2', 'AWS::EC2::Instance', 'attached_to', 'AWS::EC2::Volume',
        'BlockDeviceMappings[*].Ebs.VolumeId',
        'arn:aws:ec2:{region}:{account}:volume/{value}', true);

POST http://engine-inventory/api/v1/admin/rules/reload
```

### Port-forward
```bash
kubectl port-forward svc/engine-inventory 8022:80 -n threat-engine-engines
```