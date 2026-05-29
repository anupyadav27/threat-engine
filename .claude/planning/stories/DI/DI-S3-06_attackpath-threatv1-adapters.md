# DI-S3-06 — Attack-Path + Threat-V1 Adapters
**Sprint**: DI-S3 | **Points**: 13 | **Status**: Ready for Dev

## Goal
Switch attack-path and threat_v1 to read from `asset_inventory` + `asset_relationships` (DI DB)
when `DI_ENGINE_ENABLED=true`. These are the highest-complexity adapters: both engines read from
two source DBs and the attack-path engine has a critical JSONB public-indicator filter that must
be preserved exactly.

## Engine Positions
- Attack-path: Stage ~6.5 | engine-attack-path | `.claude/agents/threat.md`
- Threat-v1: Stage 4 | engine-threat-v1:80 → 8021 | `.claude/agents/threat.md`
- Image tags: `yadavanup84/engine-attack-path:v-attack-path-di1`, `yadavanup84/engine-threat-v1:v-threat-v1-di1`

## Files to Modify

### Attack-Path
- `engines/attack-path/attack_path_engine/run_scan.py` — `_mark_internet_exposed_from_discoveries()`: `discovery_findings` → `asset_inventory`; `get_discoveries_conn()` → DI DB conn when `DI_ENGINE_ENABLED=true`
- `engines/attack-path/attack_path_engine/graph/pg_graph.py` — `inventory_relationships` → `asset_relationships`; `INVENTORY_DB_*` → `DI_DB_*` when `DI_ENGINE_ENABLED=true`
- `deployment/aws/eks/engines/engine-attack-path.yaml` — replace `DISCOVERIES_DB_*` + `INVENTORY_DB_*` blocks with `DI_DB_*` + `DI_ENGINE_ENABLED=true`

### Threat-V1
- `engines/threat_v1/threat_v1/graph/resource_resolver.py` — `inventory_findings` → `asset_inventory`; `INVENTORY_DB_*` → `DI_DB_*` when `DI_ENGINE_ENABLED=true`; alias `resource_name AS resource_id`
- `engines/threat_v1/threat_v1/graph/edge_builder.py` — `inventory_relationships` → `asset_relationships`; `INVENTORY_DB_*` → `DI_DB_*` when `DI_ENGINE_ENABLED=true`
- `deployment/aws/eks/engines/engine-threat-v1.yaml` — replace `INVENTORY_DB_*` with `DI_DB_*` + `DI_ENGINE_ENABLED=true`

## Technical Notes

### Attack-path: _mark_internet_exposed_from_discoveries()
```python
def _mark_internet_exposed_from_discoveries(inventory_conn, tenant_id, scan_run_id):
    if DI_ENGINE_ENABLED:
        source_conn = psycopg2.connect(host=os.getenv("DI_DB_HOST"), ...)
        source_table = "asset_inventory"
    else:
        from engine_common.db_connections import get_discoveries_conn
        source_conn = get_discoveries_conn()
        source_table = "discovery_findings"
    try:
        with source_conn.cursor() as cur:
            cur.execute(f"""
                SELECT DISTINCT resource_uid
                FROM {source_table}
                WHERE tenant_id = %s
                  AND resource_uid IS NOT NULL AND resource_uid != ''
                  AND (
                    (emitted_fields->>'PublicIpAddress') IS NOT NULL
                    OR (emitted_fields->>'PubliclyAccessible') = 'true'
                    OR (emitted_fields->>'Scheme') = 'internet-facing'
                    OR (emitted_fields->>'FunctionUrl') IS NOT NULL
                    OR resource_type IN (
                      'apigateway.restapi','apigateway.httpapi',
                      'apigateway.v2api','apigatewayv2.api'
                    )
                  )
            """, (tenant_id,))
    finally:
        source_conn.close()
```

**JSONB filter preserved exactly**: `emitted_fields->>'PublicIpAddress'` and related operators are
identical in both `discovery_findings` and `asset_inventory`. No logic change.

**f-string for table name**: `source_table` is set from a controlled string constant (not user input).
All WHERE clause values remain parameterized (`%s`). This is safe.

**`source_conn` closed in `finally`**: mandatory — verified by security reviewer.

### Attack-path: pg_graph.py
```python
TABLE_RELS = "asset_relationships" if DI_ENGINE_ENABLED else "inventory_relationships"

def _get_conn():
    if DI_ENGINE_ENABLED:
        return psycopg2.connect(host=os.getenv("DI_DB_HOST"), ...)
    return psycopg2.connect(host=os.getenv("INVENTORY_DB_HOST"), ...)
```

Column names identical: `from_uid`, `to_uid`, `relation_type`, `from_resource_type`,
`to_resource_type`, `properties` — zero logic change.

`_ATTACK_RELEVANT_TYPES` frozenset contains relation_type enum values (not discovery_ids) — keep as-is.

### Threat-V1: resource_resolver.py
```python
TABLE_RESOURCES = "asset_inventory" if DI_ENGINE_ENABLED else "inventory_findings"
# Add alias in DI-path SELECT:
resource_name AS resource_id  -- inventory_findings has resource_id; asset_inventory has resource_name
```

### Threat-V1: edge_builder.py
```python
TABLE_RELS = "asset_relationships" if DI_ENGINE_ENABLED else "inventory_relationships"
```
Column names identical — zero logic change.

### K8s manifest changes
**engine-attack-path.yaml**: Remove `DISCOVERIES_DB_*` (5 keys) + `INVENTORY_DB_*` (5 keys); add `DI_DB_*` block.
**engine-threat-v1.yaml**: Remove `INVENTORY_DB_*` (5 keys); add `DI_DB_*` block.

## Acceptance Criteria

### Functional — Attack-Path
- [ ] `DI_ENGINE_ENABLED=false`: reads `discovery_findings` + `inventory_relationships` — unchanged
- [ ] `DI_ENGINE_ENABLED=true`: reads `asset_inventory` + `asset_relationships` from DI DB
- [ ] BFS produces ≥ 7 attack paths on test account
- [ ] Internet-facing resources (EC2 with public IP, internet-facing ALBs) appear as BFS entry points
- [ ] All `from_uid`/`to_uid` in BFS graph are in `asset_inventory.resource_uid`
- [ ] JSONB public-indicator filter (`emitted_fields->>'PublicIpAddress'`) preserved exactly
- [ ] `_ATTACK_RELEVANT_TYPES` relation_type set unchanged

### Functional — Threat-V1
- [ ] `DI_ENGINE_ENABLED=false`: reads `inventory_findings` + `inventory_relationships` — unchanged
- [ ] `DI_ENGINE_ENABLED=true`: reads `asset_inventory` + `asset_relationships` from DI DB
- [ ] T-counts within 10% of baseline (44T1 / 33T2 / 34T3)
- [ ] Crown jewel classifier finds ≥ 1 crown jewel
- [ ] Neo4j graph builds without node-label errors
- [ ] `resource_name AS resource_id` alias in `resource_resolver.py` DI-path SELECT

### Security (both)
- [ ] No DI credentials logged; `DI_DB_PASSWORD` from Secret
- [ ] `tenant_id` parameterized in all queries (both tables)
- [ ] Table name in f-string only from controlled constant — never from user input
- [ ] `source_conn` closed in `finally` block in attack-path

### RBAC Matrix
| Role | GET /api/v1/threat/* | GET /api/v1/incidents/* |
|------|---------------------|------------------------|
| platform_admin | 200 | 200 |
| org_admin | 200 | 200 |
| tenant_admin | 200 | 200 |
| analyst | 200 | 200 |
| viewer | 200 | 200 |

### Error Handling
- [ ] DI DB unreachable + `DI_ENGINE_ENABLED=true` → scan fails with ERROR; no silent fallback
- [ ] `source_conn` closed in `finally` even on exception (attack-path)

## Testing Requirements

**Unit** (4 files: `test_attack_path_run_scan_di.py`, `test_pg_graph_di.py`, `test_resource_resolver_di.py`, `test_edge_builder_di.py`):
- DI path: correct table names + DI DB conn
- Legacy path: old tables + legacy conn
- `resource_name AS resource_id` alias in `resource_resolver.py` DI-path SELECT
- JSONB filter `emitted_fields->>'PublicIpAddress'` identical on both paths
- `tenant_id` always parameterized; coverage ≥ 80% per file

**Integration — Attack-Path**:
1. Legacy BFS: record path count, entry-point UIDs
2. DI BFS: ≥ 7 paths; ≥ 90% entry-point UID overlap

**Integration — Threat-V1**:
1. Legacy T-counts recorded
2. DI T-counts: each within 10% of baseline; ≥ 1 crown jewel

**Post-deploy smoke**:
```bash
GET /api/v1/health/live (attack-path) → 200
GET /api/v1/health/live (threat-v1) → 200
kubectl logs -l app=engine-attack-path -n threat-engine-engines --tail=50 | grep -i error
kubectl logs -l app=engine-threat-v1 -n threat-engine-engines --tail=50 | grep -i error
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge (mandatory — DB conn change + BFS tenant isolation) |
| QA acceptance | cspm-qa | deploy |
| Post-deploy | cspm-post-deploy | close |

## Definition of Done
- [ ] Attack-path: `asset_inventory` + `asset_relationships` on DI path; ≥ 7 BFS paths
- [ ] Threat-v1: `asset_inventory` + `asset_relationships` on DI path; T-counts within 10%
- [ ] JSONB public-indicator filter preserved exactly in attack-path
- [ ] `resource_name AS resource_id` alias in threat-v1 resolver
- [ ] Unit tests ≥ 80% per file; integration passing
- [ ] 2 images pushed (attack-path-di1, threat-v1-di1)
- [ ] 2 K8s manifests updated (DISCOVERIES_DB_* + INVENTORY_DB_* removed; DI_DB_* added)
- [ ] bmad-security-reviewer gate passed; MEMORY.md updated

## Dependencies
- DI-S3-02 (`di_identifier_helper.py`)
- DI-S2-04 (`asset_relationships` populated with INTERNET_ACCESSIBLE + PLACED_IN relations)
- Neo4j connection unchanged (not affected)

## Rollback
```bash
kubectl set env deployment/engine-attack-path DI_ENGINE_ENABLED=false -n threat-engine-engines
kubectl set env deployment/engine-threat-v1 DI_ENGINE_ENABLED=false -n threat-engine-engines
```