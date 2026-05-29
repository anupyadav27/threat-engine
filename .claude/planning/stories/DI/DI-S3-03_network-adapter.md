# DI-S3-03 — Network Engine Adapter
**Sprint**: DI-S3 | **Points**: 8 | **Status**: Ready for Dev

## Goal
Replace the hardcoded discovery_id list in the network engine's discovery reader with
`get_discovery_ids_for_engine('network', provider)`. Switch DB from discoveries/inventory to
DI DB when `DI_ENGINE_ENABLED=true`. Switch `inventory_relationships` reads to `asset_relationships`.

## Engine Position
- Stage: 5 | K8s svc: engine-network:80 → 8004 | Agent: `.claude/agents/network-security.md`
- Image tag: `yadavanup84/engine-network-security:v-net-di1`

## Files to Modify
- `engines/network-security/network_security_engine/input/discovery_db_reader.py` — replace `NETWORK_DISCOVERY_MAP` hardcoded values with `get_discovery_ids_for_engine('network', provider)` on DI path; swap DB conn
- `engines/network-security/network_security_engine/input/inventory_reader.py` — `inventory_relationships` → `asset_relationships`; `INVENTORY_DB_*` → `DI_DB_*` on DI path
- `deployment/aws/eks/engines/engine-network.yaml` — confirm `DI_ENGINE_ENABLED` + `DI_DB_*` env (from DI-S2-05)

## Technical Notes

**NETWORK_DISCOVERY_MAP replacement**:
Current code builds a 40-item hardcoded list. On DI path, replace with:
```python
from engine_common.di_identifier_helper import get_discovery_ids_for_engine

def _get_discovery_ids(provider: str) -> list:
    if DI_ENGINE_ENABLED:
        return get_discovery_ids_for_engine('network', provider)
    return list(NETWORK_DISCOVERY_MAP.values())  # legacy unchanged
```

Keep `NETWORK_DISCOVERY_MAP` for logical-name grouping on the legacy path. On DI path, group
results by discovery_id prefix for sub-layer routing.

**DB connection swap**:
```python
def _get_conn():
    if DI_ENGINE_ENABLED:
        return psycopg2.connect(host=os.getenv("DI_DB_HOST"), ...)
    from engine_common.db_connections import get_discoveries_conn
    return get_discoveries_conn()
```

**inventory_reader.py swap** (column names identical — zero logic change):
```python
TABLE_RELS = "asset_relationships" if DI_ENGINE_ENABLED else "inventory_relationships"
```

**7-layer coverage**: All 7 sub-layers read through `NetworkDiscoveryReader.load_all_network_resources()`.
After this change, all 7 sub-layers use DI DB transparently — no per-layer changes.

## Acceptance Criteria

### Functional
- [ ] `DI_ENGINE_ENABLED=false`: hardcoded list + `discovery_findings` — unchanged
- [ ] `DI_ENGINE_ENABLED=true`: `get_discovery_ids_for_engine('network', provider)` + `asset_inventory`
- [ ] `inventory_reader.py`: `asset_relationships` on DI path (identical column names — zero logic change)
- [ ] Network findings count delta ≤ 5%
- [ ] All 7 sub-layers (isolation/reachability/ACL/SG/LB/WAF/monitoring) produce findings after switch
- [ ] Internet-facing resources found via `asset_relationships.relation_type='INTERNET_ACCESSIBLE'`
- [ ] WAF coverage: `wafv2.*` rows found in `asset_inventory`

### Security
- [ ] No DI credentials in logs; `DI_DB_PASSWORD` from Secret only
- [ ] `tenant_id` parameterized in both `asset_inventory` and `asset_relationships` queries
- [ ] `get_discovery_ids_for_engine()` result used as `ANY(%s)` — no string interpolation

### RBAC Matrix
| Role | GET /network-security/findings | POST /network-security/scan |
|------|-------------------------------|------------------------------|
| platform_admin | 200 | 200 |
| org_admin | 200 | 200 |
| tenant_admin | 200 | 200 |
| analyst | 200 | 403 |
| viewer | 403 | 403 |

### Error Handling
- [ ] `get_discovery_ids_for_engine()` returns `[]` → 0 rows, WARNING; scan completes with 0 findings
- [ ] DI DB unreachable → ERROR, no silent fallback

## Testing Requirements

**Unit** (`tests/engines/network/test_discovery_reader_di.py`):
- DI path: `get_discovery_ids_for_engine` called; `asset_inventory` queried
- Legacy path: `NETWORK_DISCOVERY_MAP.values()` used; `discovery_findings` queried
- `inventory_reader.py`: `asset_relationships` on DI; `inventory_relationships` on legacy
- `tenant_id` always parameterized; coverage ≥ 80%

**Integration**:
1. Legacy network scan: record per-layer finding counts
2. DI network scan: delta ≤ 5%; each of 7 sub-layers produces ≥ 1 finding

**Post-deploy smoke**:
```bash
GET /api/v1/health/live → 200
kubectl logs -l app=engine-network -n threat-engine-engines --tail=50 | grep -i error
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge |
| QA acceptance | cspm-qa | deploy |
| Post-deploy | cspm-post-deploy | close |

## Definition of Done
- [ ] Hardcoded 40-item list replaced with `get_discovery_ids_for_engine('network', provider)` on DI path
- [ ] `inventory_relationships` → `asset_relationships` on DI path
- [ ] Count delta ≤ 5%; all 7 sub-layers produce findings
- [ ] Unit tests ≥ 80%; integration passing
- [ ] Image pushed as `yadavanup84/engine-network-security:v-net-di1`
- [ ] K8s manifest verified; health 200; no ERROR
- [ ] bmad-security-reviewer gate passed; MEMORY.md updated

## Dependencies
- DI-S3-02 (`shared/common/di_identifier_helper.py` created)
- DI-S2-04 (`asset_relationships` populated with INTERNET_ACCESSIBLE + topology relations)
- `resource_inventory_identifier` seeded with `used_by_engines=['network']` for all 40 network discovery_ids

## Rollback
```bash
kubectl set env deployment/engine-network DI_ENGINE_ENABLED=false -n threat-engine-engines
```