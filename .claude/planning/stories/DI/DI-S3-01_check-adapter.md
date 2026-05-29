# DI-S3-01 — Check Engine Adapter
**Sprint**: DI-S3 | **Points**: 8 | **Status**: Ready for Dev

## Goal
Switch the check engine's discovery data source from `discovery_findings` (discoveries DB) to
`asset_inventory` (DI DB) when `DI_ENGINE_ENABLED=true`. Pure DB connection + table name swap
behind an env flag. No eval logic, check_findings schema, or RBAC changes.

## Engine Position
- Stage: 3 | K8s svc: engine-check:80 → 8002 | Agent: `.claude/agents/check.md`
- Image tag: `yadavanup84/engine-check-aws:v-check-di1`

## Files to Modify
- `engines/check/common/database/discovery_reader.py` — DI flag: `DI_ENGINE_ENABLED=true` → connect to `DI_DB_*`, query `asset_inventory`; alias `resource_name AS resource_id`
- `engines/check/common/database/inventory_reader.py` — same DI flag for any inventory_findings reads
- `deployment/aws/eks/engines/engine-check.yaml` — confirm `DI_ENGINE_ENABLED`, `DI_DB_*` env vars (added by DI-S2-05)

## DI Flag Pattern (apply to every reader)
```python
DI_ENGINE_ENABLED = os.getenv("DI_ENGINE_ENABLED", "false").lower() == "true"
TABLE = "asset_inventory" if DI_ENGINE_ENABLED else "discovery_findings"

def _build_conn_config() -> dict:
    if DI_ENGINE_ENABLED:
        return {"host": os.getenv("DI_DB_HOST"),
                "port": int(os.getenv("DI_DB_PORT", "5432")),
                "database": os.getenv("DI_DB_NAME", "threat_engine_di"),
                "user": os.getenv("DI_DB_USER", "postgres"),
                "password": os.getenv("DI_DB_PASSWORD", "")}
    return {"host": os.getenv("DISCOVERIES_DB_HOST", "localhost"),
            "port": int(os.getenv("DISCOVERIES_DB_PORT", "5432")),
            "database": os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
            "user": os.getenv("DISCOVERIES_DB_USER", "postgres"),
            "password": os.getenv("DISCOVERIES_DB_PASSWORD", "")}
```

**Column alias**: `asset_inventory` has `resource_name` where `discovery_findings` has `resource_id`.
Add `resource_name AS resource_id` in all DI-path SELECT clauses.

**discovery_id filter**: Check engine reads discovery_ids from `rule_discoveries` in check DB —
already DB-driven. No `get_discovery_ids_for_engine()` call needed for check engine.

**No silent fallback**: DI DB unreachable + `DI_ENGINE_ENABLED=true` → raise, do not fall back.

## Acceptance Criteria

### Functional
- [ ] `DI_ENGINE_ENABLED=false`: reads `discovery_findings` — zero behaviour change
- [ ] `DI_ENGINE_ENABLED=true`: reads `asset_inventory` from DI DB
- [ ] check_findings count delta ≤ 2% for same scan_run_id
- [ ] resource_uid in check_findings 100% canonical (no `region:name` UIDs) when DI is source
- [ ] PASS/FAIL outcomes for 10 known rules identical between old and DI source
- [ ] `resource_name` aliased as `resource_id` — downstream sees no breakage

### Security
- [ ] No DI_DB credentials in logs
- [ ] All queries include `tenant_id = %s` parameterized
- [ ] No `DEV_BYPASS_AUTH` in changed files
- [ ] `DI_DB_PASSWORD` from K8s Secret only

### RBAC Matrix
| Role | GET /api/v1/check/findings | POST /api/v1/check/scan |
|------|--------------------------|------------------------|
| platform_admin | 200 | 200 |
| org_admin | 200 | 200 |
| tenant_admin | 200 | 200 |
| analyst | 200 | 403 |
| viewer | 200 | 403 |

### Error Handling
- [ ] DI DB unreachable + `DI_ENGINE_ENABLED=true` → scan fails with ERROR log, no silent fallback
- [ ] Connection pool ≥ 3; pool exhaustion logged at WARN

## Testing Requirements

**Unit** (`tests/engines/check/test_discovery_reader_di.py`):
- `DI_ENGINE_ENABLED=true` → `asset_inventory` table + `DI_DB_HOST` conn
- `DI_ENGINE_ENABLED=false` → `discovery_findings` + `DISCOVERIES_DB_HOST`
- `resource_name AS resource_id` alias in DI-path SELECT
- `tenant_id` always parameterized
- Coverage ≥ 80% on changed reader files

**Integration**:
1. `DI_ENGINE_ENABLED=false` scan → record check_findings count
2. `DI_ENGINE_ENABLED=true` same scan → delta ≤ 2%
3. 10 test rules: PASS/FAIL identical

**Regression**: Baseline `rule_finding_counts.json` — count not decreased by > 2%

**Post-deploy smoke**:
```bash
GET /api/v1/health/live → 200
kubectl logs -l app=engine-check -n threat-engine-engines --tail=50 | grep -i error
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge |
| QA acceptance | cspm-qa | deploy |
| Post-deploy | cspm-post-deploy | close |

## Definition of Done
- [ ] `DI_ENGINE_ENABLED=true` reads `asset_inventory` from DI DB
- [ ] Finding count delta ≤ 2% validated
- [ ] Unit tests ≥ 80% coverage; integration passing
- [ ] RBAC 5×2 matrix passing
- [ ] Image pushed as `yadavanup84/engine-check-aws:v-check-di1`
- [ ] Health live → 200; no ERROR in first 50 log lines
- [ ] bmad-security-reviewer gate passed
- [ ] MEMORY.md updated

## Dependencies
- DI-S2-05 (DI_ENGINE_ENABLED + DI_DB_* env vars in manifest)
- engine-di live with `asset_inventory` populated

## Rollback
```bash
kubectl set env deployment/engine-check DI_ENGINE_ENABLED=false -n threat-engine-engines
```