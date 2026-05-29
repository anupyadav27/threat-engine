# DI-S3-02 — IAM Engine Adapter
**Sprint**: DI-S3 | **Points**: 5 | **Status**: Ready for Dev

## Goal
Switch IAM engine discovery reads from `discovery_findings` (discoveries DB, `service='iam'` filter)
to `asset_inventory` (DI DB) when `DI_ENGINE_ENABLED=true`. Replace hardcoded `service='iam'` filter
with `get_discovery_ids_for_engine('iam', provider)` lookup. Create `shared/common/di_identifier_helper.py`
used by all downstream DI-S3 adapter stories.

## Engine Position
- Stage: 5 | K8s svc: engine-iam:80 → 8003 | Agent: `.claude/agents/iam.md`
- Image tag: `yadavanup84/engine-iam:v-iam-di1`

## Files to Create / Modify
- `shared/common/di_identifier_helper.py` — CREATE: `get_discovery_ids_for_engine(engine, provider) -> List[str]`
- `engines/iam/iam_engine/input/discovery_db_reader.py` — DI flag: connect to `DI_DB_*`, query `asset_inventory`; replace `service='iam'` with `discovery_id = ANY(%s)`
- `deployment/aws/eks/engines/engine-iam.yaml` — confirm `DI_ENGINE_ENABLED` + `DI_DB_*` env (from DI-S2-05)

## di_identifier_helper.py (shared/common/)
```python
"""Shared helper: query resource_inventory_identifier for engine-specific discovery_ids."""
import os
import logging
from typing import List
import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


def get_discovery_ids_for_engine(engine: str, provider: str) -> List[str]:
    """Return discovery_ids tagged for a given engine+provider from resource_inventory_identifier.

    Args:
        engine: Engine name in used_by_engines array (e.g. 'iam', 'network', 'datasec')
        provider: CSP name ('aws', 'azure', 'gcp', 'oci', 'ibm', 'alicloud', 'k8s')

    Returns:
        List of discovery_id strings. Empty list on DB error (caller handles gracefully).
    """
    try:
        conn = psycopg2.connect(
            host=os.getenv("INVENTORY_DB_HOST"),
            port=int(os.getenv("INVENTORY_DB_PORT", "5432")),
            database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
            user=os.getenv("INVENTORY_DB_USER", "postgres"),
            password=os.getenv("INVENTORY_DB_PASSWORD", ""),
        )
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT DISTINCT
                      csp || '.' || service || '.' || (root_ops->0->>'operation') AS discovery_id
                    FROM resource_inventory_identifier
                    WHERE %s = ANY(used_by_engines)
                      AND csp = %s
                      AND should_inventory = TRUE
                    ORDER BY 1
                    """,
                    (engine, provider),
                )
                rows = cur.fetchall()
            ids = [r["discovery_id"] for r in rows if r["discovery_id"]]
            logger.info("get_discovery_ids_for_engine(%s, %s) → %d ids", engine, provider, len(ids))
            return ids
        finally:
            conn.close()
    except Exception as exc:
        logger.error("get_discovery_ids_for_engine(%s, %s) failed: %s", engine, provider, exc)
        return []
```

## IAM Reader Change (discovery_db_reader.py)

Old DI-path query:
```sql
SELECT ... FROM discovery_findings
WHERE scan_run_id = %s AND tenant_id = %s AND service = 'iam'
```

New DI-path query:
```python
discovery_ids = get_discovery_ids_for_engine('iam', provider)
# Query:
SELECT discovery_id, resource_uid, resource_type,
       emitted_fields, raw_response, account_id, region
FROM asset_inventory
WHERE scan_run_id = %s AND tenant_id = %s AND discovery_id = ANY(%s)
```
Params: `[scan_run_id, tenant_id, discovery_ids]`

## Acceptance Criteria

### Functional
- [ ] `DI_ENGINE_ENABLED=false`: reads `discovery_findings` with `service='iam'` — unchanged
- [ ] `DI_ENGINE_ENABLED=true`: reads `asset_inventory` filtered by `get_discovery_ids_for_engine('iam', provider)`
- [ ] IAM findings count delta ≤ 5%
- [ ] 5 known test policies produce same PASS/FAIL on old vs DI source
- [ ] `get_discovery_ids_for_engine('iam', 'aws')` returns ≥ 15 discovery_ids

### Security
- [ ] No credentials logged; `DI_DB_PASSWORD` from Secret only
- [ ] `tenant_id` always parameterized
- [ ] `discovery_ids` used as `ANY(%s)` — no string interpolation

### RBAC Matrix
| Role | GET /iam-security/findings | POST /iam-security/scan |
|------|--------------------------|------------------------|
| platform_admin | 200 | 200 |
| org_admin | 200 | 200 |
| tenant_admin | 200 | 200 |
| analyst | 200 | 403 |
| viewer | 403 | 403 |

### Error Handling
- [ ] `get_discovery_ids_for_engine()` returns `[]` on DB error → 0 rows, WARNING; no crash
- [ ] DI DB unreachable → ERROR log, no silent fallback

## Testing Requirements

**Unit** (`tests/engines/iam/test_discovery_reader_di.py`):
- DI path uses `DI_DB_HOST`, table `asset_inventory`
- Legacy path uses `DISCOVERIES_DB_HOST`, table `discovery_findings`
- `service='iam'` replaced by `discovery_id = ANY(%s)` on DI path
- `get_discovery_ids_for_engine` called with `('iam', provider)` on DI path
- Coverage ≥ 80% on changed reader files

**Unit** (`tests/common/test_di_identifier_helper.py`):
- Mock psycopg2: assert SQL uses parameterized `%s = ANY(used_by_engines)`
- Empty result → returns `[]`, no exception

**Integration**: Count delta ≤ 5%; 5 test policies PASS/FAIL identical

**Post-deploy smoke**:
```bash
GET /api/v1/health/live → 200
kubectl logs -l app=engine-iam -n threat-engine-engines --tail=50 | grep -i error
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge |
| QA acceptance | cspm-qa | deploy |
| Post-deploy | cspm-post-deploy | close |

## Definition of Done
- [ ] `shared/common/di_identifier_helper.py` created
- [ ] IAM reader uses `get_discovery_ids_for_engine` + `asset_inventory` on DI path
- [ ] Count delta ≤ 5%; integration passing
- [ ] Unit tests ≥ 80% coverage
- [ ] Image pushed as `yadavanup84/engine-iam:v-iam-di1`
- [ ] Health → 200; no ERROR in first 50 log lines
- [ ] bmad-security-reviewer gate passed; MEMORY.md updated

## Dependencies
- DI-S2-05 (DI_ENGINE_ENABLED + DI_DB_* in manifest)
- DI-S1-02 (`used_by_engines` column seeded in identifier table)

## Rollback
```bash
kubectl set env deployment/engine-iam DI_ENGINE_ENABLED=false -n threat-engine-engines
```