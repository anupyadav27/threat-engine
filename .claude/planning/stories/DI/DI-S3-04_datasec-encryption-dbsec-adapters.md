# DI-S3-04 — DataSec + Encryption + DBSec Adapters
**Sprint**: DI-S3 | **Points**: 8 | **Status**: Ready for Dev

## Goal
Apply the DI adapter pattern to three stage-5 engines (DataSec, Encryption, DBSec). Each engine:
replaces hardcoded service/discovery_id lists with `get_discovery_ids_for_engine()`, swaps DB
connection to DI on `DI_ENGINE_ENABLED=true`, switches `inventory_relationships` to `asset_relationships`.
Special: Encryption's ILIKE service-name pattern is eliminated and replaced with explicit discovery_id filter.

## Engine Positions
- DataSec: Stage 5 | engine-datasec:80 → 8003 | `.claude/agents/datasec.md`
- Encryption: Stage 5 | engine-encryption:80 → 8006 | `.claude/agents/encryption.md`
- DBSec: Stage 5 | engine-dbsec:80 → 8007 | `.claude/agents/dbsec.md`
- Image tags: `yadavanup84/engine-datasec:v-datasec-di1`, `yadavanup84/engine-encryption-security:v-encryption-di1`, `yadavanup84/engine-dbsec:v-dbsec-di1`

## Files to Modify

### DataSec
- `engines/datasec/data_security_engine/input/discovery_db_reader.py` — replace 16-item list with `get_discovery_ids_for_engine('datasec', provider)`; swap DB
- `engines/datasec/data_security_engine/input/inventory_reader.py` — `inventory_relationships` → `asset_relationships`; swap DB

### Encryption
- `engines/encryption-security/encryption_security_engine/input/inventory_reader.py` — replace `ILIKE '%kms%'` / `ILIKE '%acm%'` pattern with `discovery_id = ANY(%s)` using `get_discovery_ids_for_engine('encryption', provider)`; swap DB; `inventory_relationships` → `asset_relationships`

### DBSec
- `engines/dbsec/dbsec_engine/providers/base.py` — refactor `db_resource_types` abstract property to dynamic on DI path; rename existing implementations to `_static_db_resource_types`; swap DB

## Technical Notes

### DataSec — hardcoded list → identifier table
```python
DATASEC_DISCOVERY_IDS = ["aws.s3.list_buckets", "aws.s3.get_bucket_encryption", ...]  # 16 items
# DI path:
from engine_common.di_identifier_helper import get_discovery_ids_for_engine
discovery_ids = (get_discovery_ids_for_engine('datasec', provider)
                 if DI_ENGINE_ENABLED else DATASEC_DISCOVERY_IDS)
```

### Encryption — ILIKE → explicit discovery_id
ILIKE on service name is fragile. On DI path, replace entirely:
```python
discovery_ids = get_discovery_ids_for_engine('encryption', provider)
# Query:
WHERE discovery_id = ANY(%s) AND tenant_id = %s
```
KMS keys, ACM certs, Secrets Manager rows are all tagged `used_by_engines=['encryption']` in
identifier table. No ILIKE needed.

Verify: `grep -r "ILIKE.*kms\|ILIKE.*acm" engines/encryption-security/` → 0 lines in DI-path branches.

### DBSec — abstract property refactor
```python
# base.py
@property
def db_resource_types(self) -> List[str]:
    if DI_ENGINE_ENABLED:
        from engine_common.di_identifier_helper import get_discovery_ids_for_engine
        ids = get_discovery_ids_for_engine('dbsec', self.provider)
        if ids:
            return ids
    return self._static_db_resource_types()

@property
def _static_db_resource_types(self) -> List[str]:
    raise NotImplementedError
# Subclasses: rename db_resource_types → _static_db_resource_types
```

### Shared K8s env block (all three — DI_DB_* confirmed by DI-S2-05)
For Encryption: remove existing `DISCOVERIES_DB_*` and `INVENTORY_DB_*` blocks (replaced by DI_DB_*).

## Acceptance Criteria

### Functional — DataSec
- [ ] `DI_ENGINE_ENABLED=false`: hardcoded list, `discovery_findings` — unchanged
- [ ] `DI_ENGINE_ENABLED=true`: identifier table + `asset_inventory`
- [ ] S3 classification findings present; delta ≤ 5%
- [ ] `inventory_relationships` → `asset_relationships` on DI path

### Functional — Encryption
- [ ] ILIKE pattern removed from DI path (grep verifies 0 occurrences in DI path)
- [ ] KMS findings + cert expiry findings present; delta ≤ 5%
- [ ] No ILIKE in DI-path code branches of changed files

### Functional — DBSec
- [ ] `_static_db_resource_types` works on legacy path (no regression)
- [ ] `get_discovery_ids_for_engine('dbsec', provider)` called on DI path
- [ ] RDS/Aurora/DynamoDB findings present; delta ≤ 5%

### Security (all three)
- [ ] No DI credentials logged
- [ ] `tenant_id` in parameterized WHERE on every query
- [ ] No `DEV_BYPASS_AUTH` or hardcoded passwords

### RBAC Matrix (all three)
| Role | GET findings | POST scan |
|------|-------------|-----------|
| platform_admin | 200 | 200 |
| org_admin | 200 | 200 |
| tenant_admin | 200 | 200 |
| analyst | 200 | 403 |
| viewer | 403 | 403 |

### Error Handling
- [ ] `get_discovery_ids_for_engine()` returns `[]` → 0 rows, WARNING; no crash
- [ ] DI DB unreachable → ERROR, no silent fallback

## Testing Requirements

**Unit** (3 files: `test_datasec_reader_di.py`, `test_encryption_reader_di.py`, `test_dbsec_reader_di.py`):
- DI vs legacy path assertions per engine
- Encryption: ILIKE absent in DI path; `discovery_id = ANY(%s)` present
- DBSec: `_static_db_resource_types` called on legacy; `get_discovery_ids_for_engine` on DI
- Coverage ≥ 80% per changed file

**Integration** (per engine): legacy count → DI count; delta ≤ 5%; key findings present

**Post-deploy smoke** (3 engines):
```bash
GET /api/v1/data-security/health/live → 200
GET /api/v1/encryption/health/live → 200
GET /api/v1/database-security/health/live → 200
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge (ILIKE removal + all 3 engines) |
| QA acceptance | cspm-qa | deploy |
| Post-deploy | cspm-post-deploy | close |

## Definition of Done
- [ ] All 3 engines read `asset_inventory` + `asset_relationships` on DI path
- [ ] Encryption ILIKE removed; replaced with identifier table lookup
- [ ] DBSec abstract property refactored
- [ ] Per-engine count delta ≤ 5%
- [ ] Unit tests ≥ 80% per file; integration passing
- [ ] 3 images pushed (datasec-di1, encryption-di1, dbsec-di1)
- [ ] 3 health checks → 200; no ERROR in logs
- [ ] bmad-security-reviewer gate passed; MEMORY.md updated

## Dependencies
- DI-S3-02 (`di_identifier_helper.py`)
- DI-S2-04 (`asset_relationships` populated)
- identifier table seeded for datasec / encryption / dbsec engines

## Rollback
```bash
kubectl set env deployment/engine-datasec DI_ENGINE_ENABLED=false -n threat-engine-engines
kubectl set env deployment/engine-encryption DI_ENGINE_ENABLED=false -n threat-engine-engines
kubectl set env deployment/engine-dbsec DI_ENGINE_ENABLED=false -n threat-engine-engines
```