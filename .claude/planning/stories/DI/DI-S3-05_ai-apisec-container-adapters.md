# DI-S3-05 — AI-Sec + API-Sec + Container-Sec Adapters
**Sprint**: DI-S3 | **Points**: 8 | **Status**: Ready for Dev

## Goal
Apply the DI adapter to AI Security, API Security, and Container Security engines. Replace
hardcoded service/resource_type filter lists with `get_discovery_ids_for_engine()`. The
AI-sec `CATALOG_NOISE_DISCOVERY_IDS` exclusion list is eliminated on DI path — those discovery_ids
are not registered in `used_by_engines` so they are implicitly excluded.

## Engine Positions
- AI Security: Stage 5 | engine-ai-security:80 → 8032 | `.claude/agents/ai-security.md`
- API Security: Stage 5 | engine-api-security:80 → 8035
- Container Security: Stage 5 | engine-container-sec:80 → 8008 | `.claude/agents/container-security.md`
- Image tags: `v-ai-security-di1`, `v-apisec-di1`, `v-container-di1`

## Files to Modify

### AI Security
- `engines/ai-security/ai_security_engine/input/discovery_reader.py` — replace `AI_SERVICES` frozenset + `CATALOG_NOISE_DISCOVERY_IDS` exclusion with `get_discovery_ids_for_engine('ai-security', provider)` on DI path; swap DB

### API Security
- `engines/api-security/api_security_engine/input/discovery_reader.py` — replace `_API_RESOURCE_TYPES` tuple + update `load_waf_associations()` to use `discovery_id = ANY(%s)` on DI path; swap DB

### Container Security
- `engines/container-security/container_security_engine/providers/base.py` — `discovery_services` abstract property → dynamic on DI path via `get_discovery_ids_for_engine('container-security', provider)`; rename existing to `_static_discovery_services` in all subclasses

## Technical Notes

### AI Security — catalog noise eliminated implicitly
Current query: `service = ANY(%s) AND discovery_id != ALL(%s)` (AI_SERVICES + CATALOG_NOISE exclusion).
DI path: `discovery_id = ANY(%s)` using identifier table result.
The 7 catalog noise discovery_ids are not tagged `used_by_engines=['ai-security']` — they will not
appear in the result. Exclusion is implicit and maintenance-free.
Keep `AI_SERVICES` and `CATALOG_NOISE_DISCOVERY_IDS` constants for the legacy path — unused on DI path.

### API Security — WAF association update
`load_waf_associations()` currently filters by `resource_type IN ('aws.wafv2.web_acl_association', ...)`.
On DI path: `discovery_id IN (%s, %s)` with exact discovery_id strings from identifier table.
Confirm exact discovery_id strings before coding.

### Container Security — base refactor (same as DBSec pattern in DI-S3-04)
```python
@property
def discovery_services(self) -> List[str]:
    if DI_ENGINE_ENABLED:
        from engine_common.di_identifier_helper import get_discovery_ids_for_engine
        ids = get_discovery_ids_for_engine('container-security', self.provider)
        if ids:
            return ids
    return self._static_discovery_services()
```

## Acceptance Criteria

### Functional — AI Security
- [ ] `DI_ENGINE_ENABLED=false`: `AI_SERVICES` + noise exclusion used, reads `discovery_findings`
- [ ] `DI_ENGINE_ENABLED=true`: identifier table, reads `asset_inventory`
- [ ] SageMaker + Bedrock findings present; delta ≤ 5%
- [ ] Catalog noise discovery_ids produce 0 rows on DI path (not in identifier table)
- [ ] No hardcoded `AI_SERVICES` in DI-path code branch

### Functional — API Security
- [ ] `_API_RESOURCE_TYPES` replaced on DI path with identifier table lookup
- [ ] API Gateway + WAF findings present; delta ≤ 5%
- [ ] `load_waf_associations()` uses discovery_id filter on DI path

### Functional — Container Security
- [ ] `_static_discovery_services` contains former hardcoded list; legacy unchanged
- [ ] DI path calls `get_discovery_ids_for_engine('container-security', provider)`
- [ ] EKS cluster findings present; delta ≤ 5%

### Security (all three)
- [ ] No DI credentials logged; `DI_DB_PASSWORD` from Secret
- [ ] `tenant_id` parameterized in every query
- [ ] No `DEV_BYPASS_AUTH`

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

**Unit** (3 files):
- DI vs legacy path assertions per engine
- AI-sec: catalog noise exclusion absent on DI path
- API-sec: `_API_RESOURCE_TYPES` absent; WAF uses discovery_id
- Container-sec: `_static_discovery_services` on legacy; `get_discovery_ids_for_engine` on DI
- Coverage ≥ 80% per changed file

**Integration** (3 engines): count delta ≤ 5%; key findings present

**Post-deploy smoke**:
```bash
GET /api/v1/ai-security/health/live → 200
GET /api/v1/container-security/health/live → 200
kubectl logs -l app=engine-api-security -n threat-engine-engines --tail=50 | grep -i error
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge |
| QA acceptance | cspm-qa | deploy |
| Post-deploy | cspm-post-deploy | close |

## Definition of Done
- [ ] All 3 engines use `get_discovery_ids_for_engine()` on DI path; no hardcoded lists in DI branches
- [ ] AI-sec catalog noise eliminated implicitly
- [ ] API-sec WAF query updated
- [ ] Container-sec base refactored
- [ ] Count delta ≤ 5% per engine; key findings present
- [ ] Unit ≥ 80% coverage; integration passing
- [ ] 3 images pushed; 3 health checks → 200; no ERROR in logs
- [ ] bmad-security-reviewer gate passed; MEMORY.md updated

## Dependencies
- DI-S3-02 (`di_identifier_helper.py`)
- identifier table seeded for ai-security / api-sec / container-security engines
- API Security apisec_001+002+003 migrations applied

## Rollback
```bash
kubectl set env deployment/engine-ai-security DI_ENGINE_ENABLED=false -n threat-engine-engines
kubectl set env deployment/engine-api-security DI_ENGINE_ENABLED=false -n threat-engine-engines
kubectl set env deployment/engine-container-sec DI_ENGINE_ENABLED=false -n threat-engine-engines
```