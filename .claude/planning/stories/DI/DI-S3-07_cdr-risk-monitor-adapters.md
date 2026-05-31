# DI-S3-07 — CDR + Risk + Pipeline-Monitor + Threat-Narrative Adapters
**Sprint**: DI-S3 | **Points**: 8 | **Status**: Ready for Dev

## Goal
Apply the DI adapter to 4 remaining components. CDR: replace LIKE-based log source queries on
`discovery_findings` with exact discovery_id lookup from identifier table. Risk: switch resource
context reads to `asset_inventory`. Pipeline monitor: update count table + step label. Threat
narrative: switch `discovery_findings` read to `asset_inventory`.

## Engine Positions
- CDR: Stage 5 (CronWorkflow) | engine-cdr:80 → 8000 | `.claude/agents/cdr.md`
- Risk: Stage 7 | engine-risk:80 → 8009 | `.claude/agents/risk.md`
- Pipeline Monitor: standalone | engine-pipeline-monitor:80 → 8000 | `.claude/agents/pipeline-monitor.md`
- Threat Narrative: Stage 8 | engine-threat-narrative
- Image tags: `v-cdr-di1`, `v-risk-di1`, `v-monitor-di1`, `v-narrative-di1`

## Files to Modify

### CDR
- `engines/cdr/cdr_engine/source_discovery/log_source_finder.py` — replace LIKE patterns on `discovery_findings` with `asset_inventory WHERE discovery_id = ANY(%s)` using `get_discovery_ids_for_engine('cdr', provider)`

### Risk
- `engines/risk/` — find and update `get_discoveries_conn()` / `get_inventory_conn()` calls for resource context reads; switch to `DI_DB_*` + `asset_inventory` on DI path
- `deployment/aws/eks/engines/engine-risk.yaml` — replace `DISCOVERIES_DB_*` + `INVENTORY_DB_*` with `DI_DB_*`

### Pipeline Monitor
- `engines/pipeline-monitor/` — update count query table (`asset_inventory` on DI path); update step label (`"di"` on DI path)

### Threat Narrative
- `engines/fix/threat_narrative/threat_narrative_engine/db_reader.py` — `discovery_findings` → `asset_inventory`; `DISCOVERIES_DB_*` → `DI_DB_*` on DI path; alias `resource_name AS resource_id`

## Technical Notes

### CDR — LIKE → explicit discovery_id
Current (approximate):
```sql
WHERE service = 'cloudtrail'
   OR discovery_id LIKE '%cloudtrail%'
   OR service = 'ec2' AND discovery_id LIKE '%flow_log%'
```

New DI path (one call):
```python
cdr_ids = get_discovery_ids_for_engine('cdr', provider)
WHERE discovery_id = ANY(%s) AND tenant_id = %s AND scan_run_id = %s
```

CloudTrail, VPC flow log, ALB access log, S3 access log discovery_ids are all tagged
`used_by_engines=['cdr']` in identifier table. Single query replaces 4 LIKE queries.
Caller groups results by discovery_id prefix to determine log category.

Keep LIKE patterns in legacy path unchanged.

### Risk — scoring vs context reads
Risk scoring reads from `security_findings` (unchanged — not affected by DI sprint).
Only resource context enrichment (account_id/region lookups for uncached resource_uids) reads
`discovery_findings`/`inventory_findings`. Search for `get_discoveries_conn()` and
`get_inventory_conn()` in `engines/risk/` — if absent, this story has no code change (just manifest).

### Pipeline Monitor — step label
```python
step_name = "di" if DI_ENGINE_ENABLED else "discoveries"
count_table = "asset_inventory" if DI_ENGINE_ENABLED else "discovery_findings"
```
UI pipeline-monitor view handles arbitrary step names — no frontend change.

### Threat Narrative — alias
`db_reader.py` reads discovery rows for natural-language context. On DI path:
- `FROM discovery_findings` → `FROM asset_inventory`
- `DISCOVERIES_DB_*` → `DI_DB_*`
- If reader references `row["resource_id"]`: add `resource_name AS resource_id` alias

## Acceptance Criteria

### Functional — CDR
- [ ] LIKE-based queries replaced with `discovery_id = ANY(%s)` on DI path
- [ ] CloudTrail trail rows found in `asset_inventory` on DI path
- [ ] No LIKE pattern in DI-path code branches (grep: 0 results)
- [ ] CDR cron completes with ≥ 1 log source found (or 0 with WARNING if no cloudtrail in test account)

### Functional — Risk
- [ ] Resource context reads use `asset_inventory` on DI path
- [ ] Risk scores computed from `security_findings` — unchanged
- [ ] No `get_discoveries_conn()` or `get_inventory_conn()` on DI path

### Functional — Pipeline Monitor
- [ ] `di` step shown in SSE event stream when `DI_ENGINE_ENABLED=true`
- [ ] Asset count from `asset_inventory` in scan progress events

### Functional — Threat Narrative
- [ ] Discovery context loaded from `asset_inventory` on DI path
- [ ] Narrative output for known test scenario non-empty

### Security (all four)
- [ ] No DI credentials logged; `DI_DB_PASSWORD` from Secret
- [ ] `tenant_id` parameterized in all queries
- [ ] LIKE patterns replaced with `ANY(%s)` on DI path — no user input in SQL strings

### RBAC Matrix (CDR)
| Role | GET /ciem/* | GET /risk/* |
|------|------------|------------|
| platform_admin | 200 | 200 |
| org_admin | 200 | 200 |
| tenant_admin | 200 | 200 |
| analyst | 200 | 200 |
| viewer | 403 | 200 |

### Error Handling
- [ ] `get_discovery_ids_for_engine('cdr', provider)` returns `[]` → 0 log sources, WARNING; no crash
- [ ] DI DB unreachable → ERROR; no silent fallback for any component

## Testing Requirements

**Unit** (4 files: `test_cdr_log_source_finder_di.py`, `test_risk_reader_di.py`, `test_pipeline_monitor_di.py`, `test_threat_narrative_reader_di.py`):
- CDR: LIKE absent on DI path; `ANY(%s)` present
- Pipeline monitor: step label = `"di"` on DI path
- Coverage ≥ 80% per changed file

**Integration**: CDR log sources > 0; risk context enriched; pipeline monitor SSE shows `di` step

**Post-deploy smoke**:
```bash
GET /api/v1/health/live (cdr) → 200
GET /api/v1/health/live (risk) → 200
kubectl logs -l app=engine-cdr -n threat-engine-engines --tail=50 | grep -i error
kubectl logs -l app=engine-risk -n threat-engine-engines --tail=50 | grep -i error
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge (LIKE → parameterized; 4 engines) |
| QA acceptance | cspm-qa | deploy |
| Post-deploy | cspm-post-deploy | close |

## Definition of Done
- [ ] CDR LIKE patterns replaced with identifier table lookup on DI path
- [ ] Risk context reads use `asset_inventory` on DI path
- [ ] Pipeline monitor shows `di` step on DI path
- [ ] Threat narrative uses `asset_inventory` on DI path
- [ ] Unit ≥ 80% coverage; integration passing
- [ ] 4 images pushed (cdr-di1, risk-di1, monitor-di1, narrative-di1)
- [ ] 4 K8s manifests updated; health → 200; no ERROR
- [ ] bmad-security-reviewer gate passed; MEMORY.md updated

## Dependencies
- DI-S3-02 (`di_identifier_helper.py`)
- identifier table seeded with `used_by_engines=['cdr']` for CloudTrail, flow log, ALB, S3 discovery_ids

## Rollback
```bash
kubectl set env deployment/engine-cdr DI_ENGINE_ENABLED=false -n threat-engine-engines
kubectl set env deployment/engine-risk DI_ENGINE_ENABLED=false -n threat-engine-engines
kubectl set env deployment/engine-pipeline-monitor DI_ENGINE_ENABLED=false -n threat-engine-engines
kubectl set env deployment/engine-threat-narrative DI_ENGINE_ENABLED=false -n threat-engine-engines
```