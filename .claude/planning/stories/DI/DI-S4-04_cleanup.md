# DI-S4-04 — Cleanup (Retire engine-discoveries + engine-inventory)
**Sprint**: DI-S4 | **Points**: 5 | **Status**: Blocked (requires DI-S4-03 stable for 2 weeks)

## Goal
After 2 weeks of stable production running on engine-di, retire the legacy engines: delete
K8s deployments for engine-discoveries and engine-inventory, remove their routing from the API
gateway, archive their DB schemas, and remove legacy code paths from the 16 downstream engine
adapters.

## Minimum Stability Period
**Do not execute DI-S4-04 until engine-di has been running in production for ≥ 14 days with:**
- 0 rollbacks
- < 1% di_scan_errors rate per scan
- All downstream engine finding counts stable (within 2% of baseline for 5 consecutive scans)

## Cleanup Steps (execute in order)

### Step 1: Remove Legacy Routing from API Gateway
```python
# shared/api_gateway/main.py — remove:
"discoveries": {
    "url": os.getenv("DISCOVERIES_ENGINE_URL", "http://engine-discoveries"),
    "prefixes": ["/api/v1/discoveries", "/api/v1/discovery"],
},
"inventory": {
    "url": os.getenv("INVENTORY_ENGINE_URL", "http://engine-inventory"),
    "prefixes": ["/api/v1/inventory"],
},
```
Deploy updated gateway.

### Step 2: Delete Legacy K8s Deployments
```bash
kubectl delete deployment engine-discoveries -n threat-engine-engines
kubectl delete deployment engine-inventory -n threat-engine-engines
kubectl delete service engine-discoveries -n threat-engine-engines
kubectl delete service engine-inventory -n threat-engine-engines
```

### Step 3: Remove Legacy Manifest Files
```bash
git rm deployment/aws/eks/engines/engine-discoveries.yaml
git rm deployment/aws/eks/engines/engine-inventory.yaml
```

### Step 4: Remove Legacy Code Paths from 16 Adapters
For each adapter (DI-S3-01 through DI-S3-07), remove:
- The `if not DI_ENGINE_ENABLED:` branch and the legacy path code
- The `DISCOVERIES_DB_*` and `INVENTORY_DB_*` connection config code
- The `DI_ENGINE_ENABLED` check (remove the env var gate entirely — code always uses DI path)
- Hardcoded discovery_id lists that were preserved as legacy fallbacks
- `NETWORK_DISCOVERY_MAP`, `AI_SERVICES`, `CATALOG_NOISE_DISCOVERY_IDS`, `_API_RESOURCE_TYPES`,
  `DATASEC_DISCOVERY_IDS` constants (replaced by identifier table)

```python
# After cleanup, reader code should look like:
def load_resources(self, scan_run_id, tenant_id, provider):
    discovery_ids = get_discovery_ids_for_engine('network', provider)
    conn = _get_di_conn()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT resource_uid, resource_type, emitted_fields, ...
            FROM asset_inventory
            WHERE scan_run_id = %s AND tenant_id = %s AND discovery_id = ANY(%s)
        """, (scan_run_id, tenant_id, discovery_ids))
    # No if/else, no legacy path
```

### Step 5: Archive Legacy DB Schemas
The legacy DBs (`threat_engine_discoveries`, `threat_engine_inventory`) stay on RDS with their
data intact for 90 days post-cutover as a safety net. After 90 days:
```bash
# Drop legacy DBs (RDS — requires out-of-band confirmation)
# Document in SECRETS-CREDENTIALS.md and DATABASE-SCHEMA.md
```
Remove legacy DB env vars from remaining engine manifests:
```bash
for engine in engine-check engine-iam ...; do
  kubectl set env deployment/$engine \
    DISCOVERIES_DB_HOST- DISCOVERIES_DB_PORT- DISCOVERIES_DB_NAME- \
    DISCOVERIES_DB_USER- DISCOVERIES_DB_PASSWORD- \
    INVENTORY_DB_HOST- INVENTORY_DB_PORT- INVENTORY_DB_NAME- \
    INVENTORY_DB_USER- INVENTORY_DB_PASSWORD- \
    DI_ENGINE_ENABLED- \
    -n threat-engine-engines
done
```

### Step 6: Remove DI_ENGINE_ENABLED Feature Flag from Manifests
The flag is no longer needed — all engines always use DI DB.
Clean up `DI_ENGINE_ENABLED` env var from all 16 manifests.

### Step 7: Update Documentation
- `shared/database/schemas/` — archive `discoveries_schema.sql`, `inventory_schema.sql`
- `.claude/documentation/DATABASE-SCHEMA.md` — remove discoveries/inventory DB entries; add DI DB
- `.claude/documentation/API_REFERENCE_ALL_ENGINES.md` — remove engine-discoveries + engine-inventory
- `.claude/context/agents.ndjson` — update discoveries + inventory entries (or remove if deprecated)
- `CLAUDE.md` — update architecture section: remove engine-discoveries and engine-inventory from pipeline order

### Step 8: Remove Legacy Engine Source Code (Optional — archive instead)
Rather than deleting `engines/discoveries/` and `engines/inventory/` immediately, move to
`engines/_archived/discoveries/` and `engines/_archived/inventory/`. Permanent deletion after
90-day data retention period.

## Acceptance Criteria

### Functional
- [ ] `GET /gateway/api/v1/discoveries/*` → 404 (route removed)
- [ ] `GET /gateway/api/v1/inventory/*` → 404 (route removed)
- [ ] engine-discoveries pod: `kubectl get pods -l app=engine-discoveries` → 0 rows
- [ ] engine-inventory pod: `kubectl get pods -l app=engine-inventory` → 0 rows
- [ ] All 16 engines start without `DISCOVERIES_DB_*` or `INVENTORY_DB_*` env vars (no startup crash)
- [ ] Full pipeline scan completes after cleanup: same pass rates as before cleanup

### Security
- [ ] Legacy DB credentials removed from all K8s manifests after cleanup
- [ ] Legacy DB secrets not deleted until 90-day retention confirmed complete
- [ ] No `DEV_BYPASS_AUTH` introduced during code cleanup

### Error Handling
- [ ] Gateway removal of discoveries/inventory routes: any external caller gets 404 (not 500 crash)
- [ ] DB cleanup performed only after 14-day stability confirmation

## Testing Requirements

**Post-cleanup smoke**:
```bash
# Verify legacy endpoints gone
curl -sf http://$ELB/gateway/api/v1/discoveries/ && echo "FAIL - should return 404" || echo "PASS - 404"
curl -sf http://$ELB/gateway/api/v1/inventory/ && echo "FAIL - should return 404" || echo "PASS - 404"

# Full scan still works
argo submit -n argo deployment/aws/eks/argo/cspm-pipeline.yaml \
  --parameter scan_run_id=$(python3 -c "import uuid; print(uuid.uuid4())")
# Scan must complete; check findings count ≥ 95% of baseline
```

**Code cleanup verification**:
```bash
# No legacy DB references in adapter code
grep -r "DISCOVERIES_DB_HOST\|INVENTORY_DB_HOST\|discovery_findings\|inventory_findings" \
  engines/ --include="*.py" | grep -v "_archived\|test_\|\.pyc"
# Expected: 0 results
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| 14-day stability confirmation | bmad-sm | Step 1 execution |
| Code review | bmad-security-reviewer | merge |
| QA acceptance | cspm-qa | Step 2 execution |
| Post-cleanup | cspm-post-deploy | close |

## Definition of Done
- [ ] Gateway routes for discoveries/inventory removed
- [ ] engine-discoveries and engine-inventory K8s resources deleted
- [ ] Legacy manifest files removed from git
- [ ] All 16 adapter code paths cleaned (no if/else for DI flag — pure DI path)
- [ ] Hardcoded discovery_id lists removed (replaced by identifier table)
- [ ] `DI_ENGINE_ENABLED` feature flag removed from all manifests
- [ ] Full post-cleanup pipeline scan completes with ≥ 95% of baseline findings
- [ ] Documentation updated (DATABASE-SCHEMA.md, API_REFERENCE, CLAUDE.md)
- [ ] Legacy engine code archived to `engines/_archived/`
- [ ] MEMORY.md updated: engine-discoveries and engine-inventory retired; DI sprint complete

## Dependencies
- DI-S4-03 stable for ≥ 14 days (hard gate)
- No open incidents related to DI engine

## Rollback (if cleanup causes issues)
At Step 2 (K8s deletion), rollback requires re-deploying legacy manifests from git history:
```bash
git show HEAD~1:deployment/aws/eks/engines/engine-discoveries.yaml | kubectl apply -f -
git show HEAD~1:deployment/aws/eks/engines/engine-inventory.yaml | kubectl apply -f -
```
Then re-add gateway routes and restore `DI_ENGINE_ENABLED=false` on all adapters.
This is a significant rollback — prefer investigating issues rather than rolling back at this stage.