# DI-S4-03 — Cutover (Flip DI_ENGINE_ENABLED=true on All Engines)
**Sprint**: DI-S4 | **Points**: 5 | **Status**: Blocked (requires DI-S4-02 sign-off)

## Goal
Flip `DI_ENGINE_ENABLED=true` on all 16 downstream engine manifests and `DI_PIPELINE_ENABLED=true`
in the Argo pipeline. This is the production cutover — no code changes, only configuration.

## Prerequisites (HARD GATES — do not proceed without all passing)
- [ ] DI-S4-02 validation report signed off by bmad-sm and cspm-qa
- [ ] All 10 sign-off checks in DI-S4-02 passed (table fully populated with PASS)
- [ ] Sensitive field scrubbing verified (Check 9)
- [ ] 0 AuthError in di_scan_errors
- [ ] Maintenance window scheduled (recommend off-peak hours)

## Cutover Steps (execute in order)

### Step 1: Flip Argo Pipeline
```bash
# Update Argo workflow default parameters
kubectl patch configmap argo-workflow-config -n argo \
  --type=merge --patch='{"data":{"DI_PIPELINE_ENABLED":"true"}}'
```
Or: edit `cspm-pipeline.yaml` to set `DI_PIPELINE_ENABLED=true` as default parameter value.
```bash
kubectl apply -f deployment/aws/eks/argo/cspm-pipeline.yaml
```

### Step 2: Flip All 16 Downstream Engines
```bash
# Batch flip — do NOT flip one-by-one; flip atomically to avoid mixed state
for engine in \
  engine-check engine-iam engine-network-security engine-datasec \
  engine-encryption engine-dbsec engine-ai-security engine-api-security \
  engine-container-sec engine-attack-path engine-threat-v1 engine-cdr \
  engine-risk engine-pipeline-monitor engine-threat-narrative; do
  kubectl set env deployment/$engine DI_ENGINE_ENABLED=true -n threat-engine-engines
  echo "Flipped $engine"
done

# Log collector (separate resource type)
kubectl set env daemonset/log-collector DI_ENGINE_ENABLED=true -n threat-engine-engines 2>/dev/null || \
  kubectl set env deployment/log-collector DI_ENGINE_ENABLED=true -n threat-engine-engines
```

### Step 3: Monitor Rollout
```bash
# Watch all deployments roll out
kubectl get deployments -n threat-engine-engines -w | grep -E "engine|log-"

# Wait for all pods to restart with new env
kubectl rollout status deployment/engine-check -n threat-engine-engines
kubectl rollout status deployment/engine-iam -n threat-engine-engines
# ... (for each engine)
```

### Step 4: Trigger First Post-Cutover Scan
```bash
# Use Argo UI or CLI to submit a full pipeline scan
argo submit -n argo deployment/aws/eks/argo/cspm-pipeline.yaml \
  --parameter scan_run_id=$(python3 -c "import uuid; print(uuid.uuid4())")
```

### Step 5: Monitor Scan Progress
```bash
# Watch Argo DAG
argo watch -n argo <workflow-name>

# Monitor engine-di logs during scan
kubectl logs -f -l app=engine-di -n threat-engine-engines --tail=100

# Check di_scan_errors
kubectl exec -n threat-engine-engines deployment/engine-di -- python3 -c "
import psycopg2, os
conn = psycopg2.connect(host=os.getenv('DI_DB_HOST'), port=5432,
                        database='threat_engine_di', user='postgres',
                        password=os.getenv('DI_DB_PASSWORD'))
with conn.cursor() as cur:
    cur.execute('SELECT error_type, count(*) FROM di_scan_errors WHERE created_at > NOW()-INTERVAL \'1 hour\' GROUP BY error_type')
    for row in cur.fetchall():
        print(row)
"
```

### Step 6: Post-Cutover Health Checks
```bash
# All engine health checks
for engine in engine-check engine-iam engine-network-security engine-datasec \
  engine-encryption engine-dbsec engine-attack-path engine-threat-v1 engine-cdr engine-risk; do
  echo -n "$engine: "
  kubectl exec -n threat-engine-engines deployment/$engine -- \
    python3 -c "
import urllib.request
try:
    urllib.request.urlopen('http://localhost:8002/api/v1/health/live').read()
    print('OK')
except Exception as e:
    print('FAIL:', e)
"
done
```

## Rollback Plan (execute if any health check fails or scan errors spike)

### Immediate Rollback (< 5 minutes to execute)
```bash
# Flip all engines back to DI_ENGINE_ENABLED=false
for engine in \
  engine-check engine-iam engine-network-security engine-datasec \
  engine-encryption engine-dbsec engine-ai-security engine-api-security \
  engine-container-sec engine-attack-path engine-threat-v1 engine-cdr \
  engine-risk engine-pipeline-monitor engine-threat-narrative; do
  kubectl set env deployment/$engine DI_ENGINE_ENABLED=false -n threat-engine-engines
done

# Flip Argo pipeline back
kubectl patch configmap argo-workflow-config -n argo \
  --type=merge --patch='{"data":{"DI_PIPELINE_ENABLED":"false"}}'

echo "ROLLBACK COMPLETE"
```

### Rollback Criteria (auto-trigger these checks 30 minutes after cutover)
- `di_scan_errors` AuthError count > 0 → immediate rollback
- Any downstream engine health check fails → immediate rollback
- First post-cutover scan `check_findings` count < 90% of pre-cutover baseline → investigate

## Acceptance Criteria

### Functional
- [ ] All 16 engines running with `DI_ENGINE_ENABLED=true` after Step 2
- [ ] First post-cutover scan completes (`di` step = completed in Argo DAG)
- [ ] `check_findings` count for first post-cutover scan ≥ 90% of pre-cutover baseline
- [ ] Attack-path BFS produces ≥ 7 paths
- [ ] All engine health checks → 200

### Security
- [ ] Rollback plan tested in staging before production cutover
- [ ] Cutover executed during scheduled maintenance window
- [ ] All pod images verified correct (VSCode linter revert protection)

### Error Handling
- [ ] `di_scan_errors` AuthError = 0 (mandatory — any AuthError means credential resolution broke)
- [ ] If rollback needed: < 5 minutes to complete (batch kubectl set env)

## Testing Requirements

**Post-cutover smoke** (30 minutes after cutover):
```sql
-- First post-cutover scan completeness
SELECT provider, count(*) FROM asset_inventory
WHERE scan_run_id = '<POST_CUTOVER_SCAN_RUN_ID>'
GROUP BY provider;
-- Must be ≥ 90% of pre-cutover counts

SELECT count(*) FROM di_scan_errors
WHERE scan_run_id = '<POST_CUTOVER_SCAN_RUN_ID>'
  AND error_type = 'AuthError';
-- Must be: 0
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Cutover approval | bmad-sm + cspm-qa | Step 1 execution |
| Post-cutover | cspm-post-deploy | close story |

## Definition of Done
- [ ] All 16 engines running with `DI_ENGINE_ENABLED=true`
- [ ] Argo pipeline running with `DI_PIPELINE_ENABLED=true`
- [ ] First post-cutover scan completes without AuthErrors
- [ ] Post-cutover health checks all → 200
- [ ] `check_findings` count ≥ 90% of baseline
- [ ] MEMORY.md updated: DI cutover complete; DI_ENGINE_ENABLED=true on all 16 engines

## Dependencies
- DI-S4-02 validation report signed off (hard gate — no exceptions)
- All DI-S3-* engines deployed

## This Story Has No Rollback Procedure After DoD
Once DI-S4-03 is closed as Done, engine-di is the primary data source. Rollback to legacy
requires reverting all DI-S3 code changes, which is DI-S4-04-level work.