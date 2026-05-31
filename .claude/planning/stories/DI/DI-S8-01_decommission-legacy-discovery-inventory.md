# DI-S8-01 — Decommission Legacy Discovery + Inventory Engines
**Sprint**: DI-S8 | **Type**: Cleanup + Migration | **Status**: Ready for Dev
**Points**: 5 | **Priority**: High

---

## Problem

With `di-pipeline-enabled=true` confirmed working (DI-S7-01 complete), the legacy
`engine-discoveries` and `engine-inventory` engines are now dead code in the pipeline.
They are still deployed to EKS, still consuming on-demand node capacity, and still
referenced in BFF/gateway code that no longer serves live traffic.

**Current state (to be removed):**
- Two long-lived on-demand pods: `engine-discoveries` (port 8001) and `engine-inventory` (port 8022)
- Argo pipeline: `discovery` + `inventory` DAG steps (skipped when `di-pipeline-enabled=true`)
- BFF `scan_timing.py`: calls `engine-discoveries` for `/api/v1/discovery/{scan_run_id}/timing`
- Gateway `main.py` SERVICE_ROUTES: `discoveries` (→ port 8001) and `inventory` (→ port 8022)
- Gateway `_shared.py` ENGINE_URLS: `DISCOVERIES_URL`, `INVENTORY_URL` constants
- K8s YAML: `deployment/aws/eks/engines/engine-discoveries.yaml`, `engine-inventory.yaml`

---

## Solution

Full decommission in two phases:

**Phase A — Pipeline (no code change, no redeploy needed):**
Remove the `discovery` and `inventory` DAG tasks from `cspm-pipeline.yaml` and the
`discovery-only` entrypoint DAG. Flip `di-pipeline-enabled` default from `false` to `true`.

**Phase B — BFF + Gateway:**
- `scan_timing.py`: Replace discoveries call with DI engine `/api/v1/di/status/{scan_run_id}`
  (already has `resources_enumerated`, `resources_written`, `relationships_written`,
  `started_at`, `completed_at` — all the timing fields needed)
- `main.py`: Remove `discoveries` and `inventory` from SERVICE_ROUTES
- `_shared.py`: Remove `DISCOVERIES_URL`, `INVENTORY_URL`, their ENGINE_URLS entries
- Rebuild + push gateway image, apply to EKS

**Phase C — Infrastructure:**
- Scale down or delete `engine-discoveries` and `engine-inventory` Deployments
- Delete the K8s YAML files (or mark them with `# DECOMMISSIONED` header)

---

## Implementation

### 1. cspm-pipeline.yaml — Remove legacy steps + flip default

**File**: `deployment/aws/eks/argo/cspm-pipeline.yaml`

Changes:
```yaml
# 1. Change default
- name: di-pipeline-enabled
  value: "true"   # was "false"

# 2. Remove the entire `discovery` task block (was Step 2b):
#    - name: discovery
#      depends: "create-orchestration-record"
#      when: "\"{{workflow.parameters.di-pipeline-enabled}}\" != \"true\""
#      templateRef: ...

# 3. Remove the entire `inventory` task block (was Step 3):
#    - name: inventory
#      depends: "discovery"
#      when: "\"{{workflow.parameters.di-pipeline-enabled}}\" != \"true\""
#      templateRef: ...

# 4. Simplify the `check` depends clause (remove inventory references):
#    depends: "di.Succeeded || di.Skipped"   # was: (inventory.Succeeded || ...) && (di.Succeeded || ...)

# 5. Remove the `discovery-only` DAG (entire template)
# 6. Remove `di-pipeline-enabled` parameter (no longer needed — DI always runs)
# 7. Remove `when:` from the `di` task (always runs, no condition needed)
```

Apply:
```bash
kubectl apply -f deployment/aws/eks/argo/cspm-pipeline.yaml
```

### 2. scan_timing.py — Redirect to DI engine

**File**: `shared/api_gateway/bff/scan_timing.py`

Replace the discoveries HTTP call with a call to `engine-di` `/api/v1/di/status/{scan_run_id}`.
The DI status response contains all fields needed for scan timing:
- `started_at`, `completed_at` → timing
- `resources_written`, `relationships_written` → result counts
- `status`, `phase` → completion state
- `error_count` (if available) → error rate

New endpoint to add to DI engine if missing: `GET /api/v1/di/scans` (list recent scans with timing).
Or query the DI DB directly via the existing `/api/v1/di/status/{scan_run_id}` endpoint.

### 3. shared/api_gateway/_shared.py — Remove dead constants

**File**: `shared/api_gateway/bff/_shared.py`

Remove from `ENGINE_URLS`:
```python
# DELETE:
"discoveries": os.getenv("DISCOVERIES_ENGINE_URL", "http://engine-discoveries"),
"inventory": os.getenv("INVENTORY_ENGINE_URL", "http://engine-inventory:8022"),
```

Remove module-level constants:
```python
# DELETE:
INVENTORY_URL = ENGINE_URLS["inventory"]
DISCOVERIES_URL = ENGINE_URLS["discoveries"]
```

### 4. main.py — Remove gateway routes

**File**: `shared/api_gateway/main.py`

Remove from SERVICE_ROUTES:
```python
# DELETE:
"discoveries": {
    "url": "http://engine-discoveries:8001",
    "prefix": "/api/v1/discovery",
    "health": "/api/v1/health",
},
"inventory": {
    "url": "http://engine-inventory:8022",
    "prefix": "/api/v1/inventory",
    "health": "/health",
},
```

### 5. K8s — Scale down deployments

```bash
kubectl scale deployment engine-discoveries --replicas=0 -n threat-engine-engines
kubectl scale deployment engine-inventory --replicas=0 -n threat-engine-engines
```

Mark YAML files as decommissioned (add header comment, do NOT delete — keep for rollback reference):
```yaml
# DECOMMISSIONED — replaced by engine-di (DI-S8-01, 2026-05-24)
# Scale: kubectl scale deployment engine-discoveries --replicas=0 -n threat-engine-engines
# Rollback: kubectl scale deployment engine-discoveries --replicas=1 -n threat-engine-engines
```

### 6. Rebuild + push gateway + apply

```bash
docker build -t yadavanup84/api-gateway:v-di-cutover1 -f shared/api_gateway/Dockerfile .
docker push yadavanup84/api-gateway:v-di-cutover1
kubectl set image deployment/api-gateway api-gateway=yadavanup84/api-gateway:v-di-cutover1 -n threat-engine-engines
kubectl rollout status deployment/api-gateway -n threat-engine-engines
```

---

## Acceptance Criteria

- [ ] `di-pipeline-enabled` default is `"true"` in cspm-pipeline.yaml
- [ ] `discovery` and `inventory` DAG tasks removed from pipeline
- [ ] `check` depends clause only references `di.Succeeded || di.Skipped`
- [ ] `discovery-only` template removed from pipeline
- [ ] `scan_timing.py` uses DI engine (not discoveries engine) for timing data
- [ ] `DISCOVERIES_URL` and `INVENTORY_URL` constants removed from `_shared.py`
- [ ] `discoveries` and `inventory` SERVICE_ROUTES removed from `main.py`
- [ ] Gateway image rebuilt + deployed with new tag
- [ ] `engine-discoveries` and `engine-inventory` pods scaled to 0
- [ ] Full pipeline run with only `engine-di` produces check findings correctly
- [ ] No broken BFF endpoints after gateway redeploy

---

## Pre-requisites

- [ ] DI-S7-01 end-to-end Argo K8s Job test passes (scan completes, check engine reads findings)
- [ ] At least one full pipeline run with `di-pipeline-enabled=true` completing through `check` step

## Rollback Plan

1. `kubectl scale deployment engine-discoveries --replicas=1 -n threat-engine-engines`
2. `kubectl scale deployment engine-inventory --replicas=1 -n threat-engine-engines`
3. Revert cspm-pipeline.yaml: `di-pipeline-enabled` default back to `"false"`
4. `kubectl apply -f deployment/aws/eks/argo/cspm-pipeline.yaml`
5. Roll back gateway to previous tag

---

## Cost Impact

Removing 2 on-demand pods (engine-discoveries + engine-inventory) from the on-demand node group:
- Estimated savings: ~$30-50/month (2x t3.medium or equivalent)
- DI scan spot instances cost only during active scans (~$0.15/scan)