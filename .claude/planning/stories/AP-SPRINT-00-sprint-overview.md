# AP-SPRINT — Attack Path + CDR Consolidation Sprint

## Sprint Goal
Fix all reliability bugs in the attack-path engine, fix CDR pipeline issues, and move the Neo4j graph build from `engine-threat` into `engine-attack-path` so that `engine-threat` is no longer needed in the pipeline (it continues serving UI/BFF endpoints only).

## Sprint Date
2026-05-24

## Stories

| ID | Title | Status | Priority |
|----|-------|--------|----------|
| AP-SPRINT-01 | Attack Path + CDR Bug Fixes (7 bugs) | DONE | P0 |
| AP-SPRINT-02 | Graph Build Migration: engine-threat → engine-attack-path | DONE | P1 |

## Pipeline Impact

### Before
```
... → graph-build (engine-threat) → attack-path-scan (engine-attack-path) → ...
```

### After
```
... → graph-build (engine-attack-path) → attack-path-scan (engine-attack-path) → ...
```

`engine-threat` serves only: `/api/v1/threat`, `/api/v1/intel`, `/api/v1/hunt` (UI + BFF).

## Deploy Sequence

### Step 1 — Build images
```bash
# Attack path (includes graph_builder, graph_queries, new endpoints, boto3)
docker build -t yadavanup84/engine-attack-path:v-ap-graph1 \
  -f engines/attack-path/Dockerfile .

# CDR (finally block fix)
docker build -t yadavanup84/engine-cdr:v-cdr-bugfix1 \
  -f engines/cdr/Dockerfile .

# API Gateway (SERVICE_ROUTES updated)
docker build -t yadavanup84/engine-api-gateway:v-gw-ap-graph1 \
  -f shared/api_gateway/Dockerfile .
```

### Step 2 — Push images
```bash
docker push yadavanup84/engine-attack-path:v-ap-graph1
docker push yadavanup84/engine-cdr:v-cdr-bugfix1
docker push yadavanup84/engine-api-gateway:v-gw-ap-graph1
```

### Step 3 — Update K8s manifests with new image tags
```bash
kubectl set image deployment/engine-attack-path \
  engine-attack-path=yadavanup84/engine-attack-path:v-ap-graph1 \
  -n threat-engine-engines

kubectl set image deployment/engine-cdr \
  engine-cdr=yadavanup84/engine-cdr:v-cdr-bugfix1 \
  -n threat-engine-engines

kubectl set image deployment/engine-api-gateway \
  engine-api-gateway=yadavanup84/engine-api-gateway:v-gw-ap-graph1 \
  -n threat-engine-engines
```

### Step 4 — Verify rollouts
```bash
kubectl rollout status deployment/engine-attack-path -n threat-engine-engines
kubectl rollout status deployment/engine-cdr -n threat-engine-engines
kubectl rollout status deployment/engine-api-gateway -n threat-engine-engines
```

### Step 5 — Post-deploy smoke
```bash
# Graph build endpoint now on attack-path
curl -s http://engine-attack-path/api/v1/health/live

# Trigger a test pipeline run and confirm:
# 1. graph-build Argo step hits engine-attack-path (check Argo logs)
# 2. attack-path-scan follows and produces paths_found > 0
# 3. composite flags in resource_security_posture are populated for all tenant resources
```

## Files Changed Summary

| File | Change |
|------|--------|
| `engines/attack-path/attack_path_engine/db/posture_updater.py` | Bug 1: tenant-only scope for composite flags |
| `engines/attack-path/attack_path_engine/run_scan.py` | Bug 2: commit after exposed UPDATE; Bug 3: av_cache; Bug 6: log msg; Bug 7: LOWER(status) |
| `engines/attack-path/attack_path_engine/graph/pg_graph.py` | Bug 4a: continue after crown jewel |
| `engines/attack-path/attack_path_engine/core/scorer.py` | Bug 4b: lowercase entry type lookup |
| `engines/cdr/run_scan.py` | Bug 5: CIEM→CDR rename + finally block |
| `engines/attack-path/attack_path_engine/graph/graph_builder.py` | New: copied + logger renamed |
| `engines/attack-path/attack_path_engine/graph/graph_queries.py` | New: copied + logger renamed |
| `engines/attack-path/attack_path_engine/api/routes.py` | Graph build endpoints added |
| `engines/attack-path/requirements.txt` | Added boto3==1.29.7 |
| `shared/api_gateway/main.py` | /api/v1/graph moved to attack-path prefixes |
| `deployment/aws/eks/argo/cspm-templates-primitives.yaml` | graph-build URLs → engine-attack-path |