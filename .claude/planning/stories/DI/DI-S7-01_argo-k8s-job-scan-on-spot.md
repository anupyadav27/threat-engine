# DI-S7-01 — Argo K8s Job Scan on Spot Instances
**Sprint**: DI-S7 | **Type**: Architecture + Infrastructure | **Status**: Code Complete — Pending Deploy
**Points**: 8 | **Priority**: High

---

## Problem

DI scan ran as a `nohup` process inside the long-lived `engine-di` API server pod.

Consequences (observed in production):
1. **Any deploy kills running scans** — every `kubectl apply` triggers rolling restart, SIGTERM-ing active scan. AWS full scan (4+ hours) was killed 3× during DI sprint.
2. **No isolation** — a crashed scan affects API server health probes.
3. **No cost optimization** — scans run on the same on-demand node as the API server.
4. **No retry semantics** — mid-scan crash = lost scan with no K8s-native retry.

---

## Solution

Run each DI scan as a **K8s Job** created by the Argo pipeline `resource` step, scheduled on **spot instance node pools**. The `engine-di` API server pod remains on on-demand nodes for health checks and BFF queries — only scan Jobs move to spot.

```
Argo Workflow step: di
        │
        ▼
  resource: action: create     ──►  K8s Job on di-scan-spot node group
  (Job name: di-scan-<scan_run_id>)      (tolerations + nodeSelector)
        │
        ▼
  Argo watches Job (successCondition: status.succeeded == 1)
        │
        ▼
  Continue pipeline (check, threat, ...)
```

---

## Implementation — Code Complete ✓

### 1. `run_scan.py` — `include_services` from orchestration metadata
**File**: `engines/di/run_scan.py`

Added 4 lines after loading `meta`: if `--services` CLI arg is absent, read `include_services`
from the DB orchestration record (set by Argo `create-orch-record` step). This means targeted
scans via Argo now work without passing `--services` on the command line.

```python
if services is None:
    meta_services = meta.get("include_services")
    if isinstance(meta_services, list) and meta_services:
        services = meta_services
```

### 2. Spot Node Group
**File**: `deployment/aws/eks/spot-nodegroup/di-scan-spot-nodegroup.yaml`

eksctl managed node group `di-scan-spot` in `vulnerability-eks-cluster`:
- Instance types: m5.2xlarge, m5a.2xlarge, m4.2xlarge, m6i.2xlarge (8 vCPU, 32 GB each)
- Capacity: SPOT, minSize=0, maxSize=10 (scales to 0 when idle)
- Labels: `workload-type: di-scan`, `lifecycle: spot`
- Taint: `workload-type=di-scan:NoSchedule` (only DI scan Jobs land here)

**Apply**:
```bash
eksctl create nodegroup -f deployment/aws/eks/spot-nodegroup/di-scan-spot-nodegroup.yaml
```

### 3. Argo RBAC — Job creation
**File**: `deployment/aws/eks/spot-nodegroup/argo-job-creator-rbac.yaml`

Role `argo-job-creator` + RoleBinding for `default` service account in `threat-engine-engines`:
- Grants: `batch/jobs: create, get, watch, list, delete, patch`
- Grants: `pods, pods/log: get, watch, list`

**Apply**:
```bash
kubectl apply -f deployment/aws/eks/spot-nodegroup/argo-job-creator-rbac.yaml
```

### 4. K8s Job Manifest (reference)
**File**: `deployment/aws/eks/jobs/engine-di-scan-job.yaml`

Reference manifest for manual one-off runs:
```bash
export SCAN_RUN_ID=<uuid>
export IMAGE_TAG=v-di-s5-1
envsubst < deployment/aws/eks/jobs/engine-di-scan-job.yaml | kubectl apply -f -
```

### 5. Argo Pipeline — DI step replaced with K8s Job
**File**: `deployment/aws/eks/argo/cspm-pipeline.yaml`

- Added `di-image-tag` workflow parameter (default: `v-di-s5-1`)
- Replaced `trigger-and-poll` HTTP step with `resource: action: create` step
- Job spec embedded inline in the Argo manifest with `{{workflow.parameters.*}}` substitutions
- `backoffLimit: 1` — one automatic retry on spot interruption
- `ttlSecondsAfterFinished: 3600` — auto-cleanup after 1 hour

**Apply** (apply primitives first):
```bash
kubectl apply -f deployment/aws/eks/argo/cspm-templates-primitives.yaml
kubectl apply -f deployment/aws/eks/argo/cspm-pipeline.yaml
```

---

## Parallel Capacity — Spot vs On-Demand

| Setting | On-Demand (current) | Spot m5.2xlarge |
|---------|--------------------|--------------------|
| Instance | t3.medium (2vCPU, 4GB) | m5.2xlarge (8vCPU, 32GB) |
| `MAX_GLOBAL_WORKERS` | 10 | **20** |
| `MAX_REGIONAL_WORKERS` | 30 | **60** |
| AWS full scan estimate | ~4 hours | **~2 hours** |
| Cost/scan | ~$0.40 | **~$0.15 (spot)** |

Scans are I/O-bound (waiting on CSP API responses), not CPU-bound. Doubling workers
is safe — AWS adaptive retry handles throttling automatically. The 8 vCPU gives headroom
to burst higher if needed (raise `MAX_REGIONAL_WORKERS` to 80 for aggressive scanning).

---

## Deploy Checklist

- [ ] `eksctl create nodegroup` — create `di-scan-spot` spot node group
- [ ] `kubectl apply -f argo-job-creator-rbac.yaml` — RBAC for Job creation
- [ ] `docker build -t yadavanup84/engine-di:v-di-s5-1 -f engines/di/Dockerfile .`
- [ ] `docker push yadavanup84/engine-di:v-di-s5-1`
- [ ] `kubectl apply -f cspm-templates-primitives.yaml`
- [ ] `kubectl apply -f cspm-pipeline.yaml`
- [ ] Update `engine-di.yaml` deployment image tag to `v-di-s5-1`
- [ ] Set `di-pipeline-enabled=true` on workflow parameter default
- [ ] Test: submit Argo workflow, verify Job appears in `threat-engine-engines` namespace
- [ ] Test: verify Job runs on a node with `workload-type=di-scan` label
- [ ] Test: `kubectl apply -f engine-di.yaml` does NOT kill the running Job

---

## Acceptance Criteria

- [x] `run_scan.py` reads `include_services` from orchestration metadata
- [x] `deployment/aws/eks/spot-nodegroup/di-scan-spot-nodegroup.yaml` exists
- [x] `deployment/aws/eks/spot-nodegroup/argo-job-creator-rbac.yaml` exists
- [x] `deployment/aws/eks/jobs/engine-di-scan-job.yaml` template exists
- [x] Argo pipeline `di` step creates K8s Job (not HTTP trigger)
- [x] `di-image-tag` workflow parameter added
- [x] `MAX_REGIONAL_WORKERS=60` in Job spec (2× current)
- [ ] Node group `di-scan-spot` provisioned in EKS cluster
- [ ] RBAC applied to cluster
- [ ] Image `v-di-s5-1` built and pushed
- [ ] End-to-end: Argo workflow creates Job → Job completes → rows written with correct service names + relationships
- [ ] `kubectl apply -f engine-di.yaml` does NOT interrupt an active DI scan Job