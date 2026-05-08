# CSPM Pipeline Architecture

Developer reference for the Argo-based scan pipeline. Last updated: 2026-04-10.

---

## Pod Types

There are two distinct pod types in this system. Understanding the difference is critical
before making any changes to the pipeline or Kubernetes manifests.

### 1. Engine API Pods (Deployments — always-on)

Long-running FastAPI/uvicorn servers. One Deployment per engine, running on on-demand nodes.

**These must never be scaled to 0.**

Reason: the UI BFF (gateway) calls engine APIs directly for live data queries, independent
of whether a scan is running. Scaling them down causes immediate 503 errors in the UI.
The old `scale-up-engines` / `scale-down-engines` pipeline steps were removed on 2026-04-10
for this reason.

Engines with always-on API pods:
- `engine-check` (port 8002)
- `engine-threat` (port 8020)
- `engine-compliance` (port 8000)
- `engine-iam` (port 8001)
- `engine-datasec` (port 8003)
- `engine-inventory` (port 8022)
- `engine-risk` (runs on port 8005 internally)
- `engine-onboarding` (port 8008)

### 2. Scanner Job Pods (K8s Jobs — ephemeral, spot nodes)

Created per scan trigger. Run `run_scan.py`, write results to the engine DB, then exit.
Scheduled on the `vulnerability-spot-scanners` node group (taint: `spot-scanner=true:NoSchedule`).

The discovery engine is **scanner-only** — it has no API pod.

### 3. Argo Step Pods (ephemeral, spot nodes)

Each step in the Argo DAG runs as a short-lived pod (also on spot). These pods are
lightweight orchestration scripts: they call engine API pods via HTTP POST, poll for
job completion, and update `scan_orchestration` in the DB.

---

## Two Docker Images Per Engine

Most engines build two images from the same source:

| Role | Entrypoint | Deployed as |
|------|-----------|-------------|
| API image | `uvicorn api_server:app --host 0.0.0.0 --port <N>` | Always-on Deployment |
| Scanner image | `python run_scan.py` | K8s Job (per scan) |

Exceptions:
- **discoveries**: scanner image only (no API server)
- **onboarding, gateway, frontend**: API image only (no scanner)

---

## Pipeline Flow

```
User / Scheduler / Onboarding API
         |
         v
   trigger-scan.sh
   (submits WorkflowTemplate with scan_run_id, tenant_id, account_id)
         |
         v
   Argo Workflow: cspm-scan-pipeline
         |
         +--[1] run-discovery
         |       Creates K8s Job on spot node
         |       Argo polls until job status = Completed
         |       Writes findings → discoveries DB
         |
         +--[2] run-inventory  (HTTP POST → engine-inventory)
         +--[3] run-check      (HTTP POST → engine-check)
         |       Sequential: inventory must finish before check
         |
         +--[4] run-threat     (HTTP POST → engine-threat)
         |
         +--[5a] run-compliance  \
         +--[5b] run-iam          > parallel (HTTP POST to each API pod)
         +--[5c] run-datasec    /
         |
         v
   onExit: pipeline-exit-handler
         Reads scan_orchestration.overall_status
         If status != 'completed' → sets status = 'failed'
         Guarantees DB never left in hanging 'running' state
```

`scan_run_id` is the single UUID passed to every engine. No per-engine scan IDs.

---

## Why Engine API Pods Must Never Be Scaled to 0

1. The UI gateway (`/gateway/api/v1/views/*`) proxies requests to engine APIs synchronously.
   If an engine pod is at 0 replicas, the BFF returns a 503 immediately.

2. Scale-up from 0 takes ~60 seconds (pod scheduling + container pull + startup probe).
   This was adding unacceptable latency to every pipeline run.

3. Spot nodes for scanner Jobs already provide the bulk of cost savings.
   Keeping API pods on on-demand at replica=1 costs very little in comparison.

---

## Logs (MinIO Artifact Repository)

Argo stores each step's stdout/stderr as an artifact in MinIO.

- Bucket: `argo-logs` (in-cluster MinIO)
- Logs are visible in the Argo Workflows UI under each workflow run → step → logs tab
- To access the Argo UI locally:

```bash
kubectl port-forward svc/argo-server 2746:2746 -n argo
# Open https://localhost:2746
```

---

## Triggering a Scan

```bash
# Full pipeline (most common)
bash deployment/aws/eks/argo/trigger-scan.sh <scan-run-id> <tenant-id> <account-id>

# Single engine (for re-running one stage)
argo submit deployment/aws/eks/argo/cspm-pipeline.yaml \
  --from workflowtemplate/cspm-single-engine \
  -p scan_run_id=<uuid> \
  -p engine=check \
  -p tenant_id=<tid> \
  -p account_id=<aid> \
  -n argo
```

The `scan_run_id` must already exist in `scan_orchestration` before the workflow is submitted.
The onboarding API creates this row when a scan is initiated via the UI.

---

## Node Placement Summary

| Pod type | Node group | Instance type | Spot? |
|----------|-----------|---------------|-------|
| Engine API Deployments | default on-demand | varies | No |
| Argo controller | argo namespace (on-demand) | — | No |
| Argo step pods | vulnerability-spot-scanners | c5a.2xlarge (16 GB) | Yes |
| Scanner Job pods | vulnerability-spot-scanners | c5a.2xlarge (16 GB) | Yes |

Spot node group: min=0, max=20, scales up when Jobs are submitted.

---

## Common Debugging

```bash
# List all workflow runs (recent first)
argo list -n argo

# Tail logs for a workflow (all steps)
argo logs <workflow-name> -n argo --follow

# Watch workflow progress live
argo watch <workflow-name> -n argo

# Check engine API pod health
kubectl get pods -n threat-engine-engines
kubectl logs -l app=engine-threat -n threat-engine-engines --tail=100

# Check scanner Job pods
kubectl get jobs -n threat-engine-engines
kubectl logs job/<job-name> -n threat-engine-engines

# Scan stuck in 'running'? Check exit handler logs
kubectl logs -l workflows.argoproj.io/workflow=<name> -n argo | grep exit

# Port-forward an engine API for local testing
kubectl port-forward svc/engine-check 8002:80 -n threat-engine-engines

# Check scan status in DB (requires postgres port-forward)
kubectl port-forward svc/postgres 5432:5432 -n threat-engine-engines
# psql -h localhost -U postgres -d threat_engine_onboarding \
#   -c "SELECT scan_run_id, overall_status, engines_completed FROM scan_orchestration ORDER BY created_at DESC LIMIT 5;"
```

---

## Key Files

| File | Purpose |
|------|---------|
| `cspm-pipeline.yaml` | Main Argo WorkflowTemplate (DAG + all step definitions) |
| `trigger-scan.sh` | Shell wrapper to submit a workflow with correct parameters |
| `04-scan-rbac.yaml` | RBAC giving Argo permission to create Jobs in threat-engine-engines ns |
| `00-namespace.yaml` | Namespace definitions |
| `01-install.sh` | Argo installation script |
