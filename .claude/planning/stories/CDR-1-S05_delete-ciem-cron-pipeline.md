# CDR-1-S05: Delete Stale ciem-cron-pipeline.yaml

## Sprint
CDR-1 — Correctness Sprint

## Priority
P2 — Cleanup. The old `ciem-cron-pipeline.yaml` calls `http://engine-ciem/` which does not exist as a deployed service (the engine runs at `engine-cdr`). If this CronWorkflow fires, it will silently fail on every hourly tick and pollute Argo with failed workflow runs.

## Story
As the platform operator, I need the stale `ciem-cron-pipeline.yaml` CronWorkflow deleted from Argo and the file removed from the repo, so that the Argo UI is clean and there are no phantom hourly failures.

## Background

During the CDR/CIEM consolidation, the engine was renamed from `engine-ciem` to `engine-cdr`. The new `cdr-cron-pipeline.yaml` (5-wave DAG with attack-path trigger) is the active pipeline. The old `ciem-cron-pipeline.yaml` was never removed. It calls `http://engine-ciem/api/v1/internal/scan/all` — a service that does not exist — on every hourly schedule.

The CronWorkflow may or may not be installed in the `argo` namespace. Must check before deleting.

## Files to Delete

- `deployment/aws/eks/argo/ciem-cron-pipeline.yaml`

## Steps

### 1. Check if CronWorkflow is installed in Argo

```bash
kubectl get cronworkflow -n argo | grep ciem
```

If it exists:
```bash
kubectl delete cronworkflow ciem-cron-pipeline -n argo
```

Verify deletion:
```bash
kubectl get cronworkflow -n argo
# ciem-cron-pipeline should not appear
```

### 2. Delete the file from repo

```bash
git rm deployment/aws/eks/argo/ciem-cron-pipeline.yaml
```

### 3. Confirm cdr-cron-pipeline is the only CDR-related CronWorkflow

```bash
kubectl get cronworkflow -n argo | grep cdr
# Should show: cdr-cron-pipeline    RUNNING   ...
```

Confirm it is on the correct 5-wave schedule:
```bash
kubectl describe cronworkflow cdr-cron-pipeline -n argo | grep -A5 "Schedule"
# Should show: 0 * * * * (hourly)
```

## Acceptance Criteria

- [ ] `deployment/aws/eks/argo/ciem-cron-pipeline.yaml` deleted from repo
- [ ] `kubectl get cronworkflow -n argo` no longer shows `ciem-cron-pipeline`
- [ ] `kubectl get cronworkflow -n argo` still shows `cdr-cron-pipeline` running
- [ ] No Argo failed workflow runs with `engine-ciem` in logs after deletion
- [ ] Git commit with `git rm` — file gone from history tip

## Security Checklist

- [ ] Confirm `cdr-cron-pipeline.yaml` is the authoritative CDR pipeline before deleting the old one
- [ ] Do not delete `cdr-cron-pipeline.yaml` by mistake

## Definition of Done

- [ ] File deleted via `git rm`
- [ ] CronWorkflow deleted from Argo namespace (if it existed)
- [ ] `kubectl get cronworkflow -n argo` output verified clean
- [ ] Commit pushed to dev branch