# INFRA-01 — Argo MinIO Artifact Bucket Bootstrap
**Sprint**: Infrastructure | **Points**: 2 | **Status**: Ready for Dev

## Problem
All CSPM scan pipelines are failing immediately at the `create-orchestration-record` step with:
```
Error (exit code 1): failed to put file: The specified bucket does not exist
```

Root cause: Argo is configured to use MinIO (`minio.argo.svc.cluster.local:9000`) as its artifact
store, and expects a bucket named `argo-logs`. MinIO was running but the bucket was never created.
This has been blocking ALL pipeline scans (seen in scan_runs table: every recent row has
`overall_status = 'failed'`).

## What Was Done (temporary fix 2026-05-23)
The `argo-logs` bucket was manually created via port-forward + boto3:
```python
s3 = boto3.client("s3", endpoint_url="http://localhost:9000",
                  aws_access_key_id="admin", aws_secret_access_key="password", ...)
s3.create_bucket(Bucket="argo-logs")
```
This unblocked the pipeline (scan `cspm-scan-pipeline-cl997` started running after fix).

## Permanent Fix Required
The bucket creation must be idempotent and survive MinIO pod restarts/redeployments.

### Option A — MinIO bucket init Job (preferred)
Create a one-shot K8s Job that runs after MinIO is ready and creates required buckets:
```yaml
# deployment/aws/eks/argo/minio-bucket-init.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: minio-bucket-init
  namespace: argo
spec:
  template:
    spec:
      containers:
      - name: init
        image: python:3.11-slim
        command: [python3, -c, "...boto3 create_bucket..."]
        env:
        - name: MINIO_ACCESS_KEY
          valueFrom:
            secretKeyRef:
              name: my-minio-cred
              key: accesskey
        - name: MINIO_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: my-minio-cred
              key: secretkey
      restartPolicy: OnFailure
```

### Option B — MinIO init container on workflow-controller
Add an init container to the Argo `workflow-controller` deployment that creates the bucket on startup.

### Option C — MinIO lifecycle config
Configure MinIO with a startup script that creates required buckets automatically.

## Files to Create/Modify
- `deployment/aws/eks/argo/minio-bucket-init.yaml` — one-shot bucket creation Job
- `deployment/aws/eks/argo/README.md` — document that minio-bucket-init must be applied after any MinIO redeploy

## Acceptance Criteria

### Functional
- [ ] `argo-logs` bucket exists in MinIO and persists across MinIO pod restarts
- [ ] New Argo pipeline scan submitted after fix completes `create-orchestration-record` step without error
- [ ] Job is idempotent — running twice does not error

### Infrastructure
- [ ] minio-bucket-init Job is applied to EKS and completes (`kubectl get jobs -n argo`)
- [ ] MinIO pod restart followed by minio-bucket-init re-run still produces a working bucket

### Error Handling  
- [ ] minio-bucket-init Job uses `if_bucket_exists='ignore'` (boto3) so re-runs are safe

## Why This Matters
Every CSPM pipeline scan (discovery → check → threat → compliance → risk) runs via Argo.
Without `argo-logs` bucket, every scan fails at step 1. All `scan_runs.overall_status` rows
were `failed` because of this, including DI sprint validation scans.

## Monitoring
After fix, verify:
```bash
# Submit a test scan
argo submit -n threat-engine-engines --from workflowtemplate/cspm-scan-pipeline \
  --parameter scan-run-id=$(python3 -c "import uuid; print(uuid.uuid4())") \
  --parameter tenant-id=test-tenant-002 \
  --parameter account-id=588989875114 \
  --parameter provider=aws \
  --parameter credential-ref=threat-engine/account/588989875114

# Confirm create-orchestration-record step succeeds (✔ not ✗)
argo get -n threat-engine-engines <workflow-name>
```

## Definition of Done
- [ ] minio-bucket-init.yaml committed and applied to EKS
- [ ] Argo pipeline scan completes `create-orchestration-record` step ✔
- [ ] Manual bucket creation no longer needed after MinIO restart