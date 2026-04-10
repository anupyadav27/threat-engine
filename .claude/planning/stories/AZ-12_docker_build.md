---
story_id: AZ-12
title: Build engine-discoveries-azure Docker Image + Deploy to EKS
status: done
sprint: azure-track-wave-6
depends_on: [AZ-05, SHARED-02]
blocks: [AZ-13]
sme: DevOps
estimate: 1 day
---

# Story: Build engine-discoveries-azure Docker Image + Deploy to EKS

## Context
The Azure discovery scanner runs as a separate K8s Deployment (`engine-discoveries-azure`) so it doesn't bloat the AWS image with azure-mgmt-* packages. The image follows the 3-stage Docker build from SHARED-02.

## Files to Create/Modify

- `engines/discoveries/providers/azure/Dockerfile` — per-CSP image
- `deployment/aws/eks/engines/engine-discoveries-azure.yaml` — K8s Deployment + Service

## Implementation Notes

**Dockerfile:**
```dockerfile
FROM python:3.11-slim AS base
WORKDIR /app
COPY engines/discoveries/requirements-base.txt .
RUN pip install --no-cache-dir -r requirements-base.txt

FROM base AS azure-sdk
COPY engines/discoveries/providers/azure/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM azure-sdk AS final
COPY engines/discoveries/ ./engines/discoveries/
COPY shared/ ./shared/
COPY catalog/azure/ ./catalog/azure/
RUN adduser --disabled-password --gecos '' appuser \
    && chown -R appuser /app
USER appuser
CMD ["python", "engines/discoveries/run_scan.py"]
```

Build context is REPO ROOT (not engines/discoveries/) — same as AWS.

**K8s Deployment manifest mirrors** `deployment/aws/eks/engines/engine-discoveries.yaml` with:
- `app: engine-discoveries-azure`
- `image: yadavanup84/engine-discoveries-azure:v1.azure.YYYYMMDD`
- `envFrom.secretRef.name: azure-creds` (NOT optional — `optional: false`)
- Same resource requests/limits as AWS discovery
- Same spot node tolerations

**Image tag format:** `v1.azure.YYYYMMDD` (e.g., `v1.azure.20260409`)

## Acceptance Criteria
- [ ] `docker build -t yadavanup84/engine-discoveries-azure:v1.azure.20260409 -f engines/discoveries/providers/azure/Dockerfile .` succeeds from repo root
- [ ] `docker run --rm yadavanup84/engine-discoveries-azure:v1.azure.20260409 python -c 'from engines.discoveries.providers.azure.scanner.service_scanner import AzureDiscoveryScanner; print("OK")'` prints OK
- [ ] K8s manifest applied: `kubectl apply -f deployment/aws/eks/engines/engine-discoveries-azure.yaml`
- [ ] `kubectl get deployment engine-discoveries-azure -n threat-engine-engines` shows READY
- [ ] `GET http://engine-discoveries-azure/api/v1/health/live` returns 200

## Definition of Done
- [ ] Image pushed to registry
- [ ] K8s deployment rolling out
- [ ] Health check passing
- [ ] `optional: false` confirmed on `azure-creds` secretRef