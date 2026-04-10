# Docker Image Split Strategy — Per-CSP

## Rationale

The discovery engine was split into per-CSP images to:
1. Keep image sizes small (AWS SDK alone is 200MB+; Azure SDK adds another 150MB)
2. Allow independent versioning and rollout per CSP
3. Limit blast radius of CVEs in CSP-specific SDK layers
4. Enable parallel builds in CI

## Current State

| Image | Tag | Status |
|-------|-----|--------|
| `yadavanup84/engine-discoveries-aws` | `latest` | Deployed (EKS) |
| `yadavanup84/engine-discoveries-azure` | — | Not built yet |
| `yadavanup84/engine-discoveries-gcp` | — | Not built yet |
| `yadavanup84/engine-discoveries-k8s` | — | Not built yet |
| `yadavanup84/engine-discoveries-oci` | — | Not built yet |
| `yadavanup84/engine-discoveries-ibm` | — | Not built yet |
| `yadavanup84/engine-discoveries-alicloud` | — | Not built yet |

## Dockerfile Pattern

Each CSP Dockerfile lives at:
`engines/discoveries/providers/{csp}/Dockerfile`

### Base pattern (all CSPs inherit):
```dockerfile
FROM python:3.11-slim AS base
WORKDIR /app
# Common deps: fastapi, psycopg2, pydantic
COPY engines/discoveries/requirements-base.txt .
RUN pip install --no-cache-dir -r requirements-base.txt

FROM base AS csp-layer
# CSP-specific SDK
COPY engines/discoveries/providers/{csp}/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM csp-layer AS final
COPY engines/discoveries/ ./engines/discoveries/
COPY shared/ ./shared/
RUN adduser --disabled-password --gecos '' appuser && chown -R appuser /app
USER appuser
CMD ["python", "engines/discoveries/run_scan.py"]
```

### Per-CSP SDK packages

| CSP | Key packages |
|-----|-------------|
| AWS | `boto3>=1.34`, `botocore>=1.34` |
| Azure | `azure-mgmt-compute`, `azure-mgmt-network`, `azure-mgmt-storage`, `azure-mgmt-keyvault`, `azure-mgmt-sql`, `azure-identity`, `azure-mgmt-authorization`, `azure-mgmt-containerservice` |
| GCP | `google-cloud-compute`, `google-cloud-storage`, `google-cloud-container`, `google-cloud-iam`, `google-cloud-kms`, `google-api-python-client` |
| K8s | `kubernetes>=28.1` |
| OCI | `oci>=2.120` |
| IBM | `ibm-platform-services`, `ibm-vpc`, `ibm-cloud-sdk-core`, `ibm-boto3` |
| AliCloud | `alibabacloud-ecs20140526`, `alibabacloud-vpc20160428`, `alibabacloud-ram20150501`, `alibabacloud-tea-openapi` |

## Kubernetes Deployment Split

Each CSP gets its own Deployment in `deployment/aws/eks/engines/`:

```
engine-discoveries-aws.yaml     ← already exists
engine-discoveries-azure.yaml   ← to create
engine-discoveries-gcp.yaml     ← to create
engine-discoveries-k8s.yaml     ← to create
engine-discoveries-oci.yaml     ← to create (when creds available)
engine-discoveries-ibm.yaml     ← to create (when creds available)
engine-discoveries-alicloud.yaml ← to create (when creds available)
```

Each Deployment:
- Runs on spot nodes (taint: `spot-scanner=true:NoSchedule`)
- Has CSP-specific secret env vars mounted
- Scales to 0 when not scanning (replicas: 0 in base spec, Argo sets replicas=1)

## Versioning Strategy

Pattern: `{image}:v{major}.{csp}.{date}`
- Example: `yadavanup84/engine-discoveries-azure:v1.azure.20260410`
- Rationale: CSP-specific version tracks which iteration of azure scanner code

For stability, also tag: `{image}:stable` (last known-good per CSP)

## Build Commands

```bash
# AWS (already exists)
docker build -t yadavanup84/engine-discoveries-aws:latest \
  -f engines/discoveries/providers/aws/Dockerfile .

# Azure (to build after code is written)
docker build -t yadavanup84/engine-discoveries-azure:v1.azure.20260410 \
  -f engines/discoveries/providers/azure/Dockerfile .

# GCP
docker build -t yadavanup84/engine-discoveries-gcp:v1.gcp.20260410 \
  -f engines/discoveries/providers/gcp/Dockerfile .

# K8s
docker build -t yadavanup84/engine-discoveries-k8s:v1.k8s.20260410 \
  -f engines/discoveries/providers/k8s/Dockerfile .
```

## Other Engines (Check, IAM, DataSec, etc.)

Other engines currently use a single image serving all CSPs. They are provider-agnostic
at the code level (provider is a query filter, not code path). No split needed until:
- Engine has CSP-specific SDK dependencies (currently none besides discoveries)
- Image size becomes a constraint
- CSP-specific code paths diverge significantly

Exception: If Azure/GCP require different SDK versions that conflict with each other,
consider splitting at that point. For now, keep single image per non-discovery engine.
