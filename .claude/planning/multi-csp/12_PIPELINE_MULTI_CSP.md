# Multi-CSP Pipeline Strategy — Argo Workflows

## Design Principle

One Argo WorkflowTemplate per CSP, sharing the same DAG structure.
The AWS pipeline (`cspm-scan-pipeline`) is the reference implementation.
Each CSP pipeline replaces `engine-discoveries-aws` with `engine-discoveries-{csp}`.

All other engines (check, inventory, threat, compliance, iam, datasec) are
CSP-agnostic — they filter by `provider` field in their queries.

## Current State

| Pipeline | File | Status |
|----------|------|--------|
| `cspm-scan-pipeline` (AWS) | `deployment/aws/eks/argo/cspm-pipeline.yaml` | Production |
| `cspm-azure-pipeline` | — | Not created |
| `cspm-gcp-pipeline` | — | Not created |
| `cspm-k8s-pipeline` | — | Not created |
| `cspm-oci-pipeline` | — | Not created (needs creds) |
| `cspm-ibm-pipeline` | — | Not created (needs creds) |
| `cspm-alicloud-pipeline` | — | Not created (needs creds) |

## Pipeline Template per CSP

### Differences from AWS pipeline:
1. Discovery step uses `engine-discoveries-{csp}` image
2. Discovery step mounts `{csp}-creds` secret instead of `aws-creds`
3. `provider` parameter value changes (`azure`, `gcp`, etc.)
4. Check/inventory/threat/compliance steps are IDENTICAL — filter by `provider`

### Shared DAG structure:
```
discovery-{csp}
    └── inventory (provider={csp})
         └── check (provider={csp})
              └── threat (provider={csp})
                   ├── compliance (provider={csp})
                   ├── iam (provider={csp})
                   └── datasec (provider={csp})
```

### Trigger script (multi-CSP):
```bash
# Trigger Azure scan
bash deployment/aws/eks/argo/trigger-scan.sh \
  <scan-run-id> <tenant-id> <account-id> azure

# Trigger GCP scan
bash deployment/aws/eks/argo/trigger-scan.sh \
  <scan-run-id> <tenant-id> <project-id> gcp

# Trigger K8s scan
bash deployment/aws/eks/argo/trigger-scan.sh \
  <scan-run-id> <tenant-id> <cluster-id> k8s
```

The trigger script passes `provider` as a workflow parameter.

## Argo WorkflowTemplate Parameterization

To avoid 7 duplicate YAML files, parameterize the single pipeline:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
metadata:
  name: cspm-scan-pipeline
spec:
  arguments:
    parameters:
      - name: scan-run-id
      - name: tenant-id
      - name: account-id
      - name: provider
        value: "aws"   # default

  templates:
    - name: discovery
      container:
        image: "yadavanup84/engine-discoveries-{{workflow.parameters.provider}}:latest"
        env:
          - name: PROVIDER
            value: "{{workflow.parameters.provider}}"
        # CSP creds injected via envFrom based on provider
        # IMPORTANT: optional: false for real providers (azure, gcp) — silent credential
        # failure with optional: true causes 0-finding scans with no error.
        # K8s uses in_cluster auth — k8s-creds secret is NOT created; handled by
        # the k8s-specific branch below (credential_type=in_cluster sentinel).
        envFrom:
          - secretRef:
              name: "{{workflow.parameters.provider}}-creds"
              optional: false  # hard fail if creds missing — never silently scan with no auth

  # Pre-flight credential validation step (runs before discovery for non-k8s providers)
  # Validates secret exists + is non-empty before committing to a full scan run.
  templates:
    - name: preflight-credential-check
      script:
        image: bitnami/kubectl:latest
        command: [bash]
        source: |
          PROVIDER="{{workflow.parameters.provider}}"
          if [ "$PROVIDER" = "k8s" ]; then
            echo "K8s uses in_cluster auth — no external secret needed. Skipping."
            exit 0
          fi
          kubectl get secret "${PROVIDER}-creds" -n threat-engine-engines > /dev/null 2>&1
          if [ $? -ne 0 ]; then
            echo "ERROR: ${PROVIDER}-creds secret not found. Cannot proceed with scan."
            exit 1
          fi
          echo "Credential secret ${PROVIDER}-creds found. Proceeding."
```

## Parallel Multi-CSP Scanning

To scan multiple CSPs simultaneously for a tenant, submit separate workflows:

```bash
# Submit AWS + Azure + GCP in parallel
for provider in aws azure gcp; do
  argo submit deployment/aws/eks/argo/cspm-pipeline.yaml \
    -p scan-run-id=$(uuidgen) \
    -p tenant-id=$TENANT_ID \
    -p account-id=$ACCOUNT_ID \
    -p provider=$provider \
    -n argo
done
```

Each workflow is independent — no cross-CSP dependencies.
The `scan_runs` table tracks each separately by `scan_run_id`.

## scan_orchestration Schema Support

The `scan_runs` table already has `provider` column. A multi-CSP scan
generates one `scan_run_id` per provider. The UI summary aggregates
across all `scan_run_id`s for a tenant.

```sql
-- Multi-CSP scan overview
SELECT provider, overall_status, COUNT(*) as resource_count
FROM scan_runs
WHERE tenant_id = 'abc123'
  AND started_at >= NOW() - INTERVAL '24 hours'
GROUP BY provider, overall_status;
```

## Implementation Sequence

### Phase 1: Parameterize AWS pipeline (no new CSP work)
- Modify `cspm-pipeline.yaml` to accept `provider` parameter
- Change discovery step image to `engine-discoveries-{{provider}}`
- Change secret ref to `{{provider}}-creds`
- Test: submit with `provider=aws` (existing behavior, no regression)

### Phase 2: Azure (credentials available)
- Build `engine-discoveries-azure` image
- Create `azure-creds` K8s secret
- Submit pipeline with `provider=azure`
- Validate full DAG runs (check/inventory/threat filter by `provider=azure`)

### Phase 3: GCP (credentials available)
- Build `engine-discoveries-gcp` image
- Create `gcp-creds` K8s secret
- Submit with `provider=gcp`

### Phase 4: K8s (EKS dogfood)
- Build `engine-discoveries-k8s` image (uses in-cluster ServiceAccount)
- No external secret needed — uses cluster RBAC
- Submit with `provider=k8s`

### Phase 5-7: OCI, IBM, AliCloud
- Pending credential provisioning
- Follow same pattern as Phase 2

## onboarding Integration

The onboarding engine should:
1. Receive account credentials from UI
2. Store in K8s secret (`{provider}-creds`)
3. Trigger appropriate pipeline with `provider` parameter
4. No hardcoding of AWS — generic across all CSPs

File to update: `engines/onboarding/` (dispatch logic, secret creation)
