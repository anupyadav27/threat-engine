---
story_id: SHARED-06
title: Fix Argo Discovery URL to be Provider-Dynamic
status: done
sprint: azure-track-wave-1
depends_on: []
blocks: [AZ-13]
sme: DevOps
estimate: 0.5 days
---

# Story: Fix Argo Discovery URL to be Provider-Dynamic

## Context
`cspm-pipeline.yaml` currently hardcodes `http://engine-discoveries/` as the discovery service URL. With per-CSP images deployed as separate K8s Services (`engine-discoveries-aws`, `engine-discoveries-azure`, etc.), the URL must be dynamic based on the `provider` workflow parameter.

## Files to Modify

- `deployment/aws/eks/argo/cspm-pipeline.yaml`

## Implementation Notes

Find the discovery step (search for `http://engine-discoveries`) and change to:
```yaml
# Before:
url: "http://engine-discoveries/api/v1/scan"

# After:
url: "http://engine-discoveries-{{workflow.parameters.provider}}/api/v1/scan"
```

Also ensure the `provider` parameter has a default value of `"aws"` so existing AWS scans are unaffected:
```yaml
arguments:
  parameters:
    - name: provider
      value: "aws"   # default — existing AWS scans use this
```

**K8s Service naming must match:**
- `engine-discoveries-aws` → existing AWS service (may need rename if currently `engine-discoveries`)
- `engine-discoveries-azure` → created in AZ-12

Check if current AWS service is named `engine-discoveries` or `engine-discoveries-aws`:
```bash
kubectl get svc -n threat-engine-engines | grep discoveries
```
If it's `engine-discoveries`, either rename to `engine-discoveries-aws` or add an alias service.

## Acceptance Criteria
- [ ] `argo submit ... -p provider=aws` routes to `engine-discoveries-aws` service
- [ ] `argo submit ... -p provider=azure` routes to `engine-discoveries-azure` service
- [ ] Dry-run `--dry-run=client` shows correct URL substitution
- [ ] Existing AWS scan still completes successfully (regression)

## Definition of Done
- [ ] YAML updated
- [ ] AWS K8s service naming verified/aligned
- [ ] Dry-run confirms URL routing